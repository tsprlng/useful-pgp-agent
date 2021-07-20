// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! These tests rely mainly on the card-app abstraction layer in
//! openpgp-card. However, for crypto-operations, higher level APIs and
//! Sequoia PGP are used.
//!
//! The main purpose of this test suite is to be able to test the behavior
//! of different OpenPGP card implementation.
//!
//! These tests assert (and fail) in cases where a certain behavior is
//! expected from all cards, and a card doesn't conform.
//! However, in some aspects, card behavior is expected to diverge, and
//! it's not ok for us to just fail and reject the card's output.
//! Even when it contradicts the OpenPGP card spec.
//!
//! For such cases, these tests return a TestOutput, which is a
//! Vec<TestResult>, to document the return values of the card in question.
//!
//! e.g.: the Yubikey 5 fails to handle the VERIFY command with empty data
//! (see OpenPGP card spec, 7.2.2: "If the command is called
//! without data, the actual access status of the addressed password is
//! returned or the access status is set to 'not verified'").
//!
//! The Yubikey 5 erroneously returns Status 0x6a80 ("Incorrect parameters in
//! the command data field").

use anyhow::{anyhow, Error, Result};
use thiserror::Error;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Cert;

use openpgp_card::apdu::PcscClient;
use openpgp_card::card_app::CardApp;
use openpgp_card::errors::{OcErrorStatus, OpenpgpCardError};
use openpgp_card::{CardClientBox, Sex};
use openpgp_card_scdc::ScdClient;

mod util;

#[derive(Debug)]
enum TestCard {
    Pcsc(&'static str),
    Scdc(&'static str),
}

impl TestCard {
    fn open(&self) -> Result<CardApp> {
        match self {
            Self::Pcsc(ident) => {
                for card in PcscClient::list_cards()? {
                    let card_client = Box::new(card) as CardClientBox;
                    let mut ca = CardApp::new(card_client);

                    // Select OpenPGP applet
                    let res = ca.select()?;
                    res.check_ok()?;

                    // Set Card Capabilities (chaining, command length, ..)
                    let ard = ca.get_app_data()?;
                    ca = ca.init_caps(&ard)?;

                    let app_id = CardApp::get_aid(&ard)?;

                    if &app_id.ident().as_str() == ident {
                        // println!("opened pcsc card {}", ident);

                        return Ok(ca);
                    }
                }

                Err(anyhow!("Pcsc card {} not found", ident))
            }
            Self::Scdc(serial) => {
                // FIXME
                const SOCKET: &str = "/run/user/1000/gnupg/S.scdaemon";

                let mut card = ScdClient::new(SOCKET)?;
                card.select_card(serial)?;

                let card_client = Box::new(card) as CardClientBox;

                let mut ca = CardApp::new(card_client);

                // Set Card Capabilities (chaining, command length, ..)
                let ard = ca.get_app_data()?;
                ca = ca.init_caps(&ard)?;

                // println!("opened scdc card {}", serial);

                Ok(ca)
            }
        }
    }
}

#[derive(Debug)]
enum TestResult {
    Status([u8; 2]),
    Text(String),
}

type TestOutput = Vec<TestResult>;

#[derive(Error, Debug)]
pub enum TestError {
    #[error("Failed to upload key {0} ({1})")]
    KeyUploadError(String, Error),

    #[error(transparent)]
    OPGP(#[from] OpenpgpCardError),

    #[error(transparent)]
    OCard(#[from] OcErrorStatus),

    #[error(transparent)]
    Other(#[from] anyhow::Error), // source and Display delegate to anyhow::Error
}

/// Run after each "upload keys", if key *was* uploaded (?)
fn test_decrypt(
    mut ca: &mut CardApp,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    assert_eq!(
        param.len(),
        2,
        "test_decrypt needs filenames for 'cert' and 'encrypted'"
    );

    let cert = Cert::from_file(param[0])?;
    let msg =
        std::fs::read_to_string(param[1]).expect("Unable to read ciphertext");

    let res = ca.verify_pw1("123456")?;
    res.check_ok()?;

    let res = openpgp_card_sequoia::decrypt(&mut ca, &cert, msg.into_bytes())?;
    let plain = String::from_utf8_lossy(&res);

    assert_eq!(plain, "Hello world!\n");

    Ok(vec![])
}

/// Run after each "upload keys", if key *was* uploaded (?)
fn test_sign(
    mut ca: &mut CardApp,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    assert_eq!(param.len(), 1, "test_sign needs a filename for 'cert'");

    let res = ca.verify_pw1_for_signing("123456")?;
    res.check_ok()?;

    let cert = Cert::from_file(param[0])?;

    let msg = "Hello world, I am signed.";
    let sig = openpgp_card_sequoia::sign(&mut ca, &cert, &mut msg.as_bytes())?;

    // validate sig
    assert!(util::verify_sig(&cert, msg.as_bytes(), sig.as_bytes())?);

    Ok(vec![])
}

fn check_key_upload_metadata(
    ca: &mut CardApp,
    meta: &[(String, u32)],
) -> Result<()> {
    let ard = ca.get_app_data()?;

    // check fingerprints
    let card_fp = CardApp::get_fingerprints(&ard)?;

    let sig = card_fp.signature().expect("signature fingerprint");
    assert_eq!(format!("{:X}", sig), meta[0].0);

    let dec = card_fp.decryption().expect("decryption fingerprint");
    assert_eq!(format!("{:X}", dec), meta[1].0);

    let auth = card_fp
        .authentication()
        .expect("authentication fingerprint");
    assert_eq!(format!("{:X}", auth), meta[2].0);

    // get_key_generation_times
    let card_kg = CardApp::get_key_generation_times(&ard)?;

    let sig: u32 =
        card_kg.signature().expect("signature creation time").into();
    assert_eq!(sig, meta[0].1);

    let dec: u32 = card_kg
        .decryption()
        .expect("decryption creation time")
        .into();
    assert_eq!(dec, meta[1].1);

    let auth: u32 = card_kg
        .authentication()
        .expect("authentication creation time")
        .into();
    assert_eq!(auth, meta[2].1);

    Ok(())
}

fn check_key_upload_algo_attrs() -> Result<()> {
    // get_algorithm_attributes
    // FIXME

    Ok(())
}

fn test_upload_keys(
    ca: &mut CardApp,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    assert_eq!(
        param.len(),
        1,
        "test_upload_keys needs a filename for 'cert'"
    );

    let verify = ca.verify_pw3("12345678")?;
    verify.check_ok()?;

    let cert = Cert::from_file(param[0])?;

    let meta = util::upload_subkeys(ca, &cert)
        .map_err(|e| TestError::KeyUploadError(param[0].to_string(), e))?;

    check_key_upload_metadata(ca, &meta)?;

    // FIXME: implement
    check_key_upload_algo_attrs()?;

    Ok(vec![])
}

fn test_keygen() {
    // FIXME
    // (implementation of this functionality is still missing in openpgp-card)
    unimplemented!()
}

fn test_reset(
    ca: &mut CardApp,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    let _res = ca.factory_reset()?;
    Ok(vec![])
}

/// Sets name, lang, sex, url; then reads the fields from the card and
/// compares the values with the expected values.
///
/// Returns an empty TestOutput, throws errors for unexpected Status codes
/// and for unequal field values.
fn test_set_user_data(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let res = ca.verify_pw3("12345678")?;
    res.check_ok()?;

    // name
    let res = ca.set_name("Bar<<Foo")?;
    res.check_ok()?;

    // lang
    let res = ca.set_lang("deen")?;
    res.check_ok()?;

    // sex
    let res = ca.set_sex(Sex::Female)?;
    res.check_ok()?;

    // url
    let res = ca.set_url("https://duckduckgo.com/")?;
    res.check_ok()?;

    // read all the fields back again, expect equal data
    let ch = ca.get_cardholder_related_data()?;

    assert_eq!(ch.name, Some("Bar<<Foo".to_string()));
    assert_eq!(ch.lang, Some(vec![['d', 'e'], ['e', 'n']]));
    assert_eq!(ch.sex, Some(Sex::Female));

    let url = ca.get_url()?;
    assert_eq!(url, "https://duckduckgo.com/".to_string());

    Ok(vec![])
}

/// Outputs:
/// - verify pw3 (check) -> Status
/// - verify pw1 (check) -> Status
fn test_verify(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    // Steps:
    //
    // - try to set name without verify, assert result is not ok
    // - verify pw3 + pin -> Status
    // - verify pw3 (check) -> Status
    // - set name -> Status
    // - get name -> Text(name)
    // - verify pw1 + pin -> Status
    // - verify pw1 (check) -> Status
    // - set name -> Status
    // - get name -> Text(name)

    let mut out = vec![];

    // try to set name without verify, assert result is not ok!
    let res = ca.set_name("Notverified<<Hello")?;
    assert_eq!(res.status(), [0x69, 0x82]); // "Security status not satisfied"

    let res = ca.verify_pw3("12345678")?;
    res.check_ok()?;

    let check = ca.check_pw3()?;
    // don't "check_ok()" - yubikey5 returns an error code!
    out.push(TestResult::Status(check.status()));

    let res = ca.set_name("Admin<<Hello")?;
    res.check_ok()?;

    let cardholder = ca.get_cardholder_related_data()?;
    assert_eq!(cardholder.name, Some("Admin<<Hello".to_string()));

    let res = ca.verify_pw1("123456")?;
    res.check_ok()?;

    let check = ca.check_pw3()?;
    // don't "check_ok()" - yubikey5 returns an error code
    out.push(TestResult::Status(check.status()));

    let res = ca.set_name("There<<Hello")?;
    res.check_ok()?;

    let cardholder = ca.get_cardholder_related_data()?;
    assert_eq!(cardholder.name, Some("There<<Hello".to_string()));

    Ok(out)
}

fn run_test(
    card: &mut TestCard,
    t: fn(&mut CardApp, &[&str]) -> Result<TestOutput, TestError>,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    println!();
    println!("Test card {:?}", card);

    let mut ca = card.open()?;

    let ard = ca.get_app_data()?;

    let app_id = CardApp::get_aid(&ard)?;

    println!("Running Test on {}:", app_id.ident());

    t(&mut ca, param)
}

fn main() -> Result<()> {
    env_logger::init();

    let cards = vec![
        // TestCard::Scdc("D276000124010200FFFEF1420A7A0000"), /* Gnuk emulated */
        // TestCard::Scdc("D2760001240103040006160191800000"), /* Yubikey 5 */
        // TestCard::Scdc("D27600012401030400050000A8350000"), /* FLOSS Card 3.4 */
        // TestCard::Scdc("D276000124010200FFFE571831460000"), /* Gnuk Rysim (green) */
        // TestCard::Scdc("D276000124010200FFFE4231EB6E0000"), /* Gnuk FST */
        TestCard::Pcsc("0006:16019180"), /* Yubikey 5 */
        TestCard::Pcsc("0005:0000A835"), /* FLOSS Card 3.4 */
        TestCard::Pcsc("FFFE:57183146"), /* Gnuk Rysim (green) */
        TestCard::Pcsc("FFFE:4231EB6E"), /* Gnuk FST */
    ];

    for mut card in cards {
        println!("reset");
        let _ = run_test(&mut card, test_reset, &[])?;

        println!("verify");
        let verify_out = run_test(&mut card, test_verify, &[])?;
        println!("{:x?}", verify_out);

        println!("set user data");
        let userdata_out = run_test(&mut card, test_set_user_data, &[])?;
        println!("{:x?}", userdata_out);

        for (key, ciphertext) in [
            ("data/rsa2k.sec", "data/encrypted_to_rsa2k.asc"),
            ("data/rsa4k.sec", "data/encrypted_to_rsa4k.asc"),
            ("data/25519.sec", "data/encrypted_to_25519.asc"),
            ("data/nist256.sec", "data/encrypted_to_nist256.asc"),
            ("data/nist521.sec", "data/encrypted_to_nist521.asc"),
        ] {
            // upload keys
            println!("Upload key '{}'", key);
            let upload_res = run_test(&mut card, test_upload_keys, &[key]);

            if let Err(TestError::KeyUploadError(s, _)) = upload_res {
                // The card doesn't support this key type, so skip to the
                // next key - don't try to decrypt/sign for this key.

                println!(
                    "Upload of key {} to card {:?} failed -> skip",
                    key, card
                );
                continue;
            }

            let upload_out = upload_res?;
            println!("{:x?}", upload_out);
            println!();

            // decrypt
            println!("Decrypt");
            let dec_out =
                run_test(&mut card, test_decrypt, &[key, ciphertext])?;
            println!("{:x?}", dec_out);
            println!();

            // sign
            println!("Sign");
            let sign_out = run_test(&mut card, test_sign, &[key])?;
            println!("{:x?}", sign_out);
            println!();
        }

        // FIXME: generate keys

        // FIXME: upload key with password
    }

    Ok(())
}
