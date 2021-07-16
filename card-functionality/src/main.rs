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

use anyhow::Result;
use std::collections::HashMap;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Cert;

use openpgp_card::apdu::PcscClient;
use openpgp_card::card_app::CardApp;
use openpgp_card::{CardClientBox, KeyType, Sex};

mod util;

#[derive(Debug)]
enum TestResult {
    Status([u8; 2]),
    Text(String),
}

type TestOutput = Vec<TestResult>;

/// Map: Card ident -> TestOutput
type TestsOutput = HashMap<String, TestOutput>;

/// Run after each "upload keys", if key *was* uploaded (?)
fn test_decrypt() {
    // FIXME
    unimplemented!()
}

/// Run after each "upload keys", if key *was* uploaded (?)
fn test_sign() {
    // FIXME
    unimplemented!()
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

fn test_upload_keys_rsa_2k(ca: &mut CardApp) -> Result<TestOutput> {
    let verify = ca.verify_pw3("12345678")?;
    verify.check_ok()?;

    let cert = Cert::from_file("data/rsa2k.sec")?;
    let meta = util::upload_subkeys(ca, &cert)?;

    check_key_upload_metadata(ca, &meta)?;
    check_key_upload_algo_attrs()?;

    Ok(vec![])
}

fn test_upload_keys_25519() {
    // FIXME
    unimplemented!()

    // check if card supports 25519, if not that's ok, return this
    // information and don't try upload.

    // upload key

    // test upload general - checks
}

fn test_keygen() {
    // FIXME
    // (implementation of this functionality is still missing in openpgp-card)
    unimplemented!()
}

fn test_reset(ca: &mut CardApp) -> Result<TestOutput> {
    let res = ca.factory_reset()?;
    Ok(vec![])
}

/// Sets name, lang, sex, url; then reads the fields from the card and
/// compares the values with the expected values.
///
/// Returns an empty TestOutput, throws errors for unexpected Status codes
/// and for unequal field values.
fn test_set_user_data(ca: &mut CardApp) -> Result<TestOutput> {
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
fn test_verify(ca: &mut CardApp) -> Result<TestOutput> {
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
    cards: &[&str],
    t: fn(&mut CardApp) -> Result<TestOutput>,
) -> Result<TestsOutput> {
    let mut out = HashMap::new();

    for card in PcscClient::list_cards()? {
        let card_client = Box::new(card) as CardClientBox;

        let mut ca = CardApp::new(card_client);

        // Select OpenPGP applet
        let res = ca.select()?;
        res.check_ok()?;

        // Set Card Capabilities (chaining, command length, ..)
        let ard = ca.get_app_data()?;
        ca = ca.init_caps(&ard)?;

        let ard = ca.get_app_data()?;
        let app_id = CardApp::get_aid(&ard)?;

        if cards.contains(&app_id.ident().as_str()) {
            println!("Running Test on {}:", app_id.ident());

            let res = t(&mut ca);

            out.insert(app_id.ident(), res?);
        }
    }

    Ok(out)
}

fn main() -> Result<()> {
    env_logger::init();

    // list of card idents to runs the tests on
    let cards = vec![
        "0006:16019180", /* Yubikey 5 */
        "0005:0000A835", /* FLOSS Card 3.4 */
        "FFFE:57183146", /* Gnuk Rysim (green) */

                         // "FFFE:4231EB6E", /* Gnuk FST */
    ];

    // println!("reset");
    // let _ = run_test(&cards, test_reset)?;
    //
    // println!("verify");
    // let verify_out = run_test(&cards, test_verify)?;
    // println!("{:x?}", verify_out);
    //
    // println!("set user data");
    // let userdata_out = run_test(&cards, test_set_user_data)?;
    // println!("{:x?}", userdata_out);

    // upload RSA keys
    println!("upload RSA2k key");
    let upload_out = run_test(&cards, test_upload_keys_rsa_2k)?;
    println!("{:x?}", upload_out);

    // sign
    // decrypt

    // upload 25519 keys
    // sign
    // decrypt

    // upload some key with pw

    Ok(())
}
