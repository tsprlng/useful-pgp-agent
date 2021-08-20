// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{Error, Result};
use std::str::FromStr;
use std::string::FromUtf8Error;
use thiserror::Error;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::Timestamp;
use sequoia_openpgp::Cert;

use openpgp_card::algorithm::AlgoSimple;
use openpgp_card::card_app::CardApp;
use openpgp_card::errors::{OcErrorStatus, OpenpgpCardError};
use openpgp_card::{KeyType, Sex};
use openpgp_card_sequoia::{
    make_cert, public_key_material_to_key, public_to_fingerprint,
};

use crate::cards::TestCardApp;
use crate::util;

#[derive(Debug)]
pub enum TestResult {
    Status(OcErrorStatus),
    StatusOk,
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

    #[error(transparent)]
    Utf8Error(#[from] FromUtf8Error),
}

/// Run after each "upload keys", if key *was* uploaded (?)
pub fn test_decrypt(
    mut ca: &mut CardApp,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    assert_eq!(
        param.len(),
        2,
        "test_decrypt needs filenames for 'cert' and 'encrypted'"
    );

    let cert = Cert::from_str(param[0])?;
    let msg = param[1].to_string();

    ca.verify_pw1("123456")?;

    let res = openpgp_card_sequoia::decrypt(&mut ca, &cert, msg.into_bytes())?;
    let plain = String::from_utf8_lossy(&res);

    assert_eq!(plain, "Hello world!\n");

    Ok(vec![])
}

/// Run after each "upload keys", if key *was* uploaded (?)
pub fn test_sign(
    mut ca: &mut CardApp,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    assert_eq!(param.len(), 1, "test_sign needs a filename for 'cert'");

    ca.verify_pw1_for_signing("123456")?;

    let cert = Cert::from_str(param[0])?;

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

pub fn test_print_caps(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let ard = ca.get_app_data()?;

    let hist = CardApp::get_historical(&ard)?;
    println!("hist: {:#?}", hist);

    let ecap = CardApp::get_extended_capabilities(&ard)?;
    println!("ecap: {:#?}", ecap);

    let eli = CardApp::get_extended_length_information(&ard)?;
    println!("eli: {:#?}", eli);

    Ok(vec![])
}

pub fn test_print_algo_info(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let ard = ca.get_app_data()?;

    let dec = CardApp::get_algorithm_attributes(&ard, KeyType::Decryption)?;
    println!("Current algorithm for the decrypt slot: {}", dec);

    println!();

    let algo = ca.list_supported_algo();
    if let Ok(Some(algo)) = algo {
        println!("Card algorithm list:\n{}", algo);
    }

    Ok(vec![])
}

pub fn test_upload_keys(
    ca: &mut CardApp,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    assert_eq!(
        param.len(),
        1,
        "test_upload_keys needs a filename for 'cert'"
    );

    ca.verify_pw3("12345678")?;

    let cert = Cert::from_file(param[0])?;

    let meta = util::upload_subkeys(ca, &cert)
        .map_err(|e| TestError::KeyUploadError(param[0].to_string(), e))?;

    check_key_upload_metadata(ca, &meta)?;

    // FIXME: implement
    check_key_upload_algo_attrs()?;

    Ok(vec![])
}

/// Generate keys for each of the three KeyTypes
pub fn test_keygen(
    ca: &mut CardApp,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    ca.verify_pw3("12345678")?;

    // Generate all three subkeys on card
    let algo = param[0];

    let alg = AlgoSimple::from(algo);

    let (pkm, ts) =
        ca.generate_key_simple(public_to_fingerprint, KeyType::Signing, alg)?;
    let key_sig = public_key_material_to_key(
        &pkm,
        KeyType::Signing,
        Timestamp::from(ts).into(),
    )?;

    let (pkm, ts) = ca.generate_key_simple(
        public_to_fingerprint,
        KeyType::Decryption,
        alg,
    )?;
    let key_dec = public_key_material_to_key(
        &pkm,
        KeyType::Decryption,
        Timestamp::from(ts).into(),
    )?;

    let (pkm, ts) = ca.generate_key_simple(
        public_to_fingerprint,
        KeyType::Authentication,
        alg,
    )?;
    let key_aut = public_key_material_to_key(
        &pkm,
        KeyType::Authentication,
        Timestamp::from(ts).into(),
    )?;

    // Generate a Cert for this set of generated keys

    let cert = make_cert(ca, key_sig, key_dec, key_aut)?;
    let armored = String::from_utf8(cert.armored().to_vec()?)?;

    let res = TestResult::Text(armored);

    Ok(vec![res])
}

/// Construct public key based on data from the card
pub fn test_get_pub(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let ard = ca.get_app_data()?;
    let key_gen = CardApp::get_key_generation_times(&ard)?;

    // --

    let sig = ca.get_pub_key(KeyType::Signing)?;
    let ts = Timestamp::from(key_gen.signature().unwrap().get()).into();
    let key = openpgp_card_sequoia::public_key_material_to_key(
        &sig,
        KeyType::Signing,
        ts,
    )?;

    println!(" sig key data from card -> {:x?}", key);

    // --

    let dec = ca.get_pub_key(KeyType::Decryption)?;
    let ts = Timestamp::from(key_gen.decryption().unwrap().get()).into();
    let key = openpgp_card_sequoia::public_key_material_to_key(
        &dec,
        KeyType::Decryption,
        ts,
    )?;

    println!(" dec key data from card -> {:x?}", key);

    // --

    let auth = ca.get_pub_key(KeyType::Authentication)?;
    let ts = Timestamp::from(key_gen.authentication().unwrap().get()).into();
    let key = openpgp_card_sequoia::public_key_material_to_key(
        &auth,
        KeyType::Authentication,
        ts,
    )?;

    println!(" auth key data from card -> {:x?}", key);

    // FIXME: assert that key FP is equal to FP from card

    // ca.generate_key(fp, KeyType::Decryption)?;
    // ca.generate_key(fp, KeyType::Authentication)?;

    Ok(vec![])
}

pub fn test_reset(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let _res = ca.factory_reset()?;
    Ok(vec![])
}

/// Sets name, lang, sex, url; then reads the fields from the card and
/// compares the values with the expected values.
///
/// Returns an empty TestOutput, throws errors for unexpected Status codes
/// and for unequal field values.
pub fn test_set_user_data(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    ca.verify_pw3("12345678")?;

    // name
    ca.set_name("Bar<<Foo")?;

    // lang
    ca.set_lang("deen")?;

    // sex
    ca.set_sex(Sex::Female)?;

    // url
    ca.set_url("https://duckduckgo.com/")?;

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
pub fn test_verify(
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
    let res = ca.set_name("Notverified<<Hello");

    if let Err(OpenpgpCardError::OcStatus(s)) = res {
        assert_eq!(s, OcErrorStatus::SecurityStatusNotSatisfied);
    } else {
        panic!("Status should be 'SecurityStatusNotSatisfied'");
    }

    ca.verify_pw3("12345678")?;

    match ca.check_pw3() {
        Err(OpenpgpCardError::OcStatus(s)) => {
            // e.g. yubikey5 returns an error status!
            out.push(TestResult::Status(s));
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => out.push(TestResult::StatusOk),
    }

    ca.set_name("Admin<<Hello")?;

    let cardholder = ca.get_cardholder_related_data()?;
    assert_eq!(cardholder.name, Some("Admin<<Hello".to_string()));

    ca.verify_pw1("123456")?;

    match ca.check_pw3() {
        Err(OpenpgpCardError::OcStatus(s)) => {
            // e.g. yubikey5 returns an error status!
            out.push(TestResult::Status(s));
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => out.push(TestResult::StatusOk),
    }

    ca.set_name("There<<Hello")?;

    let cardholder = ca.get_cardholder_related_data()?;
    assert_eq!(cardholder.name, Some("There<<Hello".to_string()));

    Ok(out)
}

pub fn run_test(
    card: &mut TestCardApp,
    t: fn(&mut CardApp, &[&str]) -> Result<TestOutput, TestError>,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut ca = card.get_card_app()?;
    let ard = ca.get_app_data()?;
    let _app_id = CardApp::get_aid(&ard)?;

    t(&mut ca, param)
}
