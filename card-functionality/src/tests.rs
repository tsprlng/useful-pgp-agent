// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{Error, Result};
use std::convert::TryInto;
use std::time::SystemTime;
use thiserror::Error;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::types::Timestamp;
use sequoia_openpgp::Cert;

use openpgp_card::card_app::CardApp;
use openpgp_card::errors::{OcErrorStatus, OpenpgpCardError};
use openpgp_card::{
    Algo, Curve, EccAttrs, EccType, KeyType, PublicKeyMaterial, RsaAttrs, Sex,
};

use crate::cards::{TestCard, TestConfig};
use crate::util;

#[derive(Debug)]
pub enum TestResult {
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
pub fn test_decrypt(
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
pub fn test_sign(
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

/// Generate keys for each of the three KeyTypes
pub fn test_keygen(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let verify = ca.verify_pw3("12345678")?;
    verify.check_ok()?;

    // RSA 1024, e=17
    let rsa1k = Algo::Rsa(RsaAttrs {
        len_n: 1024,
        len_e: 17,
        import_format: 0,
    });

    // RSA 2048, e=17
    let rsa2k = Algo::Rsa(RsaAttrs {
        len_n: 2048,
        len_e: 17,
        import_format: 0,
    });

    // RSA 3072, e=17
    let rsa3k = Algo::Rsa(RsaAttrs {
        len_n: 3072,
        len_e: 17,
        import_format: 0,
    });

    // RSA 4096, e=32
    let rsa4k = Algo::Rsa(RsaAttrs {
        len_n: 4096,
        len_e: 32,
        import_format: 0,
    });

    // ed25519 sign
    let ed25519 = Algo::Ecc(EccAttrs {
        ecc_type: EccType::EdDSA,
        curve: Curve::Ed25519,
        import_format: None,
    });

    // cv25519 dec
    let cv25519 = Algo::Ecc(EccAttrs {
        ecc_type: EccType::ECDH,
        curve: Curve::Cv25519,
        import_format: None,
    });

    // nist256 sig, auth
    let nist256_ecdsa = Algo::Ecc(EccAttrs {
        ecc_type: EccType::ECDSA,
        curve: Curve::NistP256r1,
        import_format: None,
    });

    // nist256 dec
    let nist256_ecdh = Algo::Ecc(EccAttrs {
        ecc_type: EccType::ECDH,
        curve: Curve::NistP256r1,
        import_format: None,
    });

    let fp =
        |pkm: &PublicKeyMaterial, ts: SystemTime, kt: KeyType, algo: &Algo| {
            // FIXME: store creation timestamp

            let key =
                openpgp_card_sequoia::public_key_material_to_key(pkm, kt, ts)?;

            let fp = key.fingerprint();
            let fp = fp.as_bytes();
            assert_eq!(fp.len(), 20);

            Ok(fp.try_into().unwrap())
        };

    // ------

    let (pkm, ts) =
        ca.generate_key(fp, KeyType::Signing, Some(&nist256_ecdsa))?;
    let key_sig = openpgp_card_sequoia::public_key_material_to_key(
        &pkm,
        KeyType::Signing,
        SystemTime::from(Timestamp::from(ts)),
    )?;

    println!("key sig: {:?}", key_sig);

    // ------

    let (pkm, ts) =
        ca.generate_key(fp, KeyType::Decryption, Some(&nist256_ecdh))?;
    let key_dec = openpgp_card_sequoia::public_key_material_to_key(
        &pkm,
        KeyType::Decryption,
        SystemTime::from(Timestamp::from(ts)),
    )?;

    println!("key dec: {:?}", key_dec);

    // ------

    let (pkm, ts) =
        ca.generate_key(fp, KeyType::Authentication, Some(&nist256_ecdsa))?;
    let key_aut = openpgp_card_sequoia::public_key_material_to_key(
        &pkm,
        KeyType::Authentication,
        SystemTime::from(Timestamp::from(ts)),
    )?;

    println!("key auth: {:?}", key_aut);

    // ---- make cert

    unimplemented!("return Cert as text");

    Ok(vec![])
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

pub fn run_test(
    card: &mut TestCard,
    t: fn(&mut CardApp, &[&str]) -> Result<TestOutput, TestError>,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut ca = card.open()?;
    let ard = ca.get_app_data()?;
    let _app_id = CardApp::get_aid(&ard)?;

    t(&mut ca, param)
}
