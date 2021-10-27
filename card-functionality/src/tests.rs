// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use std::str::FromStr;
use std::string::FromUtf8Error;
use thiserror;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::{NullPolicy, StandardPolicy};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::Cert;

use openpgp_card;
use openpgp_card::algorithm::AlgoSimple;
use openpgp_card::card_do::{KeyGenerationTime, Sex};
use openpgp_card::{CardApp, Error, KeyType, StatusBytes};
use openpgp_card_sequoia::util::{
    make_cert, public_key_material_to_key, public_to_fingerprint,
};

use crate::cards::TestCardApp;
use crate::util;

#[derive(Debug)]
pub enum TestResult {
    Status(StatusBytes),
    StatusOk,
    Text(String),
}

type TestOutput = Vec<TestResult>;

#[derive(thiserror::Error, Debug)]
pub enum TestError {
    #[error("Failed to upload key {0} ({1})")]
    KeyUploadError(String, anyhow::Error),

    #[error(transparent)]
    OPGP(#[from] Error),

    #[error(transparent)]
    OCard(#[from] StatusBytes),

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

    let p = StandardPolicy::new();

    let res = openpgp_card_sequoia::util::decrypt(
        &mut ca,
        &cert,
        msg.into_bytes(),
        &p,
    )?;
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

    let p = StandardPolicy::new();

    let msg = "Hello world, I am signed.";
    let sig = openpgp_card_sequoia::util::sign(
        &mut ca,
        &cert,
        &mut msg.as_bytes(),
        &p,
    )?;

    // validate sig
    assert!(util::verify_sig(&cert, msg.as_bytes(), sig.as_bytes())?);

    Ok(vec![])
}

fn check_key_upload_metadata(
    ca: &mut CardApp,
    meta: &[(String, KeyGenerationTime)],
) -> Result<()> {
    let ard = ca.get_application_related_data()?;

    // check fingerprints
    let card_fp = ard.get_fingerprints()?;

    let sig = card_fp.signature().expect("signature fingerprint");
    assert_eq!(format!("{:X}", sig), meta[0].0);

    let dec = card_fp.decryption().expect("decryption fingerprint");
    assert_eq!(format!("{:X}", dec), meta[1].0);

    let auth = card_fp
        .authentication()
        .expect("authentication fingerprint");
    assert_eq!(format!("{:X}", auth), meta[2].0);

    // get_key_generation_times
    let card_kg = ard.get_key_generation_times()?;

    let sig = card_kg.signature().expect("signature creation time");
    assert_eq!(sig, &meta[0].1);

    let dec = card_kg.decryption().expect("decryption creation time");
    assert_eq!(dec, &meta[1].1);

    let auth = card_kg
        .authentication()
        .expect("authentication creation time");
    assert_eq!(auth, &meta[2].1);

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
    let ard = ca.get_application_related_data()?;

    let aid = ard.get_application_id()?;
    println!("aid: {:#x?}", aid);

    let hist = ard.get_historical()?;
    println!("hist: {:#?}", hist);

    let ecap = ard.get_extended_capabilities()?;
    println!("ecap: {:#?}", ecap);

    let eli = ard.get_extended_length_information()?;
    println!("eli: {:#?}", eli);

    Ok(vec![])
}

pub fn test_print_algo_info(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let ard = ca.get_application_related_data()?;

    let dec = ard.get_algorithm_attributes(KeyType::Decryption)?;
    println!("Current algorithm for the decrypt slot: {}", dec);

    println!();

    let algo = ca.get_algo_info();
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

    let p = StandardPolicy::new();

    let meta = util::upload_subkeys(ca, &cert, &p)
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

    println!(" Generate subkey for Signing");
    let (pkm, ts) =
        ca.generate_key_simple(public_to_fingerprint, KeyType::Signing, alg)?;
    let key_sig = public_key_material_to_key(&pkm, KeyType::Signing, ts)?;

    println!(" Generate subkey for Decryption");
    let (pkm, ts) = ca.generate_key_simple(
        public_to_fingerprint,
        KeyType::Decryption,
        alg,
    )?;
    let key_dec = public_key_material_to_key(&pkm, KeyType::Decryption, ts)?;

    println!(" Generate subkey for Authentication");
    let (pkm, ts) = ca.generate_key_simple(
        public_to_fingerprint,
        KeyType::Authentication,
        alg,
    )?;
    let key_aut =
        public_key_material_to_key(&pkm, KeyType::Authentication, ts)?;

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
    let ard = ca.get_application_related_data()?;
    let key_gen = ard.get_key_generation_times()?;

    // --

    let sig = ca.get_pub_key(KeyType::Signing)?;
    let ts = key_gen.signature().unwrap().get().into();
    let key = public_key_material_to_key(&sig, KeyType::Signing, ts)?;

    println!(" sig key data from card -> {:x?}", key);

    // --

    let dec = ca.get_pub_key(KeyType::Decryption)?;
    let ts = key_gen.decryption().unwrap().get().into();
    let key = public_key_material_to_key(&dec, KeyType::Decryption, ts)?;

    println!(" dec key data from card -> {:x?}", key);

    // --

    let auth = ca.get_pub_key(KeyType::Authentication)?;
    let ts = key_gen.authentication().unwrap().get().into();
    let key = public_key_material_to_key(&auth, KeyType::Authentication, ts)?;

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

    assert_eq!(ch.name(), Some("Bar<<Foo"));
    assert_eq!(
        ch.lang().expect("Language setting is None"),
        &[['d', 'e'], ['e', 'n']]
    );
    assert_eq!(ch.sex(), Some(Sex::Female));

    let url = ca.get_url()?;
    assert_eq!(url, "https://duckduckgo.com/".to_string());

    Ok(vec![])
}

pub fn test_private_data(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut out = vec![];

    println!();

    let d = ca.get_private(1)?;
    println!("data 1 {:?}", d);

    ca.verify_pw1("123456")?;

    ca.set_private(1, "Foo bar1!".as_bytes().to_vec())?;
    ca.set_private(3, "Foo bar3!".as_bytes().to_vec())?;

    ca.verify_pw3("12345678")?;

    ca.set_private(2, "Foo bar2!".as_bytes().to_vec())?;
    ca.set_private(4, "Foo bar4!".as_bytes().to_vec())?;

    let d = ca.get_private(1)?;
    println!("data 1 {:?}", d);
    let d = ca.get_private(2)?;
    println!("data 2 {:?}", d);
    let d = ca.get_private(3)?;
    println!("data 3 {:?}", d);
    let d = ca.get_private(4)?;
    println!("data 4 {:?}", d);

    Ok(out)
}

pub fn test_cardholder_cert(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut out = vec![];

    println!();

    match ca.get_cardholder_certificate() {
        Ok(res) => out
            .push(TestResult::Text(format!("got cert {:x?}", res.get_data()))),
        Err(e) => {
            out.push(TestResult::Text(format!(
                "get_cardholder_certificate failed: {:?}",
                e
            )));
            return Ok(out);
        }
    };

    ca.verify_pw3("12345678")?;

    let data = "Foo bar baz!".as_bytes();

    match ca.set_cardholder_certificate(data.to_vec()) {
        Ok(resp) => out.push(TestResult::Text("set cert ok".to_string())),
        Err(e) => {
            out.push(TestResult::Text(format!(
                "set_cardholder_certificate: {:?}",
                e
            )));
            return Ok(out);
        }
    }

    let res = ca.get_cardholder_certificate()?;
    out.push(TestResult::Text("get cert ok".to_string()));

    if res.get_data() != data {
        out.push(TestResult::Text(format!(
            "get after set doesn't match original data: {:x?}",
            data
        )));
        return Ok(out);
    };

    // try using slot 2

    match ca.select_data(2, &[0x7F, 0x21]) {
        Ok(res) => out.push(TestResult::Text("select_data ok".to_string())),
        Err(e) => {
            out.push(TestResult::Text(format!("select_data: {:?}", e)));
            return Ok(out);
        }
    }

    Ok(out)
}

pub fn test_pw_status(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut out = vec![];

    let ard = ca.get_application_related_data()?;
    let mut pws = ard.get_pw_status_bytes()?;

    println!("pws {:?}", pws);

    ca.verify_pw3("12345678")?;

    pws.set_pw1_cds_multi(true);
    pws.set_pw1_pin_block(true);

    ca.set_pw_status_bytes(&pws, false)?;

    let ard = ca.get_application_related_data()?;
    let pws = ard.get_pw_status_bytes()?;
    println!("pws {:?}", pws);

    Ok(out)
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

    if let Err(Error::CardStatus(s)) = res {
        assert_eq!(s, StatusBytes::SecurityStatusNotSatisfied);
    } else {
        panic!("Status should be 'SecurityStatusNotSatisfied'");
    }

    ca.verify_pw3("12345678")?;

    match ca.check_pw3() {
        Err(Error::CardStatus(s)) => {
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
    assert_eq!(cardholder.name(), Some("Admin<<Hello"));

    ca.verify_pw1("123456")?;

    match ca.check_pw3() {
        Err(Error::CardStatus(s)) => {
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
    assert_eq!(cardholder.name(), Some("There<<Hello"));

    Ok(out)
}

pub fn test_change_pw(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut out = vec![];

    // first do admin-less pw1 on gnuk
    // (NOTE: Gnuk requires a key to be loaded before allowing pw changes!)
    println!("change pw1");
    ca.change_pw1("123456", "abcdef00")?;

    // also set admin pw, which means pw1 is now only user-pw again, on gnuk
    println!("change pw3");
    // ca.change_pw3("abcdef00", "abcdefgh")?; // gnuk
    ca.change_pw3("12345678", "abcdefgh")?;

    println!("change pw1");
    ca.change_pw1("abcdef00", "abcdef")?; // gnuk

    // ca.change_pw1("123456", "abcdef")?;

    println!("verify bad pw1");
    match ca.verify_pw1("123456ab") {
        Err(Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied)) => {
            // this is expected
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => panic!("this value for pw1 should be considered wrong!"),
    }

    println!("verify good pw1");
    ca.verify_pw1("abcdef")?;

    println!("verify bad pw3");
    match ca.verify_pw3("00000000") {
        Err(Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied)) => {
            // this is expected
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => panic!("this value for pw3 should be considered wrong!"),
    }

    println!("verify good pw3");
    ca.verify_pw3("abcdefgh")?;

    println!("change pw3 back to default");
    ca.change_pw3("abcdefgh", "12345678")?;

    println!("change pw1 back to default");
    ca.change_pw1("abcdef", "123456")?;

    Ok(out)
}

pub fn test_reset_retry_counter(
    ca: &mut CardApp,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut out = vec![];

    // set pw3, then pw1 (to bring gnuk into non-admin mode)
    println!("set pw3");
    ca.change_pw3("12345678", "12345678")?;
    println!("set pw1");
    ca.change_pw1("123456", "123456")?;

    println!("break pw1");
    let _ = ca.verify_pw1("wrong0");
    let _ = ca.verify_pw1("wrong0");
    let _ = ca.verify_pw1("wrong0");
    let res = ca.verify_pw1("wrong0");

    match res {
        Err(Error::CardStatus(StatusBytes::AuthenticationMethodBlocked)) => {
            // this is expected
        }
        Err(Error::CardStatus(
            StatusBytes::IncorrectParametersCommandDataField,
        )) => {
            println!(
                "yk says IncorrectParametersCommandDataField when PW \
            error count is exceeded"
            );
        }
        Err(e) => {
            panic!("unexpected error {:?}", e);
        }
        Ok(_) => panic!("use of pw1 should be blocked!"),
    }

    println!("verify pw3");
    ca.verify_pw3("12345678")?;

    println!("set resetting code");
    ca.set_resetting_code("abcdefgh".as_bytes().to_vec())?;

    println!("reset retry counter");
    // ca.reset_retry_counter_pw1("abcdef".as_bytes().to_vec(), None)?;
    let res = ca.reset_retry_counter_pw1(
        "abcdef".as_bytes().to_vec(),
        Some("abcdefgh".as_bytes().to_vec()),
    );

    println!("verify good pw1");
    ca.verify_pw1("abcdef")?;

    println!("verify bad pw1");
    match ca.verify_pw1("00000000") {
        Err(Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied)) => {
            // this is expected
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => panic!("this value for pw1 should be considered wrong!"),
    }

    Ok(out)
}

pub fn run_test(
    card: &mut TestCardApp,
    t: fn(&mut CardApp, &[&str]) -> Result<TestOutput, TestError>,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut ca = card.get_card_app()?;
    let ard = ca.get_application_related_data()?;
    let _app_id = ard.get_application_id()?;

    t(&mut ca, param)
}
