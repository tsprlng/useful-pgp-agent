// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;
use std::str::FromStr;
use std::string::FromUtf8Error;

use anyhow::Result;
use openpgp_card::algorithm::AlgoSimple;
use openpgp_card::card_do::{KeyGenerationTime, Sex};
use openpgp_card::{Error, KeyType, StatusBytes};
use openpgp_card_sequoia::sq_util;
use openpgp_card_sequoia::state::{Admin, Open, Transaction};
use openpgp_card_sequoia::util::{
    make_cert, public_key_material_and_fp_to_key, public_key_material_to_key,
};
use openpgp_card_sequoia::Card;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::Cert;
use thiserror;

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
pub fn test_decrypt(tx: &mut Card<Transaction>, param: &[&str]) -> Result<TestOutput, TestError> {
    assert_eq!(
        param.len(),
        2,
        "test_decrypt needs filenames for 'cert' and 'encrypted'"
    );

    let msg = param[1].to_string();

    let p = StandardPolicy::new();

    let mut user = tx.to_user_card("123456")?;
    let d = user.decryptor(&|| {})?;

    let res = sq_util::decrypt(d, msg.into_bytes(), &p)?;
    let plain = String::from_utf8_lossy(&res);

    assert_eq!(plain, "Hello world!\n");

    Ok(vec![])
}

/// Run after each "upload keys", if key *was* uploaded (?)
pub fn test_sign(tx: &mut Card<Transaction>, param: &[&str]) -> Result<TestOutput, TestError> {
    assert_eq!(param.len(), 1, "test_sign needs a filename for 'cert'");

    let cert = Cert::from_str(param[0])?;

    let mut sign = tx.to_signing_card("123456").unwrap();
    let s = sign.signer(&|| {})?;

    let msg = "Hello world, I am signed.";
    let sig = sq_util::sign(s, &mut msg.as_bytes())?;

    // validate sig
    assert!(util::verify_sig(&cert, msg.as_bytes(), sig.as_bytes())?);

    Ok(vec![])
}

fn check_key_upload_metadata(
    admin: &mut Card<Admin>,
    meta: &[(String, KeyGenerationTime)],
) -> Result<()> {
    admin.as_transaction().reload_ard()?;

    // check fingerprints
    let card_fp = admin.as_transaction().fingerprints()?;

    let sig = card_fp.signature().expect("signature fingerprint");
    assert_eq!(format!("{sig:X}"), meta[0].0);

    let dec = card_fp.decryption().expect("decryption fingerprint");
    assert_eq!(format!("{dec:X}"), meta[1].0);

    let auth = card_fp
        .authentication()
        .expect("authentication fingerprint");
    assert_eq!(format!("{auth:X}"), meta[2].0);

    // get_key_generation_times
    let card_kg = admin.as_transaction().key_generation_times()?;

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
    pgp: &mut openpgp_card::Card,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut pgpt = pgp.transaction()?;

    let ard = pgpt.application_related_data()?;

    let aid = ard.application_id()?;
    println!("aid: {aid:#x?}");

    let hist = ard.historical_bytes()?;
    println!("hist: {hist:#?}");

    let ecap = ard.extended_capabilities()?;
    println!("ecap: {ecap:#?}");

    let eli = ard.extended_length_information()?;
    println!("eli: {eli:#?}");

    Ok(vec![])
}

pub fn test_print_algo_info(
    pgp: &mut openpgp_card::Card,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut pgpt = pgp.transaction()?;

    let ard = pgpt.application_related_data()?;

    let dec = ard.algorithm_attributes(KeyType::Decryption)?;
    println!("Current algorithm for the decrypt slot: {dec}");

    println!();

    let algo = pgpt.algorithm_information();
    if let Ok(Some(algo)) = algo {
        println!("Card algorithm list:\n{algo}");
    }

    Ok(vec![])
}

pub fn test_upload_keys(
    tx: &mut Card<Transaction>,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    assert_eq!(
        param.len(),
        1,
        "test_upload_keys needs a filename for 'cert'"
    );

    let cert = Cert::from_file(param[0])?;
    let p = StandardPolicy::new();

    let mut admin = tx.to_admin_card("12345678")?;

    let meta = util::upload_subkeys(&mut admin, &cert, &p)
        .map_err(|e| TestError::KeyUploadError(param[0].to_string(), e))?;

    check_key_upload_metadata(&mut admin, &meta)?;

    // FIXME: implement
    check_key_upload_algo_attrs()?;

    Ok(vec![])
}

/// Generate keys for each of the three KeyTypes
pub fn test_keygen(tx: &mut Card<Transaction>, param: &[&str]) -> Result<TestOutput, TestError> {
    let mut admin = tx
        .to_admin_card("12345678")
        .expect("Couldn't get Admin card");

    // Generate all three subkeys on card
    let algo = param[0];

    let alg = AlgoSimple::try_from(algo)?;

    println!(" Generate subkey for Signing");
    admin.set_algorithm(KeyType::Signing, alg)?;
    let (pkm, ts) = admin.generate_key(KeyType::Signing)?;
    let key_sig = public_key_material_to_key(&pkm, KeyType::Signing, &ts, None, None)?;

    println!(" Generate subkey for Decryption");
    admin.set_algorithm(KeyType::Decryption, alg)?;
    let (pkm, ts) = admin.generate_key(KeyType::Decryption)?;
    let key_dec = public_key_material_to_key(&pkm, KeyType::Decryption, &ts, None, None)?;

    println!(" Generate subkey for Authentication");
    admin.set_algorithm(KeyType::Authentication, alg)?;
    let (pkm, ts) = admin.generate_key(KeyType::Authentication)?;
    let key_aut = public_key_material_to_key(&pkm, KeyType::Authentication, &ts, None, None)?;

    tx.reload_ard()?;

    // Generate a Cert for this set of generated keys
    let cert = make_cert(
        tx,
        key_sig,
        Some(key_dec),
        Some(key_aut),
        Some("123456"),
        &|| {},
        &|| {},
        &[],
    )?;
    let armored = String::from_utf8(cert.armored().to_vec()?)?;

    let res = TestResult::Text(armored);

    Ok(vec![res])
}

/// Construct public key based on data from the card
pub fn test_get_pub(mut card: Card<Open>, _param: &[&str]) -> Result<TestOutput, TestError> {
    let mut transaction = card.transaction()?;

    let times = transaction.key_generation_times()?;
    let fps = transaction.fingerprints()?;

    // --

    let sig = transaction.public_key_material(KeyType::Signing)?;
    let ts = times.signature().unwrap().get().into();
    let key =
        public_key_material_and_fp_to_key(&sig, KeyType::Signing, &ts, fps.signature().unwrap())?;

    println!(" sig key data from card -> {key:x?}");

    // --

    let dec = transaction.public_key_material(KeyType::Decryption)?;
    let ts = times.decryption().unwrap().get().into();
    let key = public_key_material_and_fp_to_key(
        &dec,
        KeyType::Decryption,
        &ts,
        fps.decryption().unwrap(),
    )?;

    println!(" dec key data from card -> {key:x?}");

    // --

    let auth = transaction.public_key_material(KeyType::Authentication)?;
    let ts = times.authentication().unwrap().get().into();
    let key = public_key_material_and_fp_to_key(
        &auth,
        KeyType::Authentication,
        &ts,
        fps.authentication().unwrap(),
    )?;

    println!(" auth key data from card -> {key:x?}");

    Ok(vec![])
}

pub fn test_reset(tx: &mut Card<Transaction>, _param: &[&str]) -> Result<TestOutput, TestError> {
    tx.factory_reset()?;
    Ok(vec![])
}

/// Sets name, lang, sex, url; then reads the fields from the card and
/// compares the values with the expected values.
///
/// Returns an empty TestOutput, throws errors for unexpected Status codes
/// and for unequal field values.
pub fn test_set_user_data(
    tx: &mut Card<Transaction>,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut admin = tx.to_admin_card("12345678")?;

    // name
    admin.set_cardholder_name("Bar<<Foo")?;

    // lang
    admin.set_lang(&[['d', 'e'].into(), ['e', 'n'].into()])?;

    // sex
    admin.set_sex(Sex::Female)?;

    // url
    admin.set_url("https://duckduckgo.com/")?;

    // reload application releated data
    tx.reload_ard()?;

    // compare the reloaded fields, expect equal data
    let ch = tx.cardholder_related_data()?;

    assert_eq!(ch.name(), Some("Bar<<Foo".as_bytes()));
    assert_eq!(
        ch.lang().expect("Language setting is None"),
        &[['d', 'e'].into(), ['e', 'n'].into()]
    );
    assert_eq!(ch.sex(), Some(Sex::Female));

    let url = tx.url()?;
    assert_eq!(&url, "https://duckduckgo.com/");

    Ok(vec![])
}

pub fn test_set_login_data(
    tx: &mut Card<Transaction>,
    _params: &[&str],
) -> std::result::Result<TestOutput, TestError> {
    let mut admin = tx.to_admin_card("12345678")?;

    let test_login = "someone@somewhere.com";
    admin.set_login_data(test_login.as_bytes())?;

    // Read the previously set login data
    let read_login_data = tx.login_data()?;

    assert_eq!(&read_login_data, test_login.as_bytes());

    Ok(vec![])
}

// pub fn test_private_data(mut card: Card<Open>, _param: &[&str]) -> Result<TestOutput, TestError> {
//     let mut transaction = card.transaction()?;
//
//     let out = vec![];
//
//     println!();
//
//     let d = transaction.private_use_do(1)?;
//     println!("data 1 {d:?}");
//
//     transaction.verify_pw1_user("123456")?;
//
//     transaction.set_private_use_do(1, "Foo bar1!".as_bytes().to_vec())?;
//     transaction.set_private_use_do(3, "Foo bar3!".as_bytes().to_vec())?;
//
//     transaction.verify_pw3("12345678")?;
//
//     transaction.set_private_use_do(2, "Foo bar2!".as_bytes().to_vec())?;
//     transaction.set_private_use_do(4, "Foo bar4!".as_bytes().to_vec())?;
//
//     let d = transaction.private_use_do(1)?;
//     println!("data 1 {d:?}");
//     let d = transaction.private_use_do(2)?;
//     println!("data 2 {d:?}");
//     let d = transaction.private_use_do(3)?;
//     println!("data 3 {d:?}");
//     let d = transaction.private_use_do(4)?;
//     println!("data 4 {d:?}");
//
//     Ok(out)
// }

// pub fn test_cardholder_cert(
//     card_tx: &mut CardApp,
//     _param: &[&str],
// ) -> Result<TestOutput, TestError> {
//     let mut out = vec![];
//
//     println!();
//
//     match card_tx.cardholder_certificate() {
//         Ok(res) => {
//             out.push(TestResult::Text(format!("got cert {:x?}", res.data())))
//         }
//         Err(e) => {
//             out.push(TestResult::Text(format!(
//                 "get_cardholder_certificate failed: {:?}",
//                 e
//             )));
//             return Ok(out);
//         }
//     };
//
//     card_tx.verify_pw3("12345678")?;
//
//     let data = "Foo bar baz!".as_bytes();
//
//     match card_tx.set_cardholder_certificate(data.to_vec()) {
//         Ok(_resp) => out.push(TestResult::Text("set cert ok".to_string())),
//         Err(e) => {
//             out.push(TestResult::Text(format!(
//                 "set_cardholder_certificate: {:?}",
//                 e
//             )));
//             return Ok(out);
//         }
//     }
//
//     let res = card_tx.cardholder_certificate()?;
//     out.push(TestResult::Text("get cert ok".to_string()));
//
//     if res.data() != data {
//         out.push(TestResult::Text(format!(
//             "get after set doesn't match original data: {:x?}",
//             data
//         )));
//         return Ok(out);
//     };
//
//     // try using slot 2
//
//     match card_tx.select_data(2, &[0x7F, 0x21]) {
//         Ok(_res) => out.push(TestResult::Text("select_data ok".to_string())),
//         Err(e) => {
//             out.push(TestResult::Text(format!("select_data: {:?}", e)));
//             return Ok(out);
//         }
//     }
//
//     Ok(out)
// }

pub fn test_pw_status(mut card: Card<Open>, _param: &[&str]) -> Result<TestOutput, TestError> {
    let mut transaction = card.transaction()?;

    let out = vec![];

    let mut pws = transaction.pw_status_bytes()?;

    println!("pws {pws:?}");

    let mut admin = transaction.to_admin_card("12345678")?;

    pws.set_pw1_cds_valid_once(false);
    pws.set_pw1_pin_block(true);

    admin.set_pw_status_bytes(&pws, false)?;

    transaction.reload_ard()?;

    let pws = transaction.pw_status_bytes()?;
    println!("pws {pws:?}");

    Ok(out)
}

/// Outputs:
/// - verify pw3 (check) -> Status
/// - verify pw1 (check) -> Status
pub fn test_verify(mut card: Card<Open>, _param: &[&str]) -> Result<TestOutput, TestError> {
    let mut transaction = card.transaction()?;

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
    let mut admin = transaction.to_admin_card(None)?;
    let res = admin.set_cardholder_name("Notverified<<Hello");

    if let Err(Error::CardStatus(s)) = res {
        assert_eq!(s, StatusBytes::SecurityStatusNotSatisfied);
    } else {
        panic!("Status should be 'SecurityStatusNotSatisfied'");
    }

    transaction.verify_admin_pin("12345678")?;

    match transaction.check_admin_verified() {
        Err(Error::CardStatus(s)) => {
            // e.g. yubikey5 returns an error status!
            out.push(TestResult::Status(s));
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => out.push(TestResult::StatusOk),
    }

    let mut admin = transaction.to_admin_card(None)?;

    admin.set_cardholder_name("Admin<<Hello")?;

    transaction.reload_ard()?;

    let cardholder = transaction.cardholder_related_data()?;
    assert_eq!(cardholder.name(), Some("Admin<<Hello".as_bytes()));

    transaction.verify_user_pin("123456")?;

    match transaction.check_user_verified() {
        Err(Error::CardStatus(s)) => {
            // e.g. yubikey5 returns an error status!
            out.push(TestResult::Status(s));
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => out.push(TestResult::StatusOk),
    }

    let mut admin = transaction.to_admin_card(None)?;

    admin.set_cardholder_name("There<<Hello")?;

    transaction.reload_ard()?;
    let cardholder = transaction.cardholder_related_data()?;
    assert_eq!(cardholder.name(), Some("There<<Hello".as_bytes()));

    Ok(out)
}

pub fn test_change_pw(mut card: Card<Open>, _param: &[&str]) -> Result<TestOutput, TestError> {
    let mut transaction = card.transaction()?;

    let out = vec![];

    // first do admin-less pw1 on gnuk
    // (NOTE: Gnuk requires a key to be loaded before allowing pw changes!)
    println!("change pw1");
    transaction.change_user_pin("123456", "abcdef00")?;

    // also set admin pw, which means pw1 is now only user-pw again, on gnuk
    println!("change pw3");
    // ca.change_pw3("abcdef00", "abcdefgh")?; // gnuk
    transaction.change_admin_pin("12345678", "abcdefgh")?;

    println!("change pw1");
    transaction.change_user_pin("abcdef00", "abcdef")?; // gnuk

    // ca.change_pw1("123456", "abcdef")?;

    println!("verify bad pw1");
    match transaction.verify_user_pin("123456ab") {
        Err(Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied)) => {
            // this is expected
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => panic!("this value for pw1 should be considered wrong!"),
    }

    println!("verify good pw1");
    transaction.verify_user_pin("abcdef")?;

    println!("verify bad pw3");
    match transaction.verify_admin_pin("00000000") {
        Err(Error::CardStatus(StatusBytes::SecurityStatusNotSatisfied)) => {
            // this is expected
        }
        Err(_) => {
            panic!("unexpected error");
        }
        Ok(_) => panic!("this value for pw3 should be considered wrong!"),
    }

    println!("verify good pw3");
    transaction.verify_admin_pin("abcdefgh")?;

    println!("change pw3 back to default");
    transaction.change_admin_pin("abcdefgh", "12345678")?;

    println!("change pw1 back to default");
    transaction.change_user_pin("abcdef", "123456")?;

    Ok(out)
}

pub fn test_reset_retry_counter(
    mut card: Card<Open>,
    _param: &[&str],
) -> Result<TestOutput, TestError> {
    let mut transaction = card.transaction()?;

    let out = vec![];

    // set pw3, then pw1 (to bring gnuk into non-admin mode)
    println!("set pw3");
    transaction.change_admin_pin("12345678", "12345678")?;
    println!("set pw1");
    transaction.change_user_pin("123456", "123456")?;

    println!("break pw1");
    let _ = transaction.verify_user_pin("wrong0");
    let _ = transaction.verify_user_pin("wrong0");
    let _ = transaction.verify_user_pin("wrong0");
    let res = transaction.verify_user_pin("wrong0");

    match res {
        Err(Error::CardStatus(StatusBytes::AuthenticationMethodBlocked)) => {
            // this is expected
        }
        Err(Error::CardStatus(StatusBytes::IncorrectParametersCommandDataField)) => {
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
    transaction.verify_admin_pin("12345678")?;

    println!("set resetting code");
    let mut admin = transaction.to_admin_card(None)?;
    admin.set_resetting_code("abcdefgh")?;

    println!("reset retry counter");
    // ca.reset_retry_counter_pw1("abcdef".as_bytes().to_vec(), None)?;
    let _res = transaction.reset_user_pin("abcdef", "abcdefgh");

    println!("verify good pw1");
    transaction.verify_user_pin("abcdef")?;

    println!("verify bad pw1");
    match transaction.verify_user_pin("00000000") {
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
    card: &mut Card<Transaction>,
    t: fn(&mut Card<Transaction>, &[&str]) -> Result<TestOutput, TestError>,
    param: &[&str],
) -> Result<TestOutput, TestError> {
    t(card, param)
}
