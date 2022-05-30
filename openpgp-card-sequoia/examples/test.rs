// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use std::env;
use std::error::Error;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::Cert;

use openpgp_card::card_do::Sex;
use openpgp_card::{KeyType, OpenPgp};
use openpgp_card_pcsc::PcscBackend;

use openpgp_card_sequoia::card::Open;
use openpgp_card_sequoia::sq_util;

// Filename of test key and test message to use

// const TEST_KEY_PATH: &str = "example/test4k.sec";
// const TEST_ENC_MSG: &str = "example/encrypted_to_rsa4k.asc";

// const TEST_KEY_PATH: &str = "example/nist521.sec";
// const TEST_KEY_PATH: &str = "example/nist521.sec";
// const TEST_ENC_MSG: &str = "example/encrypted_to_nist521.asc";

const TEST_KEY_PATH: &str = "example/test25519.sec";
const TEST_ENC_MSG: &str = "example/encrypted_to_25519.asc";

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Ident of an OpenPGP card to use for these tests
    let test_card_ident = env::var("TEST_CARD_IDENT");

    if let Ok(test_card_ident) = test_card_ident {
        let mut card = PcscBackend::open_by_ident(&test_card_ident, None)?;
        let mut pgp = OpenPgp::new(&mut card);

        let mut open = Open::new(pgp.transaction()?)?;

        // card metadata

        let app_id = open.application_identifier()?;
        println!("{:x?}\n", app_id);

        let eli = open.extended_length_information()?;
        println!("extended_length_info: {:?}\n", eli);

        let hist = open.historical_bytes()?;
        println!("{:#x?}\n", hist);

        let ext = open.extended_capabilities()?;
        println!("{:#x?}\n", ext);

        let pws = open.pw_status_bytes()?;
        println!("{:#x?}\n", pws);

        // cardholder
        let ch = open.cardholder_related_data()?;
        println!("{:#x?}\n", ch);

        // crypto-ish metadata
        let fp = open.fingerprints()?;
        println!("Fingerprint {:#x?}\n", fp);

        match open.algorithm_information() {
            Ok(Some(ai)) => println!("Algorithm information:\n{}", ai),
            Ok(None) => println!("No Algorithm information found"),
            Err(e) => println!("Error getting Algorithm information: {:?}", e),
        }

        println!("Current algorithm attributes on card:");
        let algo = open.algorithm_attributes(KeyType::Signing)?;
        println!("Sig: {}", algo);
        let algo = open.algorithm_attributes(KeyType::Decryption)?;
        println!("Dec: {}", algo);
        let algo = open.algorithm_attributes(KeyType::Authentication)?;
        println!("Aut: {}", algo);

        println!();

        // ---------------------------------------------
        //  CAUTION: Write commands ahead!
        //  Try not to overwrite your production cards.
        // ---------------------------------------------

        assert_eq!(app_id.ident(), test_card_ident.to_ascii_uppercase());

        let check = open.check_admin_verified();
        println!("has admin (pw3) been verified yet?\n{:x?}\n", check);

        println!("factory reset\n");
        open.factory_reset()?;

        open.verify_admin(b"12345678")?;
        println!("verify for admin ok");

        let check = open.check_user_verified();
        println!("has user (pw1/82) been verified yet? {:x?}", check);

        // Use Admin access to card
        let mut admin = open.admin_card().expect("just verified");

        println!();

        let res = admin.set_name("Bar<<Foo")?;
        println!("set name {:x?}", res);

        let res = admin.set_sex(Sex::NotApplicable)?;
        println!("set sex {:x?}", res);

        let res = admin.set_lang(&[['e', 'n'].into()])?;
        println!("set lang {:x?}", res);

        let res = admin.set_url("https://keys.openpgp.org")?;
        println!("set url {:x?}", res);

        let cert = Cert::from_file(TEST_KEY_PATH)?;
        let p = StandardPolicy::new();

        if let Some(vka) = sq_util::subkey_by_type(&cert, &p, KeyType::Signing)? {
            println!("Upload signing key");
            admin.upload_key(vka, KeyType::Signing, None)?;
        }

        if let Some(vka) = sq_util::subkey_by_type(&cert, &p, KeyType::Decryption)? {
            println!("Upload decryption key");
            admin.upload_key(vka, KeyType::Decryption, None)?;
        }

        if let Some(vka) = sq_util::subkey_by_type(&cert, &p, KeyType::Authentication)? {
            println!("Upload auth key");
            admin.upload_key(vka, KeyType::Authentication, None)?;
        }

        println!();

        // -----------------------------
        //  Open fresh Card for decrypt
        // -----------------------------
        let mut card = PcscBackend::open_by_ident(&test_card_ident, None)?;
        let mut pgp = OpenPgp::new(&mut card);

        let mut open = Open::new(pgp.transaction()?)?;

        // Check that we're still using the expected card
        let app_id = open.application_identifier()?;
        assert_eq!(app_id.ident(), test_card_ident.to_ascii_uppercase());

        let check = open.check_user_verified();
        println!("has user (pw1/82) been verified yet?\n{:x?}\n", check);

        open.verify_user(b"123456")?;
        println!("verify for user (pw1/82) ok");

        let check = open.check_user_verified();
        println!("has user (pw1/82) been verified yet?\n{:x?}\n", check);

        // Use User access to card
        let mut user = open
            .user_card()
            .expect("We just validated, this should not fail");

        let cert = Cert::from_file(TEST_KEY_PATH)?;
        let msg = std::fs::read_to_string(TEST_ENC_MSG).expect("Unable to read file");

        println!("Encrypted message:\n{}", msg);

        let sp = StandardPolicy::new();
        let d = user.decryptor(&cert, &|| {
            println!("Touch confirmation needed for decryption")
        })?;
        let res = sq_util::decryption_helper(d, msg.into_bytes(), &sp)?;

        let plain = String::from_utf8_lossy(&res);
        println!("Decrypted plaintext: {}", plain);

        assert_eq!(plain, "Hello world!\n");

        // -----------------------------
        //  Open fresh Card for signing
        // -----------------------------
        let mut card = PcscBackend::open_by_ident(&test_card_ident, None)?;
        let mut pgp = OpenPgp::new(&mut card);

        let mut open = Open::new(pgp.transaction()?)?;

        // Sign
        open.verify_user_for_signing(b"123456")?;
        println!("verify for sign (pw1/81) ok\n");

        // Use Sign access to card
        let mut sign = open.signing_card().expect("just verified");

        let cert = Cert::from_file(TEST_KEY_PATH)?;

        let text = "Hello world, I am signed.";

        let signer = sign.signer(&cert, &|| {})?;
        let sig = sq_util::sign_helper(signer, &mut text.as_bytes())?;

        println!("Signature from card:\n{}", sig)

        // FIXME: validate sig
    } else {
        println!("Please set environment variable TEST_CARD_IDENT.");
        println!();

        println!("NOTE: the configured card will get overwritten!");
        println!("So do NOT use your production card for testing.");
        println!();

        println!("The following OpenPGP cards are connected to your system:");

        for mut card in PcscBackend::cards(None)? {
            let mut pgp = OpenPgp::new(&mut card);

            let open = Open::new(pgp.transaction()?)?;

            println!(" {}", open.application_identifier()?.ident());
        }
    }

    Ok(())
}
