// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::env;
use std::error::Error;

use anyhow::Result;
use openpgp_card::card_do::Sex;
use openpgp_card::KeyType;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::sq_util;
use openpgp_card_sequoia::{state::Open, Card};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::Cert;

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
        let backend = PcscBackend::open_by_ident(&test_card_ident, None)?;

        let mut card: Card<Open> = backend.into();
        let mut transaction = card.transaction()?;

        // card metadata

        let app_id = transaction.application_identifier()?;
        println!("{:x?}\n", app_id);

        let eli = transaction.extended_length_information()?;
        println!("extended_length_info: {:?}\n", eli);

        let hist = transaction.historical_bytes()?;
        println!("{:#x?}\n", hist);

        let ext = transaction.extended_capabilities()?;
        println!("{:#x?}\n", ext);

        let pws = transaction.pw_status_bytes()?;
        println!("{:#x?}\n", pws);

        // cardholder
        let ch = transaction.cardholder_related_data()?;
        println!("{:#x?}\n", ch);

        // crypto-ish metadata
        let fp = transaction.fingerprints()?;
        println!("Fingerprint {:#x?}\n", fp);

        match transaction.algorithm_information() {
            Ok(Some(ai)) => println!("Algorithm information:\n{}", ai),
            Ok(None) => println!("No Algorithm information found"),
            Err(e) => println!("Error getting Algorithm information: {:?}", e),
        }

        println!("Current algorithm attributes on card:");
        let algo = transaction.algorithm_attributes(KeyType::Signing)?;
        println!("Sig: {}", algo);
        let algo = transaction.algorithm_attributes(KeyType::Decryption)?;
        println!("Dec: {}", algo);
        let algo = transaction.algorithm_attributes(KeyType::Authentication)?;
        println!("Aut: {}", algo);

        println!();

        // ---------------------------------------------
        //  CAUTION: Write commands ahead!
        //  Try not to overwrite your production cards.
        // ---------------------------------------------

        assert_eq!(app_id.ident(), test_card_ident.to_ascii_uppercase());

        let check = transaction.check_admin_verified();
        println!("has admin (pw3) been verified yet?\n{:x?}\n", check);

        println!("factory reset\n");
        transaction.factory_reset()?;

        transaction.verify_admin(b"12345678")?;
        println!("verify for admin ok");

        let check = transaction.check_user_verified();
        println!("has user (pw1/82) been verified yet? {:x?}", check);

        // Use Admin access to card
        let mut admin = transaction.admin_card().expect("just verified");

        println!();

        admin.set_name("Bar<<Foo")?;
        println!("set name - ok");

        admin.set_sex(Sex::NotApplicable)?;
        println!("set sex - ok");

        admin.set_lang(&[['e', 'n'].into()])?;
        println!("set lang - ok");

        admin.set_url("https://keys.openpgp.org")?;
        println!("set url - ok");

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
        let backend = PcscBackend::open_by_ident(&test_card_ident, None)?;

        let mut card: Card<Open> = backend.into();
        let mut transaction = card.transaction()?;

        // Check that we're still using the expected card
        let app_id = transaction.application_identifier()?;
        assert_eq!(app_id.ident(), test_card_ident.to_ascii_uppercase());

        let check = transaction.check_user_verified();
        println!("has user (pw1/82) been verified yet?\n{:x?}\n", check);

        transaction.verify_user(b"123456")?;
        println!("verify for user (pw1/82) ok");

        let check = transaction.check_user_verified();
        println!("has user (pw1/82) been verified yet?\n{:x?}\n", check);

        // Use User access to card
        let mut user = transaction
            .user_card()
            .expect("We just validated, this should not fail");

        let _cert = Cert::from_file(TEST_KEY_PATH)?;
        let msg = std::fs::read_to_string(TEST_ENC_MSG).expect("Unable to read file");

        println!("Encrypted message:\n{}", msg);

        let sp = StandardPolicy::new();
        let d = user.decryptor(&|| println!("Touch confirmation needed for decryption"))?;
        let res = sq_util::decryption_helper(d, msg.into_bytes(), &sp)?;

        let plain = String::from_utf8_lossy(&res);
        println!("Decrypted plaintext: {}", plain);

        assert_eq!(plain, "Hello world!\n");

        // -----------------------------
        //  Open fresh Card for signing
        // -----------------------------
        let backend = PcscBackend::open_by_ident(&test_card_ident, None)?;

        let mut card: Card<Open> = backend.into();
        let mut transaction = card.transaction()?;

        // Sign
        transaction.verify_user_for_signing(b"123456")?;
        println!("verify for sign (pw1/81) ok\n");

        // Use Sign access to card
        let mut sign = transaction.signing_card().expect("just verified");

        let _cert = Cert::from_file(TEST_KEY_PATH)?;

        let text = "Hello world, I am signed.";

        let signer = sign.signer(&|| {})?;
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

        for backend in PcscBackend::cards(None)? {
            let mut card: Card<Open> = backend.into();
            let open = card.transaction()?;

            println!(" {}", open.application_identifier()?.ident());
        }
    }

    Ok(())
}
