// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use std::env;
use std::error::Error;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Cert;

use openpgp_card::card_do::Sex;
use openpgp_card::{CardApp, KeyType};
use openpgp_card_pcsc::PcscClient;
// use openpgp_card_scdc::ScdClient;

use openpgp_card_sequoia::CardBase;

// Filename of test key and test message to use:

const TEST_KEY_PATH: &str = "example/test4k.sec";
const TEST_ENC_MSG: &str = "example/encrypted_to_rsa4k.asc";

// const TEST_KEY_PATH: &str = "example/nist521.sec";
// const TEST_ENC_MSG: &str = "example/encrypted_to_nist521.asc";

// const TEST_KEY_PATH: &str = "example/test25519.sec";
// const TEST_ENC_MSG: &str = "example/encrypted_to_25519.asc";

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // Ident of the OpenPGP Card that will be used for tests.
    let test_card_ident = env::var("TEST_CARD_IDENT");

    // // "serial" for opening a specific card through scdaemon
    // let test_card_serial = env::var("TEST_CARD_SERIAL")?;

    if let Ok(test_card_ident) = test_card_ident {
        println!("** get card");
        let mut oc =
            CardBase::open_card(PcscClient::open_by_ident(&test_card_ident)?)?;

        // let mut oc = CardBase::open_card(ScdClient::open_by_serial(
        //     None,
        //     &test_card_serial,
        // )?)?;

        // card metadata

        println!("** get aid");
        let app_id = oc.get_application_id()?;

        println!("app id: {:x?}\n\n", app_id);
        println!(" ident: {:?}\n\n", app_id.ident());

        let eli = oc.get_extended_length_information()?;
        println!("extended_length_info: {:?}\n\n", eli);

        let hist = oc.get_historical()?;
        println!("historical {:#x?}", hist);

        let ext = oc.get_extended_capabilities()?;
        println!("extended_capabilities {:#x?}", ext);

        let pws = oc.get_pw_status_bytes()?;
        println!("PW Status Bytes {:#x?}", pws);

        // cardholder

        let ch = oc.get_cardholder_related_data()?;
        println!("card holder {:x?}", ch);

        // crypto-ish metadata

        let fp = oc.get_fingerprints()?;
        println!("fp {:#x?}", fp);

        let sst = oc.get_security_support_template()?;
        println!("sst {:x?}", sst);

        match oc.list_supported_algo() {
            Ok(Some(ai)) => println!("algo information {:#?}", ai),
            Ok(None) => println!(" no algo information found"),
            Err(e) => println!(" error getting algo information: {:?}", e),
        }

        let algo = oc.get_algorithm_attributes(KeyType::Signing)?;
        println!("algo sig {:?}", algo);
        let algo = oc.get_algorithm_attributes(KeyType::Decryption)?;
        println!("algo dec {:?}", algo);
        let algo = oc.get_algorithm_attributes(KeyType::Authentication)?;
        println!("algo aut {:?}", algo);

        // ---------------------------------------------
        //  CAUTION: Write commands ahead!
        //  Try not to overwrite your production cards.
        // ---------------------------------------------
        assert_eq!(app_id.ident(), test_card_ident);

        let check = oc.check_pw3();
        println!("has pw3 been verified yet? {:x?}", check);

        oc.factory_reset()?;

        match oc.verify_pw3("12345678") {
            Ok(mut oc_admin) => {
                println!("pw3 verify ok");

                let check = oc_admin.check_pw3();
                println!("has pw3 been verified yet? {:x?}", check);

                let res = oc_admin.set_name("Bar<<Foo")?;
                println!("set name {:x?}", res);

                let res = oc_admin.set_sex(Sex::NotApplicable)?;
                println!("set sex {:x?}", res);

                let res = oc_admin.set_lang("en")?;
                println!("set lang {:x?}", res);

                let res = oc_admin.set_url("https://keys.openpgp.org")?;
                println!("set url {:x?}", res);

                let cert = Cert::from_file(TEST_KEY_PATH)?;

                openpgp_card_sequoia::upload_from_cert_yolo(
                    &mut oc_admin,
                    &cert,
                    KeyType::Decryption,
                    None,
                )?;

                openpgp_card_sequoia::upload_from_cert_yolo(
                    &mut oc_admin,
                    &cert,
                    KeyType::Signing,
                    None,
                )?;

                // TODO: test keys currently have no auth-capable key
                // openpgp_card_sequoia::upload_from_cert(
                //     &oc_admin,
                //     &cert,
                //     KeyType::Authentication,
                //     None,
                // )?;
            }
            _ => panic!(),
        }

        // -----------------------------
        //  Open fresh Card for decrypt
        // -----------------------------

        let mut oc =
            CardBase::open_card(PcscClient::open_by_ident(&test_card_ident)?)?;

        // let mut oc = CardBase::open_card(ScdClient::open_by_serial(
        //     None,
        //     &test_card_serial,
        // )?)?;

        let app_id = oc.get_application_id()?;

        // Check that we're still using the expected card
        assert_eq!(app_id.ident(), test_card_ident);

        let check = oc.check_pw1();
        println!("has pw1/82 been verified yet? {:x?}", check);

        match oc.verify_pw1("123456") {
            Ok(mut oc_user) => {
                println!("pw1 82 verify ok");

                let check = oc_user.check_pw1();
                println!("has pw1/82 been verified yet? {:x?}", check);

                let cert = Cert::from_file(TEST_KEY_PATH)?;
                let msg = std::fs::read_to_string(TEST_ENC_MSG)
                    .expect("Unable to read file");

                println!("{:?}", msg);

                let res = openpgp_card_sequoia::decrypt(
                    &mut oc_user.get_card_app(),
                    &cert,
                    msg.into_bytes(),
                )?;

                let plain = String::from_utf8_lossy(&res);
                println!("decrypted plaintext: {}", plain);

                assert_eq!(plain, "Hello world!\n");
            }
            _ => panic!("verify pw1 failed"),
        }

        // -----------------------------
        //  Open fresh Card for signing
        // -----------------------------
        let oc =
            CardBase::open_card(PcscClient::open_by_ident(&test_card_ident)?)?;

        // let oc = CardBase::open_card(ScdClient::open_by_serial(
        //     None,
        //     &test_card_serial,
        // )?)?;

        // Sign
        match oc.verify_pw1_for_signing("123456") {
            Ok(mut oc_user) => {
                println!("pw1 81 verify ok");

                let cert = Cert::from_file(TEST_KEY_PATH)?;

                let text = "Hello world, I am signed.";
                let res = openpgp_card_sequoia::sign(
                    oc_user.get_card_app(),
                    &cert,
                    &mut text.as_bytes(),
                );

                println!("res sign {:?}", res);

                println!("res: {}", res?)

                // FIXME: validate sig
            }
            _ => panic!("verify pw1 failed"),
        }
    } else {
        println!("Please set environment variable TEST_CARD_IDENT.");
        println!();

        println!("NOTE: the configured card will get overwritten!");
        println!("So do NOT use your production card for testing.");
        println!();

        println!("The following OpenPGP cards are connected to your system:");

        let cards = PcscClient::list_cards()?;
        for c in cards {
            let mut ca = CardApp::from(c);

            let ard = ca.get_application_related_data()?;
            let app_id = ard.get_application_id()?;

            let ident = app_id.ident();
            println!(" '{}'", ident);
        }
    }

    Ok(())
}
