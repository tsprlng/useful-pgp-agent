// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::str::FromStr;

use anyhow::Result;
use card_functionality::cards::TestConfig;
use card_functionality::tests::*;
use card_functionality::util;
use openpgp_card_sequoia::state::Open;
use openpgp_card_sequoia::Card;
use sequoia_openpgp::Cert;

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let config = if args.len() <= 1 {
        TestConfig::load("config/test-cards.toml")?
    } else {
        TestConfig::load(&args[1])?
    };

    let cards = config.into_cardapps();

    for card in cards {
        println!("** Run tests on card {} **", card.get_name());

        let mut c: Card<Open> = card.get_card()?;
        println!(" -> Card opened");
        let mut tx = c.transaction()?;
        println!("    started transaction");

        // println!("Get pubkey");
        // let _ = run_test(&mut card, test_get_pub, &[])?;
        //
        // panic!();

        // println!("Caps");
        // let _ = run_test(&mut card, test_print_caps, &[])?;
        // // continue; // only print caps

        println!("Reset");
        let _ = run_test(&mut tx, test_reset, &[])?;

        // println!("Algo info");
        // let _ = run_test(&mut card, test_print_algo_info, &[])?;

        // Set user data because keygen expects a name (for the user id)
        println!("Set user data");
        let _ = run_test(&mut tx, test_set_user_data, &[])?;

        let algos = {
            let config = card.get_config();
            if let Some(keygen) = &config.keygen {
                keygen.clone()
            } else {
                vec![]
            }
        };

        for algo in algos {
            println!("Generate key [{algo}]");

            let res = run_test(&mut tx, test_keygen, &[&algo])?;

            if let TestResult::Text(cert_str) = &res[0] {
                // sign
                print!("  Sign");
                let sign_out = run_test(&mut tx, test_sign, &[cert_str])?;
                println!(" {sign_out:x?}");

                // decrypt
                let cert = Cert::from_str(cert_str)?;
                let ciphertext = util::encrypt_to("Hello world!\n", &cert)?;

                print!("  Decrypt");
                let dec_out = run_test(&mut tx, test_decrypt, &[cert_str, &ciphertext])?;
                println!(" {dec_out:x?}");
            } else {
                panic!("Didn't get back a Cert from test_keygen");
            };
        }

        println!();
    }

    Ok(())
}
