// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use std::str::FromStr;

use card_functionality::cards::TestConfig;
use card_functionality::tests::*;
use card_functionality::util;
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

    for mut card in cards {
        println!("** Run tests on card {} **", card.get_name());

        // println!("Get pubkey");
        // let _ = run_test(&mut card, test_get_pub, &[])?;
        //
        // panic!();

        // println!("Caps");
        // let _ = run_test(&mut card, test_print_caps, &[])?;
        // // continue; // only print caps

        println!("Reset");
        let _ = run_test(&mut card, test_reset, &[])?;

        // println!("Algo info");
        // let _ = run_test(&mut card, test_print_algo_info, &[])?;

        // Set user data because keygen expects a name (for the user id)
        println!("Set user data");
        let _ = run_test(&mut card, test_set_user_data, &[])?;

        let algos = {
            let config = card.get_config();
            if let Some(keygen) = &config.keygen {
                keygen.clone()
            } else {
                vec![]
            }
        };

        for algo in algos {
            println!("Generate key [{}]", algo);

            let res = run_test(&mut card, test_keygen, &[&algo])?;

            if let TestResult::Text(cert) = &res[0] {
                // sign
                print!("  Sign");
                let sign_out = run_test(&mut card, test_sign, &[cert])?;
                println!(" {:x?}", sign_out);

                // decrypt
                let c = Cert::from_str(cert)?;
                let ciphertext = util::encrypt_to("Hello world!\n", &c)?;

                print!("  Decrypt");
                let dec_out =
                    run_test(&mut card, test_decrypt, &[cert, &ciphertext])?;
                println!(" {:x?}", dec_out);
            } else {
                panic!("Didn't get back a Cert from test_keygen");
            };
        }

        println!();
    }

    Ok(())
}
