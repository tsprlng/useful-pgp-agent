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
        println!("** Run tests on card '{}' **", card.get_name());

        let mut c: Card<Open> = card.get_card()?;
        println!(" -> Card opened");

        println!("Reset");
        let _ = run_test(&mut c, test_reset, &[])?;

        print!("Set user data");
        let userdata_out = run_test(&mut c, test_set_user_data, &[])?;
        println!(" {userdata_out:x?}");

        println!("Set login data");
        let login_data_out = run_test(&mut c, test_set_login_data, &[])?;
        println!(" {login_data_out:x?}");

        let key_files = {
            let config = card.get_config();
            if let Some(import) = &config.import {
                import.clone()
            } else {
                vec![]
            }
        };

        for key_file in &key_files {
            // upload keys
            print!("Upload key '{key_file}'");
            let upload_res = run_test(&mut c, test_upload_keys, &[key_file]);

            if let Err(TestError::KeyUploadError(_file, err)) = &upload_res {
                // The card doesn't support this key type, so skip to the
                // next key - don't try to decrypt/sign for this key.

                println!(" => Upload failed ({err:?}), skip tests");

                continue;
            }

            let upload_out = upload_res?;
            println!(" {upload_out:x?}");

            let key = std::fs::read_to_string(key_file).expect("Unable to read ciphertext");

            // decrypt
            print!("  Decrypt");

            let cert = Cert::from_str(&key)?;
            let ciphertext = util::encrypt_to("Hello world!\n", &cert)?;

            let dec_out = run_test(&mut c, test_decrypt, &[&key, &ciphertext])?;
            println!(" {dec_out:x?}");

            // sign
            print!("  Sign");

            let sign_out = run_test(&mut c, test_sign, &[&key])?;
            println!(" {sign_out:x?}");
        }

        // FIXME: import key with password

        println!();
    }

    Ok(())
}
