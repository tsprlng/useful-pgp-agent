// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;

use card_functionality::cards::TestConfig;
use card_functionality::tests::*;

fn main() -> Result<()> {
    env_logger::init();

    let config = TestConfig::open("config/test-cards.toml")?;

    let cards = config.get_cards();

    for mut card in cards {
        println!("** Run tests on card {:?} **", card);

        println!("Reset");
        let _ = run_test(&mut card, test_reset, &[])?;

        print!("Set user data");
        let userdata_out = run_test(&mut card, test_set_user_data, &[])?;
        println!(" {:x?}", userdata_out);

        for (key, ciphertext) in [
            ("data/rsa2k.sec", "data/encrypted_to_rsa2k.asc"),
            ("data/rsa4k.sec", "data/encrypted_to_rsa4k.asc"),
            ("data/25519.sec", "data/encrypted_to_25519.asc"),
            ("data/nist256.sec", "data/encrypted_to_nist256.asc"),
            ("data/nist521.sec", "data/encrypted_to_nist521.asc"),
        ] {
            // upload keys
            print!("Upload key '{}'", key);
            let upload_res = run_test(&mut card, test_upload_keys, &[key]);

            if let Err(TestError::KeyUploadError(_file, err)) = &upload_res {
                // The card doesn't support this key type, so skip to the
                // next key - don't try to decrypt/sign for this key.

                println!(" => Upload failed ({:?}), skip tests", err);

                continue;
            }

            let upload_out = upload_res?;
            println!(" {:x?}", upload_out);

            let key = std::fs::read_to_string(key)
                .expect("Unable to read ciphertext");

            // decrypt
            print!("  Decrypt");
            let msg =
                std::fs::read_to_string(ciphertext).unwrap_or_else(|_| {
                    panic!(
                        "Unable to read ciphertext from file {}",
                        ciphertext
                    )
                });

            let dec_out = run_test(&mut card, test_decrypt, &[&key, &msg])?;
            println!(" {:x?}", dec_out);

            // sign
            print!("  Sign");

            let sign_out = run_test(&mut card, test_sign, &[&key])?;
            println!(" {:x?}", sign_out);
        }

        // FIXME: import key with password

        println!();
    }

    Ok(())
}
