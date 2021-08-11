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

        println!("Generate key");
        let res = run_test(&mut card, test_keygen, &[])?;

        if let TestResult::Text(cert) = &res[0] {
            println!("cert\n{}", cert);
        };

        // panic!();

        println!();
    }

    Ok(())
}
