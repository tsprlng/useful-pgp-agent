// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;

use card_functionality::cards::TestConfig;
use card_functionality::tests::*;

fn main() -> Result<()> {
    env_logger::init();

    let config = TestConfig::load("config/test-cards.toml")?;

    let cards = config.into_cardapps();

    for mut card in cards {
        println!("** Run tests on card '{}' **", card.get_name());

        // println!("Get pubkey");
        // let _ = run_test(&mut card, test_get_pub, &[])?;
        //
        // panic!();

        println!("Caps");
        let _ = run_test(&mut card, test_print_caps, &[])?;
        // continue; // only print caps

        // println!("Reset");
        // let _ = run_test(&mut card, test_reset, &[])?;

        // println!("Algo info");
        // let _ = run_test(&mut card, test_print_algo_info, &[])?;

        // println!("Generate key");
        // let _ = run_test(&mut card, test_keygen, &[])?;
        //
        // panic!();

        // print!("Verify");
        // let verify_out = run_test(&mut card, test_verify, &[])?;
        // println!(" {:x?}", verify_out);

        print!("PW Status bytes");
        let pw_out = run_test(&mut card, test_pw_status, &[])?;
        println!(" {:x?}", pw_out);

        println!();
    }

    Ok(())
}
