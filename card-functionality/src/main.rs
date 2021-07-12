// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use std::env;

use openpgp_card::apdu::PcscClient;
use openpgp_card::card_app::CardApp;
use openpgp_card::CardClientBox;

fn test(mut ca: CardApp) -> Result<()> {
    let res = ca.verify_pw3("12345678");
    println!("res verify pw3 {:x?}", res);

    let check = ca.check_pw3();
    println!("has pw3 been verified yet? {:x?}", check);

    let res = ca.set_name("Admin<<Hello");
    println!("set name res {:x?}", res);
    res?.check_ok()?;

    let cardholder = ca.get_cardholder_related_data()?;
    println!("get name1: {}", cardholder.name.expect("name unset"));

    let res = ca.verify_pw1("123456");
    println!("res verify pw1 {:x?}", res);

    let check = ca.check_pw3();
    println!("has pw3 been verified yet? {:x?}", check);

    let res = ca.set_name("There<<Hello");
    println!("set name {:x?}", res);

    let cardholder = ca.get_cardholder_related_data()?;
    println!("get name2: {}", cardholder.name.expect("name unset"));

    Ok(())
}

fn main() -> Result<()> {
    let cards = PcscClient::list_cards()?;

    // Ident of the OpenPGP Card that will be used for tests.
    let test_card_ident =
        env::var("TEST_CARD_IDENT").expect("TEST_CARD_IDENT is not set");

    for card in cards {
        let card_client = Box::new(card) as CardClientBox;

        let mut ca = CardApp::new(card_client);

        let res = ca.select()?;
        res.check_ok()?;

        let ard = ca.get_app_data()?;
        let app_id = CardApp::get_aid(&ard)?;

        println!("Opened Card: ident {}", app_id.ident());
        if app_id.ident() == test_card_ident {
            println!("Running Test on {}", app_id.ident());

            test(ca)?;
        }
    }

    Ok(())
}
