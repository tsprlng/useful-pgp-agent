// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use std::env;

use openpgp_card::apdu::PcscClient;
use openpgp_card::card_app::CardApp;
use openpgp_card::CardClientBox;
use std::collections::HashMap;

#[derive(Debug)]
enum TestResult {
    Status([u8; 2]),
    Text(String),
}

type TestOutput = Vec<TestResult>;

/// outputs:
/// - verify pw3 + pin -> Status
/// - verify pw3 (check) -> Status
/// - set name -> Status
/// - get name -> Text(name)
/// - verify pw1 + pin -> Status
/// - verify pw1 (check) -> Status
/// - set name -> Status
/// - get name -> Text(name)
fn test_verify(ca: &mut CardApp) -> Result<TestOutput> {
    let mut out = vec![];

    let res = ca.verify_pw3("12345678")?;
    out.push(TestResult::Status(res.status()));

    let check = ca.check_pw3()?;
    out.push(TestResult::Status(check.status()));

    let res = ca.set_name("Admin<<Hello")?;
    out.push(TestResult::Status(res.status()));
    res.check_ok()?;

    let cardholder = ca.get_cardholder_related_data()?;
    out.push(TestResult::Text(cardholder.name.unwrap()));

    let res = ca.verify_pw1("123456")?;
    out.push(TestResult::Status(res.status()));

    let check = ca.check_pw3()?;
    out.push(TestResult::Status(check.status()));

    let res = ca.set_name("There<<Hello")?;
    out.push(TestResult::Status(res.status()));
    res.check_ok()?;

    let cardholder = ca.get_cardholder_related_data()?;
    out.push(TestResult::Text(cardholder.name.unwrap()));

    Ok(out)
}

fn run_test(
    cards: &[&str],
    t: fn(&mut CardApp) -> Result<TestOutput>,
) -> Result<HashMap<String, TestOutput>> {
    let mut out = HashMap::new();

    for card in PcscClient::list_cards()? {
        let card_client = Box::new(card) as CardClientBox;
        let mut ca = CardApp::new(card_client);

        let res = ca.select()?;
        res.check_ok()?;

        let ard = ca.get_app_data()?;
        let app_id = CardApp::get_aid(&ard)?;

        if cards.contains(&app_id.ident().as_str()) {
            println!("Running Test on {}:", app_id.ident());

            let res = t(&mut ca);
            println!("{:x?}", res);

            out.insert(app_id.ident(), res?);
        }
    }

    Ok(out)
}

fn main() -> Result<()> {
    // Ident of the OpenPGP Card that will be used for tests.
    let test_card_ident =
        env::var("TEST_CARD_IDENT").expect("TEST_CARD_IDENT is not set");

    // list of card idents to runs the tests on
    let cards = vec![
        "0006:16019180", // Yubikey 5
        "0005:0000A835", // FLOSS Card 3.4
        "FFFE:57183146", // Rysim Gnuk (green)
    ];

    let _verify_res = run_test(&cards, test_verify)?;

    Ok(())
}
