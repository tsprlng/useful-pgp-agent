// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use std::collections::HashMap;

use openpgp_card::apdu::PcscClient;
use openpgp_card::card_app::CardApp;
use openpgp_card::{CardClientBox, Sex};

#[derive(Debug)]
enum TestResult {
    Status([u8; 2]),
    Text(String),
}

type TestOutput = Vec<TestResult>;

/// Sets name, lang, sex, url; then reads the fields from the card and
/// compares the values with the expected values.
///
/// Returns an empty TestOutput, throws errors for unexpected Status codes
/// and for unequal field values.
fn test_set_user_data(ca: &mut CardApp) -> Result<TestOutput> {
    let res = ca.verify_pw3("12345678")?;
    res.check_ok()?;

    // name
    let res = ca.set_name("Bar<<Foo")?;
    res.check_ok()?;

    // lang
    let res = ca.set_lang("deen")?;
    res.check_ok()?;

    // sex
    let res = ca.set_sex(Sex::Female)?;
    res.check_ok()?;

    // url
    let res = ca.set_url("https://duckduckgo.com/")?;
    res.check_ok()?;

    // read all the fields back again, expect equal data
    let ch = ca.get_cardholder_related_data()?;

    assert_eq!(ch.name, Some("Bar<<Foo".to_string()));
    assert_eq!(ch.lang, Some(vec![['d', 'e'], ['e', 'n']]));
    assert_eq!(ch.sex, Some(Sex::Female));

    let url = ca.get_url()?;
    assert_eq!(url, "https://duckduckgo.com/".to_string());

    Ok(vec![])
}

/// Outputs:
/// - verify pw3 (check) -> Status
/// - verify pw1 (check) -> Status
fn test_verify(ca: &mut CardApp) -> Result<TestOutput> {
    // Steps:
    //
    // - try to set name without verify, assert result is not ok
    // - verify pw3 + pin -> Status
    // - verify pw3 (check) -> Status
    // - set name -> Status
    // - get name -> Text(name)
    // - verify pw1 + pin -> Status
    // - verify pw1 (check) -> Status
    // - set name -> Status
    // - get name -> Text(name)

    let mut out = vec![];

    // try to set name without verify, assert result is not ok!
    let res = ca.set_name("Notverified<<Hello")?;
    assert_eq!(res.status(), [0x69, 0x82]); // "Security status not satisfied"

    let res = ca.verify_pw3("12345678")?;
    res.check_ok()?;

    let check = ca.check_pw3()?;
    // don't "check_ok()" - yubikey5 returns an error code!
    out.push(TestResult::Status(check.status()));

    let res = ca.set_name("Admin<<Hello")?;
    res.check_ok()?;

    let cardholder = ca.get_cardholder_related_data()?;
    assert_eq!(cardholder.name, Some("Admin<<Hello".to_string()));

    let res = ca.verify_pw1("123456")?;
    res.check_ok()?;

    let check = ca.check_pw3()?;
    // don't "check_ok()" - yubikey5 returns an error code
    out.push(TestResult::Status(check.status()));

    let res = ca.set_name("There<<Hello")?;
    res.check_ok()?;

    let cardholder = ca.get_cardholder_related_data()?;
    assert_eq!(cardholder.name, Some("There<<Hello".to_string()));

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
    // list of card idents to runs the tests on
    let cards = vec![
        "0006:16019180", // Yubikey 5
        "0005:0000A835", // FLOSS Card 3.4
        "FFFE:57183146", // Rysim Gnuk (green)
    ];

    let _verify_res = run_test(&cards, test_verify)?;
    let _userdata_res = run_test(&cards, test_set_user_data)?;

    Ok(())
}
