// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pre-defined `Command` values for the OpenPGP card application

use crate::apdu::command::Command;

/// 7.2.1 SELECT
/// (select the OpenPGP application on the card)
pub(crate) fn select_openpgp() -> Command {
    Command::new(
        0x00,
        0xA4,
        0x04,
        0x00,
        vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01],
    )
}

/// 7.2.6 GET DATA
/// ('tag' must consist of either one or two bytes)
fn get_data(tag: &[u8]) -> Command {
    assert!(!tag.is_empty() && tag.len() <= 2);

    let (p1, p2) = if tag.len() == 2 {
        (tag[0], tag[1])
    } else {
        (0, tag[0])
    };

    Command::new(0x00, 0xCA, p1, p2, vec![])
}

/// GET DO "Application related data"
pub(crate) fn get_application_data() -> Command {
    get_data(&[0x6E])
}

/// GET DO "private use"
pub(crate) fn get_private_do(num: u8) -> Command {
    get_data(&[0x01, num])
}

/// GET DO "Uniform resource locator"
pub(crate) fn get_url() -> Command {
    get_data(&[0x5F, 0x50])
}

/// GET DO "Cardholder related data"
pub(crate) fn cardholder_related_data() -> Command {
    get_data(&[0x65])
}

/// GET DO "Security support template"
pub(crate) fn get_security_support_template() -> Command {
    get_data(&[0x7A])
}

/// GET DO "Cardholder certificate"
pub(crate) fn get_cardholder_certificate() -> Command {
    get_data(&[0x7F, 0x21])
}

/// GET DO "List of supported Algorithm attributes"
pub(crate) fn get_algo_list() -> Command {
    get_data(&[0xFA])
}

/// GET RESPONSE
pub(crate) fn get_response() -> Command {
    Command::new(0x00, 0xC0, 0x00, 0x00, vec![])
}

/// SELECT DATA
pub(crate) fn select_data(num: u8, data: Vec<u8>) -> Command {
    Command::new(0x00, 0xA5, num, 0x04, data)
}

/// VERIFY pin for PW1 (81)
pub(crate) fn verify_pw1_81(pin: Vec<u8>) -> Command {
    Command::new(0x00, 0x20, 0x00, 0x81, pin)
}

/// VERIFY pin for PW1 (82)
pub(crate) fn verify_pw1_82(pin: Vec<u8>) -> Command {
    Command::new(0x00, 0x20, 0x00, 0x82, pin)
}

/// VERIFY pin for PW3 (83)
pub(crate) fn verify_pw3(pin: Vec<u8>) -> Command {
    Command::new(0x00, 0x20, 0x00, 0x83, pin)
}

/// 7.2.8 PUT DATA,
/// ('tag' must consist of either one or two bytes)
pub(crate) fn put_data(tag: &[u8], data: Vec<u8>) -> Command {
    assert!(!tag.is_empty() && tag.len() <= 2);

    let (p1, p2) = if tag.len() == 2 {
        (tag[0], tag[1])
    } else {
        (0, tag[0])
    };
    Command::new(0x00, 0xda, p1, p2, data)
}

/// PUT DO "private use"
pub(crate) fn put_private_do(num: u8, data: Vec<u8>) -> Command {
    put_data(&[0x01, num], data)
}

/// PUT DO Name
pub(crate) fn put_name(name: Vec<u8>) -> Command {
    put_data(&[0x5b], name)
}

/// PUT DO Language preferences
pub(crate) fn put_lang(lang: Vec<u8>) -> Command {
    put_data(&[0x5f, 0x2d], lang)
}

/// PUT DO Sex
pub(crate) fn put_sex(sex: u8) -> Command {
    put_data(&[0x5f, 0x35], vec![sex])
}

/// PUT DO Uniform resource locator (URL)
pub(crate) fn put_url(url: Vec<u8>) -> Command {
    put_data(&[0x5f, 0x50], url)
}

/// PUT DO "PW status bytes"
pub(crate) fn put_pw_status(data: Vec<u8>) -> Command {
    put_data(&[0xc4], data)
}

/// PUT DO "Cardholder certificate"
pub(crate) fn put_cardholder_certificate(data: Vec<u8>) -> Command {
    put_data(&[0x7F, 0x21], data)
}

/// Change PW1 (user pin).
/// This can be used to reset the counter and set a pin.
pub(crate) fn change_pw1(pin: Vec<u8>) -> Command {
    Command::new(0x00, 0x2C, 0x02, 0x81, pin)
}

/// Change PW3 (admin pin)
pub(crate) fn change_pw3(oldpin: Vec<u8>, newpin: Vec<u8>) -> Command {
    let mut fullpin = oldpin;
    fullpin.extend(newpin.iter());

    Command::new(0x00, 0x24, 0x00, 0x83, fullpin)
}

/// 7.2.10 PSO: COMPUTE DIGITAL SIGNATURE
pub(crate) fn signature(data: Vec<u8>) -> Command {
    Command::new(0x00, 0x2A, 0x9e, 0x9a, data)
}

/// 7.2.11 PSO: DECIPHER (decryption)
pub(crate) fn decryption(data: Vec<u8>) -> Command {
    Command::new(0x00, 0x2A, 0x80, 0x86, data)
}

/// 7.2.14 GENERATE ASYMMETRIC KEY PAIR
pub(crate) fn gen_key(data: Vec<u8>) -> Command {
    Command::new(0x00, 0x47, 0x80, 0x00, data)
}

/// Read public key template (see 7.2.14)
pub(crate) fn get_pub_key(data: Vec<u8>) -> Command {
    Command::new(0x00, 0x47, 0x81, 0x00, data)
}

/// key import (see 4.4.3.12, 7.2.8)
pub(crate) fn key_import(data: Vec<u8>) -> Command {
    // The key import uses a PUT DATA command with odd INS (DB) and an
    // Extended header list (DO 4D) as described in ISO 7816-8

    Command::new(0x00, 0xDB, 0x3F, 0xFF, data)
}

/// 7.2.16 TERMINATE DF
pub(crate) fn terminate_df() -> Command {
    Command::new(0x00, 0xe6, 0x00, 0x00, vec![])
}

/// 7.2.17 ACTIVATE FILE
pub(crate) fn activate_file() -> Command {
    Command::new(0x00, 0x44, 0x00, 0x00, vec![])
}
