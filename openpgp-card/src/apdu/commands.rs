// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

/// APDU Commands for OpenPGP card operations
use crate::apdu::command::Command;

/// Select the OpenPGP applet
pub fn select_openpgp() -> Command {
    Command::new(
        0x00,
        0xA4,
        0x04,
        0x00,
        vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01],
    )
}

/// Get DO "Application related data"
pub fn get_application_data() -> Command {
    Command::new(0x00, 0xCA, 0x00, 0x6E, vec![])
}

/// Get DO "Uniform resource locator"
pub fn get_url() -> Command {
    Command::new(0x00, 0xCA, 0x5F, 0x50, vec![])
}

/// Get DO "Cardholder related data"
pub fn cardholder_related_data() -> Command {
    Command::new(0x00, 0xCA, 0x00, 0x65, vec![])
}

/// Get DO "Security support template"
pub fn get_security_support_template() -> Command {
    Command::new(0x00, 0xCA, 0x00, 0x7A, vec![])
}

/// Get DO "List of supported Algorithm attributes"
pub fn get_algo_list() -> Command {
    Command::new(0x00, 0xCA, 0x00, 0xFA, vec![])
}

/// GET RESPONSE
pub fn get_response() -> Command {
    Command::new(0x00, 0xC0, 0x00, 0x00, vec![])
}

/// VERIFY pin for PW1 (81)
pub fn verify_pw1_81(pin: Vec<u8>) -> Command {
    Command::new(0x00, 0x20, 0x00, 0x81, pin)
}

/// VERIFY pin for PW1 (82)
pub fn verify_pw1_82(pin: Vec<u8>) -> Command {
    Command::new(0x00, 0x20, 0x00, 0x82, pin)
}

/// VERIFY pin for PW3 (83)
pub fn verify_pw3(pin: Vec<u8>) -> Command {
    Command::new(0x00, 0x20, 0x00, 0x83, pin)
}

/// TERMINATE DF
pub fn terminate_df() -> Command {
    Command::new(0x00, 0xe6, 0x00, 0x00, vec![])
}

/// ACTIVATE FILE
pub fn activate_file() -> Command {
    Command::new(0x00, 0x44, 0x00, 0x00, vec![])
}

/// 7.2.8 PUT DATA,
/// ('tag' must consist of either one or two bytes)
pub fn put_data(tag: &[u8], data: Vec<u8>) -> Command {
    assert!(!tag.is_empty() && tag.len() <= 2);

    let (p1, p2) = if tag.len() == 2 {
        (tag[0], tag[1])
    } else {
        (0, tag[0])
    };
    Command::new(0x00, 0xda, p1, p2, data)
}

/// PUT DO Name
pub fn put_name(name: Vec<u8>) -> Command {
    put_data(&[0x5b], name)
}

/// PUT DO Language preferences
pub fn put_lang(lang: Vec<u8>) -> Command {
    put_data(&[0x5f, 0x2d], lang)
}

/// PUT DO Sex
pub fn put_sex(sex: u8) -> Command {
    put_data(&[0x5f, 0x35], vec![sex])
}

/// PUT DO Uniform resource locator (URL)
pub fn put_url(url: Vec<u8>) -> Command {
    put_data(&[0x5f, 0x50], url)
}

/// Change PW1 (user pin).
/// This can be used to reset the counter and set a pin.
pub fn change_pw1(pin: Vec<u8>) -> Command {
    Command::new(0x00, 0x2C, 0x02, 0x81, pin)
}

/// Change PW3 (admin pin)
pub fn change_pw3(oldpin: Vec<u8>, newpin: Vec<u8>) -> Command {
    let mut fullpin = oldpin;
    fullpin.extend(newpin.iter());

    Command::new(0x00, 0x24, 0x00, 0x83, fullpin)
}

/// Creates new APDU for decryption operation
pub fn decryption(data: Vec<u8>) -> Command {
    Command::new(0x00, 0x2A, 0x80, 0x86, data)
}

/// Creates new APDU for decryption operation
pub fn signature(data: Vec<u8>) -> Command {
    Command::new(0x00, 0x2A, 0x9e, 0x9a, data)
}
