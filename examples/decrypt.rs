// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::File;

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::{Deserializable, Message};

fn main() -> testresult::TestResult {
    let card = PcscBackend::cards(None)?.next().unwrap()?;
    let mut card = openpgp_card::Card::new(card)?;
    let mut tx = card.transaction()?;

    let pwd = &std::env::args().collect::<Vec<_>>()[1];
    eprintln!("with pwd = {pwd}");

    tx.card()
        .verify_pw1_user(pwd.as_bytes().to_vec().into())
        .expect("Verify");

    let cs = CardSlot::init_from_card(&mut tx, KeyType::Decryption, &|| {
        eprintln!("touch confirmation needed")
    })?;
    let (message, _headers) = Message::from_armor_single(File::open("message2.asc")?)?;
    eprintln!("message: {:?}", &message);

    let decrypted = cs.decrypt_message(&message)?;
    eprintln!("decrypted: {:?}", &decrypted);

    if let Message::Literal(data) = decrypted {
        println!("{}", String::from_utf8_lossy(data.data()));
    }

    Ok(())
}
