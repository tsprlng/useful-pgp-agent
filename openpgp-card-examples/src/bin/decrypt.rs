// SPDX-FileCopyrightText: 2021 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-License-Identifier: MIT OR Apache-2.0

use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Card;

use openpgp::parse::{stream::DecryptorBuilder, Parse};
use openpgp::policy::StandardPolicy;
use sequoia_openpgp as openpgp;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() < 2 {
        eprintln!("Usage: decrypt card-ident pin-file");
        return Ok(());
    }

    let card_ident = &args[0];
    let pin_file = &args[1];

    let card_backend = PcscBackend::open_by_ident(card_ident, None)?;

    let mut card = Card::new(card_backend);
    let mut open = card.transaction()?;

    let pin = std::fs::read(pin_file)?;

    open.verify_user(&pin)?;

    let mut user = open.user_card().unwrap();

    let p = StandardPolicy::new();

    let d = user.decryptor(&|| println!("Touch confirmation needed for decryption"))?;
    let stdin = std::io::stdin();

    let mut stdout = std::io::stdout();

    let db = DecryptorBuilder::from_reader(stdin)?;
    let mut decryptor = db.with_policy(&p, None, d)?;

    std::io::copy(&mut decryptor, &mut stdout)?;

    Ok(())
}
