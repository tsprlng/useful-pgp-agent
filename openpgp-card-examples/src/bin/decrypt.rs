// SPDX-FileCopyrightText: 2021 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-License-Identifier: MIT OR Apache-2.0

use card_backend_pcsc::PcscBackend;
use openpgp_card_sequoia::{state::Open, Card};
use sequoia_openpgp::parse::{stream::DecryptorBuilder, Parse};
use sequoia_openpgp::policy::StandardPolicy;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() < 2 {
        eprintln!("Usage: decrypt card-ident pin-file");
        return Ok(());
    }

    let card_ident = &args[0];
    let pin_file = &args[1];

    let cards = PcscBackend::card_backends(None)?;

    let mut card: Card<Open> = Card::<Open>::open_by_ident(cards, card_ident)?;
    let mut transaction = card.transaction()?;

    let pin = std::fs::read(pin_file)?;

    transaction.verify_user(&pin)?;

    let mut user = transaction.user_card().unwrap();

    let p = StandardPolicy::new();

    let d = user.decryptor(&|| println!("Touch confirmation needed for decryption"))?;
    let stdin = std::io::stdin();

    let mut stdout = std::io::stdout();

    let db = DecryptorBuilder::from_reader(stdin)?;
    let mut decryptor = db.with_policy(&p, None, d)?;

    std::io::copy(&mut decryptor, &mut stdout)?;

    Ok(())
}
