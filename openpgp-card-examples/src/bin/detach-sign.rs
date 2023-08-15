// SPDX-FileCopyrightText: 2021 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-License-Identifier: MIT OR Apache-2.0

use card_backend_pcsc::PcscBackend;
use openpgp_card_sequoia::{state::Open, Card};
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() < 2 {
        eprintln!("Usage: detach-sign card-ident pin-file");
        return Ok(());
    }

    let card_ident = &args[0];
    let pin_file = &args[1];

    let cards = PcscBackend::card_backends(None)?;

    let mut card: Card<Open> = Card::<Open>::open_by_ident(cards, card_ident)?;
    let mut transaction = card.transaction()?;

    let pin = std::fs::read(pin_file)?;

    let mut sign = transaction.to_signing_card(&pin)?;
    let s = sign.signer(&|| println!("Touch confirmation needed for signing"))?;

    let stdout = std::io::stdout();

    let message = Message::new(stdout);

    let message = Armorer::new(message).build()?;

    let signer = Signer::new(message, s);

    let mut signer = signer.detached().build()?;

    std::io::copy(&mut std::io::stdin(), &mut signer)?;

    signer.finalize()?;

    Ok(())
}
