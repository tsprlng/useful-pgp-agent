// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::{state::Open, Card};

fn main() -> Result<()> {
    println!("The following OpenPGP cards are connected to your system:");

    for backend in PcscBackend::cards(None)? {
        let mut card: Card<Open> = backend.into();
        println!(" {}", card.transaction()?.application_identifier()?.ident());
    }

    Ok(())
}
