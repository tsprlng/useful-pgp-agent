// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use pcsc::Transaction;

use openpgp_card_pcsc::{PcscClient, PcscTxClient};
use openpgp_card_sequoia::card::Open;

fn main() -> Result<()> {
    println!("The following OpenPGP cards are connected to your system:");

    for mut card in PcscClient::cards()? {
        let cc = card.card_caps();

        let mut tx: Transaction =
            openpgp_card_pcsc::start_tx!(card.card(), true)?;
        let mut txc = PcscTxClient::new(&mut tx, cc);

        let open = Open::new(&mut txc)?;
        println!(" {}", open.application_identifier()?.ident());
    }

    Ok(())
}
