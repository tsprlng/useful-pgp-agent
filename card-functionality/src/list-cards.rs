// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;

use openpgp_card::CardBackend;
use openpgp_card_pcsc::PcscCard;
use openpgp_card_sequoia::card::Open;

fn main() -> Result<()> {
    println!("The following OpenPGP cards are connected to your system:");

    for mut card in PcscCard::cards(None)? {
        let mut txc = <dyn CardBackend>::transaction(&mut card)?;

        let open = Open::new(&mut *txc)?;
        println!(" {}", open.application_identifier()?.ident());
    }

    Ok(())
}
