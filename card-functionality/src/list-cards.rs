// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;

use openpgp_card::OpenPgp;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;

fn main() -> Result<()> {
    println!("The following OpenPGP cards are connected to your system:");

    for mut card in PcscBackend::cards(None)? {
        let mut pgp = OpenPgp::new(&mut card);
        let open = Open::new(pgp.transaction()?)?;
        println!(" {}", open.application_identifier()?.ident());
    }

    Ok(())
}
