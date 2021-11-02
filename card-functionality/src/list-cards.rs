// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;

use openpgp_card_pcsc::PcscClient;
use openpgp_card_sequoia::card::Open;

fn main() -> Result<()> {
    println!("The following OpenPGP cards are connected to your system:");

    for ccb in PcscClient::cards()? {
        let mut ca = ccb.into();
        let open = Open::open(&mut ca)?;
        println!(" {}", open.application_identifier()?.ident());
    }

    Ok(())
}
