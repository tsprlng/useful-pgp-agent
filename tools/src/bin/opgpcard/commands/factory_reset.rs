// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use clap::Parser;
use openpgp_card_sequoia::card::{Card, Open};

use crate::util;

#[derive(Parser, Debug)]
pub struct FactoryResetCommand {
    #[clap(name = "card ident", short = 'c', long = "card")]
    ident: String,
}

pub fn factory_reset(command: FactoryResetCommand) -> Result<()> {
    println!("Resetting Card {}", command.ident);
    let backend = util::open_card(&command.ident)?;
    let mut open: Card<Open> = backend.into();

    let mut card = open.transaction()?;
    card.factory_reset().map_err(|e| anyhow!(e))
}
