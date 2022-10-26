// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use clap::{Parser, ValueEnum};

use openpgp_card_sequoia::card::Card;

use crate::util;

#[derive(Parser, Debug)]
pub struct SetIdentityCommand {
    #[clap(name = "card ident", short = 'c', long = "card")]
    ident: String,

    #[clap(name = "identity", value_enum)]
    id: SetIdentityId,
}

#[derive(ValueEnum, Debug, Clone)]
pub enum SetIdentityId {
    #[clap(name = "0")]
    Zero,
    #[clap(name = "1")]
    One,
    #[clap(name = "2")]
    Two,
}

impl From<SetIdentityId> for u8 {
    fn from(id: SetIdentityId) -> Self {
        match id {
            SetIdentityId::Zero => 0,
            SetIdentityId::One => 1,
            SetIdentityId::Two => 2,
        }
    }
}

pub fn set_identity(command: SetIdentityCommand) -> Result<(), Box<dyn std::error::Error>> {
    let backend = util::open_card(&command.ident)?;
    let mut card = Card::new(backend);
    let mut open = card.transaction()?;

    open.set_identity(u8::from(command.id))?;
    Ok(())
}
