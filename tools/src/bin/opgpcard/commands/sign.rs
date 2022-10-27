// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use clap::Parser;

use std::path::{Path, PathBuf};

use openpgp_card_sequoia::card::{Card, Open};
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};

use crate::util;

#[derive(Parser, Debug)]
pub struct SignCommand {
    #[clap(name = "card ident", short = 'c', long = "card")]
    pub ident: String,

    /// User PIN file
    #[clap(short = 'p', long = "user-pin")]
    pub user_pin: Option<PathBuf>,

    #[clap(name = "detached", short = 'd', long = "detached")]
    pub detached: bool,

    /// Input file (stdin if unset)
    #[clap(name = "input")]
    pub input: Option<PathBuf>,
}

pub fn sign(command: SignCommand) -> Result<(), Box<dyn std::error::Error>> {
    if command.detached {
        sign_detached(&command.ident, command.user_pin, command.input.as_deref())
    } else {
        Err(anyhow::anyhow!("Only detached signatures are supported for now").into())
    }
}

pub fn sign_detached(
    ident: &str,
    pin_file: Option<PathBuf>,
    input: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = util::open_or_stdin(input)?;

    let backend = util::open_card(ident)?;
    let mut open: Card<Open> = backend.into();
    let mut card = open.transaction()?;

    if card.fingerprints()?.signature().is_none() {
        return Err(anyhow!("Can't sign: this card has no key in the signing slot.").into());
    }

    let user_pin = util::get_pin(&mut card, pin_file, crate::ENTER_USER_PIN);

    let mut sign = util::verify_to_sign(&mut card, user_pin.as_deref())?;
    let s = sign.signer(&|| println!("Touch confirmation needed for signing"))?;

    let message = Armorer::new(Message::new(std::io::stdout())).build()?;
    let mut signer = Signer::new(message, s).detached().build()?;

    std::io::copy(&mut input, &mut signer)?;
    signer.finalize()?;

    Ok(())
}
