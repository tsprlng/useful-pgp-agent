// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use clap::Parser;

use std::path::PathBuf;

use openpgp_card_sequoia::card::{Card, Open};
use sequoia_openpgp::{
    parse::{stream::DecryptorBuilder, Parse},
    policy::StandardPolicy,
};

use crate::util;

#[derive(Parser, Debug)]
pub struct DecryptCommand {
    #[clap(
        name = "card ident",
        short = 'c',
        long = "card",
        help = "Identifier of the card to use"
    )]
    ident: String,

    #[clap(
        name = "User PIN file",
        short = 'p',
        long = "user-pin",
        help = "Optionally, get User PIN from a file"
    )]
    pin_file: Option<PathBuf>,

    /// Input file (stdin if unset)
    #[clap(name = "input")]
    input: Option<PathBuf>,

    /// Output file (stdout if unset)
    #[clap(name = "output", long = "output", short = 'o')]
    pub output: Option<PathBuf>,
}

pub fn decrypt(command: DecryptCommand) -> Result<(), Box<dyn std::error::Error>> {
    let p = StandardPolicy::new();

    let input = util::open_or_stdin(command.input.as_deref())?;

    let backend = util::open_card(&command.ident)?;
    let mut open: Card<Open> = backend.into();
    let mut card = open.transaction()?;

    if card.fingerprints()?.decryption().is_none() {
        return Err(anyhow!("Can't decrypt: this card has no key in the decryption slot.").into());
    }

    let user_pin = util::get_pin(&mut card, command.pin_file, crate::ENTER_USER_PIN);

    let mut user = util::verify_to_user(&mut card, user_pin.as_deref())?;
    let d = user.decryptor(&|| println!("Touch confirmation needed for decryption"))?;

    let db = DecryptorBuilder::from_reader(input)?;
    let mut decryptor = db.with_policy(&p, None, d)?;

    let mut sink = util::open_or_stdout(command.output.as_deref())?;
    std::io::copy(&mut decryptor, &mut sink)?;

    Ok(())
}
