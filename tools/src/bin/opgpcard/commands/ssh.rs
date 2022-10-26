// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use clap::Parser;

use openpgp_card_sequoia::card::Card;
use openpgp_card_sequoia::types::KeyType;

use crate::output;
use crate::pick_card_for_reading;
use crate::util;
use crate::versioned_output::{OutputBuilder, OutputFormat, OutputVersion};

#[derive(Parser, Debug)]
pub struct SshCommand {
    #[clap(name = "card ident", short = 'c', long = "card")]
    pub ident: Option<String>,
}

pub fn print_ssh(
    format: OutputFormat,
    output_version: OutputVersion,
    command: SshCommand,
) -> Result<()> {
    let mut output = output::Ssh::default();

    let ident = command.ident;

    let backend = pick_card_for_reading(ident)?;
    let mut card = Card::new(backend);
    let mut open = card.transaction()?;

    let ident = open.application_identifier()?.ident();
    output.ident(ident.clone());

    // Print fingerprint of authentication subkey
    let fps = open.fingerprints()?;

    if let Some(fp) = fps.authentication() {
        output.authentication_key_fingerprint(fp.to_string());
    }

    // Show authentication subkey as openssh public key string
    if let Ok(pkm) = open.public_key(KeyType::Authentication) {
        if let Ok(ssh) = util::get_ssh_pubkey_string(&pkm, ident) {
            output.ssh_public_key(ssh);
        }
    }

    println!("{}", output.print(format, output_version)?);
    Ok(())
}
