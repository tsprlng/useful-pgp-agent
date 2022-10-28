// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use clap::Parser;
use openpgp_card_sequoia::{state::Open, Card};

use crate::output;
use crate::pick_card_for_reading;
use crate::versioned_output::{OutputBuilder, OutputFormat, OutputVersion};

#[derive(Parser, Debug)]
pub struct InfoCommand {
    #[clap(
        name = "card ident",
        short = 'c',
        long = "card",
        help = "Identifier of the card to use"
    )]
    pub ident: Option<String>,
}

/// print metadata information about a card
pub fn print_info(
    format: OutputFormat,
    output_version: OutputVersion,
    command: InfoCommand,
) -> Result<()> {
    let mut output = output::Info::default();

    let backend = pick_card_for_reading(command.ident)?;
    let mut open: Card<Open> = backend.into();
    let mut card = open.transaction()?;

    let ai = card.application_identifier()?;

    output.ident(ai.ident());

    let version = ai.version().to_be_bytes();
    output.card_version(format!("{}.{}", version[0], version[1]));

    output.application_id(ai.to_string());
    output.manufacturer_id(format!("{:04X}", ai.manufacturer()));
    output.manufacturer_name(ai.manufacturer_name().to_string());

    if let Some(cc) = card.historical_bytes()?.card_capabilities() {
        for line in cc.to_string().lines() {
            let line = line.strip_prefix("- ").unwrap_or(line);
            output.card_capability(line.to_string());
        }
    }
    if let Some(csd) = card.historical_bytes()?.card_service_data() {
        for line in csd.to_string().lines() {
            let line = line.strip_prefix("- ").unwrap_or(line);
            output.card_service_data(line.to_string());
        }
    }

    if let Some(eli) = card.extended_length_information()? {
        for line in eli.to_string().lines() {
            let line = line.strip_prefix("- ").unwrap_or(line);
            output.extended_length_info(line.to_string());
        }
    }

    let ec = card.extended_capabilities()?;
    for line in ec.to_string().lines() {
        let line = line.strip_prefix("- ").unwrap_or(line);
        output.extended_capability(line.to_string());
    }

    // Algorithm information (list of supported algorithms)
    if let Ok(Some(ai)) = card.algorithm_information() {
        for line in ai.to_string().lines() {
            let line = line.strip_prefix("- ").unwrap_or(line);
            output.algorithm(line.to_string());
        }
    }

    // FIXME: print KDF info

    // YubiKey specific (?) firmware version
    if let Ok(ver) = card.firmware_version() {
        let ver = ver.iter().map(u8::to_string).collect::<Vec<_>>().join(".");
        output.firmware_version(ver);
    }

    println!("{}", output.print(format, output_version)?);

    Ok(())
}
