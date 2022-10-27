// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use clap::Parser;

use sequoia_openpgp::Cert;

use openpgp_card_sequoia::card::{Card, Open, Transaction};
use openpgp_card_sequoia::types::CardBackend;
use openpgp_card_sequoia::util::make_cert;
use openpgp_card_sequoia::PublicKey;

mod cli;
mod commands;
mod output;
mod util;
mod versioned_output;

use cli::OUTPUT_VERSIONS;
use versioned_output::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

const ENTER_USER_PIN: &str = "Enter User PIN:";
const ENTER_ADMIN_PIN: &str = "Enter Admin PIN:";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let cli = cli::Cli::parse();

    match cli.cmd {
        cli::Command::OutputVersions {} => {
            output_versions(cli.output_version);
        }
        cli::Command::List {} => {
            list_cards(cli.output_format, cli.output_version)?;
        }
        cli::Command::Status(cmd) => {
            commands::status::print_status(cli.output_format, cli.output_version, cmd)?;
        }
        cli::Command::Info(cmd) => {
            commands::info::print_info(cli.output_format, cli.output_version, cmd)?;
        }
        cli::Command::Ssh(cmd) => {
            commands::ssh::print_ssh(cli.output_format, cli.output_version, cmd)?;
        }
        cli::Command::Pubkey(cmd) => {
            commands::pubkey::print_pubkey(cli.output_format, cli.output_version, cmd)?;
        }
        cli::Command::SetIdentity(cmd) => {
            commands::set_identity::set_identity(cmd)?;
        }
        cli::Command::Decrypt(cmd) => {
            commands::decrypt::decrypt(cmd)?;
        }
        cli::Command::Sign(cmd) => {
            commands::sign::sign(cmd)?;
        }
        cli::Command::Attestation(cmd) => {
            commands::attestation::attestation(cli.output_format, cli.output_version, cmd)?;
        }
        cli::Command::FactoryReset(cmd) => {
            commands::factory_reset::factory_reset(cmd)?;
        }
        cli::Command::Admin(cmd) => {
            commands::admin::admin(cli.output_format, cli.output_version, cmd)?;
        }
        cli::Command::Pin(cmd) => {
            commands::pin::pin(&cmd.ident, cmd.cmd)?;
        }
    }

    Ok(())
}

fn output_versions(chosen: OutputVersion) {
    for v in OUTPUT_VERSIONS.iter() {
        if v == &chosen {
            println!("* {}", v);
        } else {
            println!("  {}", v);
        }
    }
}

fn list_cards(format: OutputFormat, output_version: OutputVersion) -> Result<()> {
    let cards = util::cards()?;
    let mut output = output::List::default();
    if !cards.is_empty() {
        for backend in cards {
            let mut open: Card<Open> = backend.into();

            output.push(open.transaction()?.application_identifier()?.ident());
        }
    }
    println!("{}", output.print(format, output_version)?);
    Ok(())
}

/// Return a card for a read operation. If `ident` is None, and exactly one card
/// is plugged in, that card is returned. (We don't This
fn pick_card_for_reading(ident: Option<String>) -> Result<Box<dyn CardBackend + Send + Sync>> {
    if let Some(ident) = ident {
        Ok(util::open_card(&ident)?)
    } else {
        let mut cards = util::cards()?;
        if cards.len() == 1 {
            Ok(cards.pop().unwrap())
        } else if cards.is_empty() {
            Err(anyhow::anyhow!("No cards found"))
        } else {
            // The output version for OutputFormat::Text doesn't matter (it's ignored).
            list_cards(OutputFormat::Text, OutputVersion::new(0, 0, 0))?;

            println!("Specify which card to use with '--card <card ident>'\n");

            Err(anyhow::anyhow!("Found more than one card"))
        }
    }
}

fn get_cert(
    card: &mut Card<Transaction>,
    key_sig: PublicKey,
    key_dec: Option<PublicKey>,
    key_aut: Option<PublicKey>,
    user_pin: Option<&[u8]>,
    user_ids: &[String],
    prompt: &dyn Fn(),
) -> Result<Cert> {
    if user_pin.is_none() && card.feature_pinpad_verify() {
        println!(
            "The public cert will now be generated.\n\n\
             You will need to enter your User PIN multiple times during this process.\n\n"
        );
    }

    make_cert(
        card,
        key_sig,
        key_dec,
        key_aut,
        user_pin,
        prompt,
        &|| println!("Touch confirmation needed for signing"),
        user_ids,
    )
}
