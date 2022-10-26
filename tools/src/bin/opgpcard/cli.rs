// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::{AppSettings, Parser};

use crate::commands;
use crate::{OutputFormat, OutputVersion};

pub const OUTPUT_VERSIONS: &[OutputVersion] = &[OutputVersion::new(0, 9, 0)];
pub const DEFAULT_OUTPUT_VERSION: OutputVersion = OutputVersion::new(0, 9, 0);

#[derive(Parser, Debug)]
#[clap(
    name = "opgpcard",
    author = "Heiko Schäfer <heiko@schaefer.name>",
    version,
    global_setting(AppSettings::DeriveDisplayOrder),
    about = "A tool for inspecting and configuring OpenPGP cards."
)]
pub struct Cli {
    /// Produce output in the chosen format.
    #[clap(long, value_enum, default_value_t = OutputFormat::Text)]
    pub output_format: OutputFormat,

    /// Pick output version to use, for non-textual formats.
    #[clap(long, default_value_t = DEFAULT_OUTPUT_VERSION)]
    pub output_version: OutputVersion,

    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Show all output versions that are supported. Mark the
    /// currently chosen one with a star.
    OutputVersions {},

    /// Enumerate available OpenPGP cards
    List {},

    /// Show information about the data on a card
    Status(commands::status::StatusCommand),

    /// Show technical details about a card
    Info(commands::info::InfoCommand),

    /// Display a card's authentication key as an SSH public key
    Ssh(commands::ssh::SshCommand),

    /// Export the key data on a card as an OpenPGP public key
    Pubkey(commands::pubkey::PubkeyCommand),

    /// Administer data on a card (including keys and metadata)
    Admin(commands::admin::AdminCommand),

    /// PIN management (change PINs, reset blocked PINs)
    Pin(commands::pin::PinCommand),

    /// Decrypt data using a card
    Decrypt(commands::decrypt::DecryptCommand),

    /// Sign data using a card
    Sign(commands::sign::SignCommand),

    /// Attestation management (Yubico)
    Attestation(commands::attestation::AttestationCommand),

    /// Completely reset a card (deletes all data, including the keys on the card!)
    FactoryReset(commands::factory_reset::FactoryResetCommand),

    /// Change identity (applies only to Nitrokey Start)
    SetIdentity(commands::set_identity::SetIdentityCommand),
}
