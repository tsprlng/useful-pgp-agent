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
    /// Enumerate available OpenPGP cards
    List {},

    /// Show information about the data on a card
    Status(commands::status::StatusCommand),

    /// Show technical details about a card
    Info(commands::info::InfoCommand),

    /// Show a card's authentication key as an SSH public key
    Ssh(commands::ssh::SshCommand),

    /// Export the key data on a card as an OpenPGP public key
    Pubkey(commands::pubkey::PubkeyCommand),

    /// Administer data on a card (including keys and metadata)
    Admin(commands::admin::AdminCommand),

    /// PIN management (change PINs, reset blocked PINs)
    #[clap(
        long_about = indoc::indoc! { "
            PIN management (change PINs, reset blocked PINs)

            OpenPGP cards use PINs (numerical passwords) to verify that a user is allowed to \
            perform an operation. There are two PINs for regular operation, User PIN and Admin \
            PIN, and one optional Resetting Code.

            The User PIN is required to use cryptographic operations on a card (such as \
            decryption or signing).
            The Admin PIN is needed to configure a card (for example to import an OpenPGP key \
            into the card) or to unblock the User PIN.
            The Resetting Code only allows unblocking the User PIN. This is useful if the user \
            doesn't have access to the Admin PIN.

            By default, on unconfigured (or factory reset) cards, the User PIN is typically set to
            123456, and the Admin PIN is set to 12345678."
        },
    )]
    Pin(commands::pin::PinCommand),

    /// Decrypt data using a card
    Decrypt(commands::decrypt::DecryptCommand),

    /// Sign data using a card
    ///
    /// Currently, only detached signatures are supported.
    Sign(commands::sign::SignCommand),

    /// Attestation management (Yubico only)
    ///
    /// Yubico implements a proprietary extension to the OpenPGP card standard to
    /// cryptographically certify that a certain asymmetric key has been generated on device, and
    /// not imported.
    ///
    /// This feature is available on YubiKey 5 devices with firmware version 5.2 or newer.
    Attestation(commands::attestation::AttestationCommand),

    /// Completely reset a card (deletes all data including keys!)
    FactoryReset(commands::factory_reset::FactoryResetCommand),

    /// Change identity (Nitrokey Start only)
    ///
    /// A Nitrokey Start device contains three distinct virtual OpenPGP cards, select the identity
    /// of the virtual card to activate.
    SetIdentity(commands::set_identity::SetIdentityCommand),

    /// Show supported output format versions
    #[clap(
        long_about = indoc::indoc! { "
        Show supported output format versions for JSON and YAML output.

        Mark the currently chosen one with a star."
        }
    )]
    OutputVersions {},
}
