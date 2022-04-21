// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::{AppSettings, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(
    name = "opgpcard",
    author = "Heiko Schäfer <heiko@schaefer.name>",
    disable_help_subcommand(true),
    global_setting(AppSettings::DeriveDisplayOrder),
    about = "A tool for managing OpenPGP cards."
)]
pub struct Cli {
    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    List {},
    Status {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: Option<String>,

        #[clap(name = "verbose", short = 'v', long = "verbose")]
        verbose: bool,
    },
    Info {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: Option<String>,
    },
    Ssh {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: Option<String>,
    },
    Pubkey {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: Option<String>,

        #[clap(name = "User PIN file", short = 'p', long = "user-pin")]
        user_pin: Option<PathBuf>,
    },
    FactoryReset {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,
    },
    SetIdentity {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        #[clap(name = "identity")]
        id: u8,
    },
    Admin {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        #[clap(name = "Admin PIN file", short = 'P', long = "admin-pin")]
        admin_pin: Option<PathBuf>,

        #[clap(subcommand)]
        cmd: AdminCommand,
    },
    Pin {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        #[clap(subcommand)]
        cmd: PinCommand,
    },
    Decrypt {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        #[clap(name = "User PIN file", short = 'p', long = "user-pin")]
        user_pin: Option<PathBuf>,

        #[clap(name = "recipient-cert-file", short = 'r', long = "recipient-cert")]
        cert_file: PathBuf,

        /// Input file (stdin if unset)
        #[clap(name = "input")]
        input: Option<PathBuf>,
    },
    Sign {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        /// User PIN file
        #[clap(short = 'p', long = "user-pin")]
        user_pin: Option<PathBuf>,

        #[clap(name = "detached", short = 'd', long = "detached")]
        detached: bool,

        #[clap(name = "signer-cert-file", short = 's', long = "signer-cert")]
        cert_file: PathBuf,

        /// Input file (stdin if unset)
        #[clap(name = "input")]
        input: Option<PathBuf>,
    },
}

#[derive(Parser, Debug)]
pub enum AdminCommand {
    /// Set name
    Name { name: String },

    /// Set URL
    Url { url: String },

    /// Import a Key.
    ///
    /// If no fingerprint is provided, the key will only be imported if
    /// there are zero or one (sub)keys for each key slot on the card.
    Import {
        keyfile: PathBuf,

        #[clap(name = "Signature key fingerprint", short = 's', long = "sig-fp")]
        sig_fp: Option<String>,

        #[clap(name = "Decryption key fingerprint", short = 'd', long = "dec-fp")]
        dec_fp: Option<String>,

        #[clap(name = "Authentication key fingerprint", short = 'a', long = "auth-fp")]
        auth_fp: Option<String>,
    },
    /// Generate a Key.
    ///
    /// A signing key is always created, decryption and authentication keys
    /// are optional.
    Generate {
        #[clap(name = "User PIN file", short = 'p', long = "user-pin")]
        user_pin: Option<PathBuf>,

        /// Output file (stdout if unset)
        #[clap(name = "output", long = "output", short = 'o')]
        output: Option<PathBuf>,

        #[clap(long = "no-decrypt")]
        no_decrypt: bool,

        #[clap(long = "no-auth")]
        no_auth: bool,

        /// Algorithm (rsa2048|rsa3072|rsa4096|nistp256|nistp384|nistp521|25519)
        #[clap()]
        algo: Option<String>,
    },
}

#[derive(Parser, Debug)]
pub enum PinCommand {
    /// Set User PIN
    SetUser {
        #[clap(name = "User PIN file old", short = 'p', long = "user-pin-old")]
        user_pin_old: Option<PathBuf>,

        #[clap(name = "User PIN file new", short = 'q', long = "user-pin-new")]
        user_pin_new: Option<PathBuf>,
    },

    /// Set Admin PIN
    SetAdmin {
        #[clap(name = "Admin PIN file old", short = 'P', long = "admin-pin-old")]
        admin_pin_old: Option<PathBuf>,

        #[clap(name = "Admin PIN file new", short = 'Q', long = "admin-pin-new")]
        admin_pin_new: Option<PathBuf>,
    },

    /// Reset User PIN with admin PIN
    ResetUser {
        #[clap(name = "Admin PIN file", short = 'P', long = "admin-pin")]
        admin_pin: Option<PathBuf>,

        #[clap(name = "User PIN file new", short = 'p', long = "user-pin-new")]
        user_pin_new: Option<PathBuf>,
    },

    /// Set Resetting Code
    SetReset {
        #[clap(name = "Admin PIN file", short = 'P', long = "admin-pin")]
        admin_pin: Option<PathBuf>,

        #[clap(name = "Resetting code file", short = 'r', long = "reset-code")]
        reset_code: Option<PathBuf>,
    },

    /// Reset User PIN with 'resetting code'
    ResetUserRc {
        #[clap(name = "Resetting code file", short = 'r', long = "reset-code")]
        reset_code: Option<PathBuf>,

        #[clap(name = "User PIN file new", short = 'p', long = "user-pin-new")]
        user_pin_new: Option<PathBuf>,
    },
}
