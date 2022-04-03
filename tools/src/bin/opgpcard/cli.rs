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
