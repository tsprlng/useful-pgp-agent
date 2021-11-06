// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::AppSettings;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "opgpcard",
author = "Heiko Schäfer <heiko@schaefer.name>",
global_settings(& [AppSettings::VersionlessSubcommands,
AppSettings::DisableHelpSubcommand, AppSettings::DeriveDisplayOrder]),
about = "A tool for managing OpenPGP cards."
)]
pub struct Cli {
    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(StructOpt, Debug)]
pub enum Command {
    List {},
    Status {
        #[structopt(name = "card ident", short = "c", long = "card")]
        ident: Option<String>,

        #[structopt(name = "verbose", short = "v", long = "verbose")]
        verbose: bool,
    },
    FactoryReset {
        #[structopt(name = "card ident", short = "c", long = "card")]
        ident: String,
    },
    Admin {
        #[structopt(name = "card ident", short = "c", long = "card")]
        ident: String,

        #[structopt(name = "Admin PIN file", short = "P", long = "admin-pin")]
        admin_pin: PathBuf,

        #[structopt(subcommand)]
        cmd: AdminCommand,
    },
    Decrypt {
        #[structopt(name = "card ident", short = "c", long = "card")]
        ident: String,

        #[structopt(name = "User PIN file", short = "p", long = "user-pin")]
        user_pin: PathBuf,

        #[structopt(
            name = "recipient-cert-file",
            short = "r",
            long = "recipient-cert"
        )]
        cert_file: PathBuf,

        #[structopt(about = "Input file (stdin if unset)", name = "input")]
        input: Option<PathBuf>,
    },
    Sign {
        #[structopt(name = "card ident", short = "c", long = "card")]
        ident: String,

        #[structopt(name = "User PIN file", short = "p", long = "user-pin")]
        user_pin: PathBuf,

        #[structopt(name = "detached", short = "d", long = "detached")]
        detached: bool,

        #[structopt(
            name = "signer-cert-file",
            short = "s",
            long = "signer-cert"
        )]
        cert_file: PathBuf,

        #[structopt(about = "Input file (stdin if unset)", name = "input")]
        input: Option<PathBuf>,
    },
}

#[derive(StructOpt, Debug)]
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

        #[structopt(
            name = "Signature key fingerprint",
            short = "s",
            long = "sig-fp"
        )]
        sig_fp: Option<String>,

        #[structopt(
            name = "Decryption key fingerprint",
            short = "d",
            long = "dec-fp"
        )]
        dec_fp: Option<String>,

        #[structopt(
            name = "Authentication key fingerprint",
            short = "a",
            long = "auth-fp"
        )]
        auth_fp: Option<String>,
    },
    /// Generate a Key.
    ///
    /// A signing key is always created, decryption and authentication keys
    /// are optional.
    Generate {
        #[structopt(name = "User PIN file", short = "p", long = "user-pin")]
        user_pin: PathBuf,

        #[structopt(
            about = "Output file (stdout if unset)",
            name = "output",
            long = "output",
            short = "o"
        )]
        output: Option<PathBuf>,

        #[structopt(long = "no-decrypt")]
        no_decrypt: bool,

        #[structopt(long = "no-auth")]
        no_auth: bool,

        #[structopt(about = "Algorithm \
            (rsa2048|rsa3072|rsa4096|nistp256|nistp384|nistp521|25519)")]
        algo: Option<String>,
    },
}
