// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::{AppSettings, Parser, ValueEnum};
use std::path::PathBuf;

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
    Ssh {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: Option<String>,
    },

    /// Export the key data on a card as an OpenPGP public key
    Pubkey {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: Option<String>,

        #[clap(name = "User PIN file", short = 'p', long = "user-pin")]
        user_pin: Option<PathBuf>,

        /// User ID to add to the exported certificate representation
        #[clap(name = "User ID", short = 'u', long = "userid")]
        user_id: Vec<String>,
    },

    /// Administer data on a card (including keys and metadata)
    Admin {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        #[clap(name = "Admin PIN file", short = 'P', long = "admin-pin")]
        admin_pin: Option<PathBuf>,

        #[clap(subcommand)]
        cmd: AdminCommand,
    },

    /// PIN management (change PINs, reset blocked PINs)
    Pin {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        #[clap(subcommand)]
        cmd: PinCommand,
    },

    /// Decrypt data using a card
    Decrypt {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        #[clap(name = "User PIN file", short = 'p', long = "user-pin")]
        user_pin: Option<PathBuf>,

        /// Input file (stdin if unset)
        #[clap(name = "input")]
        input: Option<PathBuf>,
    },

    /// Sign data using a card
    Sign {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        /// User PIN file
        #[clap(short = 'p', long = "user-pin")]
        user_pin: Option<PathBuf>,

        #[clap(name = "detached", short = 'd', long = "detached")]
        detached: bool,

        /// Input file (stdin if unset)
        #[clap(name = "input")]
        input: Option<PathBuf>,
    },

    /// Attestation management (Yubico)
    Attestation {
        #[clap(subcommand)]
        cmd: AttCommand,
    },

    /// Completely reset a card (deletes all data, including the keys on the card!)
    FactoryReset {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,
    },

    /// Change identity (applies only to Nitrokey Start)
    SetIdentity {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        #[clap(name = "identity", value_enum)]
        id: SetIdentityId,
    },
}

#[derive(Parser, Debug)]
pub enum AdminCommand {
    /// Set cardholder name
    Name { name: String },

    /// Set cardholder URL
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

        #[clap(long = "no-decrypt", action = clap::ArgAction::SetFalse)]
        decrypt: bool,

        #[clap(long = "no-auth", action = clap::ArgAction::SetFalse)]
        auth: bool,

        /// Algorithm
        #[clap(value_enum)]
        algo: Option<AdminGenerateAlgo>,

        /// User ID to add to the exported certificate representation
        #[clap(name = "User ID", short = 'u', long = "userid")]
        user_id: Vec<String>,
    },

    /// Set touch policy
    Touch {
        #[clap(name = "Key slot", short = 'k', long = "key", value_enum)]
        key: BasePlusAttKeySlot,

        #[clap(name = "Policy", short = 'p', long = "policy", value_enum)]
        policy: TouchPolicy,
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

    /// Reset User PIN with Admin PIN
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

    /// Reset User PIN with 'Resetting Code'
    ResetUserRc {
        #[clap(name = "Resetting Code file", short = 'r', long = "reset-code")]
        reset_code: Option<PathBuf>,

        #[clap(name = "User PIN file new", short = 'p', long = "user-pin-new")]
        user_pin_new: Option<PathBuf>,
    },
}

#[derive(Parser, Debug)]
pub enum AttCommand {
    /// Print the card's "Attestation Certificate"
    Cert {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: Option<String>,
    },

    /// Generate "Attestation Statement" for one of the key slots on the card
    Generate {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: String,

        #[clap(name = "Key slot", short = 'k', long = "key", value_enum)]
        key: BaseKeySlot,

        #[clap(name = "User PIN file", short = 'p', long = "user-pin")]
        user_pin: Option<PathBuf>,
    },

    /// Print a "cardholder certificate" from the card.
    /// This shows the "Attestation Statement", if one has been generated.
    Statement {
        #[clap(name = "card ident", short = 'c', long = "card")]
        ident: Option<String>,

        #[clap(name = "Key slot", short = 'k', long = "key", value_enum)]
        key: BaseKeySlot,
    },
}

#[derive(ValueEnum, Debug, Clone)]
#[clap(rename_all = "UPPER")]
pub enum BaseKeySlot {
    Sig,
    Dec,
    Aut,
}

impl From<BaseKeySlot> for openpgp_card_sequoia::types::KeyType {
    fn from(ks: BaseKeySlot) -> Self {
        use openpgp_card_sequoia::types::KeyType;
        match ks {
            BaseKeySlot::Sig => KeyType::Signing,
            BaseKeySlot::Dec => KeyType::Decryption,
            BaseKeySlot::Aut => KeyType::Authentication,
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
#[clap(rename_all = "UPPER")]
pub enum BasePlusAttKeySlot {
    Sig,
    Dec,
    Aut,
    Att,
}

impl From<BasePlusAttKeySlot> for openpgp_card_sequoia::types::KeyType {
    fn from(ks: BasePlusAttKeySlot) -> Self {
        use openpgp_card_sequoia::types::KeyType;
        match ks {
            BasePlusAttKeySlot::Sig => KeyType::Signing,
            BasePlusAttKeySlot::Dec => KeyType::Decryption,
            BasePlusAttKeySlot::Aut => KeyType::Authentication,
            BasePlusAttKeySlot::Att => KeyType::Attestation,
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum TouchPolicy {
    #[clap(name = "Off")]
    Off,
    #[clap(name = "On")]
    On,
    #[clap(name = "Fixed")]
    Fixed,
    #[clap(name = "Cached")]
    Cached,
    #[clap(name = "Cached-Fixed")]
    CachedFixed,
}

impl From<TouchPolicy> for openpgp_card_sequoia::types::TouchPolicy {
    fn from(tp: TouchPolicy) -> Self {
        use openpgp_card_sequoia::types::TouchPolicy as OCTouchPolicy;
        match tp {
            TouchPolicy::On => OCTouchPolicy::On,
            TouchPolicy::Off => OCTouchPolicy::Off,
            TouchPolicy::Fixed => OCTouchPolicy::Fixed,
            TouchPolicy::Cached => OCTouchPolicy::Cached,
            TouchPolicy::CachedFixed => OCTouchPolicy::CachedFixed,
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum SetIdentityId {
    #[clap(name = "0")]
    Zero,
    #[clap(name = "1")]
    One,
    #[clap(name = "2")]
    Two,
}

impl From<SetIdentityId> for u8 {
    fn from(id: SetIdentityId) -> Self {
        match id {
            SetIdentityId::Zero => 0,
            SetIdentityId::One => 1,
            SetIdentityId::Two => 2,
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
#[clap(rename_all = "lower")]
pub enum AdminGenerateAlgo {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Nistp256,
    Nistp384,
    Nistp521,
    Curve25519,
}

impl From<AdminGenerateAlgo> for openpgp_card_sequoia::types::AlgoSimple {
    fn from(aga: AdminGenerateAlgo) -> Self {
        use openpgp_card_sequoia::types::AlgoSimple;

        match aga {
            AdminGenerateAlgo::Rsa2048 => AlgoSimple::RSA2k,
            AdminGenerateAlgo::Rsa3072 => AlgoSimple::RSA3k,
            AdminGenerateAlgo::Rsa4096 => AlgoSimple::RSA4k,
            AdminGenerateAlgo::Nistp256 => AlgoSimple::NIST256,
            AdminGenerateAlgo::Nistp384 => AlgoSimple::NIST384,
            AdminGenerateAlgo::Nistp521 => AlgoSimple::NIST521,
            AdminGenerateAlgo::Curve25519 => AlgoSimple::Curve25519,
        }
    }
}
