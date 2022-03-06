// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::{AppSettings, Parser};

#[derive(Parser, Debug)]
#[clap(
    name = "opgpcard",
    author = "Heiko Schäfer <heiko@schaefer.name>",
    disable_help_subcommand(true),
    global_setting(AppSettings::DeriveDisplayOrder),
    about = "A tool for managing OpenPGP cards."
)]
pub struct Cli {
    #[clap(name = "card ident", short = 'c', long = "card")]
    pub ident: String,

    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    SetUserPin {},
    SetAdminPin {},
    SetResetCode {},
    ResetUserPin {
        #[clap(name = "reset as admin", short = 'a', long = "admin")]
        admin: bool,
    },
}
