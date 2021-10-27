// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::AppSettings;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "opgpcard",
author = "Heiko Schäfer <heiko@schaefer.name>",
global_settings(& [AppSettings::VersionlessSubcommands,
AppSettings::DisableHelpSubcommand, AppSettings::DeriveDisplayOrder]),
about = "A tool for managing OpenPGP cards."
)]
pub struct Cli {
    #[structopt(name = "card ident", short = "c", long = "card")]
    pub ident: String,

    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(StructOpt, Debug)]
pub enum Command {
    SetUserPin {},
    SetAdminPin {},
    SetResetCode {},
    ResetUserPin {
        #[structopt(name = "reset as admin", short = "a", long = "admin")]
        admin: bool,
    },
}
