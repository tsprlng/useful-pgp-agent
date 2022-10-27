// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use openpgp_card_sequoia::card::{Card, Open, Transaction};

use crate::util;
use crate::util::{load_pin, print_gnuk_note};
use crate::{ENTER_ADMIN_PIN, ENTER_USER_PIN};

#[derive(Parser, Debug)]
pub struct PinCommand {
    #[clap(
        name = "card ident",
        short = 'c',
        long = "card",
        help = "Identifier of the card to use"
    )]
    pub ident: String,

    #[clap(subcommand)]
    pub cmd: PinSubCommand,
}

#[derive(Parser, Debug)]
pub enum PinSubCommand {
    /// Set User PIN
    ///
    /// Set a new User PIN by providing the current User PIN.
    SetUser {
        #[clap(
            name = "User PIN file old",
            short = 'p',
            long = "user-pin-old",
            help = "Optionally, get old User PIN from a file"
        )]
        user_pin_old: Option<PathBuf>,

        #[clap(
            name = "User PIN file new",
            short = 'q',
            long = "user-pin-new",
            help = "Optionally, get new User PIN from a file"
        )]
        user_pin_new: Option<PathBuf>,
    },

    /// Set Admin PIN
    ///
    /// Set a new Admin PIN by providing the current Admin PIN.
    SetAdmin {
        #[clap(
            name = "Admin PIN file old",
            short = 'P',
            long = "admin-pin-old",
            help = "Optionally, get old Admin PIN from a file"
        )]
        admin_pin_old: Option<PathBuf>,

        #[clap(
            name = "Admin PIN file new",
            short = 'Q',
            long = "admin-pin-new",
            help = "Optionally, get new Admin PIN from a file"
        )]
        admin_pin_new: Option<PathBuf>,
    },

    /// Reset User PIN with Admin PIN
    ///
    /// Set a new User PIN by providing the Admin PIN. This can also be used if the User PIN has
    /// been blocked.
    ResetUser {
        #[clap(
            name = "Admin PIN file",
            short = 'P',
            long = "admin-pin",
            help = "Optionally, get Admin PIN from a file"
        )]
        admin_pin: Option<PathBuf>,

        #[clap(
            name = "User PIN file new",
            short = 'p',
            long = "user-pin-new",
            help = "Optionally, get new User PIN from a file"
        )]
        user_pin_new: Option<PathBuf>,
    },

    /// Reset User PIN with Resetting Code
    ///
    /// Set a new User PIN by providing the Resetting Code. This can also be used if the User PIN
    /// has been blocked.
    ResetUserRc {
        #[clap(
            name = "Resetting Code file",
            short = 'r',
            long = "reset-code",
            help = "Optionally, get the Resetting Code from a file"
        )]
        reset_code: Option<PathBuf>,

        #[clap(
            name = "User PIN file new",
            short = 'p',
            long = "user-pin-new",
            help = "Optionally, get new User PIN from a file"
        )]
        user_pin_new: Option<PathBuf>,
    },

    /// Set Resetting Code
    ///
    /// Set a Resetting Code by providing the Admin PIN.
    SetReset {
        #[clap(
            name = "Admin PIN file",
            short = 'P',
            long = "admin-pin",
            help = "Optionally, get Admin PIN from a file"
        )]
        admin_pin: Option<PathBuf>,

        #[clap(
            name = "Resetting Code file",
            short = 'r',
            long = "reset-code",
            help = "Optionally, get the Resetting Code from a file"
        )]
        reset_code: Option<PathBuf>,
    },
}

pub fn pin(ident: &str, cmd: PinSubCommand) -> Result<()> {
    let backend = util::open_card(ident)?;
    let mut open: Card<Open> = backend.into();
    let card = open.transaction()?;

    match cmd {
        PinSubCommand::SetUser {
            user_pin_old,
            user_pin_new,
        } => set_user(user_pin_old, user_pin_new, card),

        PinSubCommand::SetAdmin {
            admin_pin_old,
            admin_pin_new,
        } => set_admin(admin_pin_old, admin_pin_new, card),

        PinSubCommand::ResetUser {
            admin_pin,
            user_pin_new,
        } => reset_user(admin_pin, user_pin_new, card),

        PinSubCommand::SetReset {
            admin_pin,
            reset_code,
        } => set_reset(admin_pin, reset_code, card),

        PinSubCommand::ResetUserRc {
            reset_code,
            user_pin_new,
        } => reset_user_rc(reset_code, user_pin_new, card),
    }
}

fn set_user(
    user_pin_old: Option<PathBuf>,
    user_pin_new: Option<PathBuf>,
    mut card: Card<Transaction>,
) -> Result<()> {
    let pinpad_modify = card.feature_pinpad_modify();

    let res = if !pinpad_modify {
        // get current user pin
        let user_pin1 = util::get_pin(&mut card, user_pin_old, ENTER_USER_PIN)
            .expect("this should never be None");

        // verify pin
        card.verify_user(&user_pin1)?;
        println!("PIN was accepted by the card.\n");

        let pin_new = match user_pin_new {
            None => {
                // ask user for new user pin
                util::input_pin_twice("Enter new User PIN: ", "Repeat the new User PIN: ")?
            }
            Some(path) => load_pin(&path)?,
        };

        // set new user pin
        card.change_user_pin(&user_pin1, &pin_new)
    } else {
        // set new user pin via pinpad
        card.change_user_pin_pinpad(&|| {
            println!("Enter old User PIN on card reader pinpad, then new User PIN (twice).")
        })
    };

    match res {
        Err(err) => {
            println!("\nFailed to change the User PIN!");
            println!("{:?}", err);
            print_gnuk_note(err, &card)?;
        }
        Ok(_) => println!("\nUser PIN has been set."),
    }
    Ok(())
}

fn set_admin(
    admin_pin_old: Option<PathBuf>,
    admin_pin_new: Option<PathBuf>,
    mut card: Card<Transaction>,
) -> Result<()> {
    let pinpad_modify = card.feature_pinpad_modify();

    if !pinpad_modify {
        // get current admin pin
        let admin_pin1 = util::get_pin(&mut card, admin_pin_old, ENTER_ADMIN_PIN)
            .expect("this should never be None");

        // verify pin
        card.verify_admin(&admin_pin1)?;
        // (Verifying the PIN here fixes this class of problems:
        // https://developers.yubico.com/PGP/PGP_PIN_Change_Behavior.html
        // It is also just generally more user friendly than failing later)
        println!("PIN was accepted by the card.\n");

        let pin_new = match admin_pin_new {
            None => {
                // ask user for new admin pin
                util::input_pin_twice("Enter new Admin PIN: ", "Repeat the new Admin PIN: ")?
            }
            Some(path) => load_pin(&path)?,
        };

        // set new admin pin
        card.change_admin_pin(&admin_pin1, &pin_new)?;
    } else {
        // set new admin pin via pinpad
        card.change_admin_pin_pinpad(&|| {
            println!("Enter old Admin PIN on card reader pinpad, then new Admin PIN (twice).")
        })?;
    };

    println!("\nAdmin PIN has been set.");
    Ok(())
}

fn reset_user(
    admin_pin: Option<PathBuf>,
    user_pin_new: Option<PathBuf>,
    mut card: Card<Transaction>,
) -> Result<()> {
    // verify admin pin
    match util::get_pin(&mut card, admin_pin, ENTER_ADMIN_PIN) {
        Some(admin_pin) => {
            // verify pin
            card.verify_admin(&admin_pin)?;
        }
        None => {
            card.verify_admin_pinpad(&|| println!("Enter Admin PIN on pinpad."))?;
        }
    }
    println!("PIN was accepted by the card.\n");

    // ask user for new user pin
    let pin = match user_pin_new {
        None => util::input_pin_twice("Enter new User PIN: ", "Repeat the new User PIN: ")?,
        Some(path) => load_pin(&path)?,
    };

    let res = if let Some(mut admin) = card.admin_card() {
        admin.reset_user_pin(&pin)
    } else {
        return Err(anyhow::anyhow!("Failed to use card in admin-mode."));
    };

    match res {
        Err(err) => {
            println!("\nFailed to change the User PIN!");
            print_gnuk_note(err, &card)?;
        }
        Ok(_) => println!("\nUser PIN has been set."),
    }
    Ok(())
}

fn set_reset(
    admin_pin: Option<PathBuf>,
    reset_code: Option<PathBuf>,
    mut card: Card<Transaction>,
) -> Result<()> {
    // verify admin pin
    match util::get_pin(&mut card, admin_pin, ENTER_ADMIN_PIN) {
        Some(admin_pin) => {
            // verify pin
            card.verify_admin(&admin_pin)?;
        }
        None => {
            card.verify_admin_pinpad(&|| println!("Enter Admin PIN on pinpad."))?;
        }
    }
    println!("PIN was accepted by the card.\n");

    // ask user for new resetting code
    let code = match reset_code {
        None => util::input_pin_twice(
            "Enter new resetting code: ",
            "Repeat the new resetting code: ",
        )?,
        Some(path) => load_pin(&path)?,
    };

    if let Some(mut admin) = card.admin_card() {
        admin.set_resetting_code(&code)?;
        println!("\nResetting code has been set.");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Failed to use card in admin-mode."))
    }
}

fn reset_user_rc(
    reset_code: Option<PathBuf>,
    user_pin_new: Option<PathBuf>,
    mut card: Card<Transaction>,
) -> Result<()> {
    // reset by presenting resetting code

    let rst = if let Some(path) = reset_code {
        // load resetting code from file
        load_pin(&path)?
    } else {
        // input resetting code
        rpassword::prompt_password("Enter resetting code: ")?
            .as_bytes()
            .to_vec()
    };

    // ask user for new user pin
    let pin = match user_pin_new {
        None => util::input_pin_twice("Enter new User PIN: ", "Repeat the new User PIN: ")?,
        Some(path) => load_pin(&path)?,
    };

    // reset to new user pin
    match card.reset_user_pin(&rst, &pin) {
        Err(err) => {
            println!("\nFailed to change the User PIN!");
            print_gnuk_note(err, &card)
        }
        Ok(_) => {
            println!("\nUser PIN has been set.");
            Ok(())
        }
    }
}
