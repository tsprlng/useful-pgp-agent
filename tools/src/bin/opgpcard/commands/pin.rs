// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use openpgp_card_sequoia::card::Card;

use crate::util;
use crate::util::{load_pin, print_gnuk_note};
use crate::{ENTER_ADMIN_PIN, ENTER_USER_PIN};

#[derive(Parser, Debug)]
pub struct PinCommand {
    #[clap(name = "card ident", short = 'c', long = "card")]
    pub ident: String,

    #[clap(subcommand)]
    pub cmd: PinSubCommand,
}

#[derive(Parser, Debug)]
pub enum PinSubCommand {
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

pub fn pin(ident: &str, cmd: PinSubCommand) -> Result<()> {
    let backend = util::open_card(&ident)?;
    let mut card = Card::new(backend);
    let mut open = card.transaction()?;

    let pinpad_modify = open.feature_pinpad_modify();

    match cmd {
        PinSubCommand::SetUser {
            user_pin_old,
            user_pin_new,
        } => {
            let res = if !pinpad_modify {
                // get current user pin
                let user_pin1 = util::get_pin(&mut open, user_pin_old, ENTER_USER_PIN)
                    .expect("this should never be None");

                // verify pin
                open.verify_user(&user_pin1)?;
                println!("PIN was accepted by the card.\n");

                let pin_new = match user_pin_new {
                    None => {
                        // ask user for new user pin
                        util::input_pin_twice("Enter new User PIN: ", "Repeat the new User PIN: ")?
                    }
                    Some(path) => load_pin(&path)?,
                };

                // set new user pin
                open.change_user_pin(&user_pin1, &pin_new)
            } else {
                // set new user pin via pinpad
                open.change_user_pin_pinpad(&|| {
                    println!("Enter old User PIN on card reader pinpad, then new User PIN (twice).")
                })
            };

            if res.is_err() {
                println!("\nFailed to change the User PIN!");
                println!("{:?}", res);

                if let Err(err) = res {
                    print_gnuk_note(err, &open)?;
                }
            } else {
                println!("\nUser PIN has been set.");
            }
        }
        PinSubCommand::SetAdmin {
            admin_pin_old,
            admin_pin_new,
        } => {
            if !pinpad_modify {
                // get current admin pin
                let admin_pin1 = util::get_pin(&mut open, admin_pin_old, ENTER_ADMIN_PIN)
                    .expect("this should never be None");

                // verify pin
                open.verify_admin(&admin_pin1)?;
                // (Verifying the PIN here fixes this class of problems:
                // https://developers.yubico.com/PGP/PGP_PIN_Change_Behavior.html
                // It is also just generally more user friendly than failing later)
                println!("PIN was accepted by the card.\n");

                let pin_new = match admin_pin_new {
                    None => {
                        // ask user for new admin pin
                        util::input_pin_twice(
                            "Enter new Admin PIN: ",
                            "Repeat the new Admin PIN: ",
                        )?
                    }
                    Some(path) => load_pin(&path)?,
                };

                // set new admin pin
                open.change_admin_pin(&admin_pin1, &pin_new)?;
            } else {
                // set new admin pin via pinpad
                open.change_admin_pin_pinpad(&|| {
                    println!(
                        "Enter old Admin PIN on card reader pinpad, then new Admin PIN (twice)."
                    )
                })?;
            };

            println!("\nAdmin PIN has been set.");
        }

        PinSubCommand::ResetUser {
            admin_pin,
            user_pin_new,
        } => {
            // verify admin pin
            match util::get_pin(&mut open, admin_pin, ENTER_ADMIN_PIN) {
                Some(admin_pin) => {
                    // verify pin
                    open.verify_admin(&admin_pin)?;
                }
                None => {
                    open.verify_admin_pinpad(&|| println!("Enter Admin PIN on pinpad."))?;
                }
            }
            println!("PIN was accepted by the card.\n");

            // ask user for new user pin
            let pin = match user_pin_new {
                None => util::input_pin_twice("Enter new User PIN: ", "Repeat the new User PIN: ")?,
                Some(path) => load_pin(&path)?,
            };

            let res = if let Some(mut admin) = open.admin_card() {
                admin.reset_user_pin(&pin)
            } else {
                return Err(anyhow::anyhow!("Failed to use card in admin-mode.").into());
            };

            if res.is_err() {
                println!("\nFailed to change the User PIN!");
                if let Err(err) = res {
                    print_gnuk_note(err, &open)?;
                }
            } else {
                println!("\nUser PIN has been set.");
            }
        }

        PinSubCommand::SetReset {
            admin_pin,
            reset_code,
        } => {
            // verify admin pin
            match util::get_pin(&mut open, admin_pin, ENTER_ADMIN_PIN) {
                Some(admin_pin) => {
                    // verify pin
                    open.verify_admin(&admin_pin)?;
                }
                None => {
                    open.verify_admin_pinpad(&|| println!("Enter Admin PIN on pinpad."))?;
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

            if let Some(mut admin) = open.admin_card() {
                admin.set_resetting_code(&code)?;
                println!("\nResetting code has been set.");
            } else {
                return Err(anyhow::anyhow!("Failed to use card in admin-mode.").into());
            };
        }

        PinSubCommand::ResetUserRc {
            reset_code,
            user_pin_new,
        } => {
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
            match open.reset_user_pin(&rst, &pin) {
                Err(err) => {
                    println!("\nFailed to change the User PIN!");
                    print_gnuk_note(err, &open)?;
                }
                Ok(_) => println!("\nUser PIN has been set."),
            }
        }
    }
    Ok(())
}
