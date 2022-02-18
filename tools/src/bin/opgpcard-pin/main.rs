// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use structopt::StructOpt;

use openpgp_card::{CardBackend, Error, StatusBytes};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::Open;

mod cli;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let cli = cli::Cli::from_args();

    let mut card = PcscBackend::open_by_ident(&cli.ident, None)?;
    let mut txc = card.transaction()?;

    let pinpad_verify = txc.feature_pinpad_verify();
    let pinpad_modify = txc.feature_pinpad_modify();

    let mut open = Open::new(&mut *txc)?;

    match cli.cmd {
        cli::Command::SetUserPin {} => {
            let res = if !pinpad_modify {
                // get current user pin
                let pin = rpassword::read_password_from_tty(Some(
                    "Enter user PIN: ",
                ))?;

                // verify pin
                open.verify_user(&pin)?;
                println!("PIN was accepted by the card.\n");

                // get new user pin
                let newpin1 = rpassword::read_password_from_tty(Some(
                    "Enter new user PIN: ",
                ))?;
                let newpin2 = rpassword::read_password_from_tty(Some(
                    "Repeat the new user PIN: ",
                ))?;

                if newpin1 != newpin2 {
                    return Err(anyhow::anyhow!("PINs do not match.").into());
                }

                // set new user pin
                open.change_user_pin(&pin, &newpin1)
            } else {
                // set new user pin via pinpad
                open.change_user_pin_pinpad(&|| {
                    println!(
                        "Enter old user PIN on card reader pinpad, \
                         then new user PIN (twice)."
                    )
                })
            };

            if res.is_err() {
                println!("\nFailed to change the user PIN!");
                if let Err(err) = res {
                    print_gnuk_note(err, &open)?;
                }
            } else {
                println!("\nUser PIN has been set.");
            }
        }
        cli::Command::SetAdminPin {} => {
            if !pinpad_modify {
                // get current admin pin
                let pin = rpassword::read_password_from_tty(Some(
                    "Enter admin PIN: ",
                ))?;

                // verify pin
                open.verify_admin(&pin)?;

                // get new admin pin
                let newpin1 = rpassword::read_password_from_tty(Some(
                    "Enter new admin PIN: ",
                ))?;
                let newpin2 = rpassword::read_password_from_tty(Some(
                    "Repeat the new admin PIN: ",
                ))?;

                if newpin1 != newpin2 {
                    return Err(anyhow::anyhow!("PINs do not match.").into());
                }

                // set new admin pin from input
                open.change_admin_pin(&pin, &newpin1)?;
            } else {
                // set new admin pin with pinpad
                open.change_admin_pin_pinpad(&|| {
                    println!(
                        "Enter old admin PIN on card reader pinpad, \
                         then new admin PIN (twice)."
                    )
                })?;
            }

            println!("\nAdmin PIN has been set.");
        }
        cli::Command::SetResetCode {} => {
            // verify admin pin
            if !pinpad_verify {
                // get current admin pin
                let pin = rpassword::read_password_from_tty(Some(
                    "Enter admin PIN: ",
                ))?;

                open.verify_admin(&pin)?;
            } else {
                open.verify_admin_pinpad(&|| {
                    println!("Enter admin PIN on card reader pinpad.")
                })?;
            }
            println!("PIN was accepted by the card.\n");

            if let Some(mut admin) = open.admin_card() {
                // ask user for new resetting code
                let newpin1 = rpassword::read_password_from_tty(Some(
                    "Enter new resetting code: ",
                ))?;
                let newpin2 = rpassword::read_password_from_tty(Some(
                    "Repeat the new resetting code: ",
                ))?;

                if newpin1 == newpin2 {
                    admin.set_resetting_code(&newpin1)?;
                } else {
                    return Err(anyhow::anyhow!("PINs do not match.").into());
                }
            } else {
                return Err(anyhow::anyhow!(
                    "Failed to use card in admin-mode."
                )
                .into());
            }
            println!("\nResetting code has been set.");
        }
        cli::Command::ResetUserPin { admin } => {
            // either with resetting code, or by presenting pw3

            let rst = if admin {
                if !pinpad_verify {
                    // get current admin pin
                    let pin = rpassword::read_password_from_tty(Some(
                        "Enter admin PIN: ",
                    ))?;

                    // verify pin
                    open.verify_admin(&pin)?;
                } else {
                    open.verify_admin_pinpad(&|| {
                        println!("Enter admin PIN on card reader pinpad.")
                    })?;
                }
                println!("PIN was accepted by the card.\n");

                None
            } else {
                // get resetting code
                let rst = rpassword::read_password_from_tty(Some(
                    "Enter resetting code: ",
                ))?;

                // NOTE: this code cannot be verified with the card!

                Some(rst)
            };

            // get new user pin
            let newpin1 = rpassword::read_password_from_tty(Some(
                "Enter new user PIN: ",
            ))?;
            let newpin2 = rpassword::read_password_from_tty(Some(
                "Repeat the new user PIN: ",
            ))?;

            if newpin1 != newpin2 {
                return Err(anyhow::anyhow!("PINs do not match.").into());
            }

            let res = if let Some(rst) = rst {
                // reset to new user pin
                open.reset_user_pin(&rst, &newpin1)
            } else if let Some(mut admin) = open.admin_card() {
                admin.reset_user_pin(&newpin1)
            } else {
                return Err(anyhow::anyhow!(
                    "Failed to use card in admin-mode."
                )
                .into());
            };

            if res.is_err() {
                println!("\nFailed to change the user PIN!");
                if let Err(err) = res {
                    print_gnuk_note(err, &open)?;
                }
            } else {
                println!("\nUser PIN has been set.");
            }
        }
    }

    Ok(())
}

/// Gnuk doesn't allow the User password (pw1) to be changed while no
/// private key material exists on the card.
///
/// This fn checks for Gnuk's Status code and the case that no keys exist
/// on the card, and prints a note to the user, pointing out that the
/// absence of keys on the card might be the reason for the error they get.
fn print_gnuk_note(err: Error, card: &Open) -> Result<()> {
    if matches!(
        err,
        Error::CardStatus(StatusBytes::ConditionOfUseNotSatisfied)
    ) {
        // check if no keys exist on the card
        let fps = card.fingerprints()?;
        if fps.signature() == None
            && fps.decryption() == None
            && fps.authentication() == None
        {
            println!(
                "\nNOTE: Some cards (e.g. Gnuk) don't allow \
                        User PIN change while no keys exist on the card."
            );
        }
    }
    Ok(())
}
