// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use structopt::StructOpt;

use openpgp_card::{Error, Response, StatusBytes};
use openpgp_card_pcsc::PcscClient;
use openpgp_card_sequoia::card::Open;

mod cli;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = cli::Cli::from_args();

    let ccb = PcscClient::open_by_ident(&cli.ident)?;
    let mut card = Open::open_card(ccb)?;

    match cli.cmd {
        cli::Command::SetUserPin {} => {
            // get current user pin
            let pin =
                rpassword::read_password_from_tty(Some("Enter user PIN: "))?;

            // verify pin
            card.verify_user(&pin)?;
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
            let res = card.change_user_pin(&pin, &newpin1);
            if res.is_err() {
                println!("\nFailed to change the user PIN!");
                print_gnuk_note(res, card)?;
            } else {
                println!("\nUser PIN has been set.");
            }
        }
        cli::Command::SetAdminPin {} => {
            // get current admin pin
            let pin =
                rpassword::read_password_from_tty(Some("Enter admin PIN: "))?;

            // verify pin
            card.verify_admin(&pin)?;

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

            // set new user pin
            card.change_admin_pin(&pin, &newpin1)?;

            println!("\nAdmin PIN has been set.");
        }
        cli::Command::SetResetCode {} => {
            // get current admin pin
            let pin =
                rpassword::read_password_from_tty(Some("Enter admin PIN: "))?;

            // verify admin pin
            card.verify_admin(&pin)?;
            println!("PIN was accepted by the card.\n");

            if let Some(mut admin) = card.admin_card() {
                // ask user for new resetting code
                let newpin1 = rpassword::read_password_from_tty(Some(
                    "Enter new resetting code: ",
                ))?;
                let newpin2 = rpassword::read_password_from_tty(Some(
                    "Repeat the new resetting code: ",
                ))?;

                if newpin1 == newpin2 {
                    admin.set_resetting_code(&pin)?;
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
                // get current admin pin
                let pin = rpassword::read_password_from_tty(Some(
                    "Enter admin PIN: ",
                ))?;

                // verify pin
                card.verify_admin(&pin)?;
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
                card.reset_user_pin(&rst, &newpin1)
            } else {
                if let Some(mut admin) = card.admin_card() {
                    admin.reset_user_pin(&newpin1)
                } else {
                    return Err(anyhow::anyhow!(
                        "Failed to use card in admin-mode."
                    )
                    .into());
                }
            };

            if res.is_err() {
                println!("\nFailed to change the user PIN!");
                print_gnuk_note(res, card)?;
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
fn print_gnuk_note(res: Result<Response, Error>, card: Open) -> Result<()> {
    if let Err(Error::CardStatus(StatusBytes::ConditionOfUseNotSatisfied)) =
        res
    {
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
