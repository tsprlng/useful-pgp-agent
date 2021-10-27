// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use structopt::StructOpt;

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
            card.change_user_pin(&pin, &newpin1)?;

            println!("\nUser PIN has been set.");
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

                None
            } else {
                // get current admin pin
                let rst = rpassword::read_password_from_tty(Some(
                    "Enter resetting code: ",
                ))?;

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
            if let Some(rst) = rst {
                // reset to new user pin
                card.reset_user_pin(&rst, &newpin1)?;
            } else {
                if let Some(mut admin) = card.admin_card() {
                    admin.reset_user_pin(&newpin1)?;
                } else {
                    unimplemented!()
                }
            }
            println!("\nUser PIN has been set.");
        }
    }

    Ok(())
}
