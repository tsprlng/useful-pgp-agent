// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

use openpgp_card::{CardApp, Error};
use openpgp_card_pcsc::PcscClient;
use openpgp_card_sequoia::card::{Admin, Open, Sign, User};

pub(crate) fn cards() -> Result<Vec<CardApp>> {
    PcscClient::cards()
}

pub(crate) fn open_card(ident: &str) -> Result<CardApp, Error> {
    PcscClient::open_by_ident(ident)
}

pub(crate) fn verify_to_user<'app, 'open>(
    open: &'app mut Open<'app>,
    pin_file: Option<PathBuf>,
) -> Result<User<'app, 'open>, Box<dyn std::error::Error>> {
    if let Some(path) = pin_file {
        open.verify_user(&load_pin(&path)?)?;
    } else {
        if !open.feature_pinpad_verify() {
            return Err(anyhow!(
                "No user PIN file provided, and no pinpad found"
            )
            .into());
        };

        open.verify_user_pinpad(&|| {
            println!("Enter user PIN on card reader pinpad.")
        })?;
    }

    open.user_card()
        .ok_or_else(|| anyhow!("Couldn't get user access").into())
}

pub(crate) fn verify_to_sign<'app, 'open>(
    open: &'app mut Open<'app>,
    pin_file: Option<PathBuf>,
) -> Result<Sign<'app, 'open>, Box<dyn std::error::Error>> {
    if let Some(path) = pin_file {
        open.verify_user_for_signing(&load_pin(&path)?)?;
    } else {
        if !open.feature_pinpad_verify() {
            return Err(anyhow!(
                "No user PIN file provided, and no pinpad found"
            )
            .into());
        }
        open.verify_user_for_signing_pinpad(&|| {
            println!("Enter user PIN on card reader pinpad.")
        })?;
    }
    open.signing_card()
        .ok_or_else(|| anyhow!("Couldn't get sign access").into())
}

// pub fn admin_card<'b>(&'b mut self) -> Option<Admin<'a, 'b>> {

pub(crate) fn verify_to_admin<'app, 'open>(
    open: &'open mut Open<'app>,
    pin_file: Option<PathBuf>,
) -> Result<Admin<'app, 'open>, Box<dyn std::error::Error>> {
    if let Some(path) = pin_file {
        open.verify_admin(&load_pin(&path)?)?;
    } else {
        if !open.feature_pinpad_verify() {
            return Err(anyhow!(
                "No admin PIN file provided, and no pinpad found"
            )
            .into());
        }

        open.verify_admin_pinpad(&|| {
            println!("Enter admin PIN on card reader pinpad.")
        })?;
    }
    open.admin_card()
        .ok_or_else(|| anyhow!("Couldn't get admin access").into())
}

pub(crate) fn load_pin(pin_file: &Path) -> Result<String> {
    let pin = std::fs::read_to_string(pin_file)?;
    Ok(pin.trim().to_string())
}

pub(crate) fn open_or_stdin(
    f: Option<&Path>,
) -> Result<Box<dyn std::io::Read + Send + Sync>> {
    match f {
        Some(f) => Ok(Box::new(
            std::fs::File::open(f).context("Failed to open input file")?,
        )),
        None => Ok(Box::new(std::io::stdin())),
    }
}

pub(crate) fn open_or_stdout(
    f: Option<&Path>,
) -> Result<Box<dyn std::io::Write + Send + Sync>> {
    match f {
        Some(f) => Ok(Box::new(
            std::fs::File::create(f).context("Failed to open input file")?,
        )),
        None => Ok(Box::new(std::io::stdout())),
    }
}
