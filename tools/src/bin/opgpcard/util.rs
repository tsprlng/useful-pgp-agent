// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{Context, Result};

use openpgp_card::{CardClientBox, Error};
use openpgp_card_pcsc::PcscClient;
use openpgp_card_sequoia::card::{Admin, Open, Sign, User};
use std::path::Path;

pub(crate) fn cards() -> Result<Vec<CardClientBox>> {
    PcscClient::cards()
}

pub(crate) fn open_card(ident: &str) -> Result<CardClientBox, Error> {
    PcscClient::open_by_ident(ident)
}

pub(crate) fn get_user<'app, 'open>(
    open: &'app mut Open<'app>,
    pin_file: &Path,
) -> Result<User<'app, 'open>, Box<dyn std::error::Error>> {
    open.verify_user(&get_pin(pin_file)?)?;
    open.user_card()
        .ok_or_else(|| anyhow::anyhow!("Couldn't get user access").into())
}

pub(crate) fn get_sign<'app, 'open>(
    open: &'app mut Open<'app>,
    pin_file: &Path,
) -> Result<Sign<'app, 'open>, Box<dyn std::error::Error>> {
    open.verify_user_for_signing(&get_pin(pin_file)?)?;
    open.signing_card()
        .ok_or_else(|| anyhow::anyhow!("Couldn't get sign access").into())
}

pub(crate) fn get_admin<'app, 'open>(
    open: &'app mut Open<'app>,
    pin_file: &Path,
) -> Result<Admin<'app, 'open>, Box<dyn std::error::Error>> {
    open.verify_admin(&get_pin(pin_file)?)?;
    open.admin_card()
        .ok_or_else(|| anyhow::anyhow!("Couldn't get admin access").into())
}

pub(crate) fn get_pin(pin_file: &Path) -> Result<String> {
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
