// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use clap::Parser;

use std::path::PathBuf;

use openpgp_card_sequoia::card::{Card, Open};
use sequoia_openpgp::serialize::SerializeInto;

use openpgp_card_sequoia::types::KeyType;
use openpgp_card_sequoia::util::public_key_material_and_fp_to_key;

use crate::output;
use crate::pick_card_for_reading;
use crate::util;
use crate::versioned_output::{OutputBuilder, OutputFormat, OutputVersion};

#[derive(Parser, Debug)]
pub struct PubkeyCommand {
    #[clap(
        name = "card ident",
        short = 'c',
        long = "card",
        help = "Identifier of the card to use"
    )]
    ident: Option<String>,

    #[clap(
        name = "User PIN file",
        short = 'p',
        long = "user-pin",
        help = "Optionally, get User PIN from a file"
    )]
    user_pin: Option<PathBuf>,

    /// User ID to add to the exported certificate representation
    #[clap(name = "User ID", short = 'u', long = "userid")]
    user_ids: Vec<String>,
}

pub fn print_pubkey(
    format: OutputFormat,
    output_version: OutputVersion,
    command: PubkeyCommand,
) -> Result<()> {
    let mut output = output::PublicKey::default();

    let backend = pick_card_for_reading(command.ident)?;
    let mut open: Card<Open> = backend.into();
    let mut card = open.transaction()?;

    let ident = card.application_identifier()?.ident();
    output.ident(ident);

    let user_pin = util::get_pin(&mut card, command.user_pin, crate::ENTER_USER_PIN);

    let pkm = card.public_key(KeyType::Signing)?;
    let times = card.key_generation_times()?;
    let fps = card.fingerprints()?;

    let key_sig = public_key_material_and_fp_to_key(
        &pkm,
        KeyType::Signing,
        times.signature().expect("Signature time is unset"),
        fps.signature().expect("Signature fingerprint is unset"),
    )?;

    let mut key_dec = None;
    if let Ok(pkm) = card.public_key(KeyType::Decryption) {
        if let Some(ts) = times.decryption() {
            key_dec = Some(public_key_material_and_fp_to_key(
                &pkm,
                KeyType::Decryption,
                ts,
                fps.decryption().expect("Decryption fingerprint is unset"),
            )?);
        }
    }

    let mut key_aut = None;
    if let Ok(pkm) = card.public_key(KeyType::Authentication) {
        if let Some(ts) = times.authentication() {
            key_aut = Some(public_key_material_and_fp_to_key(
                &pkm,
                KeyType::Authentication,
                ts,
                fps.authentication()
                    .expect("Authentication fingerprint is unset"),
            )?);
        }
    }

    let cert = crate::get_cert(
        &mut card,
        key_sig,
        key_dec,
        key_aut,
        user_pin.as_deref(),
        &command.user_ids,
        &|| println!("Enter User PIN on card reader pinpad."),
    )?;

    let armored = String::from_utf8(cert.armored().to_vec()?)?;
    output.public_key(armored);

    println!("{}", output.print(format, output_version)?);
    Ok(())
}
