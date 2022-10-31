// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use clap::Parser;
use openpgp_card_sequoia::{state::Open, Card};

use openpgp_card_sequoia::types::KeyType;

use crate::output;
use crate::pick_card_for_reading;
use crate::versioned_output::{OutputBuilder, OutputFormat, OutputVersion};

#[derive(Parser, Debug)]
pub struct StatusCommand {
    #[clap(
        name = "card ident",
        short = 'c',
        long = "card",
        help = "Identifier of the card to use"
    )]
    pub ident: Option<String>,

    #[clap(
        name = "verbose",
        short = 'v',
        long = "verbose",
        help = "Use verbose output"
    )]
    pub verbose: bool,

    /// Print public key material for each key slot
    #[clap(name = "pkm", short = 'K', long = "public-key-material")]
    pub pkm: bool,
}

pub fn print_status(
    format: OutputFormat,
    output_version: OutputVersion,
    command: StatusCommand,
) -> Result<()> {
    let mut output = output::Status::default();
    output.verbose(command.verbose);

    let backend = pick_card_for_reading(command.ident)?;
    let mut open: Card<Open> = backend.into();
    let mut card = open.transaction()?;

    output.ident(card.application_identifier()?.ident());

    let ai = card.application_identifier()?;
    let version = ai.version().to_be_bytes();
    output.card_version(format!("{}.{}", version[0], version[1]));

    // Cardholder Name
    if let Some(name) = card.cardholder_name()? {
        output.cardholder_name(name);
    }

    // We ignore the Cardholder "Sex" field, because it's silly and mostly unhelpful

    // Certificate URL
    let url = card.url()?;
    if !url.is_empty() {
        output.certificate_url(url);
    }

    // Language Preference
    if let Some(lang) = card.cardholder_related_data()?.lang() {
        for lang in lang {
            output.language_preference(format!("{}", lang));
        }
    }

    // key information (imported vs. generated on card)
    let ki = card.key_information().ok().flatten();

    let pws = card.pw_status_bytes()?;

    // information about subkeys

    let fps = card.fingerprints()?;
    let kgt = card.key_generation_times()?;

    let mut signature_key = output::KeySlotInfo::default();
    if let Some(fp) = fps.signature() {
        signature_key.fingerprint(fp.to_spaced_hex());
    }
    signature_key.algorithm(format!("{}", card.algorithm_attributes(KeyType::Signing)?));
    if let Some(kgt) = kgt.signature() {
        signature_key.creation_time(format!("{}", kgt.to_datetime()));
    }
    if let Some(uif) = card.uif_signing()? {
        signature_key.touch_policy(format!("{}", uif.touch_policy()));
        signature_key.touch_features(format!("{}", uif.features()));
    }
    if let Some(ks) = ki.as_ref().map(|ki| ki.sig_status()) {
        signature_key.status(format!("{}", ks));
    }

    if command.pkm {
        if let Ok(pkm) = card.public_key_material(KeyType::Signing) {
            signature_key.public_key_material(pkm.to_string());
        }
    }

    output.signature_key(signature_key);

    let sst = card.security_support_template()?;
    output.signature_count(sst.signature_count());

    let mut decryption_key = output::KeySlotInfo::default();
    if let Some(fp) = fps.decryption() {
        decryption_key.fingerprint(fp.to_spaced_hex());
    }
    decryption_key.algorithm(format!(
        "{}",
        card.algorithm_attributes(KeyType::Decryption)?
    ));
    if let Some(kgt) = kgt.decryption() {
        decryption_key.creation_time(format!("{}", kgt.to_datetime()));
    }
    if let Some(uif) = card.uif_decryption()? {
        decryption_key.touch_policy(format!("{}", uif.touch_policy()));
        decryption_key.touch_features(format!("{}", uif.features()));
    }
    if let Some(ks) = ki.as_ref().map(|ki| ki.dec_status()) {
        decryption_key.status(format!("{}", ks));
    }
    if command.pkm {
        if let Ok(pkm) = card.public_key_material(KeyType::Decryption) {
            decryption_key.public_key_material(pkm.to_string());
        }
    }
    output.decryption_key(decryption_key);

    let mut authentication_key = output::KeySlotInfo::default();
    if let Some(fp) = fps.authentication() {
        authentication_key.fingerprint(fp.to_spaced_hex());
    }
    authentication_key.algorithm(format!(
        "{}",
        card.algorithm_attributes(KeyType::Authentication)?
    ));
    if let Some(kgt) = kgt.authentication() {
        authentication_key.creation_time(format!("{}", kgt.to_datetime()));
    }
    if let Some(uif) = card.uif_authentication()? {
        authentication_key.touch_policy(format!("{}", uif.touch_policy()));
        authentication_key.touch_features(format!("{}", uif.features()));
    }
    if let Some(ks) = ki.as_ref().map(|ki| ki.aut_status()) {
        authentication_key.status(format!("{}", ks));
    }
    if command.pkm {
        if let Ok(pkm) = card.public_key_material(KeyType::Authentication) {
            authentication_key.public_key_material(pkm.to_string());
        }
    }
    output.authentication_key(authentication_key);

    let mut attestation_key = output::KeySlotInfo::default();
    if let Ok(Some(fp)) = card.attestation_key_fingerprint() {
        attestation_key.fingerprint(fp.to_spaced_hex());
    }
    if let Ok(Some(algo)) = card.attestation_key_algorithm_attributes() {
        attestation_key.algorithm(format!("{}", algo));
    }
    if let Ok(Some(kgt)) = card.attestation_key_generation_time() {
        attestation_key.creation_time(format!("{}", kgt.to_datetime()));
    }
    if let Some(uif) = card.uif_attestation()? {
        attestation_key.touch_policy(format!("{}", uif.touch_policy()));
        attestation_key.touch_features(format!("{}", uif.features()));
    }

    // TODO: get public key data for the attestation key from the card
    // if command.pkm {
    //     if let Ok(pkm) = card.public_key(KeyType::Attestation) {
    //         attestation_key.public_key_material(pkm.to_string());
    //     }
    // }

    // TODO: clarify how to reliably map `card.key_information()` output into this field (see below)
    // if let Some(ks) = ki.as_ref().map(|ki| ki.aut_status()) {
    //     attestation_key.status(format!("{}", ks));
    // }

    output.attestation_key(attestation_key);

    // technical details about the card's state
    output.user_pin_valid_for_only_one_signature(pws.pw1_cds_valid_once());

    output.user_pin_remaining_attempts(pws.err_count_pw1());
    output.admin_pin_remaining_attempts(pws.err_count_pw3());
    output.reset_code_remaining_attempts(pws.err_count_rc());

    if let Some(ki) = ki {
        let num = ki.num_additional();
        for i in 0..num {
            output.key_status(ki.additional_ref(i), ki.additional_status(i).to_string());
        }
    }

    if let Ok(fps) = card.ca_fingerprints() {
        for fp in fps.iter().flatten() {
            output.ca_fingerprint(fp.to_string());
        }
    }

    // FIXME: print "Login Data"

    println!("{}", output.print(format, output_version)?);

    Ok(())
}
