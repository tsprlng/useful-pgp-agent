// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use std::io::Write;
use std::time::SystemTime;

use sequoia_openpgp::parse::stream::{
    DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper,
};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::{Policy, StandardPolicy};
use sequoia_openpgp::serialize::stream::{
    Armorer, Encryptor, LiteralWriter, Message,
};
use sequoia_openpgp::Cert;

use openpgp_card::card_do::KeyGenerationTime;
use openpgp_card::{CardClient, KeyType};
use openpgp_card_sequoia::sq_util;
use openpgp_card_sequoia::util::vka_as_uploadable_key;

pub const SP: &StandardPolicy = &StandardPolicy::new();

pub(crate) fn upload_subkeys(
    card_client: &mut dyn CardClient,
    cert: &Cert,
    policy: &dyn Policy,
) -> Result<Vec<(String, KeyGenerationTime)>> {
    let mut out = vec![];

    for kt in &[
        KeyType::Signing,
        KeyType::Decryption,
        KeyType::Authentication,
    ] {
        if let Some(vka) = sq_util::subkey_by_type(cert, policy, *kt)? {
            // store fingerprint as return-value
            let fp = vka.fingerprint().to_hex();
            // store key creation time as return-value
            let creation = vka
                .creation_time()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;

            out.push((fp, creation.into()));

            // upload key
            let cuk = vka_as_uploadable_key(vka, None);
            card_client.key_import(cuk, *kt)?;
        }
    }

    Ok(out)
}

/// Perform signature verification for one Cert and a simple signature
/// over a message.
struct VHelper<'a> {
    cert: &'a Cert,
}

impl<'a> VHelper<'a> {
    fn new(cert: &'a Cert) -> Self {
        Self { cert }
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<Cert>> {
        // Hand out our single Cert
        Ok(vec![self.cert.clone()])
    }

    fn check(
        &mut self,
        structure: MessageStructure,
    ) -> sequoia_openpgp::Result<()> {
        // We are interested in signatures over the data (level 0 signatures)
        if let Some(MessageLayer::SignatureGroup { results }) =
            structure.into_iter().next()
        {
            match results.into_iter().next() {
                Some(Ok(_)) => Ok(()), // Good signature.
                Some(Err(e)) => Err(sequoia_openpgp::Error::from(e).into()),
                None => Err(anyhow::anyhow!("No signature")),
            }
        } else {
            Err(anyhow::anyhow!("Unexpected message structure"))
        }
    }
}

pub fn verify_sig(cert: &Cert, msg: &[u8], sig: &[u8]) -> Result<bool> {
    let vh = VHelper::new(cert);
    let mut dv = DetachedVerifierBuilder::from_bytes(&sig)?
        .with_policy(SP, None, vh)?;

    Ok(dv.verify_bytes(msg).is_ok())
}

pub fn encrypt_to(cleartext: &str, cert: &Cert) -> Result<String> {
    let p = &StandardPolicy::new();

    let mut recipients = Vec::new();

    // Make sure we add at least one subkey from every
    // certificate.
    let mut found_one = false;
    for key in cert
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
    {
        recipients.push(key);
        found_one = true;
    }

    if !found_one {
        return Err(anyhow::anyhow!(
            "No suitable encryption subkey for {}",
            cert
        ));
    }

    let mut sink = vec![];

    let message = Message::new(&mut sink);
    let message = Armorer::new(message).build()?;
    let message = Encryptor::for_recipients(message, recipients).build()?;
    let mut w = LiteralWriter::new(message).build()?;
    w.write_all(cleartext.as_bytes())?;
    w.finalize()?;

    Ok(String::from_utf8(sink).unwrap())
}
