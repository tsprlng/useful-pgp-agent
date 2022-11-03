// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Simple wrappers for performing very specific tasks with Sequoia PGP.
//!
//! These helpers are (almost) entirely unrelated to OpenPGP card.

use std::io;

use anyhow::{anyhow, Context, Result};
use openpgp_card::{Error, KeyType};
use sequoia_openpgp::armor;
use sequoia_openpgp::cert::amalgamation::key::{ErasedKeyAmalgamation, ValidErasedKeyAmalgamation};
use sequoia_openpgp::crypto;
use sequoia_openpgp::packet::key::{PublicParts, SecretParts};
use sequoia_openpgp::parse::{
    stream::{DecryptionHelper, DecryptorBuilder, VerificationHelper},
    Parse,
};
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::serialize::stream::{Message, Signer};
use sequoia_openpgp::{Cert, Fingerprint};

use crate::{CardDecryptor, CardSigner};

/// Retrieve a (sub)key from a Cert, for a given KeyType.
///
/// Returns Ok(None), if no such (sub)key exists.
/// If multiple suitable (sub)keys are found, an error is returned.
pub fn subkey_by_type<'a>(
    cert: &'a Cert,
    policy: &'a dyn Policy,
    key_type: KeyType,
) -> Result<Option<ValidErasedKeyAmalgamation<'a, SecretParts>>> {
    // Find all suitable (sub)keys for key_type.
    let valid_ka = cert
        .keys()
        .with_policy(policy, None)
        .secret()
        .alive()
        .revoked(false);
    let valid_ka = match key_type {
        KeyType::Decryption => valid_ka.for_storage_encryption(),
        KeyType::Signing => valid_ka.for_signing(),
        KeyType::Authentication => valid_ka.for_authentication(),
        _ => return Err(anyhow!("Unexpected KeyType")),
    };

    let mut vkas: Vec<_> = valid_ka.collect();

    if vkas.is_empty() {
        Ok(None)
    } else if vkas.len() == 1 {
        Ok(Some(vkas.pop().unwrap()))
    } else {
        Err(anyhow!(
            "Unexpected number of suitable (sub)key found: {}",
            vkas.len()
        ))
    }
}

/// Retrieve a private (sub)key from a Cert, by fingerprint.
pub fn private_subkey_by_fingerprint<'a>(
    cert: &'a Cert,
    policy: &'a dyn Policy,
    fingerprint: &str,
) -> Result<Option<ValidErasedKeyAmalgamation<'a, SecretParts>>> {
    let fp = Fingerprint::from_hex(fingerprint)?;

    // Find usable (sub)key with Fingerprint fp.
    let mut vkas: Vec<_> = cert
        .keys()
        .with_policy(policy, None)
        .secret()
        .alive()
        .revoked(false)
        .filter(|vka| vka.fingerprint() == fp)
        .collect();

    if vkas.is_empty() {
        Ok(None)
    } else if vkas.len() == 1 {
        Ok(Some(vkas.pop().unwrap()))
    } else {
        Err(anyhow::anyhow!(
            "Unexpected number of suitable (sub)key found: {}",
            vkas.len()
        ))
    }
}

/// Retrieve a public (sub)key from a Cert, by fingerprint.
pub fn get_subkey_by_fingerprint<'a>(
    cert: &'a Cert,
    fp: &Fingerprint,
) -> Result<Option<ErasedKeyAmalgamation<'a, PublicParts>>, Error> {
    // Find the (sub)key in `cert` that matches the fingerprint from
    // the Card's signing-key slot.
    let keys: Vec<_> = cert.keys().filter(|ka| &ka.fingerprint() == fp).collect();

    if keys.is_empty() {
        Ok(None)
    } else {
        Ok(Some(keys[0].clone()))
    }
}

/// Produce an armored signature from `input` and a Signer `s`.
pub fn sign_helper<S>(s: S, input: &mut dyn io::Read) -> Result<String>
where
    S: crypto::Signer + Send + Sync,
{
    let mut armorer = armor::Writer::new(vec![], armor::Kind::Signature)?;
    {
        let message = Message::new(&mut armorer);
        let mut message = Signer::new(message, s).detached().build()?;

        // Process input data, via message
        io::copy(input, &mut message)?;

        message.finalize()?;
    }

    let buffer = armorer.finalize()?;

    String::from_utf8(buffer).context("Failed to convert signature to utf8")
}

/// Produce decrypted plaintext from a VerificationHelper+DecryptionHelper
/// `d` and the ciphertext `msg`.
pub fn decryption_helper<D>(d: D, msg: Vec<u8>, p: &dyn Policy) -> Result<Vec<u8>>
where
    D: VerificationHelper + DecryptionHelper,
{
    let mut decrypted = Vec::new();
    {
        let reader = io::BufReader::new(&msg[..]);

        let db = DecryptorBuilder::from_reader(reader)?;
        let mut decryptor = db.with_policy(p, None, d)?;

        // Read all data from decryptor and store in decrypted
        io::copy(&mut decryptor, &mut decrypted)?;
    }

    Ok(decrypted)
}

/// Wrapper to easily perform a sign operation
pub fn sign(s: CardSigner, input: &mut dyn io::Read) -> Result<String> {
    let mut armorer = armor::Writer::new(vec![], armor::Kind::Signature)?;
    {
        let message = Message::new(&mut armorer);
        let mut message = Signer::new(message, s).detached().build()?;

        // Process input data, via message
        io::copy(input, &mut message)?;

        message.finalize()?;
    }

    let buffer = armorer.finalize()?;

    String::from_utf8(buffer).context("Failed to convert signature to utf8")
}

/// Wrapper to easily perform a decrypt operation
pub fn decrypt(d: CardDecryptor, msg: Vec<u8>, p: &dyn Policy) -> Result<Vec<u8>> {
    let mut decrypted = Vec::new();
    {
        let reader = io::BufReader::new(&msg[..]);

        let db = DecryptorBuilder::from_reader(reader)?;
        let mut decryptor = db.with_policy(p, None, d)?;

        // Read all data from decryptor and store in decrypted
        io::copy(&mut decryptor, &mut decrypted)?;
    }

    Ok(decrypted)
}
