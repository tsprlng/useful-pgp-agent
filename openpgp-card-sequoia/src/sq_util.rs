// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Simple wrappers for performing very specific tasks with Sequoia PGP.
//!
//! These helpers are (almost) entirely unrelated to OpenPGP Card.

use anyhow::{anyhow, Context, Result};
use std::io;

use openpgp::armor;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::crypto;
use openpgp::packet::key::SecretParts;
use openpgp::parse::{
    stream::{DecryptionHelper, DecryptorBuilder, VerificationHelper},
    Parse,
};
use openpgp::policy::Policy;
use openpgp::serialize::stream::{Message, Signer};
use openpgp::Cert;
use sequoia_openpgp as openpgp;

use openpgp_card::KeyType;

/// Retrieve a (sub)key from a Cert, for a given KeyType.
///
/// If no, or multiple suitable (sub)keys are found, an error is thrown.
pub fn get_subkey<'a>(
    cert: &'a Cert,
    policy: &'a dyn Policy,
    key_type: KeyType,
) -> Result<ValidErasedKeyAmalgamation<'a, SecretParts>> {
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

    if vkas.len() == 1 {
        Ok(vkas.pop().unwrap())
    } else {
        Err(anyhow!(
            "Unexpected number of suitable (sub)key found: {}",
            vkas.len()
        ))
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
pub fn decryption_helper<D>(
    d: D,
    msg: Vec<u8>,
    p: &dyn Policy,
) -> Result<Vec<u8>>
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
