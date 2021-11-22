// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Simple wrappers for performing very specific tasks with Sequoia PGP.
//!
//! These helpers are (almost) entirely unrelated to OpenPGP card.

use anyhow::{anyhow, Context, Result};
use std::io;

use openpgp::armor;
use openpgp::cert::amalgamation::{
    key::ValidErasedKeyAmalgamation, ValidAmalgamation, ValidateAmalgamation,
};
use openpgp::crypto;
use openpgp::packet::key::{PublicParts, SecretParts};
use openpgp::parse::{
    stream::{DecryptionHelper, DecryptorBuilder, VerificationHelper},
    Parse,
};
use openpgp::policy::Policy;
use openpgp::serialize::stream::{Message, Signer};
use openpgp::types::RevocationStatus;
use openpgp::{Cert, Fingerprint};
use sequoia_openpgp as openpgp;

use openpgp_card::{Error, KeyType};

/// Retrieve a (sub)key from a Cert, for a given KeyType.
///
/// Returns Ok(None), if no such (sub)key exists.
/// If multiple suitable (sub)keys are found, an error is returned.
pub fn get_subkey_by_type<'a>(
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
pub fn get_priv_subkey_by_fingerprint<'a>(
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
    policy: &'a dyn Policy,
    fp: &Fingerprint,
    check_revocation: bool,
) -> Result<Option<ValidErasedKeyAmalgamation<'a, PublicParts>>, Error> {
    // FIXME: if `test_revocation`, then first check if the primary key is
    // revoked?

    // Find the (sub)key in `cert` that matches the fingerprint from
    // the Card's signing-key slot.
    let keys: Vec<_> =
        cert.keys().filter(|ka| &ka.fingerprint() == fp).collect();

    // Exactly one matching (sub)key should be found. If not, fail!
    if keys.len() == 1 {
        // Check if the (sub)key is valid/alive, return error
        // otherwise
        let validkey = keys[0].clone().with_policy(policy, None)?;
        validkey.alive()?;

        if check_revocation {
            if let RevocationStatus::Revoked(_) = validkey.revocation_status()
            {
                return Err(Error::InternalError(anyhow!(
                    "(Sub)key {} in the cert is revoked",
                    fp
                )));
            }
        }

        Ok(Some(validkey))
    } else if keys.is_empty() {
        Ok(None)
    } else if keys.len() == 2 {
        Err(Error::InternalError(anyhow!(
            "Found two results for {}, probably the cert has the \
                 primary as a subkey?",
            fp
        )))
    } else {
        Err(Error::InternalError(anyhow!(
            "Found {} results for (sub)key {}, this is unexpected",
            keys.len(),
            fp
        )))
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
