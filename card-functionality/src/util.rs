// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};

use sequoia_openpgp::cert::amalgamation::key::ValidKeyAmalgamation;
use sequoia_openpgp::packet::key::{SecretParts, UnspecifiedRole};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::Cert;

use openpgp_card::card_app::CardApp;
use openpgp_card::KeyType;
use openpgp_card_sequoia::vka_as_uploadable_key;
use std::time::SystemTime;

pub const SP: &StandardPolicy = &StandardPolicy::new();

pub(crate) fn upload_subkeys(
    ca: &mut CardApp,
    cert: &Cert,
) -> Result<Vec<(String, u32)>> {
    let mut out = vec![];

    for kt in [
        KeyType::Signing,
        KeyType::Decryption,
        KeyType::Authentication,
    ] {
        let vka = get_subkey(cert, kt)?;

        // store fingerprint as return-value
        let fp = vka.fingerprint().to_hex();
        // store key creation time as return-value
        let creation = vka
            .creation_time()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        out.push((fp, creation));

        // upload key
        let cuk = vka_as_uploadable_key(vka, None);
        let _ = ca.upload_key(cuk, kt)?;
    }

    Ok(out)
}

fn get_subkey(
    cert: &Cert,
    key_type: KeyType,
) -> Result<ValidKeyAmalgamation<'_, SecretParts, UnspecifiedRole, bool>> {
    // Find all suitable (sub)keys for key_type.
    let mut valid_ka = cert
        .keys()
        .with_policy(SP, None)
        .secret()
        .alive()
        .revoked(false);
    valid_ka = match key_type {
        KeyType::Decryption => valid_ka.for_storage_encryption(),
        KeyType::Signing => valid_ka.for_signing(),
        KeyType::Authentication => valid_ka.for_authentication(),
        _ => return Err(anyhow!("Unexpected KeyType")),
    };

    // FIXME: for now, we just pick the first (sub)key from the list
    if let Some(vka) = valid_ka.next() {
        Ok(vka)
    } else {
        Err(anyhow!("No suitable (sub)key found"))
    }
}
