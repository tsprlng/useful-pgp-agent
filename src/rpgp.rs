// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use chrono::{DateTime, Utc};
use openpgp_card::ocard::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::ocard::crypto::{EccType, PublicKeyMaterial};
use openpgp_card::ocard::data::{Fingerprint, KeyGenerationTime};
use openpgp_card::ocard::KeyType;
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::PublicKey;
use pgp::types::{EcdsaPublicParams, KeyTrait, KeyVersion, PublicParams, Version};

/// value pairs that we'll consider in ECDH parameter auto-detection
const ECDH_PARAM: &[(Option<HashAlgorithm>, Option<SymmetricKeyAlgorithm>)] = &[
    (
        Some(HashAlgorithm::SHA2_256),
        Some(SymmetricKeyAlgorithm::AES128),
    ),
    (
        Some(HashAlgorithm::SHA2_512),
        Some(SymmetricKeyAlgorithm::AES256),
    ),
    (
        Some(HashAlgorithm::SHA2_384),
        Some(SymmetricKeyAlgorithm::AES256),
    ),
    (
        Some(HashAlgorithm::SHA2_384),
        Some(SymmetricKeyAlgorithm::AES192),
    ),
    (
        Some(HashAlgorithm::SHA2_256),
        Some(SymmetricKeyAlgorithm::AES256),
    ),
];

fn pubkey(
    algo: PublicKeyAlgorithm,
    created: DateTime<Utc>,
    param: PublicParams,
) -> Result<PublicKey, pgp::errors::Error> {
    PublicKey::new(
        Version::New,
        KeyVersion::V4, // FIXME: handle other OpenPGP key versions, later
        algo,
        created,
        None,
        param,
    )
}

fn map_curve(c: &Curve) -> Result<ECCCurve, pgp::errors::Error> {
    Ok(match c {
        Curve::NistP256r1 => ECCCurve::P256,
        Curve::NistP384r1 => ECCCurve::P384,
        Curve::NistP521r1 => ECCCurve::P521,
        Curve::BrainpoolP256r1 => ECCCurve::BrainpoolP256r1,
        Curve::BrainpoolP384r1 => ECCCurve::BrainpoolP384r1,
        Curve::BrainpoolP512r1 => ECCCurve::BrainpoolP512r1,
        Curve::Ed25519 => ECCCurve::Ed25519,
        Curve::Cv25519 => ECCCurve::Curve25519,

        _ => {
            return Err(pgp::errors::Error::Unimplemented(format!(
                "Can't map curve {:?}",
                c
            )))
        }
    })
}

pub(crate) fn map_card_err(e: openpgp_card::Error) -> pgp::errors::Error {
    pgp::errors::Error::Message(format!("openpgp_card error: {:?}", e))
}

/// Get PublicKey for an openpgp-card PublicKeyMaterial, KeyGenerationTime and Fingerprint.
///
/// For ECC decryption keys, possible values for the parameters `hash` and `alg_sym` will be tested.
/// If a key with matching fingerprint is found in this way, it is considered the correct key,
/// and returned.
///
/// The Fingerprint of the retrieved PublicKey is always validated against the `Fingerprint` as
/// stored on the card. If the fingerprints don't match, an Error is returned.
pub fn public_key_material_and_fp_to_key(
    pkm: &PublicKeyMaterial,
    key_type: KeyType,
    created: &KeyGenerationTime,
    fingerprint: &Fingerprint,
) -> Result<PublicKey, pgp::errors::Error> {
    // Possible hash/sym parameters based on statistics over 2019-12 SKS dump:
    // https://gitlab.com/sequoia-pgp/sequoia/-/issues/838#note_909813463

    let param: &[_] = match (pkm, key_type) {
        (PublicKeyMaterial::E(_), KeyType::Decryption) => ECDH_PARAM,
        _ => &[(None, None)],
    };

    for (hash, alg_sym) in param {
        if let Ok(key) = public_key_material_to_key(pkm, key_type, created, *hash, *alg_sym) {
            // check FP
            if key.fingerprint() == fingerprint.as_bytes() {
                // return if match
                return Ok(key);
            }
        }
    }

    Err(pgp::errors::Error::Message(
        "Couldn't find key with matching fingerprint".to_string(),
    ))
}

/// Helper fn: get a PublicKey from an openpgp-card PublicKeyMaterial.
///
/// For ECC decryption keys, `hash` and `alg_sym` can be optionally specified.
pub fn public_key_material_to_key(
    pkm: &PublicKeyMaterial,
    key_type: KeyType,
    created: &KeyGenerationTime,
    hash: Option<HashAlgorithm>,
    alg_sym: Option<SymmetricKeyAlgorithm>,
) -> Result<PublicKey, pgp::errors::Error> {
    let created =
        DateTime::<Utc>::from_timestamp(created.get() as i64, 0).expect("u32 time from card");

    match pkm {
        PublicKeyMaterial::R(rsa) => pubkey(
            PublicKeyAlgorithm::RSA,
            created,
            PublicParams::RSA {
                n: rsa.n().into(),
                e: rsa.v().into(),
            },
        ),

        PublicKeyMaterial::E(ecc) => match ecc.algo() {
            AlgorithmAttributes::Ecc(ecc_attr) => {
                let typ = ecc_attr.ecc_type();

                let curve = map_curve(ecc_attr.curve())?;

                let (pka, pp) = match typ {
                    EccType::ECDH => {
                        if key_type != KeyType::Decryption {
                            return Err(pgp::errors::Error::Message(format!(
                                "ECDH is unsupported in key slot {:?}",
                                key_type
                            )));
                        }

                        let mut p = ecc.data().to_vec();
                        if curve == ECCCurve::Curve25519 && p.len() == 32 {
                            // prepend OpenPGP 0x40 prefix for curve 25519 MPI
                            p.insert(0, 0x40);
                        }

                        let hash = hash.unwrap_or(HashAlgorithm::SHA2_256); // FIXME: default?
                        let alg_sym = alg_sym.unwrap_or(SymmetricKeyAlgorithm::AES128); // FIXME: default?

                        let pp = PublicParams::ECDH {
                            curve: curve.clone(),
                            p: p.clone().into(),
                            hash,
                            alg_sym,
                        };

                        (PublicKeyAlgorithm::ECDH, pp)
                    }

                    EccType::ECDSA => (
                        PublicKeyAlgorithm::ECDSA,
                        PublicParams::ECDSA(EcdsaPublicParams::try_from_mpi(
                            ecc.data().into(),
                            curve,
                        )?),
                    ),

                    EccType::EdDSA => {
                        let mut q = ecc.data().to_vec();
                        if q.len() == 32 {
                            // Add prefix to mark that this MPI uses EdDSA point representation.
                            // See https://datatracker.ietf.org/doc/draft-koch-eddsa-for-openpgp/
                            q.insert(0, 0x40);
                        }

                        (
                            PublicKeyAlgorithm::EdDSA,
                            PublicParams::EdDSA { curve, q: q.into() },
                        )
                    }
                };

                pubkey(pka, created, pp)
            }

            _ => Err(pgp::errors::Error::Message(format!(
                "Unexpected AlgorithmAttributes type in Ecc {:?}",
                ecc.algo(),
            ))),
        },
    }
}

pub(crate) fn pubkey_from_card(
    tx: &mut openpgp_card::Card<openpgp_card::state::Transaction>,
    key_type: KeyType,
) -> Result<PublicKey, pgp::errors::Error> {
    let tx = tx.card();

    let pkm = tx.public_key(key_type).map_err(map_card_err)?;

    let ard = tx.application_related_data().map_err(map_card_err)?;
    let kgt = ard.key_generation_times().map_err(map_card_err)?;

    let Some(created) = (match key_type {
        KeyType::Signing => kgt.signature().cloned(),
        KeyType::Decryption => kgt.decryption().cloned(),
        KeyType::Authentication => kgt.authentication().cloned(),
        KeyType::Attestation => ard.attestation_key_generation_time().map_err(|e| {
            pgp::errors::Error::Message(format!("Get attestation_key_generation_time: {:?}", e,))
        })?,
    }) else {
        // KeyGenerationTime is None
        return Err(pgp::errors::Error::Message(format!(
            "No creation time set for OpenPGP card key type {:?}",
            key_type,
        )));
    };

    // FIXME: simplify, use getter in Card<>
    let Some(fingerprint) = (match key_type {
        KeyType::Signing => ard
            .fingerprints()
            .map_err(map_card_err)?
            .signature()
            .cloned(),
        KeyType::Decryption => ard
            .fingerprints()
            .map_err(map_card_err)?
            .decryption()
            .cloned(),
        KeyType::Authentication => ard
            .fingerprints()
            .map_err(map_card_err)?
            .authentication()
            .cloned(),
        _ => panic!(),
    }) else {
        return Err(pgp::errors::Error::Message(format!(
            "No fingerprint found for key slot {:?}",
            key_type
        )));
    };

    public_key_material_and_fp_to_key(&pkm, key_type, &created, &fingerprint)
}
