// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Odds and ends, will most likely be restructured.

use std::convert::TryFrom;
use std::convert::TryInto;

use anyhow::{anyhow, Result};
use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::card_do::{Fingerprint, KeyGenerationTime};
use openpgp_card::crypto_data::{CardUploadableKey, PublicKeyMaterial};
use openpgp_card::{Error, KeyType};
use sequoia_openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::packet::{
    key::{Key4, KeyRole, PrimaryRole, SecretParts, SubordinateRole},
    signature::SignatureBuilder,
    Key, UserID,
};
use sequoia_openpgp::types::{
    HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm, Timestamp,
};
use sequoia_openpgp::{Cert, Packet};

use crate::privkey::SequoiaKey;
use crate::state::Transaction;
use crate::{Card, PublicKey};

/// Create a Cert from the three subkeys on a card.
/// (Calling this multiple times will result in different Certs!)
///
/// When pw1 is None, attempt to verify via pinpad.
///
/// `prompt` notifies the user when a pinpad needs the user pin as input.
///
/// FIXME: accept optional metadata for user_id(s)?
#[allow(clippy::too_many_arguments)]
pub fn make_cert<'app>(
    open: &mut Card<Transaction<'app>>,
    key_sig: PublicKey,
    key_dec: Option<PublicKey>,
    key_aut: Option<PublicKey>,
    pw1: Option<&[u8]>,
    pinpad_prompt: &dyn Fn(),
    touch_prompt: &(dyn Fn() + Send + Sync),
    user_ids: &[String],
) -> Result<Cert> {
    let mut pp = vec![];

    // helper: use the card to perform a signing operation
    let mut sign_on_card =
        |op: &mut dyn Fn(&mut dyn sequoia_openpgp::crypto::Signer) -> Result<Signature>| {
            // Allow signing on the card
            if let Some(pw1) = pw1 {
                open.verify_user_for_signing(pw1)?;
            } else {
                open.verify_user_for_signing_pinpad(pinpad_prompt)?;
            }
            if let Some(mut sign) = open.signing_card() {
                // Card-backed signer for bindings
                let mut card_signer = sign.signer_from_public(key_sig.clone(), touch_prompt);

                // Make signature, return it
                let s = op(&mut card_signer)?;
                Ok(s)
            } else {
                Err(anyhow!("Failed to open card for signing"))
            }
        };

    // 1) use the signing key as primary key
    let pri = PrimaryRole::convert_key(key_sig.clone());
    pp.push(Packet::from(pri));

    // 1a) add a direct key signature
    let s = sign_on_card(&mut |signer| {
        SignatureBuilder::new(SignatureType::DirectKey)
            .set_key_flags(
                // Flags for primary key
                KeyFlags::empty().set_signing().set_certification(),
            )?
            .sign_direct_key(signer, key_sig.role_as_primary())
    })?;
    pp.push(s.into());

    if let Some(key_dec) = key_dec {
        // 2) add decryption key as subkey
        let sub_dec = SubordinateRole::convert_key(key_dec);
        pp.push(Packet::from(sub_dec.clone()));

        // Temporary version of the cert
        let cert = Cert::try_from(pp.clone())?;

        // 3) make binding, sign with card -> add
        let s = sign_on_card(&mut |signer| {
            sub_dec.bind(
                signer,
                &cert,
                SignatureBuilder::new(SignatureType::SubkeyBinding).set_key_flags(
                    KeyFlags::empty()
                        .set_storage_encryption()
                        .set_transport_encryption(),
                )?,
            )
        })?;
        pp.push(s.into());
    }

    if let Some(key_aut) = key_aut {
        // 4) add auth subkey
        let sub_aut = SubordinateRole::convert_key(key_aut);
        pp.push(Packet::from(sub_aut.clone()));

        // Temporary version of the cert
        let cert = Cert::try_from(pp.clone())?;

        // 5) make, sign binding -> add
        let s = sign_on_card(&mut |signer| {
            sub_aut.bind(
                signer,
                &cert,
                SignatureBuilder::new(SignatureType::SubkeyBinding)
                    .set_key_flags(KeyFlags::empty().set_authentication())?,
            )
        })?;
        pp.push(s.into());
    }

    // 6) add `user_ids`.
    for uid in user_ids.iter().map(|uid| uid.as_bytes()) {
        let uid: UserID = uid.into();
        pp.push(uid.clone().into());

        // Temporary version of the cert
        let cert = Cert::try_from(pp.clone())?;

        // 7) make, sign binding -> add
        let s = sign_on_card(&mut |signer| {
            uid.bind(
                signer,
                &cert,
                SignatureBuilder::new(SignatureType::PositiveCertification).set_key_flags(
                    // Flags for primary key
                    KeyFlags::empty().set_signing().set_certification(),
                )?,
            )
        })?;
        pp.push(s.into());
    }

    Cert::try_from(pp)
}

/// Meta-Helper fn: get a Sequoia PublicKey from an openpgp-card PublicKeyMaterial, timestamp and
/// card-Fingerprint.
///
/// For ECC decryption keys, possible values for the parameters `hash` and `sym` will be tested.
/// Once a key with matching fingerprint is found in this way, it is considered the correct key,
/// and returned.
///
/// The Fingerprint of the retrieved PublicKey is always validated against the `Fingerprint` as
/// stored on the card. If the fingerprints doesn't match, an Error is returned.
pub fn public_key_material_and_fp_to_key(
    pkm: &PublicKeyMaterial,
    key_type: KeyType,
    time: &KeyGenerationTime,
    fingerprint: &Fingerprint,
) -> Result<PublicKey, Error> {
    // Possible hash/sym parameters based on statistics over 2019-12 SKS dump:
    // https://gitlab.com/sequoia-pgp/sequoia/-/issues/838#note_909813463

    // We try these parameters in descending order of occurrence and return the PublicKey
    // once the Fingerprint matches.

    let param: &[_] = match (pkm, key_type) {
        (PublicKeyMaterial::E(_), KeyType::Decryption) => &[
            (
                Some(HashAlgorithm::SHA256),
                Some(SymmetricAlgorithm::AES128),
            ),
            (
                Some(HashAlgorithm::SHA512),
                Some(SymmetricAlgorithm::AES256),
            ),
            (
                Some(HashAlgorithm::SHA384),
                Some(SymmetricAlgorithm::AES256),
            ),
            (
                Some(HashAlgorithm::SHA384),
                Some(SymmetricAlgorithm::AES192),
            ),
            (
                Some(HashAlgorithm::SHA256),
                Some(SymmetricAlgorithm::AES256),
            ),
        ],
        _ => &[(None, None)],
    };

    for (hash, sym) in param {
        if let Ok(key) = public_key_material_to_key(pkm, key_type, time, *hash, *sym) {
            // check FP
            if key.fingerprint().as_bytes() == fingerprint.as_bytes() {
                // return if match
                return Ok(key);
            }
        }
    }

    Err(Error::InternalError(
        "Couldn't find key with matching fingerprint".to_string(),
    ))
}

/// Helper fn: get a Sequoia PublicKey from an openpgp-card PublicKeyMaterial.
///
/// For ECC decryption keys, `hash` and `sym` can be optionally specified.
pub fn public_key_material_to_key(
    pkm: &PublicKeyMaterial,
    key_type: KeyType,
    time: &KeyGenerationTime,
    hash: Option<HashAlgorithm>,
    sym: Option<SymmetricAlgorithm>,
) -> Result<PublicKey, Error> {
    let time = Timestamp::from(time.get()).into();

    match pkm {
        PublicKeyMaterial::R(rsa) => {
            let k4 = Key4::import_public_rsa(rsa.v(), rsa.n(), Some(time)).map_err(|e| {
                Error::InternalError(format!("sequoia Key4::import_public_rsa failed: {:?}", e))
            })?;

            Ok(k4.into())
        }
        PublicKeyMaterial::E(ecc) => {
            let algo = ecc.algo().clone(); // FIXME?
            if let Algo::Ecc(algo_ecc) = algo {
                let curve = match algo_ecc.curve() {
                    Curve::NistP256r1 => sequoia_openpgp::types::Curve::NistP256,
                    Curve::NistP384r1 => sequoia_openpgp::types::Curve::NistP384,
                    Curve::NistP521r1 => sequoia_openpgp::types::Curve::NistP521,
                    Curve::Ed25519 => sequoia_openpgp::types::Curve::Ed25519,
                    Curve::Cv25519 => sequoia_openpgp::types::Curve::Cv25519,
                    c => unimplemented!("unhandled curve: {:?}", c),
                };

                match key_type {
                    KeyType::Authentication | KeyType::Signing => {
                        if algo_ecc.curve() == Curve::Ed25519 {
                            // EdDSA
                            let k4 =
                                Key4::import_public_ed25519(ecc.data(), time).map_err(|e| {
                                    Error::InternalError(format!(
                                        "sequoia Key4::import_public_ed25519 failed: {:?}",
                                        e
                                    ))
                                })?;

                            Ok(Key::from(k4))
                        } else {
                            // ECDSA
                            let k4 = Key4::new(
                                time,
                                PublicKeyAlgorithm::ECDSA,
                                mpi::PublicKey::ECDSA {
                                    curve,
                                    q: mpi::MPI::new(ecc.data()),
                                },
                            )
                            .map_err(|e| {
                                Error::InternalError(format!(
                                    "sequoia Key4::new for ECDSA failed: {:?}",
                                    e
                                ))
                            })?;

                            Ok(k4.into())
                        }
                    }
                    KeyType::Decryption => {
                        if algo_ecc.curve() == Curve::Cv25519 {
                            // EdDSA
                            let k4 = Key4::import_public_cv25519(ecc.data(), hash, sym, time)
                                .map_err(|e| {
                                    Error::InternalError(format!(
                                        "sequoia Key4::import_public_cv25519 failed: {:?}",
                                        e
                                    ))
                                })?;

                            Ok(k4.into())
                        } else {
                            // ECDH
                            let k4 = Key4::new(
                                time,
                                PublicKeyAlgorithm::ECDH,
                                mpi::PublicKey::ECDH {
                                    curve,
                                    q: mpi::MPI::new(ecc.data()),
                                    hash: hash.unwrap_or_default(),
                                    sym: sym.unwrap_or_default(),
                                },
                            )
                            .map_err(|e| {
                                Error::InternalError(format!(
                                    "sequoia Key4::new for ECDH failed: {:?}",
                                    e
                                ))
                            })?;

                            Ok(k4.into())
                        }
                    }
                    _ => unimplemented!("Unsupported KeyType"),
                }
            } else {
                panic!("unexpected algo {:?}", algo);
            }
        }
        _ => unimplemented!("Unexpected PublicKeyMaterial type"),
    }
}

/// Mapping function to get a fingerprint from "PublicKeyMaterial +
/// timestamp + KeyType" (intended for use with `CardApp.generate_key()`).
///
/// For ECC decryption keys, `hash` and `sym` can be optionally specified.
pub(crate) fn public_to_fingerprint(
    pkm: &PublicKeyMaterial,
    time: &KeyGenerationTime,
    kt: KeyType,
    hash: Option<HashAlgorithm>,
    sym: Option<SymmetricAlgorithm>,
) -> Result<Fingerprint, Error> {
    // Transform PublicKeyMaterial into a Sequoia Key
    let key = public_key_material_to_key(pkm, kt, time, hash, sym)?;

    // Get fingerprint from the Sequoia Key
    let fp = key.fingerprint();
    fp.as_bytes().try_into()
}

/// Helper fn: get a CardUploadableKey for a ValidErasedKeyAmalgamation
pub fn vka_as_uploadable_key(
    vka: ValidErasedKeyAmalgamation<SecretParts>,
    password: Option<String>,
) -> Box<dyn CardUploadableKey> {
    let sqk = SequoiaKey::new(vka, password);
    Box::new(sqk)
}
