// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Odds and ends, will most likely be restructured.

use std::convert::TryFrom;
use std::convert::TryInto;
use std::io;
use std::time::SystemTime;

use anyhow::{Context, Result};

use openpgp::armor;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::crypto::mpi;
use openpgp::packet::{
    key::{Key4, KeyRole, PrimaryRole, SecretParts, SubordinateRole},
    signature::SignatureBuilder,
    Key, UserID,
};
use openpgp::parse::{stream::DecryptorBuilder, Parse};
use openpgp::policy::Policy;
use openpgp::serialize::stream::{Message, Signer};
use openpgp::types::{KeyFlags, PublicKeyAlgorithm, SignatureType, Timestamp};
use openpgp::{Cert, Packet};
use sequoia_openpgp as openpgp;
use sequoia_openpgp::types::{HashAlgorithm, SymmetricAlgorithm};

use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::card_do::{Fingerprint, KeyGenerationTime};
use openpgp_card::crypto_data::{CardUploadableKey, PublicKeyMaterial};
use openpgp_card::{Error, KeyType, OpenPgpTransaction};

use crate::card::Open;
use crate::privkey::SequoiaKey;
use crate::{decryptor, signer, PublicKey};

/// Create a Cert from the three subkeys on a card.
/// (Calling this multiple times will result in different Certs!)
///
/// When pw1 is None, attempt to verify via pinpad.
///
/// `prompt` notifies the user when a pinpad needs the user pin as input.
///
/// FIXME: accept optional metadata for user_id(s)?
pub fn make_cert<'app>(
    open: &mut Open<'app>,
    key_sig: PublicKey,
    key_dec: Option<PublicKey>,
    key_aut: Option<PublicKey>,
    pw1: Option<&[u8]>,
    pinpad_prompt: &dyn Fn(),
    touch_prompt: &(dyn Fn() + Send + Sync),
) -> Result<Cert> {
    let mut pp = vec![];

    // 1) use the signing key as primary key
    let pri = PrimaryRole::convert_key(key_sig.clone());
    pp.push(Packet::from(pri));

    if let Some(key_dec) = key_dec {
        // 2) add decryption key as subkey
        let sub_dec = SubordinateRole::convert_key(key_dec);
        pp.push(Packet::from(sub_dec.clone()));

        // Temporary version of the cert
        let cert = Cert::try_from(pp.clone())?;

        // 3) make binding, sign with card -> add
        {
            let signing_builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(SystemTime::now())?
                .set_key_validity_period(std::time::Duration::new(0, 0))?
                .set_key_flags(
                    KeyFlags::empty()
                        .set_storage_encryption()
                        .set_transport_encryption(),
                )?;

            // Allow signing on the card
            if let Some(pw1) = pw1 {
                open.verify_user_for_signing(pw1)?;
            } else {
                open.verify_user_for_signing_pinpad(pinpad_prompt)?;
            }
            if let Some(mut sign) = open.signing_card() {
                // Card-backed signer for bindings
                let mut card_signer = sign.signer_from_pubkey(key_sig.clone(), touch_prompt);

                let signing_bsig: Packet = sub_dec
                    .bind(&mut card_signer, &cert, signing_builder)?
                    .into();

                pp.push(signing_bsig);
            }
        }
    }

    if let Some(key_aut) = key_aut {
        // 4) add auth subkey
        let sub_aut = SubordinateRole::convert_key(key_aut);
        pp.push(Packet::from(sub_aut.clone()));

        // 5) make, sign binding -> add
        {
            let signing_builder = SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(SystemTime::now())?
                .set_key_validity_period(std::time::Duration::new(0, 0))?
                .set_key_flags(KeyFlags::empty().set_authentication())?;

            // Allow signing on the card
            if let Some(pw1) = pw1 {
                open.verify_user_for_signing(pw1)?;
            } else {
                open.verify_user_for_signing_pinpad(pinpad_prompt)?;
            }
            if let Some(mut sign) = open.signing_card() {
                // Card-backed signer for bindings
                let mut card_signer = sign.signer_from_pubkey(key_sig.clone(), touch_prompt);

                // Temporary version of the cert
                let cert = Cert::try_from(pp.clone())?;

                let signing_bsig: Packet = sub_aut
                    .bind(&mut card_signer, &cert, signing_builder)?
                    .into();

                pp.push(signing_bsig);
            }
        }
    }

    // 6) add user id from cardholder name (if a name is set)
    let cardholder = open.cardholder_related_data()?;

    // FIXME: accept user id/email as argument?!

    if let Some(name) = cardholder.name() {
        let uid: UserID = name.into();

        pp.push(uid.clone().into());

        // 7) make, sign binding -> add
        {
            let signing_builder = SignatureBuilder::new(SignatureType::PositiveCertification)
                .set_signature_creation_time(SystemTime::now())?
                .set_key_validity_period(std::time::Duration::new(0, 0))?
                .set_key_flags(
                    // Flags for primary key
                    KeyFlags::empty().set_signing().set_certification(),
                )?;

            // Allow signing on the card
            if let Some(pw1) = pw1 {
                open.verify_user_for_signing(pw1)?;
            } else {
                open.verify_user_for_signing_pinpad(pinpad_prompt)?;
            }

            if let Some(mut sign) = open.signing_card() {
                // Card-backed signer for bindings
                let mut card_signer = sign.signer_from_pubkey(key_sig, touch_prompt);

                // Temporary version of the cert
                let cert = Cert::try_from(pp.clone())?;

                let signing_bsig: Packet =
                    uid.bind(&mut card_signer, &cert, signing_builder)?.into();

                pp.push(signing_bsig);
            }
        }
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
                    Curve::NistP256r1 => openpgp::types::Curve::NistP256,
                    Curve::NistP384r1 => openpgp::types::Curve::NistP384,
                    Curve::NistP521r1 => openpgp::types::Curve::NistP521,
                    Curve::Ed25519 => openpgp::types::Curve::Ed25519,
                    Curve::Cv25519 => openpgp::types::Curve::Cv25519,
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

/// FIXME: this fn is used in card_functionality, but should be removed
pub fn sign(
    card_tx: &'_ mut OpenPgpTransaction<'_>,
    cert: &Cert,
    input: &mut dyn io::Read,
    touch_prompt: &(dyn Fn() + Send + Sync),
) -> Result<String> {
    let mut armorer = armor::Writer::new(vec![], armor::Kind::Signature)?;
    {
        let s = signer::CardSigner::new(card_tx, cert, touch_prompt)?;

        let message = Message::new(&mut armorer);
        let mut message = Signer::new(message, s).detached().build()?;

        // Process input data, via message
        io::copy(input, &mut message)?;

        message.finalize()?;
    }

    let buffer = armorer.finalize()?;

    String::from_utf8(buffer).context("Failed to convert signature to utf8")
}

/// FIXME: this fn is used in card_functionality, but should be removed
pub fn decrypt(
    card_tx: &'_ mut OpenPgpTransaction<'_>,
    cert: &Cert,
    msg: Vec<u8>,
    touch_prompt: &(dyn Fn() + Send + Sync),
    p: &dyn Policy,
) -> Result<Vec<u8>> {
    let mut decrypted = Vec::new();
    {
        let reader = io::BufReader::new(&msg[..]);

        let d = decryptor::CardDecryptor::new(card_tx, cert, touch_prompt)?;

        let db = DecryptorBuilder::from_reader(reader)?;
        let mut decryptor = db.with_policy(p, None, d)?;

        // Read all data from decryptor and store in decrypted
        io::copy(&mut decryptor, &mut decrypted)?;
    }

    Ok(decrypted)
}
