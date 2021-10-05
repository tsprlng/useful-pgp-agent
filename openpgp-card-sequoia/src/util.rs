// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
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

use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::card_do::{Fingerprint, KeyGenerationTime};
use openpgp_card::crypto_data::{CardUploadableKey, PublicKeyMaterial};
use openpgp_card::{CardApp, Error, KeyType};

use crate::privkey::SequoiaKey;
use crate::signer::CardSigner;
use crate::{decryptor, signer, PublicKey};

/// Create a Cert from the three subkeys on a card.
/// (Calling this multiple times will result in different Certs!)
///
/// FIXME: contains hardcoded default passwords!
///
/// FIXME: make dec/auth keys optional
///
/// FIXME: accept optional metadata for user_id(s)?
pub fn make_cert(
    ca: &mut CardApp,
    key_sig: PublicKey,
    key_dec: PublicKey,
    key_aut: PublicKey,
) -> Result<Cert> {
    let mut pp = vec![];

    // 1) use the signing key as primary key
    let pri = PrimaryRole::convert_key(key_sig.clone());
    pp.push(Packet::from(pri));

    // 2) add decryption key as subkey
    let sub_dec = SubordinateRole::convert_key(key_dec);
    pp.push(Packet::from(sub_dec.clone()));

    // Temporary version of the cert
    let cert = Cert::try_from(pp.clone())?;

    // 3) make binding, sign with card -> add
    {
        let signing_builder =
            SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(SystemTime::now())?
                .set_key_validity_period(std::time::Duration::new(0, 0))?
                .set_key_flags(
                    KeyFlags::empty()
                        .set_storage_encryption()
                        .set_transport_encryption(),
                )?;

        // Allow signing on the card
        ca.verify_pw1_for_signing("123456")?;

        // Card-backed signer for bindings
        let mut card_signer = CardSigner::with_pubkey(ca, key_sig.clone());

        let signing_bsig: Packet = sub_dec
            .bind(&mut card_signer, &cert, signing_builder)?
            .into();

        pp.push(signing_bsig);
    }

    // 4) add auth subkey
    let sub_aut = SubordinateRole::convert_key(key_aut);
    pp.push(Packet::from(sub_aut.clone()));

    // 5) make, sign binding -> add
    {
        let signing_builder =
            SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(SystemTime::now())?
                .set_key_validity_period(std::time::Duration::new(0, 0))?
                .set_key_flags(KeyFlags::empty().set_authentication())?;

        // Allow signing on the card
        ca.verify_pw1_for_signing("123456")?;

        // Card-backed signer for bindings
        let mut card_signer = CardSigner::with_pubkey(ca, key_sig.clone());

        let signing_bsig: Packet = sub_aut
            .bind(&mut card_signer, &cert, signing_builder)?
            .into();

        pp.push(signing_bsig);
    }

    // 6) add user id from name / email
    let cardholder = ca.get_cardholder_related_data()?;

    // FIXME: process name field? accept email as argument?!
    let uid: UserID =
        cardholder.name().expect("expecting name on card").into();

    pp.push(uid.clone().into());

    // 7) make, sign binding -> add
    {
        let signing_builder =
            SignatureBuilder::new(SignatureType::PositiveCertification)
                .set_signature_creation_time(SystemTime::now())?
                .set_key_validity_period(std::time::Duration::new(0, 0))?
                .set_key_flags(
                    // Flags for primary key
                    KeyFlags::empty().set_signing().set_certification(),
                )?;

        // Allow signing on the card
        ca.verify_pw1_for_signing("123456")?;

        // Card-backed signer for bindings
        let mut card_signer = CardSigner::with_pubkey(ca, key_sig);

        let signing_bsig: Packet =
            uid.bind(&mut card_signer, &cert, signing_builder)?.into();

        pp.push(signing_bsig);
    }

    Cert::try_from(pp)
}

/// Helper fn: get a Sequoia PublicKey from an openpgp-card PublicKeyMaterial
pub fn public_key_material_to_key(
    pkm: &PublicKeyMaterial,
    key_type: KeyType,
    time: KeyGenerationTime,
) -> Result<PublicKey> {
    let time = Timestamp::from(time.get()).into();

    match pkm {
        PublicKeyMaterial::R(rsa) => {
            let k4 = Key4::import_public_rsa(rsa.v(), rsa.n(), Some(time))?;

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
                                Key4::import_public_ed25519(ecc.data(), time)?;

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
                            )?;

                            Ok(k4.into())
                        }
                    }
                    KeyType::Decryption => {
                        if algo_ecc.curve() == Curve::Cv25519 {
                            // EdDSA
                            let k4 = Key4::import_public_cv25519(
                                ecc.data(),
                                None,
                                None,
                                time,
                            )?;

                            Ok(k4.into())
                        } else {
                            // FIXME: just defining `hash` and `sym` is not
                            // ok when a cert already exists

                            // ECDH
                            let k4 = Key4::new(
                                time,
                                PublicKeyAlgorithm::ECDH,
                                mpi::PublicKey::ECDH {
                                    curve,
                                    q: mpi::MPI::new(ecc.data()),
                                    hash: Default::default(),
                                    sym: Default::default(),
                                },
                            )?;

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
pub fn public_to_fingerprint(
    pkm: &PublicKeyMaterial,
    time: KeyGenerationTime,
    kt: KeyType,
) -> Result<Fingerprint, Error> {
    // Transform PublicKeyMaterial into a Sequoia Key
    let key = public_key_material_to_key(pkm, kt, time)?;

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
    ca: &mut CardApp,
    cert: &Cert,
    input: &mut dyn io::Read,
    p: &dyn Policy,
) -> Result<String> {
    let mut armorer = armor::Writer::new(vec![], armor::Kind::Signature)?;
    {
        let s = signer::CardSigner::new(ca, cert, p)?;

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
    ca: &mut CardApp,
    cert: &Cert,
    msg: Vec<u8>,
    p: &dyn Policy,
) -> Result<Vec<u8>> {
    let mut decrypted = Vec::new();
    {
        let reader = io::BufReader::new(&msg[..]);

        let d = decryptor::CardDecryptor::new(ca, cert, p)?;

        let db = DecryptorBuilder::from_reader(reader)?;
        let mut decryptor = db.with_policy(p, None, d)?;

        // Read all data from decryptor and store in decrypted
        io::copy(&mut decryptor, &mut decrypted)?;
    }

    Ok(decrypted)
}
