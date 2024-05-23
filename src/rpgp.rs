// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use chrono::{DateTime, SubsecRound, Utc};
use openpgp_card::ocard::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::ocard::crypto::{EccType, PublicKeyMaterial};
use openpgp_card::ocard::data::{Fingerprint, KeyGenerationTime};
use openpgp_card::ocard::KeyType;
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{
    KeyFlags, PacketTrait, PublicKey, PublicSubkey, SignatureConfigBuilder, SignatureType,
    Subpacket, SubpacketData, UserId,
};
use pgp::types::{
    EcdsaPublicParams, KeyTrait, KeyVersion, Mpi, PublicParams, SecretKeyTrait, SignedUser, Version,
};
use pgp::{Esk, Message, PlainSessionKey, SignedKeyDetails, SignedPublicKey, SignedPublicSubKey};

use crate::{CardSlot, Error};

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
        Curve::Curve25519 => ECCCurve::Curve25519,

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
    #[allow(clippy::expect_used)]
    let created =
        DateTime::<Utc>::from_timestamp(created.get() as i64, 0).expect("u32 time from card");

    match pkm {
        PublicKeyMaterial::R(rsa) => pubkey(
            PublicKeyAlgorithm::RSA,
            created,
            PublicParams::RSA {
                n: Mpi::from_raw_slice(rsa.n()),
                e: Mpi::from_raw_slice(rsa.v()),
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

                        let hash = hash.unwrap_or(HashAlgorithm::SHA2_256); // FIXME: get curve default from rpgp!
                        let alg_sym = alg_sym.unwrap_or(SymmetricKeyAlgorithm::AES128); // FIXME: get curve default from rpgp!

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
    let pkm = tx.public_key_material(key_type).map_err(map_card_err)?;

    let Some(created) = tx.key_generation_time(key_type).map_err(map_card_err)? else {
        // KeyGenerationTime is None
        return Err(pgp::errors::Error::Message(format!(
            "No creation time set for OpenPGP card key type {:?}",
            key_type,
        )));
    };

    let Some(fingerprint) = tx.fingerprint(key_type).map_err(map_card_err)? else {
        // Fingerprint is None
        return Err(pgp::errors::Error::Message(format!(
            "No fingerprint found for key slot {:?}",
            key_type
        )));
    };

    public_key_material_and_fp_to_key(&pkm, key_type, &created, &fingerprint)
}

pub fn decrypt(message: Message, cs: CardSlot) -> Result<Message, pgp::errors::Error> {
    let Message::Encrypted { esk, edata } = message else {
        return Err(pgp::errors::Error::Message(
            "message must be Message::Encrypted".to_string(),
        ));
    };

    let mpis = match &esk[0] {
        Esk::PublicKeyEncryptedSessionKey(ref k) => k.mpis(),
        _ => {
            return Err(pgp::errors::Error::Message(
                "Expected PublicKeyEncryptedSessionKey".to_string(),
            ))
        }
    };

    let (session_key, session_key_algorithm) =
        cs.unlock(String::new, |priv_key| priv_key.decrypt(mpis))?;

    let plain_session_key = PlainSessionKey::V4 {
        key: session_key,
        sym_alg: session_key_algorithm,
    };

    let decrypted = edata.decrypt(plain_session_key)?;

    Ok(decrypted)
}

pub fn fp_from_pub(
    pkm: &PublicKeyMaterial,
    kgt: KeyGenerationTime,
    kt: KeyType,
) -> Result<Fingerprint, openpgp_card::Error> {
    let key = public_key_material_to_key(pkm, kt, &kgt, None, None).map_err(|e| {
        openpgp_card::Error::InternalError(format!("public_key_material_to_key: {}", e))
    })?;

    let fp = key.fingerprint();

    openpgp_card::ocard::data::Fingerprint::try_from(fp.as_slice())
}

// FIXME: upstream?
fn pri_to_sub(pubkey: PublicKey) -> pgp::errors::Result<PublicSubkey> {
    PublicSubkey::new(
        pubkey.packet_version(),
        pubkey.version(),
        pubkey.algorithm(),
        *pubkey.created_at(),
        pubkey.expiration(),
        pubkey.public_params().clone(),
    )
}

/// Generate a SignedPublicKey from the three subkeys on a card.
///
/// When pw1 is None, attempt to verify via pinpad.
///
/// `prompt` notifies the user when a pinpad needs the user pin as input.
///
/// FIXME: accept optional metadata for user_id(s)?
#[allow(clippy::too_many_arguments)]
pub fn make_certificate(
    tx: &mut openpgp_card::Card<openpgp_card::state::Transaction>,
    key_sig: PublicKey,
    key_dec: Option<PublicKey>,
    key_aut: Option<PublicKey>,
    pw1: Option<&str>,
    pinpad_prompt: &dyn Fn(),
    touch_prompt: &(dyn Fn() + Send + Sync),
    user_ids: &[String],
) -> Result<SignedPublicKey, crate::Error> {
    let primary = key_sig;

    if user_ids.is_empty() {
        return Err(Error::Message(
            "a user id must be added to make a valid cert".to_string(),
        ));
    }

    // helper: use the card to perform a signing operation
    let verify_signing_pin = |txx: &mut openpgp_card::Card<
        openpgp_card::state::Transaction,
    >|
     -> Result<(), openpgp_card::Error> {
        // Allow signing on the card
        if let Some(pw1) = pw1 {
            txx.verify_user_signing_pin(pw1)?;
        } else {
            txx.verify_user_signing_pinpad(pinpad_prompt)?;
        }
        Ok(())
    };

    let mut subkeys = vec![];

    if let Some(key_dec) = key_dec {
        // add decryption key as subkey
        let key = pri_to_sub(key_dec)?;

        verify_signing_pin(tx)?;

        // make binding signature, sign with cs
        let cs = CardSlot::with_public_key(tx, KeyType::Signing, primary.clone(), touch_prompt)?;

        let mut kf = KeyFlags::default();
        kf.set_encrypt_comms(true);
        kf.set_encrypt_storage(true);

        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::SubkeyBinding)
            .pub_alg(cs.algorithm())
            .hash_alg(cs.hash_alg())
            .hashed_subpackets(vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(
                    Utc::now().trunc_subsecs(0),
                )),
                Subpacket::regular(SubpacketData::IssuerFingerprint(
                    KeyVersion::V4,
                    cs.fingerprint().into(),
                )),
                Subpacket::regular(SubpacketData::KeyFlags(kf.into())),
            ])
            .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(cs.key_id()))])
            .build()?;

        let sig = config.sign_key_binding(&cs, String::default, &key)?;

        let sps = SignedPublicSubKey {
            key,
            signatures: vec![sig],
        };

        subkeys.push(sps);
    }

    if let Some(key_aut) = key_aut {
        // add decryption key as subkey
        let key = pri_to_sub(key_aut)?;

        verify_signing_pin(tx)?;

        // make binding signature, sign with cs
        let cs = CardSlot::with_public_key(tx, KeyType::Signing, primary.clone(), touch_prompt)?;

        let mut kf = KeyFlags::default();
        kf.set_authentication(true);

        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::SubkeyBinding)
            .pub_alg(cs.algorithm())
            .hash_alg(cs.hash_alg())
            .hashed_subpackets(vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(
                    Utc::now().trunc_subsecs(0),
                )),
                Subpacket::regular(SubpacketData::IssuerFingerprint(
                    KeyVersion::V4,
                    cs.fingerprint().into(),
                )),
                Subpacket::regular(SubpacketData::KeyFlags(kf.into())),
            ])
            .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(cs.key_id()))])
            .build()?;

        let sig = config.sign_key_binding(&cs, String::default, &key)?;

        let sps = SignedPublicSubKey {
            key,
            signatures: vec![sig],
        };

        subkeys.push(sps);
    }

    let mut users = vec![];

    // add `user_ids`.
    for uid in user_ids.iter().map(|uid| uid.as_bytes()) {
        let uid = UserId::from_slice(Version::New, uid)?;

        let mut kf = KeyFlags::default();
        kf.set_certify(true);
        kf.set_sign(true);

        verify_signing_pin(tx)?;

        let cs = CardSlot::with_public_key(tx, KeyType::Signing, primary.clone(), touch_prompt)?;
        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::CertPositive)
            .pub_alg(cs.algorithm())
            .hash_alg(cs.hash_alg())
            .hashed_subpackets(vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(
                    Utc::now().trunc_subsecs(0),
                )),
                Subpacket::regular(SubpacketData::KeyFlags(kf.into())),
            ])
            .unhashed_subpackets(vec![Subpacket::regular(SubpacketData::Issuer(cs.key_id()))])
            .build()?;

        let sig = config.sign_certification(&cs, String::default, uid.tag(), &uid)?;

        let suid = SignedUser::new(uid, vec![sig]);

        users.push(suid);
    }

    // FIXME: generate a direct key signature?

    let details = SignedKeyDetails::new(vec![], vec![], users, vec![]);

    let spk = SignedPublicKey::new(primary, details, subkeys);

    Ok(spk)
}
