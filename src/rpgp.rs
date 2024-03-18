use chrono::{DateTime, Utc};
use openpgp_card::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::crypto_data::{EccType, PublicKeyMaterial};
use openpgp_card::{KeyType, Transaction};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::PublicKey;
use pgp::types::{EcdsaPublicParams, KeyTrait, KeyVersion, PublicParams, Version};

/// value pairs that we'll consider in ECDH parameter auto-detection
const ECDH_PARAM: &[(HashAlgorithm, SymmetricKeyAlgorithm)] = &[
    (HashAlgorithm::SHA2_256, SymmetricKeyAlgorithm::AES128),
    (HashAlgorithm::SHA2_512, SymmetricKeyAlgorithm::AES256),
    (HashAlgorithm::SHA2_384, SymmetricKeyAlgorithm::AES256),
    (HashAlgorithm::SHA2_384, SymmetricKeyAlgorithm::AES192),
    (HashAlgorithm::SHA2_256, SymmetricKeyAlgorithm::AES256),
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

pub(crate) fn pubkey_from_card(
    tx: &mut Transaction,
    key_type: KeyType,
) -> Result<PublicKey, pgp::errors::Error> {
    let pk = tx.public_key(key_type).map_err(map_card_err)?;

    let ard = tx.application_related_data().map_err(map_card_err)?;
    let kgt = ard.key_generation_times().map_err(map_card_err)?;

    let Some(created) = (match key_type {
        KeyType::Signing => kgt.signature().cloned(),
        KeyType::Decryption => kgt.decryption().cloned(),
        KeyType::Authentication => kgt.authentication().cloned(),
        KeyType::Attestation => ard.attestation_key_generation_time().map_err(|e| {
            pgp::errors::Error::Message(format!("Get attestation_key_generation_time: {:?}", e,))
        })?,
        _ => unimplemented!(), // FIXME: this openpgp-card type should be exhaustive
    }) else {
        // KeyGenerationTime is None
        return Err(pgp::errors::Error::Message(format!(
            "No creation time set for OpenPGP card key type {:?}",
            key_type,
        )));
    };

    let created =
        DateTime::<Utc>::from_timestamp(created.get() as i64, 0).expect("u32 time from card");

    match pk {
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

                        // read key slot fingerprint from card
                        let Some(fingerprint) = ard
                            .fingerprints()
                            .map_err(map_card_err)?
                            .decryption()
                            .cloned()
                        else {
                            return Err(pgp::errors::Error::Message(
                                "No fingerprint found in decryption key slot".to_string(),
                            ));
                        };

                        let mut p = ecc.data().to_vec();
                        if curve == ECCCurve::Curve25519 && p.len() == 32 {
                            // prepend OpenPGP 0x40 prefix for curve 25519 MPI
                            p.insert(0, 0x40);
                        }

                        // find hash/alg_sym combination that matches the fingerprint on the card
                        let pk = ECDH_PARAM
                            .iter()
                            .map(|&(hash, alg_sym)| PublicParams::ECDH {
                                curve: curve.clone(),
                                p: p.clone().into(),
                                hash,
                                alg_sym,
                            })
                            .flat_map(|pp| pubkey(PublicKeyAlgorithm::ECDH, created, pp))
                            .find(|pk| pk.fingerprint() == fingerprint.as_bytes());

                        if let Some(pk) = pk {
                            // suitable parameters were found -> return them
                            (PublicKeyAlgorithm::ECDH, pk.public_params().clone())
                        } else {
                            return Err(pgp::errors::Error::Message(
                                "No suitable ECDH parameters found for decryption key slot"
                                    .to_string(),
                            ));
                        }
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

                    _ => unimplemented!(), // FIXME: openpgp-card EccType type should be exhaustive
                };

                pubkey(pka, created, pp)
            }

            _ => Err(pgp::errors::Error::Message(format!(
                "Unexpected AlgorithmAttributes type in Ecc {:?}",
                ecc.algo(),
            ))),
        },
        _ => Err(pgp::errors::Error::Message(format!(
            "Unexpected PublicKeyMaterial type {:?}",
            pk,
        ))),
    }
}
