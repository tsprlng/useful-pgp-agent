use chrono::{DateTime, Utc};
use openpgp_card::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::crypto_data::{EccType, PublicKeyMaterial};
use openpgp_card::{KeyType, Transaction};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::PublicKey;
use pgp::types::{EcdsaPublicParams, KeyVersion, PublicParams, Version};

fn pubkey(
    algo: PublicKeyAlgorithm,
    created: DateTime<Utc>,
    param: PublicParams,
) -> Result<PublicKey, pgp::errors::Error> {
    PublicKey::new(
        Version::New,
        KeyVersion::V4, // FIXME: don't hardwire?
        algo,
        created,
        None,
        param,
    )
}

pub(crate) fn pubkey_from_card(
    tx: &mut Transaction,
    key_type: KeyType,
) -> Result<PublicKey, pgp::errors::Error> {
    let pk = tx.public_key(key_type).expect("FIXME");

    let ard = tx.application_related_data().expect("FIXME");
    let kgt = ard.key_generation_times().expect("FIXME");
    let created = match key_type {
        KeyType::Signing => kgt.signature().cloned(),
        KeyType::Decryption => kgt.decryption().cloned(),
        KeyType::Authentication => kgt.authentication().cloned(),
        KeyType::Attestation => ard.attestation_key_generation_time().expect("FIXME"),
        _ => unimplemented!(), // FIXME
    }
    .expect("FIXME");

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
                let et = ecc_attr.ecc_type();

                fn map_curve(c: &Curve) -> ECCCurve {
                    match c {
                        Curve::Ed25519 => ECCCurve::Ed25519,
                        Curve::Cv25519 => ECCCurve::Curve25519,

                        _ => unimplemented!("map_curve {:?}", c),
                    }
                }

                let curve = map_curve(ecc_attr.curve());

                let (pka, pp) = match et {
                    EccType::ECDH => (
                        PublicKeyAlgorithm::ECDH,
                        PublicParams::ECDH {
                            curve,
                            p: ecc.data().into(),
                            hash: HashAlgorithm::SHA2_512, // FIXME
                            alg_sym: SymmetricKeyAlgorithm::AES256, // FIXME
                        },
                    ),

                    EccType::ECDSA => (
                        PublicKeyAlgorithm::ECDSA,
                        PublicParams::ECDSA(
                            EcdsaPublicParams::try_from_mpi(ecc.data().into(), curve)
                                .expect("FIXME"),
                        ),
                    ),

                    EccType::EdDSA => {
                        let mut q = ecc.data().to_vec();
                        if q.len() == 32 {
                            q.insert(0, 0x40); // FIXME?
                        }

                        (
                            PublicKeyAlgorithm::EdDSA,
                            PublicParams::EdDSA { curve, q: q.into() },
                        )
                    }

                    _ => unimplemented!(),
                };

                pubkey(pka, created, pp)
            }
            _ => unimplemented!(),
        },
        _ => unimplemented!(),
    }
}
