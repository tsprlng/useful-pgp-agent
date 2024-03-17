// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fmt::{Debug, Formatter};
use std::sync::Mutex;

use card_backend_pcsc::PcscBackend;
use chrono::{DateTime, Utc};
use openpgp_card::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::crypto_data::{EccType, PublicKeyMaterial};
use openpgp_card::{Card, KeyType, Transaction};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm};
use pgp::packet::{self, PublicKey, SignatureConfig};
use pgp::types::{
    self, EcdsaPublicParams, KeyId, KeyTrait, KeyVersion, Mpi, PublicKeyTrait, PublicParams,
    SecretKeyTrait, Version,
};
use pgp::StandaloneSignature;
use rand::{CryptoRng, Rng};
use unimpl::unimpl;

struct CardSigner<'a> {
    tx: Mutex<Transaction<'a>>,

    // Which key slot does this signer operate on
    key_type: KeyType,

    // The public key material that corresponds to the key slot of this signer
    //
    // The distinction between primary and subkey is irrelevant here, but we have to use some type.
    // So we model the key data as a public primary key packet.
    pubkey: PublicKey,
}

impl<'a> CardSigner<'a> {
    fn new(
        tx: Transaction<'a>,
        key_type: KeyType,
        algo: PublicKeyAlgorithm,
        created: DateTime<Utc>,
        param: PublicParams,
    ) -> Result<Self, pgp::errors::Error> {
        let pubkey = PublicKey::new(
            Version::New,
            KeyVersion::V4, // FIXME: don't hardwire?
            algo,
            created,
            None,
            param,
        )?;

        Self::new_from_pubkey(tx, key_type, pubkey)
    }

    pub fn new_from_pubkey(
        tx: Transaction<'a>,
        key_type: KeyType,
        pubkey: PublicKey,
    ) -> Result<Self, pgp::errors::Error> {
        Ok(Self {
            tx: Mutex::new(tx),
            pubkey,
            key_type,
        })
    }

    pub fn new_from_card(
        mut tx: Transaction<'a>,
        key_type: KeyType,
    ) -> Result<Self, pgp::errors::Error> {
        let pk = tx.public_key(key_type).expect("FIXME");

        let ard = tx.application_related_data().expect("FIXME");
        let kgt = ard.key_generation_times().expect("FIXME");
        let created = match key_type {
            KeyType::Signing => kgt.signature(),
            KeyType::Decryption => kgt.decryption(),
            KeyType::Authentication => kgt.authentication(),
            _ => unimplemented!(), // FIXME
        }
        .expect("FIXME");

        let created = DateTime::<Utc>::from_timestamp(created.get() as i64, 0).unwrap();

        match pk {
            PublicKeyMaterial::R(rsa) => Self::new(
                tx,
                key_type,
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

                    Self::new(tx, key_type, pka, created, pp)
                }
                _ => unimplemented!(),
            },
            _ => unimplemented!(),
        }
    }
}

impl Debug for CardSigner<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // FIXME: also show card identifier
        write!(f, "CardSigner for {:?}", self.pubkey)?;

        Ok(())
    }
}

impl KeyTrait for CardSigner<'_> {
    fn fingerprint(&self) -> Vec<u8> {
        self.pubkey.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.pubkey.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.pubkey.algorithm()
    }
}

impl PublicKeyTrait for CardSigner<'_> {
    #[unimpl]
    fn verify_signature(
        &self,
        _hash: HashAlgorithm,
        _data: &[u8],
        _sig: &[Mpi],
    ) -> pgp::errors::Result<()>;

    #[unimpl]
    fn encrypt<R: CryptoRng + Rng>(
        &self,
        _rng: &mut R,
        _plain: &[u8],
    ) -> pgp::errors::Result<Vec<Mpi>>;

    #[unimpl]
    fn to_writer_old(&self, _writer: &mut impl std::io::Write) -> pgp::errors::Result<()>;
}

impl SecretKeyTrait for CardSigner<'_> {
    // We model the key data as a public primary key packet for this type.
    // FIXME: The choice of this type is a bit arbitrary.
    type PublicKey = PublicKey;

    fn unlock<F, G>(&self, _pw: F, _work: G) -> pgp::errors::Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&types::SecretKeyRepr) -> pgp::errors::Result<()>,
    {
        // does this get called? if so, what happens to `work`?

        unimplemented!();
    }

    fn create_signature<F>(
        &self,
        _key_pw: F,
        _hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        let mut tx = self.tx.lock().unwrap();

        let sig = match self.key_type {
            KeyType::Signing => tx.pso_compute_digital_signature(data.into()).expect("sig"),
            _ => unimplemented!(),
        };

        Ok(vec![
            Mpi::from_raw_slice(&sig[..32]),
            Mpi::from_raw_slice(&sig[32..]),
        ])
    }

    fn public_key(&self) -> Self::PublicKey {
        self.pubkey.clone()
    }
}

fn main() -> testresult::TestResult {
    const DATA: &[u8] = b"Hello World";

    let pwd = &std::env::args().collect::<Vec<_>>()[1];
    eprintln!("with pwd = {pwd}");

    // -- set up card signer
    let card = PcscBackend::cards(None)
        .expect("cards")
        .next()
        .unwrap()
        .expect("card");
    let mut card = Card::new(card).expect("card new");
    let mut tx = card.transaction().expect("tx");

    tx.verify_pw1_sign(pwd.as_bytes()).expect("Verify");

    let cs = CardSigner::new_from_card(tx, KeyType::Signing)?;

    // -- use card signer
    let signature = SignatureConfig::new_v4(
        packet::SignatureVersion::V4,
        packet::SignatureType::Binary,
        PublicKeyAlgorithm::EdDSA,
        HashAlgorithm::SHA2_256,
        vec![
            packet::Subpacket::regular(packet::SubpacketData::SignatureCreationTime(
                std::time::SystemTime::now().into(),
            )),
            packet::Subpacket::regular(packet::SubpacketData::Issuer(cs.key_id())),
        ],
        vec![],
    );

    let signature = signature.sign(&cs, String::new, DATA)?;

    let signature = StandaloneSignature { signature };
    signature
        .to_armored_writer(&mut std::fs::File::create("sig.asc").unwrap(), None)
        .unwrap();
    Ok(())
}
