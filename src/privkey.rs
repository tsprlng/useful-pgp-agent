// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use openpgp_card::ocard::crypto::{CardUploadableKey, EccKey, EccType, PrivateKeyMaterial, RSAKey};
use openpgp_card::ocard::data::{Fingerprint, KeyGenerationTime};
use openpgp_card::Error;
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::types::{EcdsaPublicParams, KeyTrait, Mpi, PlainSecretParams, PublicParams, SecretParams};
use rsa::traits::PrivateKeyParts;

enum Sec {
    Key(pgp::packet::SecretKey),
    SubKey(pgp::packet::SecretSubkey),
}

impl Sec {
    fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            Sec::Key(sk) => sk.algorithm(),
            Sec::SubKey(ssk) => ssk.algorithm(),
        }
    }

    fn public_params(&self) -> &PublicParams {
        match self {
            Sec::Key(sk) => sk.public_params(),
            Sec::SubKey(ssk) => ssk.public_params(),
        }
    }

    fn secret_params(&self) -> &SecretParams {
        match self {
            Sec::Key(sk) => sk.secret_params(),
            Sec::SubKey(ssk) => ssk.secret_params(),
        }
    }
}

/// OpenPGP secret key packet wrapped, to enable uploading to a card
pub struct UploadableKey {
    key: Sec,
    unlocked: Option<PlainSecretParams>,
}

impl From<pgp::packet::SecretKey> for UploadableKey {
    fn from(value: pgp::packet::SecretKey) -> Self {
        Self {
            key: Sec::Key(value),
            unlocked: None,
        }
    }
}

impl From<pgp::packet::SecretSubkey> for UploadableKey {
    fn from(value: pgp::packet::SecretSubkey) -> Self {
        Self {
            key: Sec::SubKey(value),
            unlocked: None,
        }
    }
}

impl UploadableKey {
    pub fn is_locked(&self) -> bool {
        match self.key.secret_params() {
            SecretParams::Plain(_) => false,
            SecretParams::Encrypted(_) => true,
        }
    }

    /// Returns:
    /// - `Ok(false)` for keys that are not password protected
    /// - `Ok(true)` for protected keys that were successfully unlocked
    /// - `Err` when the password did not unlock the key (in this case, the key cannot be imported to a card).
    pub fn try_unlock(&mut self, pw: &str) -> Result<bool, Error> {
        match self.key.secret_params() {
            SecretParams::Plain(_) => Ok(false),
            SecretParams::Encrypted(esp) => {
                if let Ok(psp) = esp.unlock(
                    || pw.to_string(),
                    self.key.algorithm(),
                    self.key.public_params(),
                ) {
                    self.unlocked = Some(psp);
                    return Ok(true);
                }

                Err(Error::InternalError("Could not unlock key".to_string()))
            }
        }
    }
}

impl CardUploadableKey for UploadableKey {
    fn private_key(&self) -> Result<PrivateKeyMaterial, Error> {
        fn to_privatekeymaterial(
            psp: &PlainSecretParams,
            pp: &PublicParams,
        ) -> Result<PrivateKeyMaterial, Error> {
            match (psp, pp) {
                (PlainSecretParams::RSA { p, q, d, .. }, PublicParams::RSA { n, e }) => {
                    let rsa_key = Rsa::new(e.clone(), d.clone(), n.clone(), p.clone(), q.clone())?;
                    Ok(PrivateKeyMaterial::R(Box::new(rsa_key)))
                }
                (PlainSecretParams::ECDSA(m), PublicParams::ECDSA(ecdsa)) => {
                    let (curve, p) = match ecdsa {
                        EcdsaPublicParams::P256 { p, .. } => (ECCCurve::P256, p),
                        EcdsaPublicParams::P384 { p, .. } => (ECCCurve::P384, p),
                        EcdsaPublicParams::P521 { p, .. } => (ECCCurve::P521, p),
                        EcdsaPublicParams::Secp256k1 { .. } => {
                            return Err(Error::UnsupportedAlgo(
                                "ECDSA with curve Secp256k1 is unsupported".to_string(),
                            ))
                        }
                        EcdsaPublicParams::Unsupported { curve, .. } => {
                            return Err(Error::UnsupportedAlgo(format!(
                                "ECDSA with curve {} is unsupported",
                                curve.name()
                            )))
                        }
                    };

                    let ecc = Ecc::new(curve, m.clone(), p.clone(), EccType::ECDSA);
                    Ok(PrivateKeyMaterial::E(Box::new(ecc)))
                }
                (PlainSecretParams::EdDSA(m), PublicParams::EdDSA { curve, q }) => {
                    let ecc = Ecc::new(curve.clone(), m.clone(), q.clone(), EccType::EdDSA);
                    Ok(PrivateKeyMaterial::E(Box::new(ecc)))
                }
                (PlainSecretParams::ECDH(m), PublicParams::ECDH { curve, p, .. }) => {
                    let ecc = Ecc::new(curve.clone(), m.clone(), p.clone(), EccType::ECDH);
                    Ok(PrivateKeyMaterial::E(Box::new(ecc)))
                }

                _ => Err(Error::UnsupportedAlgo(format!(
                    "Unsupported key material {:?}",
                    pp
                ))),
            }
        }

        let pp = self.key.public_params();

        let psp = match self.key.secret_params() {
            SecretParams::Plain(psp) => psp,
            SecretParams::Encrypted(_) => {
                if let Some(psp) = &self.unlocked {
                    psp
                } else {
                    return Err(Error::InternalError(
                        "Secret key packet wasn't unlocked".to_string(),
                    ));
                }
            }
        };

        to_privatekeymaterial(psp, pp)
    }

    fn timestamp(&self) -> KeyGenerationTime {
        let ts = match &self.key {
            Sec::Key(sk) => sk.created_at(),
            Sec::SubKey(ssk) => ssk.created_at(),
        };

        let ts = ts.timestamp() as u32;
        ts.into()
    }

    fn fingerprint(&self) -> Result<Fingerprint, Error> {
        let fp = match &self.key {
            Sec::Key(sk) => sk.fingerprint(),
            Sec::SubKey(ssk) => ssk.fingerprint(),
        };

        Fingerprint::try_from(fp.as_slice())
    }
}

struct Rsa {
    e: Mpi,
    n: Mpi,
    p: Mpi,
    q: Mpi,
    pq: Mpi,
    dp1: Mpi,
    dq1: Mpi,
}

impl Rsa {
    fn new(e: Mpi, d: Mpi, n: Mpi, p: Mpi, q: Mpi) -> Result<Self, Error> {
        let key = rsa::RsaPrivateKey::from_components(
            n.clone().into(),
            e.clone().into(),
            d.into(),
            vec![p.clone().into(), q.clone().into()],
        )
        .map_err(|e| Error::InternalError(format!("rsa error {e:?}")))?;

        let pq = key
            .qinv()
            .ok_or_else(|| Error::InternalError("pq value missing".into()))?
            .to_biguint()
            .ok_or_else(|| Error::InternalError("conversion to bigunit failed".into()))?
            .to_bytes_be()
            .into();

        let dp1 = key
            .dp()
            .ok_or_else(|| Error::InternalError("dp1 value missing".into()))?
            .to_bytes_be()
            .into();

        let dq1 = key
            .dq()
            .ok_or_else(|| Error::InternalError("dq1 value missing".into()))?
            .to_bytes_be()
            .into();

        Ok(Self {
            e,
            n,
            p,
            q,
            pq,
            dp1,
            dq1,
        })
    }
}

impl RSAKey for Rsa {
    fn e(&self) -> &[u8] {
        self.e.as_bytes()
    }

    fn p(&self) -> &[u8] {
        self.p.as_bytes()
    }

    fn q(&self) -> &[u8] {
        self.q.as_bytes()
    }

    fn pq(&self) -> Box<[u8]> {
        Box::from(self.pq.as_bytes())
    }

    fn dp1(&self) -> Box<[u8]> {
        Box::from(self.dp1.as_bytes())
    }

    fn dq1(&self) -> Box<[u8]> {
        Box::from(self.dq1.as_bytes())
    }

    fn n(&self) -> &[u8] {
        self.n.as_bytes()
    }
}

/// ECC-specific data-structure to hold private (sub)key material for upload
/// with the `openpgp-card` crate.
struct Ecc {
    curve: ECCCurve,
    private: Mpi,
    public: Mpi,
    ecc_type: EccType,

    oid: Vec<u8>,
}

impl Ecc {
    fn new(curve: ECCCurve, private: Mpi, public: Mpi, ecc_type: EccType) -> Self {
        let oid = curve.oid();

        Ecc {
            curve,
            private,
            public,
            ecc_type,
            oid,
        }
    }
}

fn pad(mut v: Vec<u8>, len: usize) -> Vec<u8> {
    while v.len() < len {
        v.insert(0, 0)
    }

    v
}

impl EccKey for Ecc {
    fn oid(&self) -> &[u8] {
        &self.oid
    }

    fn private(&self) -> Vec<u8> {
        match self.curve {
            ECCCurve::P256 => pad(self.private.to_vec(), 0x20),
            ECCCurve::P384 => pad(self.private.to_vec(), 0x30),
            ECCCurve::P521 => pad(self.private.to_vec(), 0x42),
            ECCCurve::Curve25519 | ECCCurve::Ed25519 => pad(self.private.to_vec(), 0x20),
            _ => self.private.to_vec(),
        }
    }

    fn public(&self) -> Vec<u8> {
        // FIXME: padding?
        self.public.to_vec()
    }

    fn ecc_type(&self) -> EccType {
        self.ecc_type
    }
}
