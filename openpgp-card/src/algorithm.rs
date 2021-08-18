// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{EccType, KeyType};
use anyhow::anyhow;
use std::convert::TryFrom;
use std::fmt;

/// This enum offers a shorthand way to specify algorithms (e.g. for key
/// generation).
///
/// RSA variants require "number of bits in 'e'" as parameter.
///
/// There are (at least) two common supported values for e:
///  e=17 [YK4, YK5]
///  e=32 [YK5, Floss3.4, Gnuk1.2]
#[derive(Clone, Copy, Debug)]
pub enum AlgoSimple {
    RSA1k(u16),
    RSA2k(u16),
    RSA3k(u16),
    RSA4k(u16),
    NIST256,
    NIST384,
    NIST521,
    Curve25519,
}

impl From<&str> for AlgoSimple {
    fn from(algo: &str) -> Self {
        use AlgoSimple::*;

        match algo {
            "RSA2k/17" => RSA2k(17),
            "RSA2k/32" => RSA2k(32),
            "RSA3k/17" => RSA3k(17),
            "RSA3k/32" => RSA3k(32),
            "RSA4k/17" => RSA4k(17),
            "RSA4k/32" => RSA4k(32),
            "NIST256" => NIST256,
            "NIST384" => NIST384,
            "NIST521" => NIST521,
            "Curve25519" => Curve25519,
            _ => panic!("unexpected algo {}", algo),
        }
    }
}

impl AlgoSimple {
    pub(crate) fn to_algo(&self, kt: KeyType) -> Algo {
        let et = match kt {
            KeyType::Signing | KeyType::Authentication => EccType::ECDSA,
            KeyType::Decryption => EccType::ECDH,
            _ => unimplemented!(),
        };

        match self {
            Self::RSA1k(e) => Algo::Rsa(RsaAttrs {
                len_n: 1024,
                len_e: *e,
                import_format: 0,
            }),
            Self::RSA2k(e) => Algo::Rsa(RsaAttrs {
                len_n: 2048,
                len_e: *e,
                import_format: 0,
            }),
            Self::RSA3k(e) => Algo::Rsa(RsaAttrs {
                len_n: 3072,
                len_e: *e,
                import_format: 0,
            }),
            Self::RSA4k(e) => Algo::Rsa(RsaAttrs {
                len_n: 4096,
                len_e: *e,
                import_format: 0,
            }),
            Self::NIST256 => Algo::Ecc(EccAttrs {
                curve: Curve::NistP256r1,
                ecc_type: et,
                import_format: None,
            }),
            Self::NIST384 => Algo::Ecc(EccAttrs {
                curve: Curve::NistP384r1,
                ecc_type: et,
                import_format: None,
            }),
            Self::NIST521 => Algo::Ecc(EccAttrs {
                curve: Curve::NistP521r1,
                ecc_type: et,
                import_format: None,
            }),
            Self::Curve25519 => Algo::Ecc(EccAttrs {
                curve: match kt {
                    KeyType::Signing | KeyType::Authentication => {
                        Curve::Ed25519
                    }
                    KeyType::Decryption => Curve::Cv25519,
                    _ => unimplemented!(),
                },
                ecc_type: match kt {
                    KeyType::Signing | KeyType::Authentication => {
                        EccType::EdDSA
                    }
                    KeyType::Decryption => EccType::ECDH,
                    _ => unimplemented!(),
                },
                import_format: None,
            }),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AlgoInfo(pub(crate) Vec<(KeyType, Algo)>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Algo {
    Rsa(RsaAttrs),
    Ecc(EccAttrs),
    Unknown(Vec<u8>),
}

impl fmt::Display for Algo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa(rsa) => {
                write!(f, "RSA {}, {} ", rsa.len_n, rsa.len_e)
            }
            Self::Ecc(ecc) => {
                write!(f, "{:?} ({:?})", ecc.curve, ecc.ecc_type)
            }
            Self::Unknown(u) => {
                write!(f, "Unknown: {:?}", u)
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RsaAttrs {
    pub len_n: u16,
    pub len_e: u16,
    pub import_format: u8,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EccAttrs {
    pub ecc_type: EccType,
    pub curve: Curve,
    pub import_format: Option<u8>,
}

impl EccAttrs {
    pub fn new(
        ecc_type: EccType,
        curve: Curve,
        import_format: Option<u8>,
    ) -> Self {
        Self {
            ecc_type,
            curve,
            import_format,
        }
    }

    pub fn oid(&self) -> &[u8] {
        self.curve.oid()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Curve {
    NistP256r1,
    NistP384r1,
    NistP521r1,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
    Secp256k1,
    Ed25519,
    Cv25519,
    Ed448,
    X448,
}

impl Curve {
    pub fn oid(&self) -> &[u8] {
        use Curve::*;
        match self {
            NistP256r1 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
            NistP384r1 => &[0x2B, 0x81, 0x04, 0x00, 0x22],
            NistP521r1 => &[0x2B, 0x81, 0x04, 0x00, 0x23],
            BrainpoolP256r1 => {
                &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]
            }
            BrainpoolP384r1 => {
                &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b]
            }
            BrainpoolP512r1 => {
                &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d]
            }
            Secp256k1 => &[0x2B, 0x81, 0x04, 0x00, 0x0A],
            Ed25519 => &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
            Cv25519 => {
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]
            }
            Ed448 => &[0x2b, 0x65, 0x71],
            X448 => &[0x2b, 0x65, 0x6f],
        }
    }
}

impl TryFrom<&[u8]> for Curve {
    type Error = anyhow::Error;

    fn try_from(oid: &[u8]) -> Result<Self, Self::Error> {
        use Curve::*;

        let curve = match oid {
            [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => NistP256r1,
            [0x2B, 0x81, 0x04, 0x00, 0x22] => NistP384r1,
            [0x2B, 0x81, 0x04, 0x00, 0x23] => NistP521r1,

            [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07] => {
                BrainpoolP256r1
            }
            [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b] => {
                BrainpoolP384r1
            }
            [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d] => {
                BrainpoolP512r1
            }

            [0x2B, 0x81, 0x04, 0x00, 0x0A] => Secp256k1,

            [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01] => Ed25519,
            [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01] => {
                Cv25519
            }

            [0x2b, 0x65, 0x71] => Ed448,
            [0x2b, 0x65, 0x6f] => X448,

            _ => return Err(anyhow!("Unknown curve OID {:?}", oid)),
        };

        Ok(curve)
    }
}
