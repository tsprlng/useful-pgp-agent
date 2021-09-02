// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data structures that define OpenPGP algorithms.
//!
//! [`Algo`] and its components model "Algorithm Attributes" as described in
//! the OpenPGP card specification.
//!
//! [`AlgoSimple`] offers a shorthand for specifying an algorithm,
//! specifically for key generation on the card.

use crate::crypto_data::EccType;
use crate::KeyType;

use anyhow::anyhow;
use std::convert::TryFrom;
use std::fmt;

/// A shorthand way to specify algorithms (e.g. for key generation).
///
/// RSA variants require "number of bits in 'e'" as parameter.
///
/// There are (at least) two common supported values for e:
///  e=17 [YK4, YK5]
///  e=32 [YK5, Floss3.4, Gnuk1.2]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
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
    /// Get corresponding EccType by KeyType (except for Curve25519)
    fn get_ecc_type(key_type: KeyType) -> EccType {
        match key_type {
            KeyType::Signing
            | KeyType::Authentication
            | KeyType::Attestation => EccType::ECDSA,
            KeyType::Decryption => EccType::ECDH,
        }
    }

    /// Get corresponding EccType by KeyType for Curve25519
    fn get_ecc_type_25519(key_type: KeyType) -> EccType {
        match key_type {
            KeyType::Signing
            | KeyType::Authentication
            | KeyType::Attestation => EccType::EdDSA,
            KeyType::Decryption => EccType::ECDH,
        }
    }

    /// Get corresponding Curve by KeyType for 25519 (Ed25519 vs Cv25519)
    fn get_curve_for_25519(key_type: KeyType) -> Curve {
        match key_type {
            KeyType::Signing
            | KeyType::Authentication
            | KeyType::Attestation => Curve::Ed25519,
            KeyType::Decryption => Curve::Cv25519,
        }
    }

    pub(crate) fn get_algo(&self, key_type: KeyType) -> Algo {
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
                ecc_type: Self::get_ecc_type(key_type),
                import_format: None,
            }),
            Self::NIST384 => Algo::Ecc(EccAttrs {
                curve: Curve::NistP384r1,
                ecc_type: Self::get_ecc_type(key_type),
                import_format: None,
            }),
            Self::NIST521 => Algo::Ecc(EccAttrs {
                curve: Curve::NistP521r1,
                ecc_type: Self::get_ecc_type(key_type),
                import_format: None,
            }),
            Self::Curve25519 => Algo::Ecc(EccAttrs {
                curve: Self::get_curve_for_25519(key_type),
                ecc_type: Self::get_ecc_type_25519(key_type),
                import_format: None,
            }),
        }
    }
}

/// 4.4.3.11 Algorithm Information
///
/// Modern cards (since OpenPGP card v3.4) provide a list of supported
/// algorithms for each key type. This list specifies which "Algorithm
/// Attributes" can be set for key generation or key import.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AlgoInfo(pub(crate) Vec<(KeyType, Algo)>);

/// 4.4.3.9 Algorithm Attributes
///
/// An `Algo` describes the algorithm settings for a key on the card.
///
/// This setting specifies the data format of:
/// - Key import
/// - Key generation
/// - Export of public key data from the card (e.g. after key generation)
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
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

/// RSA specific attributes of [`Algo`] ("Algorithm Attributes")
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RsaAttrs {
    len_n: u16,
    len_e: u16,
    import_format: u8,
}

impl RsaAttrs {
    pub fn new(len_n: u16, len_e: u16, import_format: u8) -> Self {
        RsaAttrs {
            len_n,
            len_e,
            import_format,
        }
    }

    pub fn len_n(&self) -> u16 {
        self.len_n
    }

    pub fn len_e(&self) -> u16 {
        self.len_e
    }

    pub fn import_format(&self) -> u8 {
        self.import_format
    }
}

/// ECC specific attributes of [`Algo`] ("Algorithm Attributes")
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EccAttrs {
    ecc_type: EccType,
    curve: Curve,
    import_format: Option<u8>,
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

    pub fn ecc_type(&self) -> EccType {
        self.ecc_type
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }

    pub fn oid(&self) -> &[u8] {
        self.curve.oid()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
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
