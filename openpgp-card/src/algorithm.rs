// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data structures that define OpenPGP algorithms.
//!
//! [`Algo`] and its components model "Algorithm Attributes" as described in
//! the OpenPGP card specification.
//!
//! [`AlgoSimple`] offers a shorthand for specifying an algorithm,
//! specifically for key generation on the card.

use crate::card_do::ApplicationRelatedData;
use crate::crypto_data::EccType;
use crate::{keys, Error, KeyType};

use anyhow::{anyhow, Result};
use std::convert::TryFrom;
use std::fmt;

/// A shorthand way to specify algorithms (e.g. for key generation).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum AlgoSimple {
    RSA1k,
    RSA2k,
    RSA3k,
    RSA4k,
    NIST256,
    NIST384,
    NIST521,
    Curve25519,
}

impl TryFrom<&str> for AlgoSimple {
    type Error = anyhow::Error;

    fn try_from(algo: &str) -> Result<Self, anyhow::Error> {
        use AlgoSimple::*;

        Ok(match algo {
            "RSA1k" => RSA1k,
            "RSA2k" => RSA2k,
            "RSA3k" => RSA3k,
            "RSA4k" => RSA4k,
            "NIST256" => NIST256,
            "NIST384" => NIST384,
            "NIST521" => NIST521,
            "Curve25519" => Curve25519,
            _ => return Err(anyhow!("unexpected algo {}", algo)),
        })
    }
}

impl AlgoSimple {
    /// Get corresponding EccType by KeyType (except for Curve25519)
    fn ecc_type(key_type: KeyType) -> EccType {
        match key_type {
            KeyType::Signing
            | KeyType::Authentication
            | KeyType::Attestation => EccType::ECDSA,
            KeyType::Decryption => EccType::ECDH,
        }
    }

    /// Get corresponding EccType by KeyType for Curve25519
    fn ecc_type_25519(key_type: KeyType) -> EccType {
        match key_type {
            KeyType::Signing
            | KeyType::Authentication
            | KeyType::Attestation => EccType::EdDSA,
            KeyType::Decryption => EccType::ECDH,
        }
    }

    /// Get corresponding Curve by KeyType for 25519 (Ed25519 vs Cv25519)
    fn curve_for_25519(key_type: KeyType) -> Curve {
        match key_type {
            KeyType::Signing
            | KeyType::Authentication
            | KeyType::Attestation => Curve::Ed25519,
            KeyType::Decryption => Curve::Cv25519,
        }
    }

    /// Return the appropriate Algo for this AlgoSimple.
    ///
    /// This mapping differs between cards, based on `ard` and `algo_info`
    /// (e.g. the exact Algo variant can have a different size for e, in RSA;
    /// also, the import_format can differ).
    pub(crate) fn determine_algo(
        &self,
        key_type: KeyType,
        ard: &ApplicationRelatedData,
        algo_info: Option<AlgoInfo>,
    ) -> Result<Algo> {
        let algo = match self {
            Self::RSA1k => Algo::Rsa(keys::determine_rsa_attrs(
                1024, key_type, ard, algo_info,
            )?),
            Self::RSA2k => Algo::Rsa(keys::determine_rsa_attrs(
                2048, key_type, ard, algo_info,
            )?),
            Self::RSA3k => Algo::Rsa(keys::determine_rsa_attrs(
                3072, key_type, ard, algo_info,
            )?),
            Self::RSA4k => Algo::Rsa(keys::determine_rsa_attrs(
                4096, key_type, ard, algo_info,
            )?),
            Self::NIST256 => Algo::Ecc(keys::determine_ecc_attrs(
                Curve::NistP256r1.oid(),
                Self::ecc_type(key_type),
                key_type,
                algo_info,
            )?),
            Self::NIST384 => Algo::Ecc(keys::determine_ecc_attrs(
                Curve::NistP384r1.oid(),
                Self::ecc_type(key_type),
                key_type,
                algo_info,
            )?),
            Self::NIST521 => Algo::Ecc(keys::determine_ecc_attrs(
                Curve::NistP521r1.oid(),
                Self::ecc_type(key_type),
                key_type,
                algo_info,
            )?),
            Self::Curve25519 => Algo::Ecc(keys::determine_ecc_attrs(
                Self::curve_for_25519(key_type).oid(),
                Self::ecc_type_25519(key_type),
                key_type,
                algo_info,
            )?),
        };

        Ok(algo)
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
                write!(
                    f,
                    "RSA {} [e {}{}]",
                    rsa.len_n,
                    rsa.len_e,
                    if rsa.import_format != 0 {
                        format!(", format {}", rsa.import_format)
                    } else {
                        "".to_string()
                    }
                )
            }
            Self::Ecc(ecc) => {
                write!(
                    f,
                    "{:?} ({:?}){}",
                    ecc.curve,
                    ecc.ecc_type,
                    if ecc.import_format == Some(0xff) {
                        " with pub"
                    } else {
                        ""
                    }
                )
            }
            Self::Unknown(u) => {
                write!(f, "Unknown: {:?}", u)
            }
        }
    }
}

impl Algo {
    /// Get a DO representation of the Algo, for setting algorithm
    /// attributes on the card.
    pub(crate) fn to_data_object(&self) -> Result<Vec<u8>, Error> {
        match self {
            Algo::Rsa(rsa) => Self::rsa_algo_attrs(rsa),
            Algo::Ecc(ecc) => Self::ecc_algo_attrs(ecc.oid(), ecc.ecc_type()),
            _ => Err(anyhow!("Unexpected Algo {:?}", self).into()),
        }
    }

    /// Helper: generate `data` for algorithm attributes with RSA
    fn rsa_algo_attrs(algo_attrs: &RsaAttrs) -> Result<Vec<u8>, Error> {
        // Algorithm ID (01 = RSA (Encrypt or Sign))
        let mut algo_attributes = vec![0x01];

        // Length of modulus n in bit
        algo_attributes.extend(&algo_attrs.len_n().to_be_bytes());

        // Length of public exponent e in bit
        algo_attributes.push(0x00);
        algo_attributes.push(algo_attrs.len_e() as u8);

        algo_attributes.push(algo_attrs.import_format());

        Ok(algo_attributes)
    }

    /// Helper: generate `data` for algorithm attributes with ECC
    fn ecc_algo_attrs(
        oid: &[u8],
        ecc_type: EccType,
    ) -> Result<Vec<u8>, Error> {
        let algo_id = match ecc_type {
            EccType::EdDSA => 0x16,
            EccType::ECDH => 0x12,
            EccType::ECDSA => 0x13,
        };

        let mut algo_attributes = vec![algo_id];
        algo_attributes.extend(oid);
        // Leave Import-Format unset, for default (pg. 35)

        Ok(algo_attributes)
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

    pub fn import_format(&self) -> Option<u8> {
        self.import_format
    }
}

/// Enum for naming ECC curves, and mapping them to/from their OIDs.
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
