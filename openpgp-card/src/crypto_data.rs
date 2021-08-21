// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data structures for cryptographic material:
//! Private key data, public key data, cryptograms for decryption, hash
//! data for signing.

use anyhow::Result;

use crate::algorithm::Algo;

/// A hash value that can be signed by the card.
pub enum Hash<'a> {
    SHA256([u8; 0x20]),
    SHA384([u8; 0x30]),
    SHA512([u8; 0x40]),
    EdDSA(&'a [u8]), // FIXME?
    ECDSA(&'a [u8]), // FIXME?
}

impl Hash<'_> {
    pub(crate) fn oid(&self) -> Option<&'static [u8]> {
        match self {
            Self::SHA256(_) => {
                Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
            }
            Self::SHA384(_) => {
                Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02])
            }
            Self::SHA512(_) => {
                Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03])
            }
            Self::EdDSA(_) => None,
            Self::ECDSA(_) => None,
        }
    }

    pub(crate) fn digest(&self) -> &[u8] {
        match self {
            Self::SHA256(d) => &d[..],
            Self::SHA384(d) => &d[..],
            Self::SHA512(d) => &d[..],
            Self::EdDSA(d) => d,
            Self::ECDSA(d) => d,
        }
    }
}

/// Data that can be decrypted on the card.
pub enum Cryptogram<'a> {
    // message/ciphertext
    RSA(&'a [u8]),

    // ephemeral
    ECDH(&'a [u8]),
}

// ---------

/// A PGP-implementation-agnostic wrapper for private key data, to upload
/// to an OpenPGP card
pub trait CardUploadableKey {
    /// private key data
    fn get_key(&self) -> Result<PrivateKeyMaterial>;

    /// timestamp of (sub)key creation
    fn get_ts(&self) -> u32;

    /// fingerprint
    fn get_fp(&self) -> [u8; 20];
}

/// Algorithm-independent container for private key material to upload to
/// an OpenPGP card
pub enum PrivateKeyMaterial {
    R(Box<dyn RSAKey>),
    E(Box<dyn EccKey>),
}

/// RSA-specific container for private key material to upload to an OpenPGP
/// card.
pub trait RSAKey {
    fn get_e(&self) -> &[u8];
    fn get_n(&self) -> &[u8];
    fn get_p(&self) -> &[u8];
    fn get_q(&self) -> &[u8];
}

/// ECC-specific container for private key material to upload to an OpenPGP
/// card.
pub trait EccKey {
    fn get_oid(&self) -> &[u8];
    fn get_scalar(&self) -> &[u8];
    fn get_type(&self) -> EccType;
}

/// Algorithm-independent container for public key material retrieved from
/// an OpenPGP card
#[derive(Debug)]
pub enum PublicKeyMaterial {
    R(RSAPub),
    E(EccPub),
}

/// RSA-specific container for public key material from an OpenPGP card.
#[derive(Debug)]
pub struct RSAPub {
    /// Modulus (a number denoted as n coded on x bytes)
    pub n: Vec<u8>,

    /// Public exponent (a number denoted as v, e.g. 65537 dec.)
    pub v: Vec<u8>,
}

/// ECC-specific container for public key material from an OpenPGP card.
#[derive(Debug)]
pub struct EccPub {
    pub data: Vec<u8>,
    pub algo: Algo,
}

/// A marker to distinguish between elliptic curve algorithms (ECDH, ECDSA,
/// EdDSA)
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum EccType {
    ECDH,
    EdDSA,
    ECDSA,
}
