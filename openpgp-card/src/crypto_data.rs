// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data structures for cryptographic material:
//! Private key data, public key data, cryptograms for decryption, hash
//! data for signing.

use crate::algorithm::Algo;
use crate::card_do::{Fingerprint, KeyGenerationTime};
use crate::{oid, Error};

/// A hash value that can be signed by the card.
#[non_exhaustive]
pub enum Hash<'a> {
    SHA256([u8; 0x20]),
    SHA384([u8; 0x30]),
    SHA512([u8; 0x40]),
    ECDSA(&'a [u8]),
    EdDSA(&'a [u8]),
}

impl Hash<'_> {
    /// This fn is currently only used in the context of creating a
    /// digestinfo for SHA*. Other OIDs are not implemented.
    pub(crate) fn oid(&self) -> Option<&'static [u8]> {
        match self {
            Self::SHA256(_) => Some(oid::SHA256),
            Self::SHA384(_) => Some(oid::SHA384),
            Self::SHA512(_) => Some(oid::SHA512),
            Self::EdDSA(_) => panic!("OIDs for EdDSA are unimplemented"),
            Self::ECDSA(_) => panic!("OIDs for ECDSA are unimplemented"),
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
#[non_exhaustive]
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
    fn private_key(&self) -> Result<PrivateKeyMaterial, crate::Error>;

    /// timestamp of (sub)key creation
    fn timestamp(&self) -> KeyGenerationTime;

    /// fingerprint
    fn fingerprint(&self) -> Result<Fingerprint, Error>;
}

/// Algorithm-independent container for private key material to upload to
/// an OpenPGP card
#[non_exhaustive]
pub enum PrivateKeyMaterial {
    R(Box<dyn RSAKey>),
    E(Box<dyn EccKey>),
}

/// RSA-specific container for private key material to upload to an OpenPGP
/// card.
pub trait RSAKey {
    // FIXME: use a mechanism like sequoia_openpgp::crypto::mem::Protected
    // for private key material?

    fn e(&self) -> &[u8];
    fn p(&self) -> &[u8];
    fn q(&self) -> &[u8];

    fn pq(&self) -> Box<[u8]>;
    fn dp1(&self) -> Box<[u8]>;
    fn dq1(&self) -> Box<[u8]>;

    fn n(&self) -> &[u8];
}

/// ECC-specific container for private key material to upload to an OpenPGP
/// card.
pub trait EccKey {
    // FIXME: use a mechanism like sequoia_openpgp::crypto::mem::Protected
    // for private key material?

    fn oid(&self) -> &[u8];
    fn private(&self) -> Vec<u8>;
    fn public(&self) -> Vec<u8>;
    fn ecc_type(&self) -> EccType;
}

/// Algorithm-independent container for public key material retrieved from
/// an OpenPGP card
#[derive(Debug)]
#[non_exhaustive]
pub enum PublicKeyMaterial {
    R(RSAPub),
    E(EccPub),
}

impl std::fmt::Display for PublicKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use hex_slice::AsHex;

        match self {
            Self::R(rsa) => {
                write!(
                    f,
                    "RSA, n: {:02X}, e: {:02X}",
                    rsa.n.plain_hex(false),
                    rsa.v.plain_hex(false)
                )
            }
            Self::E(ecc) => {
                write!(
                    f,
                    "ECC [{}], data: {:02X}",
                    ecc.algo(),
                    ecc.data.plain_hex(false)
                )
            }
        }
    }
}

/// RSA-specific container for public key material from an OpenPGP card.
#[derive(Debug)]
#[non_exhaustive]
pub struct RSAPub {
    /// Modulus (a number denoted as n coded on x bytes)
    n: Vec<u8>,

    /// Public exponent (a number denoted as v, e.g. 65537 dec.)
    v: Vec<u8>,
}

impl RSAPub {
    pub fn new(n: Vec<u8>, v: Vec<u8>) -> Self {
        Self { n, v }
    }

    pub fn n(&self) -> &[u8] {
        &self.n
    }

    pub fn v(&self) -> &[u8] {
        &self.v
    }
}

/// ECC-specific container for public key material from an OpenPGP card.
#[derive(Debug)]
#[non_exhaustive]
pub struct EccPub {
    data: Vec<u8>,
    algo: Algo,
}

impl EccPub {
    pub fn new(data: Vec<u8>, algo: Algo) -> Self {
        Self { data, algo }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
    pub fn algo(&self) -> &Algo {
        &self.algo
    }
}

/// A marker to distinguish between elliptic curve algorithms (ECDH, ECDSA,
/// EdDSA)
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[non_exhaustive]
pub enum EccType {
    ECDH,
    ECDSA,
    EdDSA,
}
