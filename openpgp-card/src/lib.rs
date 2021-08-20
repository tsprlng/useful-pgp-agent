// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Access library for
//! [OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card)
//! devices (such as Gnuk, Yubikey, or Java smartcards running an OpenPGP
//! card application).
//!
//! This library aims to offer
//! - access to all features in the OpenPGP card specification,
//! - without relying on a particular OpenPGP implementation.
//!
//! This library doesn't itself implement a means to access cards. Instead,
//! users need to supply an implementation of the [`CardClient`] trait, for
//! access to cards.
//!
//! The companion crate
//! [openpgp-card-pcsc](https://crates.io/crates/openpgp-card-pcsc)
//! offers a backend that uses [pcsclite](https://pcsclite.apdu.fr/) to
//! communicate with smartcards.
//!
//! The [openpgp-card-sequoia](https://crates.io/crates/openpgp-card-sequoia)
//! crate offers a higher level wrapper based on the
//! [Sequoia PGP](https://sequoia-pgp.org/) implementation.

use anyhow::Result;
use std::collections::HashSet;

use crate::algorithm::Algo;

pub mod algorithm;
mod apdu;
mod card_app;
pub mod errors;
mod keys;
mod parse;
mod tlv;

pub use crate::apdu::response::Response;
pub use crate::card_app::ApplicationRelatedData;
pub use crate::card_app::CardApp;

/// The CardClient trait defines communication with an OpenPGP card via a
/// backend implementation (e.g. the pcsc backend in the crate
/// openpgp-card-pcsc).
pub trait CardClient {
    /// Transmit the command data in `cmd` to the card.
    ///
    /// `buf_size` is a hint to the backend (the backend may ignore it)
    /// indicating the expected maximum response size.
    fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>>;

    /// Set the card capabilities in the CardClient.
    ///
    /// Setting these capabilities is typically part of a bootstrapping
    /// process: the information about the card's capabilities is typically
    /// requested from the card using the same CardClient instance, before
    /// the card's capabilities have been initialized.
    fn init_caps(&mut self, caps: CardCaps);

    /// Request the card's capabilities
    ///
    /// (apdu serialization makes use of this information, e.g. to
    /// determine if extended length can be used)
    fn get_caps(&self) -> Option<&CardCaps>;

    /// If a CardClient implementation introduces an additional,
    /// backend-specific limit for maximum number of bytes per command,
    /// this fn can indicate that limit by returning `Some(max_cmd_len)`.
    fn max_cmd_len(&self) -> Option<usize> {
        None
    }
}

pub type CardClientBox = Box<dyn CardClient + Send + Sync>;

/// Information about the capabilities of the card.
///
/// (This configuration is retrieved from card metadata, specifically from
/// "Card Capabilities" and "Extended length information")
#[derive(Clone, Copy, Debug)]
pub struct CardCaps {
    /// Extended Lc and Le fields
    pub ext_support: bool,

    /// Command chaining
    pub chaining_support: bool,

    /// Maximum number of bytes in a command APDU
    pub max_cmd_bytes: u16,

    /// Maximum number of bytes in a response APDU
    pub max_rsp_bytes: u16,
}

impl CardCaps {
    pub fn new(
        ext_support: bool,
        chaining_support: bool,
        max_cmd_bytes: u16,
        max_rsp_bytes: u16,
    ) -> CardCaps {
        Self {
            ext_support,
            chaining_support,
            max_cmd_bytes,
            max_rsp_bytes,
        }
    }
}

/// An OpenPGP key generation Time
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyGeneration(u32);

impl KeyGeneration {
    pub fn get(&self) -> u32 {
        self.0
    }
}

/// Container for a hash value.
/// These hash values can be signed by the card.
pub enum Hash<'a> {
    SHA256([u8; 0x20]),
    SHA384([u8; 0x30]),
    SHA512([u8; 0x40]),
    EdDSA(&'a [u8]), // FIXME?
    ECDSA(&'a [u8]), // FIXME?
}

impl Hash<'_> {
    fn oid(&self) -> Option<&'static [u8]> {
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

    fn digest(&self) -> &[u8] {
        match self {
            Self::SHA256(d) => &d[..],
            Self::SHA384(d) => &d[..],
            Self::SHA512(d) => &d[..],
            Self::EdDSA(d) => d,
            Self::ECDSA(d) => d,
        }
    }
}

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

/// Container for data to be decrypted on an OpenPGP card.
pub enum DecryptMe<'a> {
    // message/ciphertext
    RSA(&'a [u8]),

    // ephemeral
    ECDH(&'a [u8]),
}

// ----------

/// Application identifier (AID)
#[derive(Debug, Eq, PartialEq)]
pub struct ApplicationId {
    pub application: u8,

    // GnuPG says:
    // if (app->appversion >= 0x0200)
    // app->app_local->extcap.is_v2 = 1;
    //
    // if (app->appversion >= 0x0300)
    // app->app_local->extcap.is_v3 = 1;
    pub version: u16,

    pub manufacturer: u16,

    pub serial: u32,
}

/// Card Capabilities (73)
#[derive(Debug)]
pub struct CardCapabilities {
    command_chaining: bool,
    extended_lc_le: bool,
    extended_length_information: bool,
}

/// Card service data (31)
#[derive(Debug)]
pub struct CardServiceData {
    select_by_full_df_name: bool,
    select_by_partial_df_name: bool,
    dos_available_in_ef_dir: bool,
    dos_available_in_ef_atr_info: bool,
    access_services: [bool; 3],
    mf: bool,
}

/// Historical Bytes
#[derive(Debug)]
pub struct Historical {
    /// category indicator byte
    cib: u8,

    /// Card service data (31)
    csd: Option<CardServiceData>,

    /// Card Capabilities (73)
    cc: Option<CardCapabilities>,

    /// status indicator byte (o-card 3.4.1, pg 44)
    sib: u8,
}

/// Extended Capabilities
#[derive(Debug, Eq, PartialEq)]
pub struct ExtendedCap {
    pub features: HashSet<Features>,
    sm: u8,
    max_len_challenge: u16,
    max_len_cardholder_cert: u16,
    pub max_len_special_do: u16,
    pin_2_format: bool,
    mse_command: bool,
}

/// Features (first byte of Extended Capabilities)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Features {
    SecureMessaging,
    GetChallenge,
    KeyImport,
    PwStatusChange,
    PrivateUseDOs,
    AlgoAttrsChangeable,
    Aes,
    KdfDo,
}

/// Extended length information
#[derive(Debug, Eq, PartialEq)]
pub struct ExtendedLengthInfo {
    pub max_command_bytes: u16,
    pub max_response_bytes: u16,
}

/// Cardholder Related Data
#[derive(Debug)]
pub struct Cardholder {
    pub name: Option<String>,
    pub lang: Option<Vec<[char; 2]>>,
    pub sex: Option<Sex>,
}

/// Sex (according to ISO 5218)
#[derive(Debug, PartialEq)]
pub enum Sex {
    NotKnown,
    Male,
    Female,
    NotApplicable,
}

impl From<&Sex> for u8 {
    fn from(sex: &Sex) -> u8 {
        match sex {
            Sex::NotKnown => 0x30,
            Sex::Male => 0x31,
            Sex::Female => 0x32,
            Sex::NotApplicable => 0x39,
        }
    }
}

impl From<u8> for Sex {
    fn from(s: u8) -> Self {
        match s {
            0x31 => Sex::Male,
            0x32 => Sex::Female,
            0x39 => Sex::NotApplicable,
            _ => Sex::NotKnown,
        }
    }
}

/// PW status Bytes
#[derive(Debug)]
pub struct PWStatus {
    pub(crate) pw1_cds_multi: bool,
    pub(crate) pw1_derived: bool,
    pub(crate) pw1_len: u8,
    pub(crate) rc_len: u8,
    pub(crate) pw3_derived: bool,
    pub(crate) pw3_len: u8,
    pub(crate) err_count_pw1: u8,
    pub(crate) err_count_rst: u8,
    pub(crate) err_count_pw3: u8,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Fingerprint([u8; 20]);

/// A KeySet binds together a triple of information about each Key on a card
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySet<T> {
    signature: Option<T>,
    decryption: Option<T>,
    authentication: Option<T>,
}

/// Enum to identify the Key-slots on an OpenPGP card
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyType {
    Signing,
    Decryption,
    Authentication,
    Attestation,
}

impl KeyType {
    /// Get C1/C2/C3/DA values for this KeyTypes, to use as Tag
    pub fn get_algorithm_tag(&self) -> u8 {
        use KeyType::*;

        match self {
            Signing => 0xC1,
            Decryption => 0xC2,
            Authentication => 0xC3,
            Attestation => 0xDA,
        }
    }

    /// Get C7/C8/C9/DB values for this KeyTypes, to use as Tag.
    ///
    /// (NOTE: these Tags are only used for "PUT DO", but GETting
    /// fingerprint information from the card uses the combined Tag C5)
    pub fn get_fingerprint_put_tag(&self) -> u8 {
        use KeyType::*;

        match self {
            Signing => 0xC7,
            Decryption => 0xC8,
            Authentication => 0xC9,
            Attestation => 0xDB,
        }
    }

    /// Get CE/CF/D0/DD values for this KeyTypes, to use as Tag.
    ///
    /// (NOTE: these Tags are only used for "PUT DO", but GETting
    /// timestamp information from the card uses the combined Tag CD)
    pub fn get_timestamp_put_tag(&self) -> u8 {
        use KeyType::*;

        match self {
            Signing => 0xCE,
            Decryption => 0xCF,
            Authentication => 0xD0,
            Attestation => 0xDD,
        }
    }
}

#[cfg(test)]
mod test {
    use super::tlv::tag::Tag;
    use super::tlv::{Tlv, TlvEntry};

    #[test]
    fn test_tlv() {
        let cpkt = Tlv(
            Tag(vec![0x7F, 0x48]),
            TlvEntry::S(vec![
                0x91, 0x03, 0x92, 0x82, 0x01, 0x00, 0x93, 0x82, 0x01, 0x00,
            ]),
        );

        assert_eq!(
            cpkt.serialize(),
            vec![
                0x7F, 0x48, 0x0A, 0x91, 0x03, 0x92, 0x82, 0x01, 0x00, 0x93,
                0x82, 0x01, 0x00,
            ]
        );
    }
}
