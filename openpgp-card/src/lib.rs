// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use std::collections::HashSet;
use std::fmt;

pub mod apdu;
pub mod card_app;
pub mod errors;
mod keys;
mod parse;
mod tlv;

pub trait CardClient {
    fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>>;
    fn init_caps(&mut self, caps: CardCaps);
    fn get_caps(&self) -> Option<&CardCaps>;

    /// If a CardClient implementation introduces an inherent limit for
    /// maximum number of bytes per command, this fn can indicate that
    /// limit by returning `Some(max_cmd_len)`.
    fn max_cmd_len(&self) -> Option<usize> {
        None
    }
}

pub type CardClientBox = Box<dyn CardClient + Send + Sync>;

/// Information about the capabilities of the card.
/// (feature configuration from card metadata)
#[derive(Clone, Copy, Debug)]
pub struct CardCaps {
    pub ext_support: bool,
    pub chaining_support: bool,
    pub max_cmd_bytes: u16,
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

/// Algorithms for key generation.
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
    fn get(&self, kt: KeyType) -> Algo {
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
pub struct AlgoInfo(Vec<(KeyType, Algo)>);

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

    // FIXME impl trait?
    pub fn from(oid: &[u8]) -> Option<Self> {
        use Curve::*;
        match oid {
            [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => {
                Some(NistP256r1)
            }
            [0x2B, 0x81, 0x04, 0x00, 0x22] => Some(NistP384r1),
            [0x2B, 0x81, 0x04, 0x00, 0x23] => Some(NistP521r1),

            [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07] => {
                Some(BrainpoolP256r1)
            }
            [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b] => {
                Some(BrainpoolP384r1)
            }
            [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d] => {
                Some(BrainpoolP512r1)
            }

            [0x2B, 0x81, 0x04, 0x00, 0x0A] => Some(Secp256k1),

            [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01] => {
                Some(Ed25519)
            }
            [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01] => {
                Some(Cv25519)
            }

            [0x2b, 0x65, 0x71] => Some(Ed448),
            [0x2b, 0x65, 0x6f] => Some(X448),

            _ => None,
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

#[derive(Debug)]
pub struct CardCapabilities {
    command_chaining: bool,
    extended_lc_le: bool,
    extended_length_information: bool,
}

#[derive(Debug)]
pub struct CardSeviceData {
    select_by_full_df_name: bool,
    select_by_partial_df_name: bool,
    dos_available_in_ef_dir: bool,
    dos_available_in_ef_atr_info: bool,
    access_services: [bool; 3],
    mf: bool,
}

#[derive(Debug)]
pub struct Historical {
    // category indicator byte
    cib: u8,

    // Card service data (31)
    csd: Option<CardSeviceData>,

    // Card Capabilities (73)
    cc: Option<CardCapabilities>,

    // status indicator byte (o-card 3.4.1, pg 44)
    sib: u8,
}

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

#[derive(Debug, Eq, PartialEq)]
pub struct ExtendedLengthInfo {
    pub max_command_bytes: u16,
    pub max_response_bytes: u16,
}

#[derive(Debug)]
pub struct CardHolder {
    pub name: Option<String>,
    pub lang: Option<Vec<[char; 2]>>,
    pub sex: Option<Sex>,
}

#[derive(Debug, PartialEq)]
pub enum Sex {
    NotKnown,
    Male,
    Female,
    NotApplicable,
}

impl Sex {
    pub fn as_u8(&self) -> u8 {
        match self {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySet<T> {
    signature: Option<T>,
    decryption: Option<T>,
    authentication: Option<T>,
}

/// Enum to identify one of the Key-slots on an OpenPGP card
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum KeyType {
    // Algorithm attributes signature (C1)
    Signing,

    // Algorithm attributes decryption (C2)
    Decryption,

    // Algorithm attributes authentication (C3)
    Authentication,

    // Algorithm attributes Attestation key (DA, Yubico)
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
