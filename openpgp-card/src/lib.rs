// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client library for
//! [OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card)
//! devices (such as Gnuk, YubiKey, or Java smartcards running an OpenPGP
//! card application).
//!
//! This library aims to offer
//! - access to all features in the OpenPGP
//! [card specification](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf),
//! - without relying on a particular
//! [OpenPGP implementation](https://www.openpgp.org/software/developer/).
//!
//! This library can't directly access cards by itself. Instead, users
//! need to supply a backend that implements the [`CardBackend`]
//! / [`CardTransaction`] traits. The companion crate
//! [openpgp-card-pcsc](https://crates.io/crates/openpgp-card-pcsc)
//! offers a backend that uses [PC/SC](https://en.wikipedia.org/wiki/PC/SC) to
//! communicate with Smart Cards.
//!
//! The [openpgp-card-sequoia](https://crates.io/crates/openpgp-card-sequoia)
//! crate offers a higher level wrapper based on the [Sequoia PGP](https://sequoia-pgp.org/)
//! implementation.
//!
//! See the [architecture diagram](https://gitlab.com/openpgp-card/openpgp-card#architecture) for
//! a visualization.

extern crate core;

pub mod algorithm;
pub(crate) mod apdu;
pub mod card_do;
pub mod crypto_data;
mod errors;
pub(crate) mod keys;
mod oid;
mod openpgp;
mod tlv;

use std::convert::TryInto;
use std::ops::{Deref, DerefMut};

use crate::apdu::commands;
use crate::card_do::ApplicationRelatedData;
pub use crate::errors::{Error, SmartcardError, StatusBytes};
pub use crate::openpgp::{OpenPgp, OpenPgpTransaction};
use crate::tlv::{tag::Tag, value::Value, Tlv};

/// The CardBackend trait defines a connection with an OpenPGP card via a
/// backend implementation (e.g. via the pcsc backend in the crate
/// [openpgp-card-pcsc](https://crates.io/crates/openpgp-card-pcsc)),
/// A CardBackend is only used to get access to a `CardTransaction` object.
#[blanket::blanket(derive(Box))]
pub trait CardBackend {
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, Error>;
}

/// The CardTransaction trait defines communication with an OpenPGP card via a
/// backend implementation (e.g. the pcsc backend in the crate
/// [openpgp-card-pcsc](https://crates.io/crates/openpgp-card-pcsc)),
/// after opening a transaction from a CardBackend.
#[blanket::blanket(derive(Box))]
pub trait CardTransaction {
    /// Transmit the command data in `cmd` to the card.
    ///
    /// `buf_size` is a hint to the backend (the backend may ignore it)
    /// indicating the expected maximum response size.
    fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>, Error>;

    /// Set the card capabilities in the CardTransaction.
    ///
    /// Setting these capabilities is typically part of a bootstrapping
    /// process: the information about the card's capabilities is typically
    /// requested from the card using the same CardTransaction instance,
    /// before the card's capabilities have been initialized.
    fn init_card_caps(&mut self, caps: CardCaps);

    /// Request the card's capabilities
    ///
    /// (apdu serialization makes use of this information, e.g. to
    /// determine if extended length can be used)
    fn card_caps(&self) -> Option<&CardCaps>;

    /// If a CardTransaction implementation introduces an additional,
    /// backend-specific limit for maximum number of bytes per command,
    /// this fn can indicate that limit by returning `Some(max_cmd_len)`.
    fn max_cmd_len(&self) -> Option<usize> {
        None
    }

    /// Does the reader support FEATURE_VERIFY_PIN_DIRECT?
    fn feature_pinpad_verify(&self) -> bool;

    /// Does the reader support FEATURE_MODIFY_PIN_DIRECT?
    fn feature_pinpad_modify(&self) -> bool;

    /// Verify the PIN `id` via the reader pinpad
    fn pinpad_verify(&mut self, pin: PinType) -> Result<Vec<u8>, Error>;

    /// Modify the PIN `id` via the reader pinpad
    fn pinpad_modify(&mut self, pin: PinType) -> Result<Vec<u8>, Error>;

    /// Select the OpenPGP card application
    fn select(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("CardTransaction: select");
        let select_openpgp = commands::select_openpgp();
        apdu::send_command(self, select_openpgp, false)?.try_into()
    }

    /// Get the "application related data" from the card.
    ///
    /// (This data should probably be cached in a higher layer. Some parts of
    /// it are needed regularly, and it does not usually change during
    /// normal use of a card.)
    fn application_related_data(&mut self) -> Result<ApplicationRelatedData, Error> {
        let ad = commands::application_related_data();
        let resp = apdu::send_command(self, ad, true)?;
        let value = Value::from(resp.data()?, true)?;

        log::trace!(" ARD value: {:x?}", value);

        Ok(ApplicationRelatedData(Tlv::new(
            Tags::ApplicationRelatedData,
            value,
        )))
    }

    /// Get a CardApp based on a CardTransaction.
    ///
    /// It is expected that SELECT has already been performed on the card
    /// beforehand.
    ///
    /// This fn initializes the CardCaps by requesting
    /// application_related_data from the card, and setting the
    /// capabilities accordingly.
    fn initialize(&mut self) -> Result<(), Error> {
        let ard = self.application_related_data()?;

        // Determine chaining/extended length support from card
        // metadata and cache this information in the CardTransaction
        // implementation (as a CardCaps)
        let mut ext_support = false;
        let mut chaining_support = false;

        if let Ok(hist) = ard.historical_bytes() {
            if let Some(cc) = hist.card_capabilities() {
                chaining_support = cc.command_chaining();
                ext_support = cc.extended_lc_le();
            }
        }

        let ext_cap = ard.extended_capabilities()?;

        // Get max command/response byte sizes from card
        let (max_cmd_bytes, max_rsp_bytes) =
            if let Ok(Some(eli)) = ard.extended_length_information() {
                // In card 3.x, max lengths come from ExtendedLengthInfo
                (eli.max_command_bytes(), eli.max_response_bytes())
            } else if let (Some(cmd), Some(rsp)) = (ext_cap.max_cmd_len(), ext_cap.max_resp_len()) {
                // In card 2.x, max lengths come from ExtendedCapabilities
                (cmd, rsp)
            } else {
                // Fallback: use 255 if we have no information from the card
                (255, 255)
            };

        let pw_status = ard.pw_status_bytes()?;
        let pw1_max = pw_status.pw1_max_len();
        let pw3_max = pw_status.pw3_max_len();

        let caps = CardCaps {
            ext_support,
            chaining_support,
            max_cmd_bytes,
            max_rsp_bytes,
            pw1_max_len: pw1_max,
            pw3_max_len: pw3_max,
        };

        log::trace!("init_card_caps to: {:x?}", caps);

        self.init_card_caps(caps);

        Ok(())
    }
}

impl<'a> Deref for dyn CardTransaction + Send + Sync + 'a {
    type Target = dyn CardTransaction + 'a;

    fn deref(&self) -> &Self::Target {
        self
    }
}
impl<'a> DerefMut for dyn CardTransaction + Send + Sync + 'a {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
    }
}

/// Information about the capabilities of a card.
///
/// CardCaps is used to signal capabilities (chaining, extended length support, max
/// command/response sizes, max PIN lengths) of the current card to backends.
///
/// CardCaps is not intended for users of this library.
///
/// (The information is gathered from the "Card Capabilities", "Extended length information" and
/// "PWStatus" DOs)
#[derive(Clone, Copy, Debug)]
pub struct CardCaps {
    /// Does the card support extended Lc and Le fields?
    ext_support: bool,

    /// Command chaining support?
    chaining_support: bool,

    /// Maximum number of bytes in a command APDU
    max_cmd_bytes: u16,

    /// Maximum number of bytes in a response APDU
    max_rsp_bytes: u16,

    /// Maximum length of PW1
    pw1_max_len: u8,

    /// Maximum length of PW3
    pw3_max_len: u8,
}

impl CardCaps {
    pub fn ext_support(&self) -> bool {
        self.ext_support
    }

    pub fn max_rsp_bytes(&self) -> u16 {
        self.max_rsp_bytes
    }

    pub fn pw1_max_len(&self) -> u8 {
        self.pw1_max_len
    }

    pub fn pw3_max_len(&self) -> u8 {
        self.pw3_max_len
    }
}

/// Tags, as specified and used in the OpenPGP card 3.4.1 spec.
/// All tags in OpenPGP card are either 1 or 2 bytes long.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
#[allow(dead_code)]
pub(crate) enum Tags {
    // BER identifiers
    OctetString,
    Null,
    ObjectIdentifier,
    Sequence,

    // GET DATA
    PrivateUse1,
    PrivateUse2,
    PrivateUse3,
    PrivateUse4,
    ApplicationIdentifier,
    LoginData,
    Url,
    HistoricalBytes,
    CardholderRelatedData,
    Name,
    LanguagePref,
    Sex,
    ApplicationRelatedData,
    ExtendedLengthInformation,
    GeneralFeatureManagement,
    DiscretionaryDataObjects,
    ExtendedCapabilities,
    AlgorithmAttributesSignature,
    AlgorithmAttributesDecryption,
    AlgorithmAttributesAuthentication,
    PWStatusBytes,
    Fingerprints,
    CaFingerprints,
    GenerationTimes,
    KeyInformation,
    UifSig,
    UifDec,
    UifAuth,
    UifAttestation,
    SecuritySupportTemplate,
    DigitalSignatureCounter,
    CardholderCertificate,
    AlgorithmAttributesAttestation,
    FingerprintAttestation,
    CaFingerprintAttestation,
    GenerationTimeAttestation,
    KdfDo,
    AlgorithmInformation,
    CertificateSecureMessaging,
    AttestationCertificate,

    // PUT DATA (additional Tags that don't get used for GET DATA)
    FingerprintSignature,
    FingerprintDecryption,
    FingerprintAuthentication,
    CaFingerprint1,
    CaFingerprint2,
    CaFingerprint3,
    GenerationTimeSignature,
    GenerationTimeDecryption,
    GenerationTimeAuthentication,
    // FIXME: +D1, D2
    ResettingCode,
    PsoEncDecKey,

    // OTHER
    // 4.4.3.12 Private Key Template
    ExtendedHeaderList,
    CardholderPrivateKeyTemplate,
    ConcatenatedKeyData,
    CrtKeySignature,
    CrtKeyConfidentiality,
    CrtKeyAuthentication,
    PrivateKeyDataRsaPublicExponent,
    PrivateKeyDataRsaPrime1,
    PrivateKeyDataRsaPrime2,
    PrivateKeyDataRsaPq,
    PrivateKeyDataRsaDp1,
    PrivateKeyDataRsaDq1,
    PrivateKeyDataRsaModulus,
    PrivateKeyDataEccPrivateKey,
    PrivateKeyDataEccPublicKey,

    // 7.2.14 GENERATE ASYMMETRIC KEY PAIR
    PublicKey,
    PublicKeyDataRsaModulus,
    PublicKeyDataRsaExponent,
    PublicKeyDataEccPoint,

    // 7.2.11 PSO: DECIPHER
    Cipher,
    ExternalPublicKey,

    // 7.2.5 SELECT DATA
    GeneralReference,
    TagList,
}

impl From<Tags> for Vec<u8> {
    fn from(t: Tags) -> Self {
        ShortTag::from(t).into()
    }
}

impl From<Tags> for Tag {
    fn from(t: Tags) -> Self {
        ShortTag::from(t).into()
    }
}

impl From<Tags> for ShortTag {
    fn from(t: Tags) -> Self {
        match t {
            // BER identifiers https://en.wikipedia.org/wiki/X.690#BER_encoding
            Tags::OctetString => [0x04].into(),
            Tags::Null => [0x05].into(),
            Tags::ObjectIdentifier => [0x06].into(),
            Tags::Sequence => [0x30].into(),

            // GET DATA
            Tags::PrivateUse1 => [0x01, 0x01].into(),
            Tags::PrivateUse2 => [0x01, 0x02].into(),
            Tags::PrivateUse3 => [0x01, 0x03].into(),
            Tags::PrivateUse4 => [0x01, 0x04].into(),
            Tags::ApplicationIdentifier => [0x4f].into(),
            Tags::LoginData => [0x5e].into(),
            Tags::Url => [0x5f, 0x50].into(),
            Tags::HistoricalBytes => [0x5f, 0x52].into(),
            Tags::CardholderRelatedData => [0x65].into(),
            Tags::Name => [0x5b].into(),
            Tags::LanguagePref => [0x5f, 0x2d].into(),
            Tags::Sex => [0x5f, 0x35].into(),
            Tags::ApplicationRelatedData => [0x6e].into(),
            Tags::ExtendedLengthInformation => [0x7f, 0x66].into(),
            Tags::GeneralFeatureManagement => [0x7f, 0x74].into(),
            Tags::DiscretionaryDataObjects => [0x73].into(),
            Tags::ExtendedCapabilities => [0xc0].into(),
            Tags::AlgorithmAttributesSignature => [0xc1].into(),
            Tags::AlgorithmAttributesDecryption => [0xc2].into(),
            Tags::AlgorithmAttributesAuthentication => [0xc3].into(),
            Tags::PWStatusBytes => [0xc4].into(),
            Tags::Fingerprints => [0xc5].into(),
            Tags::CaFingerprints => [0xc6].into(),
            Tags::GenerationTimes => [0xcd].into(),
            Tags::KeyInformation => [0xde].into(),
            Tags::UifSig => [0xd6].into(),
            Tags::UifDec => [0xd7].into(),
            Tags::UifAuth => [0xd8].into(),
            Tags::UifAttestation => [0xd9].into(),
            Tags::SecuritySupportTemplate => [0x7a].into(),
            Tags::DigitalSignatureCounter => [0x93].into(),
            Tags::CardholderCertificate => [0x7f, 0x21].into(),
            Tags::AlgorithmAttributesAttestation => [0xda].into(),
            Tags::FingerprintAttestation => [0xdb].into(),
            Tags::CaFingerprintAttestation => [0xdc].into(),
            Tags::GenerationTimeAttestation => [0xdd].into(),
            Tags::KdfDo => [0xf9].into(),
            Tags::AlgorithmInformation => [0xfa].into(),
            Tags::CertificateSecureMessaging => [0xfb].into(),
            Tags::AttestationCertificate => [0xfc].into(),

            // PUT DATA
            Tags::FingerprintSignature => [0xc7].into(),
            Tags::FingerprintDecryption => [0xc8].into(),
            Tags::FingerprintAuthentication => [0xc9].into(),
            Tags::CaFingerprint1 => [0xca].into(),
            Tags::CaFingerprint2 => [0xcb].into(),
            Tags::CaFingerprint3 => [0xcc].into(),
            Tags::GenerationTimeSignature => [0xce].into(),
            Tags::GenerationTimeDecryption => [0xcf].into(),
            Tags::GenerationTimeAuthentication => [0xd0].into(),
            Tags::ResettingCode => [0xd3].into(),
            Tags::PsoEncDecKey => [0xd5].into(),

            // OTHER
            // 4.4.3.12 Private Key Template
            Tags::ExtendedHeaderList => [0x4d].into(),
            Tags::CardholderPrivateKeyTemplate => [0x7f, 0x48].into(),
            Tags::ConcatenatedKeyData => [0x5f, 0x48].into(),
            Tags::CrtKeySignature => [0xb6].into(),
            Tags::CrtKeyConfidentiality => [0xb8].into(),
            Tags::CrtKeyAuthentication => [0xa4].into(),
            Tags::PrivateKeyDataRsaPublicExponent => [0x91].into(),
            Tags::PrivateKeyDataRsaPrime1 => [0x92].into(), // Note: value reused!
            Tags::PrivateKeyDataRsaPrime2 => [0x93].into(),
            Tags::PrivateKeyDataRsaPq => [0x94].into(),
            Tags::PrivateKeyDataRsaDp1 => [0x95].into(),
            Tags::PrivateKeyDataRsaDq1 => [0x96].into(),
            Tags::PrivateKeyDataRsaModulus => [0x97].into(),
            Tags::PrivateKeyDataEccPrivateKey => [0x92].into(), // Note: value reused!
            Tags::PrivateKeyDataEccPublicKey => [0x99].into(),

            // 7.2.14 GENERATE ASYMMETRIC KEY PAIR
            Tags::PublicKey => [0x7f, 0x49].into(),
            Tags::PublicKeyDataRsaModulus => [0x81].into(),
            Tags::PublicKeyDataRsaExponent => [0x82].into(),
            Tags::PublicKeyDataEccPoint => [0x86].into(),

            // 7.2.11 PSO: DECIPHER
            Tags::Cipher => [0xa6].into(),
            Tags::ExternalPublicKey => [0x86].into(),

            // 7.2.5 SELECT DATA
            Tags::GeneralReference => [0x60].into(),
            Tags::TagList => [0x5c].into(),
        }
    }
}

/// A ShortTag is a Tlv tag that is guaranteed to be either 1 or 2 bytes long.
///
/// This covers any tag that can be used in the OpenPGP card context (the spec doesn't describe how
/// longer tags might be used.)
///
/// (The type tlv::Tag will usually/always contain 1 or 2 byte long tags, in this library.
/// But its length is not guaranteed by the type system)
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ShortTag {
    One(u8),
    Two(u8, u8),
}

impl From<ShortTag> for Tag {
    fn from(n: ShortTag) -> Self {
        match n {
            ShortTag::One(t0) => [t0].into(),
            ShortTag::Two(t0, t1) => [t0, t1].into(),
        }
    }
}

impl From<[u8; 1]> for ShortTag {
    fn from(v: [u8; 1]) -> Self {
        ShortTag::One(v[0])
    }
}
impl From<[u8; 2]> for ShortTag {
    fn from(v: [u8; 2]) -> Self {
        ShortTag::Two(v[0], v[1])
    }
}
impl From<ShortTag> for Vec<u8> {
    fn from(t: ShortTag) -> Self {
        match t {
            ShortTag::One(t0) => vec![t0],
            ShortTag::Two(t0, t1) => vec![t0, t1],
        }
    }
}

/// Specify a PIN to *verify* (distinguishes between `Sign`, `User` and `Admin`).
///
/// (Note that for PIN *management*, in particular changing a PIN, "signing and user" are
/// not distinguished. They always share the same PIN value `PW1`)
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PinType {
    /// Verify PW1 in mode P2=81 (for the PSO:CDS operation)
    Sign,

    /// Verify PW1 in mode P2=82 (for all other User operations)
    User,

    /// Verify PW3 (for Admin operations)
    Admin,
}

impl PinType {
    pub fn id(&self) -> u8 {
        match self {
            PinType::Sign => 0x81,
            PinType::User => 0x82,
            PinType::Admin => 0x83,
        }
    }
}

/// Identify a Key slot on an OpenPGP card
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum KeyType {
    Signing,
    Decryption,
    Authentication,
    Attestation,
}

impl KeyType {
    /// Get C1/C2/C3/DA values for this KeyTypes, to use as Tag
    fn algorithm_tag(&self) -> ShortTag {
        match self {
            Self::Signing => Tags::AlgorithmAttributesSignature,
            Self::Decryption => Tags::AlgorithmAttributesDecryption,
            Self::Authentication => Tags::AlgorithmAttributesAuthentication,
            Self::Attestation => Tags::AlgorithmAttributesAttestation,
        }
        .into()
    }

    /// Get C7/C8/C9/DB values for this KeyTypes, to use as Tag.
    ///
    /// (NOTE: these Tags are only used for "PUT DO", but GETting
    /// fingerprint information from the card uses the combined Tag C5)
    fn fingerprint_put_tag(&self) -> ShortTag {
        match self {
            Self::Signing => Tags::FingerprintSignature,
            Self::Decryption => Tags::FingerprintDecryption,
            Self::Authentication => Tags::FingerprintAuthentication,
            Self::Attestation => Tags::FingerprintAttestation,
        }
        .into()
    }

    /// Get CE/CF/D0/DD values for this KeyTypes, to use as Tag.
    ///
    /// (NOTE: these Tags are only used for "PUT DO", but GETting
    /// timestamp information from the card uses the combined Tag CD)
    fn timestamp_put_tag(&self) -> ShortTag {
        match self {
            Self::Signing => Tags::GenerationTimeSignature,
            Self::Decryption => Tags::GenerationTimeDecryption,
            Self::Authentication => Tags::GenerationTimeAuthentication,
            Self::Attestation => Tags::GenerationTimeAttestation,
        }
        .into()
    }
}

/// A KeySet binds together a triple of information about each Key on a card
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySet<T> {
    signature: Option<T>,
    decryption: Option<T>,
    authentication: Option<T>,
}

impl<T> From<(Option<T>, Option<T>, Option<T>)> for KeySet<T> {
    fn from(tuple: (Option<T>, Option<T>, Option<T>)) -> Self {
        Self {
            signature: tuple.0,
            decryption: tuple.1,
            authentication: tuple.2,
        }
    }
}

impl<T> KeySet<T> {
    pub fn signature(&self) -> Option<&T> {
        self.signature.as_ref()
    }

    pub fn decryption(&self) -> Option<&T> {
        self.decryption.as_ref()
    }

    pub fn authentication(&self) -> Option<&T> {
        self.authentication.as_ref()
    }
}
