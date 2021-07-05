// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use pcsc::*;

use apdu::{commands, response::Response};
use parse::{
    algo_attrs::Algo, algo_info::AlgoInfo, application_id::ApplicationId,
    cardholder::CardHolder, extended_cap::ExtendedCap, extended_cap::Features,
    extended_length_info::ExtendedLengthInfo, fingerprint,
    historical::Historical, pw_status::PWStatus, KeySet,
};
use tlv::Tlv;

use crate::card_app::CardApp;
use crate::errors::{OpenpgpCardError, SmartcardError};
use std::ops::Deref;

mod apdu;
mod card;
mod card_app;
pub mod errors;
mod key_upload;
mod parse;
mod tlv;

/// Information about the capabilities of the card.
/// (feature configuration from card metadata)
pub(crate) struct CardCaps {
    pub(crate) ext_support: bool,
    pub(crate) chaining_support: bool,
    pub(crate) max_cmd_bytes: u16,
}

/// Container for a hash value.
/// These hash values can be signed by the card.
pub enum Hash<'a> {
    SHA256([u8; 0x20]),
    SHA384([u8; 0x30]),
    SHA512([u8; 0x40]),
    EdDSA(&'a [u8]), // FIXME?
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
        }
    }

    fn digest(&self) -> &[u8] {
        match self {
            Self::SHA256(d) => &d[..],
            Self::SHA384(d) => &d[..],
            Self::SHA512(d) => &d[..],
            Self::EdDSA(d) => d,
        }
    }
}

/// A PGP-implementation-agnostic wrapper for private key data, to upload
/// to an OpenPGP card
pub trait CardUploadableKey {
    /// private key data
    fn get_key(&self) -> Result<PrivateKeyMaterial>;

    /// timestamp of (sub)key creation
    fn get_ts(&self) -> u64;

    /// fingerprint
    fn get_fp(&self) -> Vec<u8>;
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
#[derive(Clone, Copy)]
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

#[derive(Debug)]
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
            31 => Sex::Male,
            32 => Sex::Female,
            39 => Sex::NotApplicable,
            _ => Sex::NotKnown,
        }
    }
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

/// Representation of an opened OpenPGP card in its basic, freshly opened,
/// state (i.e. no passwords have been verified, default privileges apply).
pub struct CardBase {
    card_app: CardApp,

    // Cache of "application related data".
    //
    // FIXME: Should be invalidated when changing data on the card!
    // (e.g. uploading keys, etc)
    ard: Tlv,
}

impl CardBase {
    /// Get all cards that can be opened as an OpenPGP card applet
    pub fn list_cards() -> Result<Vec<Self>> {
        let cards = card::get_cards().map_err(|err| anyhow!(err))?;
        let ocs: Vec<_> = cards
            .into_iter()
            .map(Self::open_card)
            .map(|oc| oc.ok())
            .flatten()
            .collect();

        Ok(ocs)
    }

    /// Find an OpenPGP card by "ident", open and return it.
    ///
    /// The ident is constructed as a concatenation of manufacturer
    /// id, a colon, and the card serial. Example: "1234:5678ABCD".
    pub fn open_by_ident(ident: &str) -> Result<Self, OpenpgpCardError> {
        let cards = card::get_cards().map_err(|e| {
            OpenpgpCardError::Smartcard(SmartcardError::Error(format!(
                "{:?}",
                e
            )))
        })?;

        for card in cards {
            let res = Self::open_card(card);
            if let Ok(opened_card) = res {
                let res = opened_card.get_aid();
                if let Ok(aid) = res {
                    if aid.ident() == ident {
                        return Ok(opened_card);
                    }
                }
            }
        }

        Err(OpenpgpCardError::Smartcard(SmartcardError::CardNotFound(
            ident.to_string(),
        )))
    }

    /// Open connection to some card and select the openpgp applet
    pub fn open_yolo() -> Result<Self, OpenpgpCardError> {
        let mut cards = card::get_cards().map_err(|e| {
            OpenpgpCardError::Smartcard(SmartcardError::Error(format!(
                "{:?}",
                e
            )))
        })?;

        // randomly use the first card in the list
        let card = cards.swap_remove(0);

        Self::open_card(card)
    }

    /// Open connection to a specific card and select the openpgp applet
    fn open_card(card: Card) -> Result<Self, OpenpgpCardError> {
        let select_openpgp = commands::select_openpgp();
        let resp = apdu::send_command(&card, select_openpgp, true, None)?;

        if resp.is_ok() {
            // read and cache "application related data"
            let card_app = CardApp::new(card);
            let ard = card_app.get_app_data()?;

            // Determine chaining/extended length support from card
            // metadata and cache this information in CardApp (as a
            // CardCaps)

            let mut ext_support = false;
            let mut chaining_support = false;

            if let Ok(hist) = CardApp::get_historical(&ard) {
                if let Some(cc) = hist.get_card_capabilities() {
                    chaining_support = cc.get_command_chaining();
                    ext_support = cc.get_extended_lc_le();
                }
            }

            let max_cmd_bytes = if let Ok(Some(eli)) =
                CardApp::get_extended_length_information(&ard)
            {
                eli.max_command_bytes
            } else {
                255
            };

            let caps = CardCaps {
                ext_support,
                chaining_support,
                max_cmd_bytes,
            };
            let card_app = card_app.set_caps(caps);

            Ok(Self { card_app, ard })
        } else {
            Err(anyhow!("Couldn't open OpenPGP application").into())
        }
    }

    // --- application data ---

    /// Load "application related data".
    ///
    /// This is done once, after opening the OpenPGP card applet
    /// (the data is stored in the OpenPGPCard object).
    fn get_app_data(&self) -> Result<Tlv> {
        self.card_app.get_app_data()
    }

    pub fn get_aid(&self) -> Result<ApplicationId, OpenpgpCardError> {
        CardApp::get_aid(&self.ard)
    }

    pub fn get_historical(&self) -> Result<Historical, OpenpgpCardError> {
        CardApp::get_historical(&self.ard)
    }

    pub fn get_extended_length_information(
        &self,
    ) -> Result<Option<ExtendedLengthInfo>> {
        CardApp::get_extended_length_information(&self.ard)
    }

    pub fn get_general_feature_management() -> Option<bool> {
        unimplemented!()
    }

    pub fn get_discretionary_data_objects() {
        unimplemented!()
    }

    pub fn get_extended_capabilities(
        &self,
    ) -> Result<ExtendedCap, OpenpgpCardError> {
        CardApp::get_extended_capabilities(&self.ard)
    }

    pub fn get_algorithm_attributes(&self, key_type: KeyType) -> Result<Algo> {
        CardApp::get_algorithm_attributes(&self.ard, key_type)
    }

    /// PW status Bytes
    pub fn get_pw_status_bytes(&self) -> Result<PWStatus> {
        CardApp::get_pw_status_bytes(&self.ard)
    }

    pub fn get_fingerprints(
        &self,
    ) -> Result<KeySet<fingerprint::Fingerprint>, OpenpgpCardError> {
        CardApp::get_fingerprints(&self.ard)
    }

    pub fn get_ca_fingerprints(&self) {
        unimplemented!()
    }

    pub fn get_key_generation_times() {
        unimplemented!()
    }

    pub fn get_key_information() {
        unimplemented!()
    }

    pub fn get_uif_pso_cds() {
        unimplemented!()
    }

    pub fn get_uif_pso_dec() {
        unimplemented!()
    }

    pub fn get_uif_pso_aut() {
        unimplemented!()
    }
    pub fn get_uif_attestation() {
        unimplemented!()
    }

    // --- optional private DOs (0101 - 0104) ---

    // --- login data (5e) ---

    // --- URL (5f50) ---

    pub fn get_url(&self) -> Result<String> {
        self.card_app.get_url()
    }

    // --- cardholder related data (65) ---
    pub fn get_cardholder_related_data(&self) -> Result<CardHolder> {
        self.card_app.get_cardholder_related_data()
    }

    // --- security support template (7a) ---
    pub fn get_security_support_template(&self) -> Result<Tlv> {
        self.card_app.get_security_support_template()
    }

    // DO "Algorithm Information" (0xFA)
    pub fn list_supported_algo(&self) -> Result<Option<AlgoInfo>> {
        // The DO "Algorithm Information" (Tag FA) shall be present if
        // Algorithm attributes can be changed
        let ec = self.get_extended_capabilities()?;
        if !ec.features.contains(&Features::AlgoAttrsChangeable) {
            // Algorithm attributes can not be changed,
            // list_supported_algo is not supported
            return Ok(None);
        }

        self.card_app.list_supported_algo()
    }

    // ----------

    /// Delete all state on this OpenPGP card
    pub fn factory_reset(&self) -> Result<()> {
        self.card_app.factory_reset()
    }

    pub fn verify_pw1_for_signing(
        self,
        pin: &str,
    ) -> Result<CardSign, CardBase> {
        assert!(pin.len() >= 6); // FIXME: Err

        let res = self.card_app.verify_pw1_for_signing(pin);

        if let Ok(resp) = res {
            if resp.is_ok() {
                return Ok(CardSign { oc: self });
            }
        }

        Err(self)
    }

    pub fn check_pw1(&self) -> Result<Response, OpenpgpCardError> {
        self.card_app.check_pw1()
    }

    pub fn verify_pw1(self, pin: &str) -> Result<CardUser, CardBase> {
        assert!(pin.len() >= 6); // FIXME: Err

        let res = self.card_app.verify_pw1(pin);

        if let Ok(resp) = res {
            if resp.is_ok() {
                return Ok(CardUser { oc: self });
            }
        }

        Err(self)
    }

    pub fn check_pw3(&self) -> Result<Response, OpenpgpCardError> {
        self.card_app.check_pw3()
    }

    pub fn verify_pw3(self, pin: &str) -> Result<CardAdmin, CardBase> {
        assert!(pin.len() >= 8); // FIXME: Err

        let res = self.card_app.verify_pw3(pin);

        if let Ok(resp) = res {
            if resp.is_ok() {
                return Ok(CardAdmin { oc: self });
            }
        }

        Err(self)
    }
}

/// An OpenPGP card after successful verification of PW1 in mode 82
/// (verification for operations other than signing)
pub struct CardUser {
    oc: CardBase,
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardUser.
impl Deref for CardUser {
    type Target = CardBase;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

impl CardUser {
    /// Decrypt the ciphertext in `dm`, on the card.
    pub fn decrypt(&self, dm: DecryptMe) -> Result<Vec<u8>, OpenpgpCardError> {
        self.card_app.decrypt(dm)
    }

    /// Run decryption operation on the smartcard
    /// (7.2.11 PSO: DECIPHER)
    pub(crate) fn pso_decipher(
        &self,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        self.card_app.pso_decipher(data)
    }
}

/// An OpenPGP card after successful verification of PW1 in mode 81
/// (verification for signing)
pub struct CardSign {
    oc: CardBase,
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardUser.
impl Deref for CardSign {
    type Target = CardBase;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

// FIXME: depending on the setting in "PW1 Status byte", only one
// signature can be made after verification for signing
impl CardSign {
    /// Sign the message in `hash`, on the card.
    pub fn signature_for_hash(
        &self,
        hash: Hash,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        self.card_app.signature_for_hash(hash)
    }

    /// Run signing operation on the smartcard
    /// (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)
    pub(crate) fn compute_digital_signature(
        &self,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        self.card_app.compute_digital_signature(data)
    }
}

/// An OpenPGP card after successful verification of PW3 ("Admin privileges")
pub struct CardAdmin {
    oc: CardBase,
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardAdmin.
impl Deref for CardAdmin {
    type Target = CardBase;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

impl CardAdmin {
    pub fn set_name(&self, name: &str) -> Result<Response, OpenpgpCardError> {
        if name.len() >= 40 {
            return Err(anyhow!("name too long").into());
        }

        // All chars must be in ASCII7
        if name.chars().any(|c| !c.is_ascii()) {
            return Err(anyhow!("Invalid char in name").into());
        };

        self.card_app.set_name(name)
    }

    pub fn set_lang(&self, lang: &str) -> Result<Response, OpenpgpCardError> {
        if lang.len() > 8 {
            return Err(anyhow!("lang too long").into());
        }

        self.card_app.set_lang(lang)
    }

    pub fn set_sex(&self, sex: Sex) -> Result<Response, OpenpgpCardError> {
        self.card_app.set_sex(sex)
    }

    pub fn set_url(&self, url: &str) -> Result<Response, OpenpgpCardError> {
        if url.chars().any(|c| !c.is_ascii()) {
            return Err(anyhow!("Invalid char in url").into());
        }

        // Check for max len
        let ec = self.get_extended_capabilities()?;

        if url.len() < ec.max_len_special_do as usize {
            self.card_app.set_url(url)
        } else {
            Err(anyhow!("URL too long").into())
        }
    }

    pub fn upload_key(
        &self,
        key: Box<dyn CardUploadableKey>,
        key_type: KeyType,
    ) -> Result<(), OpenpgpCardError> {
        let algo_list = self.list_supported_algo()?;

        key_upload::upload_key(&self.card_app, key, key_type, algo_list)
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
