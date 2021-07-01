// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;

use anyhow::{anyhow, Result};
use pcsc::*;

use apdu::{commands, Le, response::Response};
use parse::{algo_attrs::Algo,
            algo_info::AlgoInfo,
            application_id::ApplicationId,
            cardholder::CardHolder,
            extended_cap::ExtendedCap,
            extended_cap::Features,
            extended_length_info::ExtendedLengthInfo,
            fingerprint,
            historical::Historical,
            KeySet};
use tlv::Tlv;

use crate::errors::{OpenpgpCardError, SmartcardError};
use crate::tlv::tag::Tag;
use crate::tlv::TlvEntry;
use std::ops::Deref;

pub mod errors;
mod apdu;
mod card;
mod key_upload;
mod parse;
mod tlv;


pub enum Hash<'a> {
    SHA256([u8; 0x20]),
    SHA384([u8; 0x30]),
    SHA512([u8; 0x40]),
    EdDSA(&'a [u8]), // FIXME?
}

impl Hash<'_> {
    fn oid(&self) -> Option<&'static [u8]> {
        match self {
            Self::SHA256(_) =>
                Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
            Self::SHA384(_) =>
                Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]),
            Self::SHA512(_) =>
                Some(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]),
            Self::EdDSA(_) => None
        }
    }

    fn digest(&self) -> &[u8] {
        match self {
            Self::SHA256(d) => &d[..],
            Self::SHA384(d) => &d[..],
            Self::SHA512(d) => &d[..],
            Self::EdDSA(d) => d
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
pub enum Sex { NotKnown, Male, Female, NotApplicable }

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

/// Representation of an opened OpenPGP card, with default privileges (i.e.
/// no passwords have been verified)
pub struct OpenPGPCard {
    card: Card,

    // Cache of "application related data".
    //
    // FIXME: Should be invalidated when changing data on the card!
    // (e.g. uploading keys, etc)
    ard: Tlv,
}

impl OpenPGPCard {
    /// Get all cards that can be opened as an OpenPGP card applet
    pub fn list_cards() -> Result<Vec<Self>> {
        let cards = card::get_cards().map_err(|err| anyhow!(err))?;
        let ocs: Vec<_> = cards.into_iter().map(Self::open_card)
            .map(|oc| oc.ok()).flatten().collect();

        Ok(ocs)
    }

    /// Find an OpenPGP card by serial number and return it.
    pub fn open_by_serial(serial: &str) -> Result<Self, OpenpgpCardError> {
        let cards = card::get_cards()
            .map_err(|e| OpenpgpCardError::Smartcard(
                SmartcardError::Error(format!("{:?}", e))))?;

        for card in cards {
            let res = Self::open_card(card);
            if let Ok(opened_card) = res {
                let res = opened_card.get_aid();
                if let Ok(aid) = res {
                    if aid.serial() == serial {
                        return Ok(opened_card);
                    }
                }
            }
        }

        Err(OpenpgpCardError::Smartcard(SmartcardError::CardNotFound))
    }

    /// Open connection to some card and select the openpgp applet
    pub fn open_yolo() -> Result<Self, OpenpgpCardError> {
        let mut cards = card::get_cards()
            .map_err(|e| OpenpgpCardError::Smartcard(
                SmartcardError::Error(format!("{:?}", e))))?;

        // randomly use the first card in the list
        let card = cards.swap_remove(0);

        Self::open_card(card)
    }

    /// Open connection to a specific card and select the openpgp applet
    fn open_card(card: Card) -> Result<Self, OpenpgpCardError> {
        let select_openpgp = commands::select_openpgp();

        let resp =
            apdu::send_command(&card, select_openpgp, Le::Short, None)?;

        if resp.is_ok() {
            // read and cache "application related data"
            let ard = Self::get_app_data(&card)?;

            Ok(Self { card, ard })
        } else {
            Err(anyhow!("Couldn't open OpenPGP application").into())
        }
    }

    // --- application data ---

    /// Load "application related data".
    ///
    /// This is done once, after opening the OpenPGP card applet
    /// (the data is stored in the OpenPGPCard object).
    fn get_app_data(card: &Card) -> Result<Tlv> {
        let ad = commands::get_application_data();
        let resp = apdu::send_command(card, ad, Le::Short, None)?;
        let entry = TlvEntry::from(resp.data()?, true)?;

        log::trace!(" App data TlvEntry: {:x?}", entry);

        Ok(Tlv(Tag::from([0x6E]), entry))
    }

    pub fn get_aid(&self) -> Result<ApplicationId, OpenpgpCardError> {
        // get from cached "application related data"
        let aid = self.ard.find(&Tag::from([0x4F]));

        if let Some(aid) = aid {
            Ok(ApplicationId::try_from(&aid.serialize()[..])?)
        } else {
            Err(anyhow!("Couldn't get Application ID.").into())
        }
    }

    pub fn get_historical(&self) -> Result<Historical, OpenpgpCardError> {
        // get from cached "application related data"
        let hist = self.ard.find(&Tag::from([0x5F, 0x52]));

        if let Some(hist) = hist {
            log::debug!("Historical bytes: {:x?}", hist);
            Historical::from(&hist.serialize())
        } else {
            Err(anyhow!("Failed to get historical bytes.").into())
        }
    }

    pub fn get_extended_length_information(&self) -> Result<Option<ExtendedLengthInfo>> {
        // get from cached "application related data"
        let eli = self.ard.find(&Tag::from([0x7F, 0x66]));

        log::debug!("Extended length information: {:x?}", eli);

        if let Some(eli) = eli {
            // The card has returned extended length information
            Ok(Some(ExtendedLengthInfo::from(&eli.serialize()[..])?))
        } else {
            // The card didn't return this (optional) DO. That is ok.
            Ok(None)
        }
    }

    pub fn get_general_feature_management() -> Option<bool> {
        unimplemented!()
    }

    pub fn get_discretionary_data_objects() {
        unimplemented!()
    }

    pub fn get_extended_capabilities(&self) -> Result<ExtendedCap, OpenpgpCardError> {
        // get from cached "application related data"
        let ecap = self.ard.find(&Tag::from([0xc0]));

        if let Some(ecap) = ecap {
            Ok(ExtendedCap::try_from(&ecap.serialize()[..])?)
        } else {
            Err(anyhow!("Failed to get extended capabilities.").into())
        }
    }

    pub fn get_algorithm_attributes(&self, key_type: KeyType) -> Result<Algo> {
        // get from cached "application related data"
        let aa = self.ard.find(&Tag::from([key_type.get_algorithm_tag()]));

        if let Some(aa) = aa {
            Algo::try_from(&aa.serialize()[..])
        } else {
            Err(anyhow!("Failed to get algorithm attributes for {:?}.",
                key_type))
        }
    }

    pub fn get_pw_status_bytes() {
        unimplemented!()
    }

    pub fn get_fingerprints(&self) -> Result<KeySet<fingerprint::Fingerprint>, OpenpgpCardError> {
        // Get from cached "application related data"
        let fp = self.ard.find(&Tag::from([0xc5]));

        if let Some(fp) = fp {
            let fp = fingerprint::from(&fp.serialize())?;

            log::debug!("Fp: {:x?}", fp);

            Ok(fp)
        } else {
            Err(anyhow!("Failed to get fingerprints.").into())
        }
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
        let _eli = self.get_extended_length_information()?;

        // FIXME: figure out Le
        let resp = apdu::send_command(&self.card, commands::get_url(), Le::Long, Some(self))?;

        log::trace!(" final response: {:x?}, data len {}",
                    resp, resp.raw_data().len());

        Ok(String::from_utf8_lossy(resp.data()?).to_string())
    }

    // --- cardholder related data (65) ---
    pub fn get_cardholder_related_data(&self) -> Result<CardHolder> {
        let crd = commands::cardholder_related_data();
        let resp = apdu::send_command(&self.card, crd, Le::Short, Some(self))?;
        resp.check_ok()?;

        CardHolder::try_from(resp.data()?)
    }

    // --- security support template (7a) ---
    pub fn get_security_support_template(&self) -> Result<Tlv> {
        let sst = commands::get_security_support_template();

        let ext = self.get_extended_length_information()?.is_some();
        let ext = if ext { Le::Long } else { Le::Short };

        let resp = apdu::send_command(&self.card, sst, ext, Some(self))?;
        resp.check_ok()?;

        log::trace!(" final response: {:x?}, data len {}",
                    resp, resp.data()?.len());

        Tlv::try_from(resp.data()?)
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

        let resp = apdu::send_command(&self.card, commands::get_algo_list(), Le::Short, Some(self))?;
        resp.check_ok()?;

        let ai = AlgoInfo::try_from(resp.data()?)?;
        Ok(Some(ai))
    }

    // ----------

    /// Delete all state on this OpenPGP card
    pub fn factory_reset(&self) -> Result<()> {
        // send 4 bad requests to verify pw1
        // [apdu 00 20 00 81 08 40 40 40 40 40 40 40 40]
        for _ in 0..4 {
            let verify = commands::verify_pw1_81([0x40; 8].to_vec());
            let resp = apdu::send_command(&self.card, verify, Le::None, Some(self))?;
            if !(resp.status() == [0x69, 0x82]
                || resp.status() == [0x69, 0x83]) {
                return Err(anyhow!("Unexpected status for reset, at pw1."));
            }
        }

        // send 4 bad requests to verify pw3
        // [apdu 00 20 00 83 08 40 40 40 40 40 40 40 40]
        for _ in 0..4 {
            let verify = commands::verify_pw3([0x40; 8].to_vec());
            let resp = apdu::send_command(&self.card, verify, Le::None, Some(self))?;

            if !(resp.status() == [0x69, 0x82]
                || resp.status() == [0x69, 0x83]) {
                return Err(anyhow!("Unexpected status for reset, at pw3."));
            }
        }

        // terminate_df [apdu 00 e6 00 00]
        let term = commands::terminate_df();
        let resp = apdu::send_command(&self.card, term, Le::None, Some(self))?;
        resp.check_ok()?;

        // activate_file [apdu 00 44 00 00]
        let act = commands::activate_file();
        let resp = apdu::send_command(&self.card, act, Le::None, Some(self))?;
        resp.check_ok()?;

        // FIXME: does the connection need to be re-opened on some cards,
        // after reset?!

        Ok(())
    }

    pub fn verify_pw1_81(self, pin: &str)
                         -> Result<OpenPGPCardUser, OpenPGPCard> {
        assert!(pin.len() >= 6); // FIXME: Err

        let verify = commands::verify_pw1_81(pin.as_bytes().to_vec());
        let res =
            apdu::send_command(&self.card, verify, Le::None, Some(&self));

        if let Ok(resp) = res {
            if resp.is_ok() {
                return Ok(OpenPGPCardUser { oc: self });
            }
        }

        Err(self)
    }

    pub fn verify_pw1_82(self, pin: &str)
                         -> Result<OpenPGPCardUser, OpenPGPCard> {
        assert!(pin.len() >= 6); // FIXME: Err

        let verify = commands::verify_pw1_82(pin.as_bytes().to_vec());
        let res =
            apdu::send_command(&self.card, verify, Le::None, Some(&self));

        if let Ok(resp) = res {
            if resp.is_ok() {
                return Ok(OpenPGPCardUser { oc: self });
            }
        }

        Err(self)
    }

    pub fn verify_pw3(self, pin: &str) -> Result<OpenPGPCardAdmin, OpenPGPCard> {
        assert!(pin.len() >= 8); // FIXME: Err

        let verify = commands::verify_pw3(pin.as_bytes().to_vec());
        let res =
            apdu::send_command(&self.card, verify, Le::None, Some(&self));

        if let Ok(resp) = res {
            if resp.is_ok() {
                return Ok(OpenPGPCardAdmin { oc: self });
            }
        }

        Err(self)
    }
}


/// An OpenPGP card after successful verification of PW1 (needs to be split
/// further to model authentication for signing)
pub struct OpenPGPCardUser {
    oc: OpenPGPCard,
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardUser.
impl Deref for OpenPGPCardUser {
    type Target = OpenPGPCard;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

impl OpenPGPCardUser {
    /// Decrypt the ciphertext in `dm`, on the card.
    pub fn decrypt(&self, dm: DecryptMe)
                   -> Result<Vec<u8>, OpenpgpCardError> {
        match dm {
            DecryptMe::RSA(message) => {
                let mut data = vec![0x0];
                data.extend_from_slice(message);

                // Call the card to decrypt `data`
                self.pso_decipher(data)
            }
            DecryptMe::ECDH(eph) => {
                // External Public Key
                let epk = Tlv(Tag(vec![0x86]),
                              TlvEntry::S(eph.to_vec()));

                // Public Key DO
                let pkdo = Tlv(Tag(vec![0x7f, 0x49]),
                               TlvEntry::C(vec![epk]));

                // Cipher DO
                let cdo = Tlv(Tag(vec![0xa6]),
                              TlvEntry::C(vec![pkdo]));

                self.pso_decipher(cdo.serialize())
            }
        }
    }

    /// Run decryption operation on the smartcard
    /// (7.2.11 PSO: DECIPHER)
    pub(crate) fn pso_decipher(&self, data: Vec<u8>)
                               -> Result<Vec<u8>, OpenpgpCardError> {
        // The OpenPGP card is already connected and PW1 82 has been verified
        let dec_cmd = commands::decryption(data);
        let resp = apdu::send_command(&self.card, dec_cmd, Le::Short, Some(self))?;
        resp.check_ok()?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }


    /// Sign the message in `hash`, on the card.
    pub fn signature_for_hash(&self, hash: Hash)
                              -> Result<Vec<u8>, OpenpgpCardError> {
        match hash {
            Hash::SHA256(_) | Hash::SHA384(_) | Hash::SHA512(_) => {
                let tlv = Tlv(Tag(vec![0x30]),
                              TlvEntry::C(
                                  vec![Tlv(Tag(vec![0x30]),
                                           TlvEntry::C(
                                               vec![Tlv(Tag(vec![0x06]),
                                                        // unwrapping is
                                                        // ok, for SHA*
                                                        TlvEntry::S(hash.oid().unwrap().to_vec())),
                                                    Tlv(Tag(vec![0x05]), TlvEntry::S(vec![]))
                                               ])),
                                       Tlv(Tag(vec!(0x04)), TlvEntry::S(hash.digest().to_vec()))
                                  ]
                              ));

                Ok(self.compute_digital_signature(tlv.serialize())?)
            }
            Hash::EdDSA(d) => {
                Ok(self.compute_digital_signature(d.to_vec())?)
            }
        }
    }

    /// Run signing operation on the smartcard
    /// (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)
    pub(crate) fn compute_digital_signature(&self, data: Vec<u8>)
                                            -> Result<Vec<u8>, OpenpgpCardError> {
        let dec_cmd = commands::signature(data);

        let resp = apdu::send_command(&self.card, dec_cmd, Le::Short, Some(self))?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }
}


/// An OpenPGP card after successful verification of PW3
pub struct OpenPGPCardAdmin {
    oc: OpenPGPCard,
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardAdmin.
impl Deref for OpenPGPCardAdmin {
    type Target = OpenPGPCard;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

impl OpenPGPCardAdmin {
    pub(crate) fn card(&self) -> &Card {
        &self.card
    }

    pub fn set_name(&self, name: &str) -> Result<Response, OpenpgpCardError> {
        if name.len() >= 40 {
            return Err(anyhow!("name too long").into());
        }

        // All chars must be in ASCII7
        if name.chars().any(|c| !c.is_ascii()) {
            return Err(anyhow!("Invalid char in name").into());
        };

        let put_name = commands::put_name(name.as_bytes().to_vec());
        apdu::send_command(self.card(), put_name, Le::Short, Some(self))
    }

    pub fn set_lang(&self, lang: &str) -> Result<Response, OpenpgpCardError> {
        if lang.len() > 8 {
            return Err(anyhow!("lang too long").into());
        }

        let put_lang = commands::put_lang(lang.as_bytes().to_vec());
        apdu::send_command(self.card(), put_lang, Le::Short, Some(self))
    }

    pub fn set_sex(&self, sex: Sex) -> Result<Response, OpenpgpCardError> {
        let put_sex = commands::put_sex(sex.as_u8());
        apdu::send_command(self.card(), put_sex, Le::Short, Some(self))
    }

    pub fn set_url(&self, url: &str) -> Result<Response, OpenpgpCardError> {
        if url.chars().any(|c| !c.is_ascii()) {
            return Err(anyhow!("Invalid char in url").into());
        }

        // Check for max len
        let ec = self.get_extended_capabilities()?;

        if url.len() < ec.max_len_special_do as usize {
            let put_url = commands::put_url(url.as_bytes().to_vec());
            apdu::send_command(self.card(), put_url, Le::Short, Some(self))
        } else {
            Err(anyhow!("URL too long").into())
        }
    }

    pub fn upload_key(
        &self,
        key: Box<dyn CardUploadableKey>,
        key_type: KeyType,
    ) -> Result<(), OpenpgpCardError> {
        key_upload::upload_key(self, key, key_type)
    }
}


#[cfg(test)]
mod test {
    use super::tlv::{Tlv, TlvEntry};
    use super::tlv::tag::Tag;

    #[test]
    fn test_tlv() {
        let cpkt =
            Tlv(Tag(vec![0x7F, 0x48]),
                TlvEntry::S(vec![0x91, 0x03,
                                 0x92, 0x82, 0x01, 0x00,
                                 0x93, 0x82, 0x01, 0x00]));

        assert_eq!(cpkt.serialize(),
                   vec![0x7F, 0x48,
                        0x0A,
                        0x91, 0x03,
                        0x92, 0x82, 0x01, 0x00,
                        0x93, 0x82, 0x01, 0x00,
                   ]);
    }
}
