// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenPGP card data objects (DO)

use anyhow::{anyhow, Error, Result};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::convert::TryInto;

use crate::algorithm::Algo;
use crate::errors::OpenpgpCardError;
use crate::tlv::Tlv;
use crate::KeyType;

mod algo_attrs;
mod algo_info;
mod application_id;
mod cardholder;
mod extended_cap;
mod extended_length_info;
mod fingerprint;
mod historical;
mod key_generation_times;
mod pw_status;

/// Application Related Data
///
/// The "application related data" DO contains a set of DOs.
/// This struct offers read access to these DOs.
///
/// Note that when any of the information in this DO changes on the card, you
/// need to read ApplicationRelatedData from the card again to receive the
/// current values.
pub struct ApplicationRelatedData(pub(crate) Tlv);

impl ApplicationRelatedData {
    /// Application identifier (AID), ISO 7816-4
    pub fn get_application_id(
        &self,
    ) -> Result<ApplicationId, OpenpgpCardError> {
        // get from cached "application related data"
        let aid = self.0.find(&[0x4f].into());

        if let Some(aid) = aid {
            Ok(ApplicationId::try_from(&aid.serialize()[..])?)
        } else {
            Err(anyhow!("Couldn't get Application ID.").into())
        }
    }

    /// Historical bytes
    pub fn get_historical(&self) -> Result<Historical, OpenpgpCardError> {
        // get from cached "application related data"
        let hist = self.0.find(&[0x5f, 0x52].into());

        if let Some(hist) = hist {
            log::debug!("Historical bytes: {:x?}", hist);
            (hist.serialize().as_slice()).try_into()
        } else {
            Err(anyhow!("Failed to get historical bytes.").into())
        }
    }

    /// Extended length information (ISO 7816-4) with maximum number of
    /// bytes for command and response.
    pub fn get_extended_length_information(
        &self,
    ) -> Result<Option<ExtendedLengthInfo>> {
        // get from cached "application related data"
        let eli = self.0.find(&[0x7f, 0x66].into());

        log::debug!("Extended length information: {:x?}", eli);

        if let Some(eli) = eli {
            // The card has returned extended length information
            Ok(Some(ExtendedLengthInfo::from(&eli.serialize()[..])?))
        } else {
            // The card didn't return this (optional) DO. That is ok.
            Ok(None)
        }
    }

    fn get_general_feature_management() -> Option<bool> {
        unimplemented!()
    }

    fn get_discretionary_data_objects() {
        unimplemented!()
    }

    /// Extended Capabilities
    pub fn get_extended_capabilities(
        &self,
    ) -> Result<ExtendedCap, OpenpgpCardError> {
        // get from cached "application related data"
        let ecap = self.0.find(&[0xc0].into());

        if let Some(ecap) = ecap {
            Ok(ExtendedCap::try_from(&ecap.serialize()[..])?)
        } else {
            Err(anyhow!("Failed to get extended capabilities.").into())
        }
    }

    /// Algorithm attributes (for each key type)
    pub fn get_algorithm_attributes(&self, key_type: KeyType) -> Result<Algo> {
        // get from cached "application related data"
        let aa = self.0.find(&[key_type.get_algorithm_tag()].into());

        if let Some(aa) = aa {
            Algo::try_from(&aa.serialize()[..])
        } else {
            Err(anyhow!(
                "Failed to get algorithm attributes for {:?}.",
                key_type
            ))
        }
    }

    /// PW status Bytes
    pub fn get_pw_status_bytes(&self) -> Result<PWStatus> {
        // get from cached "application related data"
        let psb = self.0.find(&[0xc4].into());

        if let Some(psb) = psb {
            let pws = PWStatus::try_from(&psb.serialize())?;

            log::debug!("PW Status: {:x?}", pws);

            Ok(pws)
        } else {
            Err(anyhow!("Failed to get PW status Bytes."))
        }
    }

    /// Fingerprint, per key type.
    /// Zero bytes indicate a not defined private key.
    pub fn get_fingerprints(
        &self,
    ) -> Result<KeySet<Fingerprint>, OpenpgpCardError> {
        // Get from cached "application related data"
        let fp = self.0.find(&[0xc5].into());

        if let Some(fp) = fp {
            let fp = fingerprint::to_keyset(&fp.serialize())?;

            log::debug!("Fp: {:x?}", fp);

            Ok(fp)
        } else {
            Err(anyhow!("Failed to get fingerprints.").into())
        }
    }

    /// Generation dates/times of key pairs
    pub fn get_key_generation_times(
        &self,
    ) -> Result<KeySet<KeyGenerationTime>, OpenpgpCardError> {
        let kg = self.0.find(&[0xcd].into());

        if let Some(kg) = kg {
            let kg = key_generation_times::from(&kg.serialize())?;

            log::debug!("Key generation: {:x?}", kg);

            Ok(kg)
        } else {
            Err(anyhow!("Failed to get key generation times.").into())
        }
    }
}

#[derive(Debug)]
pub struct SecuritySupportTemplate {
    // Digital signature counter [3 bytes]
    // (counts usage of Compute Digital Signature command)
    pub(crate) dsc: u32,
}

impl SecuritySupportTemplate {
    pub fn get_signature_count(&self) -> u32 {
        self.dsc
    }
}

/// An OpenPGP key generation Time
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct KeyGenerationTime(u32);

impl KeyGenerationTime {
    pub fn get(&self) -> u32 {
        self.0
    }
}

/// Application identifier (AID)
#[derive(Debug, Eq, PartialEq)]
pub struct ApplicationId {
    application: u8,
    version: u16,
    manufacturer: u16,
    serial: u32,
}

/// Card Capabilities (73)
#[derive(Debug, PartialEq)]
pub struct CardCapabilities {
    command_chaining: bool,
    extended_lc_le: bool,
    extended_length_information: bool,
}

/// Card service data (31)
#[derive(Debug, PartialEq)]
pub struct CardServiceData {
    select_by_full_df_name: bool,
    select_by_partial_df_name: bool,
    dos_available_in_ef_dir: bool,
    dos_available_in_ef_atr_info: bool,
    access_services: [bool; 3],
    mf: bool,
}

/// Historical Bytes
#[derive(Debug, PartialEq)]
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
    features: HashSet<Features>,
    sm_algo: u8,
    max_len_challenge: u16,
    max_len_cardholder_cert: u16,
    max_len_special_do: u16,
    pin_block_2_format_support: bool,
    mse_command_support: bool,
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
    max_command_bytes: u16,
    max_response_bytes: u16,
}

/// Cardholder Related Data
#[derive(Debug)]
pub struct Cardholder {
    name: Option<String>,
    lang: Option<Vec<[char; 2]>>,
    sex: Option<Sex>,
}

/// Sex (according to ISO 5218)
#[derive(Debug, PartialEq, Clone, Copy)]
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
    pub(crate) pw1_pin_block: bool,
    pub(crate) pw1_len: u8,
    pub(crate) rc_len: u8,
    pub(crate) pw3_pin_block: bool,
    pub(crate) pw3_len: u8,
    pub(crate) err_count_pw1: u8,
    pub(crate) err_count_rst: u8,
    pub(crate) err_count_pw3: u8,
}

impl PWStatus {
    pub fn set_pw1_cds_multi(&mut self, val: bool) {
        self.pw1_cds_multi = val;
    }
    pub fn set_pw1_pin_block(&mut self, val: bool) {
        self.pw1_pin_block = val;
    }
    pub fn set_pw3_pin_block(&mut self, val: bool) {
        self.pw3_pin_block = val;
    }
}

/// Fingerprint
#[derive(Clone, Eq, PartialEq)]
pub struct Fingerprint([u8; 20]);

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

/// nom parsing helper
pub(crate) fn complete<O>(result: nom::IResult<&[u8], O>) -> Result<O, Error> {
    let (rem, output) =
        result.map_err(|err| anyhow!("Parsing failed: {:?}", err))?;
    if rem.is_empty() {
        Ok(output)
    } else {
        Err(anyhow!("Parsing incomplete -- trailing data: {:x?}", rem))
    }
}
