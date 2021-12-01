// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenPGP card data objects (DO)

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::time::{Duration, UNIX_EPOCH};

use crate::{algorithm::Algo, tlv::Tlv, Error, KeySet, KeyType};

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

/// 4.4.3.1 Application Related Data
///
/// The "application related data" DO contains a set of DOs.
/// This struct offers read access to these DOs.
///
/// (Note: when any of the information in this DO changes on the card, you
/// need to re-read ApplicationRelatedData from the card to receive the
/// new values!)
pub struct ApplicationRelatedData(pub(crate) Tlv);

impl ApplicationRelatedData {
    /// Get application identifier (AID), ISO 7816-4
    pub fn application_id(&self) -> Result<ApplicationIdentifier, Error> {
        // get from cached "application related data"
        let aid = self.0.find(&[0x4f].into());

        if let Some(aid) = aid {
            Ok(ApplicationIdentifier::try_from(&aid.serialize()[..])?)
        } else {
            Err(anyhow!("Couldn't get Application ID.").into())
        }
    }

    /// Get historical bytes
    pub fn historical_bytes(&self) -> Result<HistoricalBytes, Error> {
        // get from cached "application related data"
        let hist = self.0.find(&[0x5f, 0x52].into());

        if let Some(hist) = hist {
            log::debug!("Historical bytes: {:x?}", hist);
            (hist.serialize().as_slice()).try_into()
        } else {
            Err(anyhow!("Failed to get historical bytes.").into())
        }
    }

    /// Get extended length information (ISO 7816-4), which
    /// contains maximum number of bytes for command and response.
    pub fn extended_length_information(
        &self,
    ) -> Result<Option<ExtendedLengthInfo>> {
        // get from cached "application related data"
        let eli = self.0.find(&[0x7f, 0x66].into());

        log::debug!("Extended length information: {:x?}", eli);

        if let Some(eli) = eli {
            // The card has returned extended length information
            Ok(Some((&eli.serialize()[..]).try_into()?))
        } else {
            // The card didn't return this (optional) DO. That is ok.
            Ok(None)
        }
    }

    #[allow(dead_code)]
    fn general_feature_management() -> Option<bool> {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn discretionary_data_objects() {
        unimplemented!()
    }

    /// Get extended Capabilities
    pub fn extended_capabilities(
        &self,
    ) -> Result<ExtendedCapabilities, Error> {
        // FIXME: caching?
        let app_id = self.application_id()?;
        let version = app_id.version();

        // get from cached "application related data"
        let ecap = self.0.find(&[0xc0].into());

        if let Some(ecap) = ecap {
            Ok(ExtendedCapabilities::try_from((
                &ecap.serialize()[..],
                version,
            ))?)
        } else {
            Err(anyhow!("Failed to get extended capabilities.").into())
        }
    }

    /// Get algorithm attributes (for each key type)
    pub fn algorithm_attributes(&self, key_type: KeyType) -> Result<Algo> {
        // get from cached "application related data"
        let aa = self.0.find(&[key_type.algorithm_tag()].into());

        if let Some(aa) = aa {
            Algo::try_from(&aa.serialize()[..])
        } else {
            Err(anyhow!(
                "Failed to get algorithm attributes for {:?}.",
                key_type
            ))
        }
    }

    /// Get PW status Bytes
    pub fn pw_status_bytes(&self) -> Result<PWStatusBytes> {
        // get from cached "application related data"
        let psb = self.0.find(&[0xc4].into());

        if let Some(psb) = psb {
            let pws = (&psb.serialize()[..]).try_into()?;

            log::debug!("PW Status: {:x?}", pws);

            Ok(pws)
        } else {
            Err(anyhow!("Failed to get PW status Bytes."))
        }
    }

    /// Fingerprint, per key type.
    /// Zero bytes indicate a not defined private key.
    pub fn fingerprints(&self) -> Result<KeySet<Fingerprint>, Error> {
        // Get from cached "application related data"
        let fp = self.0.find(&[0xc5].into());

        if let Some(fp) = fp {
            let fp: KeySet<Fingerprint> = (&fp.serialize()[..]).try_into()?;

            log::debug!("Fp: {:x?}", fp);

            Ok(fp)
        } else {
            Err(anyhow!("Failed to get fingerprints.").into())
        }
    }

    /// Generation dates/times of key pairs
    pub fn key_generation_times(
        &self,
    ) -> Result<KeySet<KeyGenerationTime>, Error> {
        let kg = self.0.find(&[0xcd].into());

        if let Some(kg) = kg {
            let kg: KeySet<KeyGenerationTime> =
                (&kg.serialize()[..]).try_into()?;

            log::debug!("Key generation: {:x?}", kg);

            Ok(kg)
        } else {
            Err(anyhow!("Failed to get key generation times.").into())
        }
    }
}

/// Security support template (see spec pg. 24)
#[derive(Debug)]
pub struct SecuritySupportTemplate {
    // Digital signature counter [3 bytes]
    // (counts usage of Compute Digital Signature command)
    pub(crate) dsc: u32,
}

impl SecuritySupportTemplate {
    pub fn signature_count(&self) -> u32 {
        self.dsc
    }
}

/// An OpenPGP key generation Time (see spec pg. 24)
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct KeyGenerationTime(u32);

impl KeyGenerationTime {
    pub fn get(&self) -> u32 {
        self.0
    }

    pub fn formatted(&self) -> String {
        let d = UNIX_EPOCH + Duration::from_secs(self.get() as u64);
        let datetime = DateTime::<Utc>::from(d);

        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    }
}

/// 4.2.1 Application Identifier (AID)
#[derive(Debug, Eq, PartialEq)]
pub struct ApplicationIdentifier {
    application: u8,
    version: u16,
    manufacturer: u16,
    serial: u32,
}

/// 6 Historical Bytes
#[derive(Debug, PartialEq)]
pub struct HistoricalBytes {
    /// category indicator byte
    cib: u8,

    /// Card service data (31)
    csd: Option<CardServiceData>,

    /// Card Capabilities (73)
    cc: Option<CardCapabilities>,

    /// status indicator byte (o-card 3.4.1, pg 44)
    sib: u8,
}

/// Card Capabilities (see 6 Historical Bytes)
#[derive(Debug, PartialEq)]
pub struct CardCapabilities {
    command_chaining: bool,
    extended_lc_le: bool,
    extended_length_information: bool,
}

/// Card service data (see 6 Historical Bytes
#[derive(Debug, PartialEq)]
pub struct CardServiceData {
    select_by_full_df_name: bool,
    select_by_partial_df_name: bool,
    dos_available_in_ef_dir: bool,
    dos_available_in_ef_atr_info: bool,
    access_services: [bool; 3],
    mf: bool,
}

/// 4.4.3.7 Extended Capabilities
#[derive(Debug, Eq, PartialEq)]
pub struct ExtendedCapabilities {
    secure_messaging: bool,
    get_challenge: bool,
    key_import: bool,
    pw_status_change: bool,
    private_use_dos: bool,
    algo_attrs_changeable: bool,
    aes: bool,
    kdf_do: bool,

    sm_algo: u8,
    max_len_challenge: u16,
    max_len_cardholder_cert: u16,

    max_cmd_len: Option<u16>,  // v2
    max_resp_len: Option<u16>, // v2

    max_len_special_do: Option<u16>, // v3
    pin_block_2_format_support: Option<bool>, // v3
    mse_command_support: Option<bool>, // v3
}

/// 4.1.3.1 Extended length information
#[derive(Debug, Eq, PartialEq)]
pub struct ExtendedLengthInfo {
    max_command_bytes: u16,
    max_response_bytes: u16,
}

/// Cardholder Related Data (see spec pg. 22)
#[derive(Debug, PartialEq)]
pub struct CardholderRelatedData {
    name: Option<String>,
    lang: Option<Vec<[char; 2]>>,
    sex: Option<Sex>,
}

/// 4.4.3.5 Sex (according to ISO 5218)
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

/// PW status Bytes (see spec page 23)
#[derive(Debug, PartialEq)]
pub struct PWStatusBytes {
    pub(crate) pw1_cds_valid_once: bool,
    pub(crate) pw1_pin_block: bool,
    pub(crate) pw1_len_format: u8,
    pub(crate) rc_len: u8,
    pub(crate) pw3_pin_block: bool,
    pub(crate) pw3_len_format: u8,
    pub(crate) err_count_pw1: u8,
    pub(crate) err_count_rst: u8,
    pub(crate) err_count_pw3: u8,
}

impl PWStatusBytes {
    /// Set format of PW1:
    /// `false` for UTF-8 or derived password,
    /// `true` for PIN block format 2.
    pub fn set_pw1_pin_block(&mut self, val: bool) {
        self.pw1_pin_block = val;
    }

    /// Set format of PW3:
    /// `false` for UTF-8 or derived password,
    /// `true` for PIN block format 2.
    pub fn set_pw3_pin_block(&mut self, val: bool) {
        self.pw3_pin_block = val;
    }

    /// Is PW1 (no. 81) only valid for one PSO:CDS command?
    pub fn pw1_cds_valid_once(&self) -> bool {
        self.pw1_cds_valid_once
    }

    /// Configure if PW1 (no. 81) is only valid for one PSO:CDS command.
    pub fn set_pw1_cds_valid_once(&mut self, val: bool) {
        self.pw1_cds_valid_once = val;
    }

    /// Max length of PW1
    pub fn pw1_max_len(&self) -> u8 {
        self.pw1_len_format & 0x7f
    }

    /// Max length of Resetting Code (RC) for PW1
    pub fn rc_max_len(&self) -> u8 {
        self.rc_len
    }

    /// Max length of PW3
    pub fn pw3_max_len(&self) -> u8 {
        self.pw3_len_format & 0x7f
    }

    /// Error counter of PW1 (if 0, then PW1 is blocked).
    pub fn err_count_pw1(&self) -> u8 {
        self.err_count_pw1
    }

    /// Error counter of Resetting Code (RC) (if 0, then RC is blocked).
    pub fn err_count_rc(&self) -> u8 {
        self.err_count_rst
    }

    /// Error counter of PW3 (if 0, then PW3 is blocked).
    pub fn err_count_pw3(&self) -> u8 {
        self.err_count_pw3
    }
}

/// Fingerprint (see spec pg. 23)
#[derive(Clone, Eq, PartialEq)]
pub struct Fingerprint([u8; 20]);

impl Fingerprint {
    pub fn to_spaced_hex(&self) -> String {
        let mut fp = String::new();

        for i in 0..20 {
            fp.push_str(&format!("{:02X}", self.0[i]));

            if i < 19 && (i % 2 == 1) {
                fp.push(' ');
            }
            if i == 9 {
                fp.push(' ');
            }
        }

        fp
    }
}

/// Helper fn for nom parsing
pub(crate) fn complete<O>(
    result: nom::IResult<&[u8], O>,
) -> Result<O, anyhow::Error> {
    let (rem, output) =
        result.map_err(|err| anyhow!("Parsing failed: {:?}", err))?;
    if rem.is_empty() {
        Ok(output)
    } else {
        Err(anyhow!("Parsing incomplete -- trailing data: {:x?}", rem))
    }
}
