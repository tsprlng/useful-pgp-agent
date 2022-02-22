// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Access library for
//! [OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card)
//! devices (such as Gnuk, Yubikey, or Java smartcards running an OpenPGP
//! card application).
//!
//! This library aims to offer
//! - access to all features in the OpenPGP
//! [card specification](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf),
//! - without relying on a particular
//! [OpenPGP implementation](https://www.openpgp.org/software/developer/).
//!
//! This library can't directly access cards by itself. Instead, users
//! need to supply an implementation of the [`CardBackend`]
//! / [`CardTransaction`] traits, to access cards.
//!
//! The companion crate
//! [openpgp-card-pcsc](https://crates.io/crates/openpgp-card-pcsc)
//! offers a backend that uses [pcsclite](https://pcsclite.apdu.fr/) to
//! communicate with smartcards.
//!
//! The [openpgp-card-sequoia](https://crates.io/crates/openpgp-card-sequoia)
//! crate offers a higher level wrapper based on the
//! [Sequoia PGP](https://sequoia-pgp.org/) implementation.

pub mod algorithm;
pub(crate) mod apdu;
pub mod card_do;
pub mod crypto_data;
mod errors;
pub(crate) mod keys;
mod openpgp;
mod tlv;

pub use crate::errors::{Error, SmartcardError, StatusBytes};
pub use crate::openpgp::{OpenPgp, OpenPgpTransaction};

use anyhow::Result;
use std::convert::TryInto;
use std::ops::{Deref, DerefMut};

use crate::apdu::commands;
use crate::card_do::ApplicationRelatedData;
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
    fn pinpad_verify(&mut self, id: u8) -> Result<Vec<u8>>;

    /// Modify the PIN `id` via the reader pinpad
    fn pinpad_modify(&mut self, id: u8) -> Result<Vec<u8>>;

    /// Select the OpenPGP card application
    fn select(&mut self) -> Result<Vec<u8>, Error> {
        let select_openpgp = commands::select_openpgp();
        apdu::send_command(self, select_openpgp, false)?.try_into()
    }

    /// Get the "application related data" from the card.
    ///
    /// (This data should probably be cached in a higher layer. Some parts of
    /// it are needed regularly, and it does not usually change during
    /// normal use of a card.)
    fn application_related_data(&mut self) -> Result<ApplicationRelatedData> {
        let ad = commands::application_related_data();
        let resp = apdu::send_command(self, ad, true)?;
        let value = Value::from(resp.data()?, true)?;

        log::debug!(" ARD value: {:x?}", value);

        Ok(ApplicationRelatedData(Tlv::new(Tag::from([0x6E]), value)))
    }

    /// Get a CardApp based on a CardTransaction.
    ///
    /// It is expected that SELECT has already been performed on the card
    /// beforehand.
    ///
    /// This fn initializes the CardCaps by requesting
    /// application_related_data from the card, and setting the
    /// capabilities accordingly.
    fn initialize(&mut self) -> Result<()> {
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

        log::debug!("init_card_caps to: {:x?}", caps);

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
/// This configuration can is used to determine e.g. if chaining or extended
/// length can be used when communicating with the card.
///
/// CardCaps data is used internally and can be used by card backends, it is unlikely to be
/// useful for users of this library.
///
/// (The information is retrieved from card metadata, specifically from
/// "Card Capabilities", "Extended length information" and "PWStatus")
#[derive(Clone, Copy, Debug)]
pub struct CardCaps {
    /// Extended Lc and Le fields
    ext_support: bool,

    /// Command chaining
    chaining_support: bool,

    /// Maximum number of bytes in a command APDU
    max_cmd_bytes: u16,

    /// Maximum number of bytes in a response APDU
    max_rsp_bytes: u16,

    /// Maximum length of pw1
    pw1_max_len: u8,

    /// Maximum length of pw3
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

/// Identify a Key slot on an OpenPGP card
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyType {
    Signing,
    Decryption,
    Authentication,
    Attestation,
}

impl KeyType {
    /// Get C1/C2/C3/DA values for this KeyTypes, to use as Tag
    fn algorithm_tag(&self) -> u8 {
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
    fn fingerprint_put_tag(&self) -> u8 {
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
    fn timestamp_put_tag(&self) -> u8 {
        use KeyType::*;

        match self {
            Signing => 0xCE,
            Decryption => 0xCF,
            Authentication => 0xD0,
            Attestation => 0xDD,
        }
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
