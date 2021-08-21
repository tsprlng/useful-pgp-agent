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

pub mod algorithm;
mod apdu;
mod card_app;
pub mod card_do;
pub mod crypto_data;
pub mod errors;
mod keys;
mod tlv;

pub use crate::apdu::response::Response;
pub use crate::card_app::CardApp;

/// The CardClient trait defines communication with an OpenPGP card via a
/// backend implementation (e.g. the pcsc backend in the crate
/// [openpgp-card-pcsc](https://crates.io/crates/openpgp-card-pcsc)).
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

/// A boxed CardClient (which is Send+Sync).
pub type CardClientBox = Box<dyn CardClient + Send + Sync>;

/// Configuration of the capabilities of the card.
///
/// This configuration is used to determine e.g. if chaining or extended
/// length can be used when communicating with the card.
///
/// (This configuration is retrieved from card metadata, specifically from
/// "Card Capabilities" and "Extended length information")
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
}

impl CardCaps {
    pub fn get_ext_support(&self) -> bool {
        self.ext_support
    }

    pub fn get_max_rsp_bytes(&self) -> u16 {
        self.max_rsp_bytes
    }
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
    fn get_algorithm_tag(&self) -> u8 {
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
    fn get_fingerprint_put_tag(&self) -> u8 {
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
    fn get_timestamp_put_tag(&self) -> u8 {
        use KeyType::*;

        match self {
            Signing => 0xCE,
            Decryption => 0xCF,
            Authentication => 0xD0,
            Attestation => 0xDD,
        }
    }
}
