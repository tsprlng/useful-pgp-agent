// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A higher-level wrapper around the openpgp-card crate.
//! It uses sequoia_openpgp for OpenPGP operations.
//!
//! # Backends
//!
//! To make use of this crate, you need to use a backend for communication
//! with cards. The suggested default backend is `openpgp-card-pcsc`.
//!
//! With `openpgp-card-pcsc` you can either open all available cards:
//!
//! ```no_run
//! use openpgp_card_pcsc::PcscClient;
//! use openpgp_card_sequoia::card::Open;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! for card in PcscClient::cards()? {
//!     let open = Open::open_card(card)?;
//!     println!("Found OpenPGP card with ident '{}'",
//!              open.application_identifier()?.ident());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Or you can open one particular card, by ident:
//!
//! ```no_run
//! use openpgp_card_pcsc::PcscClient;
//! use openpgp_card_sequoia::card::Open;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let card = PcscClient::open_by_ident("abcd:12345678")?;
//! let open = Open::open_card(card)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Use for cryptographic operations
//!
//! # Setting up and configuring a card
//!

use openpgp::packet::{key, Key};
use sequoia_openpgp as openpgp;

pub mod card;
mod decryptor;
mod privkey;
mod signer;
pub mod sq_util;
pub mod util;

/// Shorthand for Sequoia public key data (a single public (sub)key)
pub(crate) type PublicKey = Key<key::PublicParts, key::UnspecifiedRole>;
