// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
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
//! use openpgp_card_pcsc::PcscBackend;
//! use openpgp_card::OpenPgp;
//! use openpgp_card_sequoia::card::Open;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! for mut card in PcscBackend::cards(None)? {
//!     let mut pgp = OpenPgp::new(&mut card);
//!     let mut open = Open::new(pgp.transaction()?)?;
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
//! use openpgp_card_pcsc::PcscBackend;
//! use openpgp_card::OpenPgp;
//! use openpgp_card_sequoia::card::Open;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut card = PcscBackend::open_by_ident("abcd:12345678", None)?;
//! let mut pgp = OpenPgp::new(&mut card);
//! let mut open = Open::new(pgp.transaction()?)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Use for cryptographic operations
//!
//! ## Decryption
//!
//! To use a card for decryption, it needs to be opened, user authorization
//! needs to be available. A `sequoia_openpgp::crypto::Decryptor`
//! implementation can then be obtained by providing a Cert (public key)
//! that corresponds to the private encryption key on the card:
//!
//! ```no_run
//! use openpgp_card_pcsc::PcscBackend;
//! use openpgp_card::OpenPgp;
//! use openpgp_card_sequoia::card::Open;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Open card via PCSC
//! use sequoia_openpgp::policy::StandardPolicy;
//! let mut card = PcscBackend::open_by_ident("abcd:12345678", None)?;
//! let mut pgp = OpenPgp::new(&mut card);
//! let mut open = Open::new(pgp.transaction()?)?;
//!
//! // Get authorization for user access to the card with password
//! open.verify_user(b"123456")?;
//! let mut user = open.user_card().expect("This should not fail");
//!
//! // Get decryptor
//! let decryptor = user.decryptor(&|| { println!("Touch confirmation needed for decryption") });
//!
//! // Perform decryption operation(s)
//! // ..
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Signing
//!
//! To use a card for signing, it needs to be opened, signing authorization
//! needs to be available. A `sequoia_openpgp::crypto::Signer`
//! implementation can then be obtained by providing a Cert (public key)
//! that corresponds to the private signing key on the card.
//!
//! (Note that by default, an OpenPGP Card will only allow one signing
//! operation to be performed after the password has been presented for
//! signing. Depending on the card's configuration you need to present the
//! user password before each signing operation!)
//!
//! ```no_run
//! use openpgp_card_pcsc::PcscBackend;
//! use openpgp_card::OpenPgp;
//! use openpgp_card_sequoia::card::Open;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Open card via PCSC
//! use sequoia_openpgp::policy::StandardPolicy;
//! let mut card = PcscBackend::open_by_ident("abcd:12345678", None)?;
//! let mut pgp = OpenPgp::new(&mut card);
//! let mut open = Open::new(pgp.transaction()?)?;
//!
//! // Get authorization for signing access to the card with password
//! open.verify_user_for_signing(b"123456")?;
//! let mut user = open.signing_card().expect("This should not fail");
//!
//! // Get signer
//! let signer = user.signer(&|| println!("Touch confirmation needed for signing"));
//!
//! // Perform signing operation(s)
//! // ..
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Setting up and configuring a card
//!
//! ```no_run
//! use openpgp_card_pcsc::PcscBackend;
//! use openpgp_card::OpenPgp;
//! use openpgp_card_sequoia::card::Open;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Open card via PCSC
//! let mut card = PcscBackend::open_by_ident("abcd:12345678", None)?;
//! let mut pgp = OpenPgp::new(&mut card);
//! let mut open = Open::new(pgp.transaction()?)?;
//!
//! // Get authorization for admin access to the card with password
//! open.verify_admin(b"12345678")?;
//! let mut admin = open.admin_card().expect("This should not fail");
//!
//! // Set the Name and URL fields on the card
//! admin.set_name("Bar<<Foo")?;
//! admin.set_url("https://example.org/openpgp.asc")?;
//!
//! # Ok(())
//! # }
//! ```

use openpgp::packet::{key, Key};
use sequoia_openpgp as openpgp;

pub mod card;
mod decryptor;
mod privkey;
mod signer;
pub mod sq_util;
pub mod util;

/// Shorthand for Sequoia public key data (a single public (sub)key)
pub type PublicKey = Key<key::PublicParts, key::UnspecifiedRole>;
