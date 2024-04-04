// SPDX-FileCopyrightText: 2021-2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client library for
//! [OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card)
//! devices (such as Gnuk, Nitrokey, YubiKey, or Java smartcards running an
//! OpenPGP card application).
//!
//! This library aims to offer
//! - low-level access to all features in the OpenPGP
//! [card specification](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf)
//! via the [crate::openpgp] package,
//! - without relying on a particular
//! [OpenPGP implementation](https://www.openpgp.org/software/developer/).
//!
//! Note that this library can't directly access cards by itself.
//! Instead, users need to supply a backend that implements the
//! [`card_backend::CardBackend`] and [`card_backend::CardTransaction`] traits.
//! For example [card-backend-pcsc](https://crates.io/crates/card-backend-pcsc)
//! offers a backend implementation that uses [PC/SC](https://en.wikipedia.org/wiki/PC/SC) to
//! communicate with Smart Cards.
//!
//! See the [architecture diagram](https://gitlab.com/openpgp-card/openpgp-card#architecture)
//! for an overview of the ecosystem around this crate.

extern crate core;

mod errors;
pub mod openpgp;

pub use crate::errors::Error;
