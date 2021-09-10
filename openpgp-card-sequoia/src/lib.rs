// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A higher-level wrapper around the openpgp-card crate.
//! It uses sequoia_openpgp for OpenPGP operations.

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
