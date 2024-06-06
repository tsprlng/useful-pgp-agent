// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod cardslot;
mod privkey;
mod rpgp;

use std::fmt::Debug;

pub use cardslot::CardSlot;
pub use privkey::UploadableKey;
pub use rpgp::{
    fp_from_pub, make_certificate, public_key_material_and_fp_to_key, public_key_material_to_key,
};

/// Enum wrapper for the error types of this crate
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("rPGP error: {0}")]
    Rpgp(pgp::errors::Error),

    #[error("OpenPGP card error: {0}")]
    Ocard(openpgp_card::Error),

    #[error("Internal error: {0}")]
    Message(String),
}

impl From<pgp::errors::Error> for Error {
    fn from(value: pgp::errors::Error) -> Self {
        Error::Rpgp(value)
    }
}

impl From<openpgp_card::Error> for Error {
    fn from(value: openpgp_card::Error) -> Self {
        Error::Ocard(value)
    }
}
