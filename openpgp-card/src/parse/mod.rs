// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parsing of replies to GET DO requests.
//! Turn OpenPGP card replies into our own data structures.

pub mod algo_attrs;
pub mod algo_info;
pub mod application_id;
pub mod cardholder;
pub mod extended_cap;
pub mod extended_length_info;
pub mod fingerprint;
pub mod historical;
pub mod key_generation_times;
pub mod pw_status;

use crate::KeySet;
use anyhow::{anyhow, Error};

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

pub fn complete<O>(result: nom::IResult<&[u8], O>) -> Result<O, Error> {
    let (rem, output) =
        result.map_err(|err| anyhow!("Parsing failed: {:?}", err))?;
    if rem.is_empty() {
        Ok(output)
    } else {
        Err(anyhow!("Parsing incomplete -- trailing data: {:x?}", rem))
    }
}
