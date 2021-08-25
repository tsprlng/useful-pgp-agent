// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::anyhow;
use nom::{bytes::complete as bytes, combinator, sequence};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;

use crate::card_do::{Fingerprint, KeySet};
use crate::errors::OpenpgpCardError;

impl From<[u8; 20]> for Fingerprint {
    fn from(data: [u8; 20]) -> Self {
        Self(data)
    }
}

impl TryFrom<&[u8]> for Fingerprint {
    type Error = OpenpgpCardError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        log::trace!(
            "Fingerprint from input: {:x?}, len {}",
            input,
            input.len()
        );

        // FIXME: return error
        assert_eq!(input.len(), 20);

        let array: [u8; 20] = input.try_into().unwrap();
        Ok(array.into())
    }
}

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", self)
    }
}

impl fmt::UpperHex for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Fingerprint")
            .field(&self.to_string())
            .finish()
    }
}

fn fingerprint(input: &[u8]) -> nom::IResult<&[u8], Option<Fingerprint>> {
    combinator::map(bytes::take(20u8), |i: &[u8]| {
        if i.iter().any(|&c| c > 0) {
            use std::convert::TryInto;
            // We requested 20 bytes, so we can unwrap here
            let i: [u8; 20] = i.try_into().unwrap();
            Some(i.into())
        } else {
            None
        }
    })(input)
}

fn fingerprints(input: &[u8]) -> nom::IResult<&[u8], KeySet<Fingerprint>> {
    combinator::into(sequence::tuple((fingerprint, fingerprint, fingerprint)))(
        input,
    )
}

/// Parse three fingerprints from the card into a KeySet of Fingerprints
pub(crate) fn to_keyset(
    input: &[u8],
) -> Result<KeySet<Fingerprint>, OpenpgpCardError> {
    log::trace!("Fingerprint from input: {:x?}, len {}", input, input.len());

    // The input may be longer than 3 fingerprint, don't fail if it hasn't
    // been completely consumed.
    self::fingerprints(input)
        .map(|res| res.1)
        .map_err(|err| anyhow!("Parsing failed: {:?}", err))
        .map_err(OpenpgpCardError::InternalError)
}
