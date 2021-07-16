// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::anyhow;
use chrono::{DateTime, NaiveDateTime, Utc};
use nom::{combinator, number::complete as number, sequence};

use crate::errors::OpenpgpCardError;
use crate::parse::KeySet;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct KeyGeneration(u32);

impl From<KeyGeneration> for DateTime<Utc> {
    fn from(kg: KeyGeneration) -> Self {
        let naive_datetime = NaiveDateTime::from_timestamp(kg.0 as i64, 0);

        DateTime::from_utc(naive_datetime, Utc)
    }
}

impl From<&KeyGeneration> for u32 {
    fn from(kg: &KeyGeneration) -> Self {
        kg.0
    }
}

impl From<u32> for KeyGeneration {
    fn from(data: u32) -> Self {
        Self(data)
    }
}

fn gen_time(input: &[u8]) -> nom::IResult<&[u8], u32> {
    (number::be_u32)(input)
}

fn key_generation(input: &[u8]) -> nom::IResult<&[u8], Option<KeyGeneration>> {
    combinator::map(gen_time, |kg| match kg {
        0 => None,
        kg => Some(KeyGeneration(kg)),
    })(input)
}

fn key_generation_set(
    input: &[u8],
) -> nom::IResult<&[u8], KeySet<KeyGeneration>> {
    combinator::into(sequence::tuple((
        key_generation,
        key_generation,
        key_generation,
    )))(input)
}

pub fn from(input: &[u8]) -> Result<KeySet<KeyGeneration>, OpenpgpCardError> {
    // List of generation dates/times of key pairs, binary.
    // 4 bytes, Big Endian each for Sig, Dec and Aut. Each
    // value shall be seconds since Jan 1, 1970. Default
    // value is 00000000 (not specified).

    log::trace!(
        "Key generation times from input: {:x?}, len {}",
        input,
        input.len()
    );

    // The input may be longer than 3 key generation times, don't fail if it
    // hasn't been completely consumed.
    self::key_generation_set(input)
        .map(|res| res.1)
        .map_err(|err| anyhow!("Parsing failed: {:?}", err))
        .map_err(OpenpgpCardError::InternalError)
}
