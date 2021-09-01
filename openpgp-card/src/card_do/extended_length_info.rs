// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! 4.1.3.1 Extended length information

use anyhow::Result;
use nom::{bytes::complete::tag, number::complete as number, sequence};

use crate::card_do::{complete, ExtendedLengthInfo};

fn parse(input: &[u8]) -> nom::IResult<&[u8], (u16, u16)> {
    let (input, (_, cmd, _, resp)) =
        nom::combinator::all_consuming(sequence::tuple((
            tag([0x2, 0x2]),
            number::be_u16,
            tag([0x2, 0x2]),
            number::be_u16,
        )))(input)?;

    Ok((input, (cmd, resp)))
}

impl ExtendedLengthInfo {
    pub fn max_command_bytes(&self) -> u16 {
        self.max_command_bytes
    }

    pub fn max_response_bytes(&self) -> u16 {
        self.max_response_bytes
    }

    pub fn from(input: &[u8]) -> Result<Self> {
        let eli = complete(parse(input))?;

        Ok(Self {
            max_command_bytes: eli.0,
            max_response_bytes: eli.1,
        })
    }
}
