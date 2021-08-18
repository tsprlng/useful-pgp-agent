// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use nom::{bytes::complete as bytes, number::complete as number};
use std::convert::TryFrom;

use crate::{parse, ApplicationId};

fn parse(input: &[u8]) -> nom::IResult<&[u8], ApplicationId> {
    let (input, _) = bytes::tag([0xd2, 0x76, 0x0, 0x1, 0x24])(input)?;

    let (input, application) = number::u8(input)?;
    let (input, version) = number::be_u16(input)?;
    let (input, manufacturer) = number::be_u16(input)?;
    let (input, serial) = number::be_u32(input)?;

    let (input, _) =
        nom::combinator::all_consuming(bytes::tag([0x0, 0x0]))(input)?;

    Ok((
        input,
        ApplicationId {
            application,
            version,
            manufacturer,
            serial,
        },
    ))
}

impl TryFrom<&[u8]> for ApplicationId {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        parse::complete(parse(data))
    }
}

impl ApplicationId {
    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn manufacturer(&self) -> u16 {
        self.manufacturer
    }

    /// This ident is constructed as the concatenation of manufacturer
    /// id, a colon, and the card serial (in hexadecimal representation).
    ///
    /// It is a more easily human-readable, shorter form of the full
    /// 16-byte AID ("Application Identifier").
    ///
    /// Example: "1234:5678ABCD".
    pub fn ident(&self) -> String {
        format!("{:04X}:{:08X}", self.manufacturer, self.serial)
    }
}
