// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;

use anyhow::Result;

use crate::card_do::{Cardholder, Sex};
use crate::tlv::tag::Tag;
use crate::tlv::{Tlv, TlvEntry};

impl TryFrom<&[u8]> for Cardholder {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let entry = TlvEntry::from(data, true)?;
        let tlv = Tlv(Tag(vec![0x65]), entry);

        let name: Option<String> = tlv
            .find(&Tag::from(&[0x5b][..]))
            .map(|v| String::from_utf8_lossy(&v.serialize()).to_string());

        let lang: Option<Vec<[char; 2]>> =
            tlv.find(&Tag::from(&[0x5f, 0x2d][..])).map(|v| {
                v.serialize()
                    .chunks(2)
                    .map(|c| [c[0] as char, c[1] as char])
                    .collect()
            });

        let sex = tlv
            .find(&Tag::from(&[0x5f, 0x35][..]))
            .map(|v| v.serialize())
            .filter(|v| v.len() == 1)
            .map(|v| Sex::from(v[0]));

        Ok(Cardholder { name, lang, sex })
    }
}
