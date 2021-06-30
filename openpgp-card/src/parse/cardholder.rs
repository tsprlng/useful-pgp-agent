// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;

use anyhow::Result;

use crate::Sex;
use crate::tlv::tag::Tag;
use crate::tlv::{TlvEntry, Tlv};

#[derive(Debug)]
pub struct CardHolder {
    pub name: Option<String>,
    pub lang: Option<Vec<[char; 2]>>,
    pub sex: Option<Sex>,
}

impl TryFrom<&[u8]> for CardHolder {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let entry = TlvEntry::from(&data, true)?;
        let tlv = Tlv(Tag(vec![0x65]), entry);

        let name: Option<String> = tlv.find(&Tag::from(&[0x5b][..]))
            .map(|v| String::from_utf8_lossy(&v.serialize()).to_string());

        let lang: Option<Vec<[char; 2]>> = tlv
            .find(&Tag::from(&[0x5f, 0x2d][..]))
            .map(|v| v.serialize().chunks(2)
                .map(|c| [c[0] as char, c[1] as char]).collect()
            );

        let sex = tlv
            .find(&Tag::from(&[0x5f, 0x35][..]))
            .map(|v| v.serialize())
            .filter(|v| v.len() == 1)
            .map(|v| Sex::from(v[0]));

        Ok(CardHolder { name, lang, sex })
    }
}
