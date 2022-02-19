// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cardholder Related Data (see spec pg. 22)

use std::convert::TryFrom;

use anyhow::Result;

use crate::card_do::{CardholderRelatedData, Lang, Sex};
use crate::tlv::{value::Value, Tlv};

impl CardholderRelatedData {
    pub fn name(&self) -> Option<&[u8]> {
        self.name.as_deref()
    }

    pub fn lang(&self) -> Option<&[Lang]> {
        self.lang.as_deref()
    }

    pub fn sex(&self) -> Option<Sex> {
        self.sex
    }
}

impl TryFrom<&[u8]> for CardholderRelatedData {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let value = Value::from(data, true)?;
        let tlv = Tlv::new([0x65], value);

        let name: Option<Vec<u8>> = tlv.find(&[0x5b].into()).map(|v| v.serialize().to_vec());

        let lang: Option<Vec<Lang>> = tlv.find(&[0x5f, 0x2d].into()).map(|v| {
            v.serialize()
                .chunks(2)
                .map(|c| match c.len() {
                    2 => Lang::from(&[c[0], c[1]]),
                    1 => Lang::from(&[c[0]]),
                    _ => unreachable!(),
                })
                .collect()
        });

        let sex = tlv
            .find(&[0x5f, 0x35].into())
            .map(|v| v.serialize())
            .filter(|v| v.len() == 1)
            .map(|v| Sex::from(v[0]));

        Ok(CardholderRelatedData { name, lang, sex })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let data = [
            0x5b, 0x8, 0x42, 0x61, 0x72, 0x3c, 0x3c, 0x46, 0x6f, 0x6f, 0x5f, 0x2d, 0x4, 0x64, 0x65,
            0x65, 0x6e, 0x5f, 0x35, 0x1, 0x32,
        ];

        let ch = CardholderRelatedData::try_from(&data[..]).expect("failed to parse cardholder");

        assert_eq!(
            ch,
            CardholderRelatedData {
                name: Some("Bar<<Foo".as_bytes().to_vec()),
                lang: Some(vec![['d', 'e'].into(), ['e', 'n'].into()]),
                sex: Some(Sex::Female)
            }
        );
    }
}
