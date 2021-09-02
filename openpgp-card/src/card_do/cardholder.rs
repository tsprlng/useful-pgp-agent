// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cardholder Related Data (see spec pg. 22)

use std::convert::TryFrom;

use anyhow::Result;

use crate::card_do::{Cardholder, Sex};
use crate::tlv::{value::Value, Tlv};

impl Cardholder {
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn lang(&self) -> Option<&[[char; 2]]> {
        self.lang.as_deref()
    }

    pub fn sex(&self) -> Option<Sex> {
        self.sex
    }
}

impl TryFrom<&[u8]> for Cardholder {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        let value = Value::from(data, true)?;
        let tlv = Tlv::new([0x65], value);

        let name: Option<String> = tlv
            .find(&[0x5b].into())
            .map(|v| String::from_utf8_lossy(&v.serialize()).to_string());

        let lang: Option<Vec<[char; 2]>> =
            tlv.find(&[0x5f, 0x2d].into()).map(|v| {
                v.serialize()
                    .chunks(2)
                    .map(|c| [c[0] as char, c[1] as char])
                    .collect()
            });

        let sex = tlv
            .find(&[0x5f, 0x35].into())
            .map(|v| v.serialize())
            .filter(|v| v.len() == 1)
            .map(|v| Sex::from(v[0]));

        Ok(Cardholder { name, lang, sex })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let data = [
            0x5b, 0x8, 0x42, 0x61, 0x72, 0x3c, 0x3c, 0x46, 0x6f, 0x6f, 0x5f,
            0x2d, 0x4, 0x64, 0x65, 0x65, 0x6e, 0x5f, 0x35, 0x1, 0x32,
        ];

        let ch = Cardholder::try_from(&data[..])
            .expect("failed to parse cardholder");

        assert_eq!(
            ch,
            Cardholder {
                name: Some("Bar<<Foo".to_string()),
                lang: Some(vec![['d', 'e'], ['e', 'n']]),
                sex: Some(Sex::Female)
            }
        );
    }
}
