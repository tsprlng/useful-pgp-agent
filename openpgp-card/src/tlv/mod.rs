// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use nom::{bytes::complete as bytes, combinator};

// mod value;
pub mod length;
pub mod tag;

use crate::card_data::complete;
use tag::Tag;

#[derive(Debug, Eq, PartialEq)]
pub struct Tlv(pub Tag, pub TlvEntry);

impl Tlv {
    pub fn find(&self, tag: &Tag) -> Option<&TlvEntry> {
        if &self.0 == tag {
            Some(&self.1)
        } else {
            if let TlvEntry::C(inner) = &self.1 {
                for tlv in inner {
                    let found = tlv.find(tag);
                    if found.is_some() {
                        return found;
                    }
                }
            }
            None
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let value = self.1.serialize();
        let length = crate::tlv::tlv_encode_length(value.len() as u16);

        let mut ser = Vec::new();
        ser.extend(self.0 .0.iter());
        ser.extend(length.iter());
        ser.extend(value.iter());
        ser
    }

    fn parse(input: &[u8]) -> nom::IResult<&[u8], Tlv> {
        // read tag
        let (input, tag) = tag::tag(input)?;

        let (input, value) =
            combinator::flat_map(length::length, bytes::take)(input)?;

        let (_, entry) = TlvEntry::parse(value, tag.is_constructed())?;

        Ok((input, Self(tag, entry)))
    }

    pub fn try_from(input: &[u8]) -> Result<Self> {
        complete(Tlv::parse(input))
    }
}

pub fn tlv_encode_length(len: u16) -> Vec<u8> {
    if len > 255 {
        vec![0x82, (len >> 8) as u8, (len & 255) as u8]
    } else if len > 127 {
        vec![0x81, len as u8]
    } else {
        vec![len as u8]
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum TlvEntry {
    C(Vec<Tlv>),
    S(Vec<u8>),
}

impl TlvEntry {
    pub fn parse(data: &[u8], constructed: bool) -> nom::IResult<&[u8], Self> {
        match constructed {
            false => Ok((&[], TlvEntry::S(data.to_vec()))),
            true => {
                let mut c = vec![];
                let mut input = data;

                while !input.is_empty() {
                    let (rest, tlv) = Tlv::parse(input)?;
                    input = rest;
                    c.push(tlv);
                }

                Ok((&[], TlvEntry::C(c)))
            }
        }
    }

    pub fn from(data: &[u8], constructed: bool) -> Result<Self> {
        complete(Self::parse(data, constructed))
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            TlvEntry::S(data) => data.clone(),
            TlvEntry::C(data) => {
                let mut s = vec![];
                for t in data {
                    s.extend(&t.serialize());
                }
                s
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Tag, Tlv};
    use crate::tlv::TlvEntry;
    use anyhow::Result;
    use hex_literal::hex;

    #[test]
    fn test_tlv0() {
        let cpkt = Tlv(
            Tag(vec![0x7F, 0x48]),
            TlvEntry::S(vec![
                0x91, 0x03, 0x92, 0x82, 0x01, 0x00, 0x93, 0x82, 0x01, 0x00,
            ]),
        );

        assert_eq!(
            cpkt.serialize(),
            vec![
                0x7F, 0x48, 0x0A, 0x91, 0x03, 0x92, 0x82, 0x01, 0x00, 0x93,
                0x82, 0x01, 0x00,
            ]
        );
    }
    #[test]
    fn test_tlv() -> Result<()> {
        // From OpenPGP card spec § 7.2.6
        let data =
            hex!("5B0B546573743C3C54657374695F2D0264655F350131").to_vec();

        let (input, tlv) = Tlv::parse(&data).unwrap();

        assert_eq!(
            tlv,
            Tlv(
                Tag::from([0x5b]),
                TlvEntry::S(hex!("546573743C3C5465737469").to_vec())
            )
        );

        let (input, tlv) = Tlv::parse(input).unwrap();

        assert_eq!(
            tlv,
            Tlv(Tag::from([0x5f, 0x2d]), TlvEntry::S(hex!("6465").to_vec()))
        );

        let (input, tlv) = Tlv::parse(input).unwrap();

        assert_eq!(
            tlv,
            Tlv(Tag::from([0x5f, 0x35]), TlvEntry::S(hex!("31").to_vec()))
        );

        assert!(input.is_empty());

        Ok(())
    }

    #[test]
    fn test_tlv_yubi5() -> Result<()> {
        // 'Yubikey 5 NFC' output for GET DATA on "Application Related Data"
        let data = hex!("6e8201374f10d27600012401030400061601918000005f520800730000e00590007f740381012073820110c00a7d000bfe080000ff0000c106010800001100c206010800001100c306010800001100da06010800001100c407ff7f7f7f030003c5500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd1000000000000000000000000000000000de0801000200030081027f660802020bfe02020bfed6020020d7020020d8020020d9020020");
        let tlv = Tlv::try_from(&data[..])?;

        // outermost layer contains all bytes as value
        let entry = tlv.find(&Tag::from([0x6e])).unwrap();
        assert_eq!(entry.serialize(),
                   hex!("4f10d27600012401030400061601918000005f520800730000e00590007f740381012073820110c00a7d000bfe080000ff0000c106010800001100c206010800001100c306010800001100da06010800001100c407ff7f7f7f030003c5500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd1000000000000000000000000000000000de0801000200030081027f660802020bfe02020bfed6020020d7020020d8020020d9020020"));

        // get and verify data for ecap tag
        let entry = tlv.find(&Tag::from([0xc0])).unwrap();
        assert_eq!(entry.serialize(), hex!("7d000bfe080000ff0000"));

        let entry = tlv.find(&Tag::from([0x4f])).unwrap();
        assert_eq!(
            entry.serialize(),
            hex!("d2760001240103040006160191800000")
        );

        let entry = tlv.find(&Tag::from([0x5f, 0x52])).unwrap();
        assert_eq!(entry.serialize(), hex!("00730000e0059000"));

        let entry = tlv.find(&Tag::from([0x7f, 0x74])).unwrap();
        assert_eq!(entry.serialize(), hex!("810120"));

        let entry = tlv.find(&Tag::from([0x73])).unwrap();
        assert_eq!(entry.serialize(), hex!("c00a7d000bfe080000ff0000c106010800001100c206010800001100c306010800001100da06010800001100c407ff7f7f7f030003c5500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cd1000000000000000000000000000000000de0801000200030081027f660802020bfe02020bfed6020020d7020020d8020020d9020020"));

        let entry = tlv.find(&Tag::from([0xc0])).unwrap();
        assert_eq!(entry.serialize(), hex!("7d000bfe080000ff0000"));

        let entry = tlv.find(&Tag::from([0xc1])).unwrap();
        assert_eq!(entry.serialize(), hex!("010800001100"));

        let entry = tlv.find(&Tag::from([0xc2])).unwrap();
        assert_eq!(entry.serialize(), hex!("010800001100"));

        let entry = tlv.find(&Tag::from([0xc3])).unwrap();
        assert_eq!(entry.serialize(), hex!("010800001100"));

        let entry = tlv.find(&Tag::from([0xda])).unwrap();
        assert_eq!(entry.serialize(), hex!("010800001100"));

        let entry = tlv.find(&Tag::from([0xc4])).unwrap();
        assert_eq!(entry.serialize(), hex!("ff7f7f7f030003"));

        let entry = tlv.find(&Tag::from([0xc5])).unwrap();
        assert_eq!(entry.serialize(), hex!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));

        let entry = tlv.find(&Tag::from([0xc6])).unwrap();
        assert_eq!(entry.serialize(), hex!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));

        let entry = tlv.find(&Tag::from([0xcd])).unwrap();
        assert_eq!(
            entry.serialize(),
            hex!("00000000000000000000000000000000")
        );

        let entry = tlv.find(&Tag::from([0xde])).unwrap();
        assert_eq!(entry.serialize(), hex!("0100020003008102"));

        let entry = tlv.find(&Tag::from([0x7f, 0x66])).unwrap();
        assert_eq!(entry.serialize(), hex!("02020bfe02020bfe"));

        let entry = tlv.find(&Tag::from([0xd6])).unwrap();
        assert_eq!(entry.serialize(), hex!("0020"));

        let entry = tlv.find(&Tag::from([0xd7])).unwrap();
        assert_eq!(entry.serialize(), hex!("0020"));

        let entry = tlv.find(&Tag::from([0xd8])).unwrap();
        assert_eq!(entry.serialize(), hex!("0020"));

        let entry = tlv.find(&Tag::from([0xd9])).unwrap();
        assert_eq!(entry.serialize(), hex!("0020"));

        Ok(())
    }

    #[test]
    fn test_tlv_builder() {
        // NOTE: The data used in this example is similar to key upload,
        // but has been abridged and changed. It does not represent a
        // complete valid OpenPGP card DO!

        let a =
            Tlv(Tag::from(&[0x7F, 0x48][..]), TlvEntry::S(vec![0x92, 0x03]));

        let b = Tlv(
            Tag::from(&[0x5F, 0x48][..]),
            TlvEntry::S(vec![0x1, 0x2, 0x3]),
        );

        let tlv = Tlv(Tag::from(&[0x4d][..]), TlvEntry::C(vec![a, b]));

        assert_eq!(
            tlv.serialize(),
            &[
                0x4d, 0xb, 0x7f, 0x48, 0x2, 0x92, 0x3, 0x5f, 0x48, 0x3, 0x1,
                0x2, 0x3
            ]
        );
    }
}
