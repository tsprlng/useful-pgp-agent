// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;

use anyhow::Result;
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::combinator::map;
use nom::{branch, bytes::complete as bytes, number::complete as number};

use crate::{parse, EccType};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Algo {
    Rsa(RsaAttrs),
    Ecc(EccAttrs),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RsaAttrs {
    pub len_n: u16,
    pub len_e: u16,
    pub import_format: u8,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EccAttrs {
    pub ecc_type: EccType,
    pub oid: Vec<u8>,
    pub import_format: Option<u8>,
}

impl EccAttrs {
    pub fn new(
        ecc_type: EccType,
        curve: Curve,
        import_format: Option<u8>,
    ) -> Self {
        Self {
            ecc_type,
            oid: curve.oid().to_vec(),
            import_format,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Curve {
    NistP256r1,
    NistP384r1,
    NistP521r1,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
    Secp256k1,
    Ed25519,
    Cv25519,
    Ed448,
    X448,
}

impl Curve {
    pub fn oid(&self) -> &[u8] {
        use Curve::*;
        match self {
            NistP256r1 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
            NistP384r1 => &[0x2B, 0x81, 0x04, 0x00, 0x22],
            NistP521r1 => &[0x2B, 0x81, 0x04, 0x00, 0x23],
            BrainpoolP256r1 => {
                &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]
            }
            BrainpoolP384r1 => {
                &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b]
            }
            BrainpoolP512r1 => {
                &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d]
            }
            Secp256k1 => &[0x2B, 0x81, 0x04, 0x00, 0x0A],
            Ed25519 => &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
            Cv25519 => {
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]
            }
            Ed448 => &[0x2b, 0x65, 0x71],
            X448 => &[0x2b, 0x65, 0x6f],
        }
    }
}

fn parse_oid_cv25519(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::Cv25519.oid()), |_| Curve::Cv25519)(input)
}

fn parse_oid_ed25519(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::Ed25519.oid()), |_| Curve::Ed25519)(input)
}

fn parse_oid_secp256k1(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::Secp256k1.oid()), |_| Curve::Secp256k1)(input)
}

fn parse_oid_nist256(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::NistP256r1.oid()), |_| Curve::NistP256r1)(input)
}

fn parse_oid_nist384(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::NistP384r1.oid()), |_| Curve::NistP384r1)(input)
}

fn parse_oid_nist521(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::NistP521r1.oid()), |_| Curve::NistP521r1)(input)
}

fn parse_oid_brainpool_p256r1(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::BrainpoolP256r1.oid()), |_| {
        Curve::BrainpoolP256r1
    })(input)
}

fn parse_oid_brainpool_p384r1(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::BrainpoolP384r1.oid()), |_| {
        Curve::BrainpoolP384r1
    })(input)
}

fn parse_oid_brainpool_p512r1(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::BrainpoolP512r1.oid()), |_| {
        Curve::BrainpoolP512r1
    })(input)
}

fn parse_oid_ed448(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::Ed448.oid()), |_| Curve::Ed448)(input)
}

fn parse_oid_x448(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    map(tag(Curve::X448.oid()), |_| Curve::X448)(input)
}

fn parse_oid(input: &[u8]) -> nom::IResult<&[u8], Curve> {
    alt((
        parse_oid_nist256,
        parse_oid_nist384,
        parse_oid_nist521,
        parse_oid_brainpool_p256r1,
        parse_oid_brainpool_p384r1,
        parse_oid_brainpool_p512r1,
        parse_oid_secp256k1,
        parse_oid_ed25519,
        parse_oid_cv25519,
        parse_oid_ed448,
        parse_oid_x448,
    ))(input)
}

fn parse_rsa(input: &[u8]) -> nom::IResult<&[u8], Algo> {
    let (input, _) = bytes::tag([0x01])(input)?;

    let (input, len_n) = number::be_u16(input)?;
    let (input, len_e) = number::be_u16(input)?;
    let (input, import_format) = number::u8(input)?;

    Ok((
        input,
        Algo::Rsa(RsaAttrs {
            len_n,
            len_e,
            import_format,
        }),
    ))
}

fn parse_import_format(input: &[u8]) -> nom::IResult<&[u8], Option<u8>> {
    let (input, b) = bytes::take(1usize)(input)?;
    Ok((input, Some(b[0])))
}

fn default_import_format(input: &[u8]) -> nom::IResult<&[u8], Option<u8>> {
    Ok((input, None))
}

fn parse_ecdh(input: &[u8]) -> nom::IResult<&[u8], Algo> {
    let (input, _) = bytes::tag([0x12])(input)?;
    let (input, curve) = parse_oid(input)?;

    let (input, import_format) =
        alt((parse_import_format, default_import_format))(input)?;

    Ok((
        input,
        Algo::Ecc(EccAttrs::new(EccType::ECDH, curve, import_format)),
    ))
}

fn parse_ecdsa(input: &[u8]) -> nom::IResult<&[u8], Algo> {
    let (input, _) = bytes::tag([0x13])(input)?;
    let (input, curve) = parse_oid(input)?;

    let (input, import_format) =
        alt((parse_import_format, default_import_format))(input)?;

    Ok((
        input,
        Algo::Ecc(EccAttrs::new(EccType::ECDSA, curve, import_format)),
    ))
}

fn parse_eddsa(input: &[u8]) -> nom::IResult<&[u8], Algo> {
    let (input, _) = bytes::tag([0x16])(input)?;
    let (input, curve) = parse_oid(input)?;

    let (input, import_format) =
        alt((parse_import_format, default_import_format))(input)?;

    Ok((
        input,
        Algo::Ecc(EccAttrs::new(EccType::EdDSA, curve, import_format)),
    ))
}

pub(crate) fn parse(input: &[u8]) -> nom::IResult<&[u8], Algo> {
    branch::alt((parse_rsa, parse_ecdsa, parse_eddsa, parse_ecdh))(input)
}

impl TryFrom<&[u8]> for Algo {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        parse::complete(parse(data))
    }
}
