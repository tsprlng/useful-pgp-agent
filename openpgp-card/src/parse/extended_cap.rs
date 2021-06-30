// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use nom::{number::complete as number, combinator, sequence};
use anyhow::Result;
use std::collections::HashSet;
use crate::parse;
use crate::errors::OpenpgpCardError;
use std::convert::TryFrom;

#[derive(Debug, Eq, PartialEq)]
pub struct ExtendedCap {
    pub features: HashSet<Features>,
    sm: u8,
    max_len_challenge: u16,
    max_len_cardholder_cert: u16,
    pub max_len_special_do: u16,
    pin_2_format: bool,
    mse_command: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Features {
    SecureMessaging,
    GetChallenge,
    KeyImport,
    PwStatusChange,
    PrivateUseDOs,
    AlgoAttrsChangeable,
    Aes,
    KdfDo,
}

fn features(input: &[u8]) -> nom::IResult<&[u8], HashSet<Features>> {
    combinator::map(number::u8, |b| {
        let mut f = HashSet::new();

        if b & 0x80 != 0 { f.insert(Features::SecureMessaging); }
        if b & 0x40 != 0 { f.insert(Features::GetChallenge); }
        if b & 0x20 != 0 { f.insert(Features::KeyImport); }
        if b & 0x10 != 0 { f.insert(Features::PwStatusChange); }
        if b & 0x08 != 0 { f.insert(Features::PrivateUseDOs); }
        if b & 0x04 != 0 { f.insert(Features::AlgoAttrsChangeable); }
        if b & 0x02 != 0 { f.insert(Features::Aes); }
        if b & 0x01 != 0 { f.insert(Features::KdfDo); }

        f
    })(input)
}

fn parse(input: &[u8])
         -> nom::IResult<&[u8], (HashSet<Features>, u8, u16, u16, u16, u8, u8)> {
    nom::combinator::all_consuming(sequence::tuple((
        features,
        number::u8,
        number::be_u16,
        number::be_u16,
        number::be_u16,
        number::u8,
        number::u8)
    ))(input)
}


impl TryFrom<&[u8]> for ExtendedCap {
    type Error = OpenpgpCardError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let ec = parse::complete(parse(input))?;

        Ok(Self {
            features: ec.0,
            sm: ec.1,
            max_len_challenge: ec.2,
            max_len_cardholder_cert: ec.3,
            max_len_special_do: ec.4,
            pin_2_format: ec.5 == 1, // FIXME: error if != 0|1
            mse_command: ec.6 == 1, // FIXME: error if != 0|1
        })
    }
}


#[cfg(test)]
mod test {
    use hex_literal::hex;
    use crate::parse::extended_cap::{ExtendedCap, Features};
    use std::collections::HashSet;
    use std::iter::FromIterator;

    #[test]
    fn test_ec() {
        let data = hex!("7d 00 0b fe 08 00 00 ff 00 00");
        let ec = ExtendedCap::from(&data).unwrap();

        assert_eq!(
            ec, ExtendedCap {
                features: HashSet::from_iter(
                    vec![Features::GetChallenge, Features::KeyImport,
                         Features::PwStatusChange, Features::PrivateUseDOs,
                         Features::AlgoAttrsChangeable, Features::KdfDo]),
                sm: 0x0,
                max_len_challenge: 0xbfe,
                max_len_cardholder_cert: 0x800,
                max_len_special_do: 0xff,
                pin_2_format: false,
                mse_command: false,
            }
        );
    }
}
