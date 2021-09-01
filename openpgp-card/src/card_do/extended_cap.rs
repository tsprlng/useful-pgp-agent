// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! 4.4.3.7 Extended Capabilities

use anyhow::Result;
use nom::{combinator, number::complete as number, sequence};
use std::collections::HashSet;
use std::convert::TryFrom;

use crate::card_do::complete;
use crate::card_do::{ExtendedCap, Features};
use crate::errors::OpenpgpCardError;

fn features(input: &[u8]) -> nom::IResult<&[u8], HashSet<Features>> {
    combinator::map(number::u8, |b| {
        let mut f = HashSet::new();

        if b & 0x80 != 0 {
            f.insert(Features::SecureMessaging);
        }
        if b & 0x40 != 0 {
            f.insert(Features::GetChallenge);
        }
        if b & 0x20 != 0 {
            f.insert(Features::KeyImport);
        }
        if b & 0x10 != 0 {
            f.insert(Features::PwStatusChange);
        }
        if b & 0x08 != 0 {
            f.insert(Features::PrivateUseDOs);
        }
        if b & 0x04 != 0 {
            f.insert(Features::AlgoAttrsChangeable);
        }
        if b & 0x02 != 0 {
            f.insert(Features::Aes);
        }
        if b & 0x01 != 0 {
            f.insert(Features::KdfDo);
        }

        f
    })(input)
}

fn parse(
    input: &[u8],
) -> nom::IResult<&[u8], (HashSet<Features>, u8, u16, u16, u16, u8, u8)> {
    nom::combinator::all_consuming(sequence::tuple((
        features,
        number::u8,
        number::be_u16,
        number::be_u16,
        number::be_u16,
        number::u8,
        number::u8,
    )))(input)
}

impl ExtendedCap {
    pub fn features(&self) -> HashSet<Features> {
        self.features.clone()
    }

    pub fn max_len_special_do(&self) -> u16 {
        self.max_len_special_do
    }
}

impl TryFrom<&[u8]> for ExtendedCap {
    type Error = OpenpgpCardError;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let ec = complete(parse(input))?;

        Ok(Self {
            features: ec.0,
            sm_algo: ec.1,
            max_len_challenge: ec.2,
            max_len_cardholder_cert: ec.3,
            max_len_special_do: ec.4,
            pin_block_2_format_support: ec.5 == 1, // FIXME: error if != 0|1
            mse_command_support: ec.6 == 1,        // FIXME: error if != 0|1
        })
    }
}

#[cfg(test)]
mod test {
    use crate::card_do::extended_cap::{ExtendedCap, Features};
    use hex_literal::hex;
    use std::collections::HashSet;
    use std::convert::TryFrom;
    use std::iter::FromIterator;

    #[test]
    fn test_ec() {
        let data = hex!("7d 00 0b fe 08 00 00 ff 00 00");
        let ec = ExtendedCap::try_from(&data[..]).unwrap();

        assert_eq!(
            ec,
            ExtendedCap {
                features: HashSet::from_iter(vec![
                    Features::GetChallenge,
                    Features::KeyImport,
                    Features::PwStatusChange,
                    Features::PrivateUseDOs,
                    Features::AlgoAttrsChangeable,
                    Features::KdfDo
                ]),
                sm_algo: 0x0,
                max_len_challenge: 0xbfe,
                max_len_cardholder_cert: 0x800,
                max_len_special_do: 0xff,
                pin_block_2_format_support: false,
                mse_command_support: false,
            }
        );
    }
}
