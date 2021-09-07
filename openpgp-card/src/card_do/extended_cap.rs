// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! 4.4.3.7 Extended Capabilities

use anyhow::{anyhow, Result};
use nom::{combinator, number::complete as number, sequence};
use std::collections::HashSet;
use std::convert::TryFrom;

use crate::card_do::{complete, ExCapFeatures, ExtendedCapabilities};
use crate::Error;

fn features(input: &[u8]) -> nom::IResult<&[u8], HashSet<ExCapFeatures>> {
    combinator::map(number::u8, |b| {
        let mut f = HashSet::new();

        if b & 0x80 != 0 {
            f.insert(ExCapFeatures::SecureMessaging);
        }
        if b & 0x40 != 0 {
            f.insert(ExCapFeatures::GetChallenge);
        }
        if b & 0x20 != 0 {
            f.insert(ExCapFeatures::KeyImport);
        }
        if b & 0x10 != 0 {
            f.insert(ExCapFeatures::PwStatusChange);
        }
        if b & 0x08 != 0 {
            f.insert(ExCapFeatures::PrivateUseDOs);
        }
        if b & 0x04 != 0 {
            f.insert(ExCapFeatures::AlgoAttrsChangeable);
        }
        if b & 0x02 != 0 {
            f.insert(ExCapFeatures::Aes);
        }
        if b & 0x01 != 0 {
            f.insert(ExCapFeatures::KdfDo);
        }

        f
    })(input)
}

fn parse(
    input: &[u8],
) -> nom::IResult<&[u8], (HashSet<ExCapFeatures>, u8, u16, u16, u16, u8, u8)> {
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

impl ExtendedCapabilities {
    pub fn features(&self) -> HashSet<ExCapFeatures> {
        self.features.clone()
    }

    pub fn max_len_special_do(&self) -> u16 {
        self.max_len_special_do
    }
}

impl TryFrom<&[u8]> for ExtendedCapabilities {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let (
            features,
            sm_algo,
            max_len_challenge,
            max_len_cardholder_cert,
            max_len_special_do,
            pin_block_2_format_support,
            mse_command_support,
        ) = complete(parse(input))?;

        if pin_block_2_format_support > 1 {
            return Err(anyhow!(
                "Illegal value '{}' for pin_block_2_format_support",
                pin_block_2_format_support
            )
            .into());
        }

        // NOTE: yubikey 4 returns 255 for mse_command_support
        // if mse_command_support > 1 {
        //     return Err(anyhow!(
        //         "Illegal value '{}' for mse_command_support",
        //         mse_command_support
        //     )
        //     .into());
        // }

        Ok(Self {
            features,
            sm_algo,
            max_len_challenge,
            max_len_cardholder_cert,
            max_len_special_do,
            pin_block_2_format_support: pin_block_2_format_support != 0,
            mse_command_support: mse_command_support != 0,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::card_do::extended_cap::{ExCapFeatures, ExtendedCapabilities};
    use hex_literal::hex;
    use std::collections::HashSet;
    use std::convert::TryFrom;
    use std::iter::FromIterator;

    #[test]
    fn test_ec() {
        let data = hex!("7d 00 0b fe 08 00 00 ff 00 00");
        let ec = ExtendedCapabilities::try_from(&data[..]).unwrap();

        assert_eq!(
            ec,
            ExtendedCapabilities {
                features: HashSet::from_iter(vec![
                    ExCapFeatures::GetChallenge,
                    ExCapFeatures::KeyImport,
                    ExCapFeatures::PwStatusChange,
                    ExCapFeatures::PrivateUseDOs,
                    ExCapFeatures::AlgoAttrsChangeable,
                    ExCapFeatures::KdfDo
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
