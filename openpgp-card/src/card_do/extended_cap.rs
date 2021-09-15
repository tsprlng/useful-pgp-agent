// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! 4.4.3.7 Extended Capabilities

use anyhow::{anyhow, Result};
use std::convert::TryFrom;

use crate::card_do::ExtendedCapabilities;
use crate::Error;

impl ExtendedCapabilities {
    pub fn max_len_special_do(&self) -> Option<u16> {
        self.max_len_special_do
    }

    pub fn algo_attrs_changeable(&self) -> bool {
        self.algo_attrs_changeable
    }

    pub fn max_cmd_len(&self) -> Option<u16> {
        self.max_cmd_len
    }

    pub fn max_resp_len(&self) -> Option<u16> {
        self.max_resp_len
    }
}

impl TryFrom<(&[u8], u16)> for ExtendedCapabilities {
    type Error = Error;

    fn try_from((input, version): (&[u8], u16)) -> Result<Self, Self::Error> {
        // FIXME: check that this fn is not called excessively often

        let version = ((version >> 8) as u8, (version & 0xff) as u8);

        // FIXME: earlier versions have shorter extended capabilities
        assert!(version.0 >= 2);

        // v2.x and v3.x should have 10 byte sized extended caps
        assert_eq!(
            input.len(),
            10,
            "extended capabilities with size != 10 are currently unsupported"
        );

        let b = input[0];

        let secure_messaging = b & 0x80 != 0;
        let get_challenge = b & 0x40 != 0;
        let key_import = b & 0x20 != 0;
        let pw_status_change = b & 0x10 != 0;
        let private_use_dos = b & 0x08 != 0;
        let algo_attrs_changeable = b & 0x04 != 0;
        let aes = b & 0x02 != 0;
        let kdf_do = b & 0x01 != 0;

        let sm_algo = input[1];

        let max_len_challenge = input[2] as u16 * 256 + input[3] as u16;
        let max_len_cardholder_cert = input[4] as u16 * 256 + input[5] as u16;

        let mut max_cmd_len = None;
        let mut max_resp_len = None;

        let mut max_len_special_do = None;
        let mut pin_block_2_format_support = None;
        let mut mse_command_support = None;

        if version.0 == 2 {
            // v2.0 until v2.2
            max_cmd_len = Some(input[6] as u16 * 256 + input[7] as u16);
            max_resp_len = Some(input[8] as u16 * 256 + input[9] as u16);
        } else {
            // from v3.0
            max_len_special_do = Some(input[6] as u16 * 256 + input[7] as u16);

            let i8 = input[8];
            let i9 = input[9];

            if i8 > 1 {
                return Err(anyhow!(
                    "Illegal value '{}' for pin_block_2_format_support",
                    i8
                )
                .into());
            }

            pin_block_2_format_support = Some(i8 != 0);

            if i9 > 1 {
                return Err(anyhow!(
                    "Illegal value '{}' for mse_command_support",
                    i9
                )
                .into());
            }
            mse_command_support = Some(i9 != 0);
        }

        Ok(Self {
            secure_messaging,
            get_challenge,
            key_import,
            pw_status_change,
            private_use_dos,
            algo_attrs_changeable,
            aes,
            kdf_do,

            sm_algo,
            max_len_challenge,
            max_len_cardholder_cert,

            max_cmd_len,  // v2
            max_resp_len, // v2

            max_len_special_do,         // v3
            pin_block_2_format_support, // v3
            mse_command_support,        // v3
        })
    }
}

#[cfg(test)]
mod test {
    use crate::card_do::extended_cap::ExtendedCapabilities;
    use hex_literal::hex;
    use std::convert::TryFrom;

    #[test]
    fn test_ec() {
        // Yubikey 5
        let data = hex!("7d 00 0b fe 08 00 00 ff 00 00");
        let ec = ExtendedCapabilities::try_from((&data[..], 0x0304)).unwrap();

        assert_eq!(
            ec,
            ExtendedCapabilities {
                secure_messaging: false,
                get_challenge: true,
                key_import: true,
                pw_status_change: true,
                private_use_dos: true,
                algo_attrs_changeable: true,
                aes: false,
                kdf_do: true,
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
