// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::anyhow;

use crate::card_do::PWStatus;
use crate::errors::OpenpgpCardError;

impl PWStatus {
    pub fn try_from(input: &[u8]) -> Result<Self, OpenpgpCardError> {
        if input.len() == 7 {
            let pw1_cds_multi = input[0] == 0x01;
            let pw1_pin_block = input[1] & 0x80 != 0;
            let pw1_len = input[1] & 0x7f;
            let rc_len = input[2];
            let pw3_pin_block = input[3] & 0x80 != 0;
            let pw3_len = input[3] & 0x7f;
            let err_count_pw1 = input[4];
            let err_count_rst = input[5];
            let err_count_pw3 = input[6];

            Ok(Self {
                pw1_cds_multi,
                pw1_pin_block,
                pw1_len,
                rc_len,
                pw3_pin_block,
                pw3_len,
                err_count_pw1,
                err_count_rst,
                err_count_pw3,
            })
        } else {
            Err(OpenpgpCardError::InternalError(anyhow!(
                "Unexpected length of PW Status Bytes: {}",
                input.len()
            )))
        }
    }

    /// PUT DO for PW Status Bytes accepts either 1 or 4 bytes of data.
    /// This method generates the 1 byte version for 'long==false' and the
    /// 4 bytes version for 'long==true'.
    ///
    /// (See OpenPGP card spec, pg. 28)
    pub fn serialize_for_put(&self, long: bool) -> Vec<u8> {
        let mut data = vec![];

        data.push(if !self.pw1_cds_multi { 0 } else { 1 });

        if long {
            let mut b2 = self.pw1_len;
            if self.pw1_pin_block {
                b2 |= 0x80;
            }
            data.push(b2);

            data.push(self.rc_len);

            let mut b4 = self.pw3_len;
            if self.pw3_pin_block {
                b4 |= 0x80;
            }
            data.push(b4);
        }

        data
    }
}
