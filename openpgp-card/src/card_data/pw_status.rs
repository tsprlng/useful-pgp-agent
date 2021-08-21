// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::anyhow;

use crate::card_data::PWStatus;
use crate::errors::OpenpgpCardError;

impl PWStatus {
    pub fn try_from(input: &[u8]) -> Result<Self, OpenpgpCardError> {
        if input.len() == 7 {
            let pw1_cds_multi = input[0] == 0x01;
            let pw1_derived = input[1] & 0x80 != 0;
            let pw1_len = input[1] & 0x7f;
            let rc_len = input[2];
            let pw3_derived = input[3] & 0x80 != 0;
            let pw3_len = input[3] & 0x7f;
            let err_count_pw1 = input[4];
            let err_count_rst = input[5];
            let err_count_pw3 = input[6];

            Ok(Self {
                pw1_cds_multi,
                pw1_derived,
                pw1_len,
                rc_len,
                pw3_derived,
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
}
