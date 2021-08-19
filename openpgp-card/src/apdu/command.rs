// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::apdu::Le;
use anyhow::Result;

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug)]
pub(crate) struct Command {
    // Class byte (CLA)
    pub cla: u8,

    // Instruction byte (INS)
    pub ins: u8,

    // Parameter bytes (P1/P2)
    pub p1: u8,
    pub p2: u8,

    pub data: Vec<u8>,
}

impl Command {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Command {
            cla,
            ins,
            p1,
            p2,
            data,
        }
    }

    pub(crate) fn serialize(&self, ext: Le) -> Result<Vec<u8>> {
        // Set OpenPGP card spec, chapter 7 (pg 47)

        // FIXME: 1) get "ext" information (how long can commands and
        // responses be),
        // FIXME: 2) decide on long vs. short encoding for both Lc and Le
        // (must be the same)

        let data_len = if self.data.len() as u16 > 0xff || ext == Le::Long {
            vec![
                0,
                (self.data.len() as u16 >> 8) as u8,
                (self.data.len() as u16 & 255) as u8,
            ]
        } else {
            vec![self.data.len() as u8]
        };

        let mut buf = vec![self.cla, self.ins, self.p1, self.p2];

        if !self.data.is_empty() {
            buf.extend_from_slice(&data_len);
            buf.extend_from_slice(&self.data[..]);
        }

        // Le
        match ext {
            // FIXME? (from scd/apdu.c):
            // /* T=0 does not allow the use of Lc together with Le;
            //                  thus disable Le in this case.  */
            //               if (reader_table[slot].is_t0)
            //                 le = -1;
            Le::None => (),

            Le::Short => buf.push(0),
            Le::Long => {
                buf.push(0);
                buf.push(0);
                if self.data.is_empty() {
                    buf.push(0)
                }
            }
        }

        Ok(buf)
    }
}
