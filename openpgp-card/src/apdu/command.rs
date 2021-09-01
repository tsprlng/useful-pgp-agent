// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Data structure for APDU Commands
//! (Commands get sent to the card, which will usually send back a `Response`)

use crate::apdu::Le;
use anyhow::Result;

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug)]
pub(crate) struct Command {
    // Class byte (CLA)
    cla: u8,

    // Instruction byte (INS)
    ins: u8,

    // Parameter bytes (P1/P2)
    p1: u8,
    p2: u8,

    // NOTE: data must be smaller than 64 kbyte
    data: Vec<u8>,
}

impl Command {
    /// Create an APDU Command.
    ///
    /// `data` must be smaller than 64 kbyte. If a larger `data` is passed,
    /// this fn will panic.
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        // This constructor is the only place it gets set, so it's
        // sufficient to check it here.
        assert!(data.len() < 0x10000, "'data' too big, must be <64 kbyte");

        Command {
            cla,
            ins,
            p1,
            p2,
            data,
        }
    }

    pub(crate) fn get_ins(&self) -> u8 {
        self.ins
    }

    pub(crate) fn get_p1(&self) -> u8 {
        self.p1
    }

    pub(crate) fn get_p2(&self) -> u8 {
        self.p2
    }

    pub(crate) fn get_data(&self) -> &[u8] {
        &self.data
    }

    fn encode_len(len: u16, ext: Le) -> Vec<u8> {
        if len > 0xff || ext == Le::Long {
            vec![0, (len as u16 >> 8) as u8, (len as u16 & 255) as u8]
        } else {
            vec![len as u8]
        }
    }

    pub(crate) fn serialize(&self, ext: Le) -> Result<Vec<u8>> {
        // See OpenPGP card spec, chapter 7 (pg 47)

        // FIXME: 1) get "ext" information (how long can commands and
        // responses be),
        // FIXME: 2) decide on long vs. short encoding for both Lc and Le
        // (must be the same)

        let data_len = Self::encode_len(self.data.len() as u16, ext);

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
