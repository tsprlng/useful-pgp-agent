// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use crate::errors::OpenpgpCardError;

#[derive(Debug)]
pub struct CardCapabilities {
    command_chaining: bool,
    extended_lc_le: bool,
    extended_length_information: bool,
}

impl CardCapabilities {
    pub fn get_command_chaining(&self) -> bool {
        self.command_chaining
    }

    pub fn get_extended_lc_le(&self) -> bool {
        self.extended_lc_le
    }

    pub fn get_extended_length_information(&self) -> bool {
        self.extended_length_information
    }


    pub fn from(data: [u8; 3]) -> Self {
        let byte3 = data[2];

        let command_chaining = byte3 & 0x80 != 0;
        let extended_lc_le = byte3 & 0x40 != 0;
        let extended_length_information = byte3 & 0x20 != 0;

        Self { command_chaining, extended_lc_le, extended_length_information }
    }
}

#[derive(Debug)]
pub struct CardSeviceData {
    select_by_full_df_name: bool,
    select_by_partial_df_name: bool,
    dos_available_in_ef_dir: bool,
    dos_available_in_ef_atr_info: bool,
    access_services: [bool; 3],
    mf: bool,
}

impl CardSeviceData {
    pub fn from(data: u8) -> Self {
        let select_by_full_df_name = data & 0x80 != 0;
        let select_by_partial_df_name = data & 0x40 != 0;
        let dos_available_in_ef_dir = data & 0x20 != 0;
        let dos_available_in_ef_atr_info = data & 0x10 != 0;
        let access_services =
            [data & 0x8 != 0, data & 0x4 != 0, data & 0x2 != 0];
        let mf = data & 0x1 != 0;

        Self {
            select_by_full_df_name,
            select_by_partial_df_name,
            dos_available_in_ef_dir,
            dos_available_in_ef_atr_info,
            access_services,
            mf,
        }
    }
}

#[derive(Debug)]
pub struct Historical {
    // category indicator byte
    cib: u8,

    // Card service data (31)
    csd: Option<CardSeviceData>,

    // Card Capabilities (73)
    cc: Option<CardCapabilities>,

    // status indicator byte (o-card 3.4.1, pg 44)
    sib: u8,
}

impl Historical {
    pub fn get_card_capabilities(&self) -> Option<&CardCapabilities> {
        self.cc.as_ref()
    }

    pub fn from(data: &[u8]) -> Result<Self, OpenpgpCardError> {
        if data[0] == 0 {
            // The OpenPGP application assumes a category indicator byte
            // set to '00' (o-card 3.4.1, pg 44)

            let len = data.len();
            let cib = data[0];
            let mut csd = None;
            let mut cc = None;

            // COMPACT - TLV data objects [ISO 12.1.1.2]
            let mut ctlv = data[1..len - 3].to_vec();
            while !ctlv.is_empty() {
                match ctlv[0] {
                    0x31 => {
                        csd = Some(ctlv[1]);
                        ctlv.drain(0..2);
                    }
                    0x73 => {
                        cc = Some([ctlv[1], ctlv[2], ctlv[3]]);
                        ctlv.drain(0..4);
                    }
                    0 => { ctlv.drain(0..1); }
                    _ => unimplemented!("unexpected tlv in historical bytes")
                }
            }

            let sib =
                match data[len - 3] {
                    0 => {
                        // Card does not offer life cycle management, commands
                        // TERMINATE DF and ACTIVATE FILE are not supported
                        0
                    }
                    3 => {
                        // Initialisation state
                        // OpenPGP application can be reset to default values with
                        // an ACTIVATE FILE command
                        3
                    }
                    5 => {
                        // Operational state (activated)
                        // Card supports life cycle management, commands TERMINATE
                        // DF and ACTIVATE FILE are available
                        5
                    }
                    _ => {
                        return Err(anyhow!("unexpected status indicator in \
                        historical bytes").into());
                    }
                };

            // Ignore final two bytes: according to the spec, they should
            // show [0x90, 0x0] - but Yubikey Neo shows [0x0, 0x0].
            // It's unclear if these status bytes are ever useful to process.

            let cc = cc.map(CardCapabilities::from);
            let csd = csd.map(CardSeviceData::from);

            Ok(Self { cib, csd, cc, sib })
        } else {
            Err(anyhow!("Unexpected category indicator in historical \
            bytes").into())
        }
    }
}

// FIXME: add tests
