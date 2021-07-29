// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use futures::StreamExt;
use lazy_static::lazy_static;
use sequoia_ipc::assuan::{Client, Response};
use std::sync::Mutex;
use tokio::runtime::Runtime;

use openpgp_card::errors::OpenpgpCardError;
use openpgp_card::{CardBase, CardCaps, CardClient, CardClientBox};

lazy_static! {
    pub(crate) static ref RT: Mutex<Runtime> =
        Mutex::new(tokio::runtime::Runtime::new().unwrap());
}

/// The Assuan protocol which is used in GnuPG limits the length of commands.
/// Currently there seems to be no way to send longer commands via Assuan.
///
/// See:
/// https://www.gnupg.org/documentation/manuals/assuan/Client-requests.html#Client-requests
///
/// FIXME: This number is probably off by a few bytes (is "SCD " added in
/// communication within GnuPG? Are \r\n added?)
const ASSUAN_LINELENGTH: usize = 1000;

/// The maximum number of bytes for a command that can be sent via Assuan to
/// scdaemon.
/// Each command byte gets sent via Assuan as a two-character hex string,
/// and a few characters are used to send "APDU --exlen=abcd" (as a
/// conservative limit, 20 characters are subtracted).
///
/// In concrete terms, this limit means that with cards that do not support
/// command chaining (like the floss-shop OpenPGP Card 3.4), some commands
/// cannot be sent to the card. In particular, uploading rsa4096 keys will
/// fail via scdaemon, with such cards.
const CMD_SIZE_MAX: usize = ASSUAN_LINELENGTH / 2 - 20;

pub struct ScdClient {
    client: Client,
    card_caps: Option<CardCaps>,
}

impl ScdClient {
    /// Create a CardBase object that uses an scdaemon instance as its
    /// backend.
    pub fn open_scdc(socket: &str) -> Result<CardBase, OpenpgpCardError> {
        let card_client = ScdClient::new(socket)?;
        let card_client_box = Box::new(card_client) as CardClientBox;

        CardBase::open_card(card_client_box)
    }

    /// Create a CardBase object that uses an scdaemon instance as its
    /// backend, asking for a specific card by `serial`.
    pub fn open_scdc_by_serial(
        socket: &str,
        serial: &str,
    ) -> Result<CardBase, OpenpgpCardError> {
        let mut card_client = ScdClient::new(socket)?;

        card_client.select_card(serial)?;

        let card_client_box = Box::new(card_client) as CardClientBox;

        CardBase::open_card(card_client_box)
    }

    pub fn new(socket: &str) -> Result<Self> {
        let client = RT.lock().unwrap().block_on(Client::connect(socket))?;
        Ok(Self {
            client,
            card_caps: None,
        })
    }

    pub fn select_card(&mut self, serial: &str) -> Result<()> {
        let send = format!("SERIALNO --demand={}\n", serial);
        self.client.send(send)?;

        let mut rt = RT.lock().unwrap();

        while let Some(response) = rt.block_on(self.client.next()) {
            log::debug!("select res: {:x?}", response);

            if response.is_err() {
                return Err(anyhow!("Card not found"));
            }

            if let Ok(Response::Status { .. }) = response {
                // drop remaining lines
                while let Some(_drop) = rt.block_on(self.client.next()) {
                    log::debug!("select drop: {:x?}", _drop);
                }

                return Ok(());
            }
        }

        Err(anyhow!("Card not found"))
    }
}

impl CardClient for ScdClient {
    fn transmit(&mut self, cmd: &[u8], _: usize) -> Result<Vec<u8>> {
        log::debug!("SCDC cmd len {}", cmd.len());

        let hex = hex::encode(cmd);

        let ex = if let Some(caps) = self.card_caps {
            if caps.ext_support {
                format!("--exlen={} ", caps.max_rsp_bytes)
            } else {
                "".to_string()
            }
        } else {
            "".to_string()
        };

        let send = format!("APDU {}{}\n", ex, hex);
        log::debug!("send: '{}'", send);

        if send.len() > ASSUAN_LINELENGTH {
            return Err(anyhow!(
                "APDU command is too long ({}) to send via Assuan",
                send.len()
            ));
        }

        self.client.send(send)?;

        let mut rt = RT.lock().unwrap();

        while let Some(response) = rt.block_on(self.client.next()) {
            log::debug!("res: {:x?}", response);
            if response.is_err() {
                unimplemented!("Err: {:x?}", response);
            }

            if let Ok(Response::Data { partial }) = response {
                let res = partial;

                // drop remaining lines
                while let Some(drop) = rt.block_on(self.client.next()) {
                    log::debug!("drop: {:x?}", drop);
                }

                return Ok(res);
            }
        }

        Err(anyhow!("no response found"))
    }

    fn init_caps(&mut self, caps: CardCaps) {
        self.card_caps = Some(caps);
    }

    fn get_caps(&self) -> Option<&CardCaps> {
        self.card_caps.as_ref()
    }

    /// Return limit for APDU command size via scdaemon (based on Assuan
    /// maximum line length)
    fn max_cmd_len(&self) -> Option<usize> {
        Some(CMD_SIZE_MAX)
    }
}
