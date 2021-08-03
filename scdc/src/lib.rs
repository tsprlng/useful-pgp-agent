// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This crate provides `ScdClient`, which is an implementation of the
//! CardClient trait that uses GnuPG's scdaemon to access OpenPGP cards.

use anyhow::{anyhow, Result};
use futures::StreamExt;
use lazy_static::lazy_static;
use sequoia_ipc::assuan::{Client, Response};
use std::sync::Mutex;
use tokio::runtime::Runtime;

use openpgp_card::errors::OpenpgpCardError;
use openpgp_card::{CardCaps, CardClient, CardClientBox};

lazy_static! {
    static ref RT: Mutex<Runtime> =
        Mutex::new(tokio::runtime::Runtime::new().unwrap());
}

/// The Assuan protocol (in GnuPG) limits the length of commands.
///
/// See:
/// https://www.gnupg.org/documentation/manuals/assuan/Client-requests.html#Client-requests
///
/// Currently there seems to be no way to send longer commands via Assuan,
/// the functionality to break one command into multiple lines has
/// apparently not yet been implemented.
///
/// NOTE: This number is probably off by a few bytes (is "SCD " added in
/// communication within GnuPG? Are \r\n added?)
const ASSUAN_LINELENGTH: usize = 1000;

/// The maximum number of bytes for a command that we will send to
/// scdaemon (via Assuan).
///
/// Each command byte gets sent via Assuan as a two-character hex string.
///
/// 18 characters are used to send "APDU --exlen=abcd "
/// (So, as a defensive limit, 25 characters are subtracted).
///
/// In concrete terms, this limit means that some commands (with big
/// parameters) cannot be sent to the card, when the card doesn't support
/// command chaining (like the floss-shop OpenPGP Card 3.4).
///
/// In particular, uploading rsa4096 keys fails via scdaemon, with such cards.
const CMD_SIZE_MAX: usize = ASSUAN_LINELENGTH / 2 - 25;

pub struct ScdClient {
    client: Client,
    card_caps: Option<CardCaps>,
}

impl ScdClient {
    /// Initialize an ScdClient object that is connected to an scdaemon
    /// instance via `socket`
    fn new(socket: &str) -> Result<Self> {
        let client = RT.lock().unwrap().block_on(Client::connect(socket))?;
        Ok(Self {
            client,
            card_caps: None,
        })
    }

    /// Create a CardClientBox object that uses an scdaemon instance as its
    /// backend. If multiple cards are available, scdaemon implicitly
    /// selects one.
    pub fn open(socket: &str) -> Result<CardClientBox, OpenpgpCardError> {
        let card = ScdClient::new(socket)?;
        Ok(Box::new(card) as CardClientBox)
    }

    /// Create a CardClientBox object that uses an scdaemon instance as its
    /// backend. Requests the specific card `serial`.
    pub fn open_by_serial(
        socket: &str,
        serial: &str,
    ) -> Result<CardClientBox, OpenpgpCardError> {
        let mut card = ScdClient::new(socket)?;
        card.select_card(serial)?;

        Ok(Box::new(card) as CardClientBox)
    }

    /// Ask scdameon to switch to using a specific OpenPGP card, based on
    /// its `serial`.
    fn select_card(&mut self, serial: &str) -> Result<()> {
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
        log::trace!("SCDC cmd len {}", cmd.len());

        let hex = hex::encode(cmd);

        let ext = if self.card_caps.is_some()
            && self.card_caps.unwrap().ext_support
        {
            format!("--exlen={} ", self.card_caps.unwrap().max_rsp_bytes)
        } else {
            "".to_string()
        };

        let send = format!("APDU {}{}\n", ext, hex);
        log::debug!("SCDC command: '{}'", send);

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
                return Err(anyhow!(
                    "Unexpected error response from SCD {:?}",
                    response
                ));
            }

            if let Ok(Response::Data { partial }) = response {
                let res = partial;

                // drop remaining lines
                while let Some(drop) = rt.block_on(self.client.next()) {
                    log::trace!("drop: {:x?}", drop);
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
