// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This crate implements the experimental `ScdClient` backend for the
//! `openpgp-card` crate.
//! It uses GnuPG's scdaemon (via GnuPG Agent) to access OpenPGP cards.

use anyhow::{anyhow, Result};
use futures::StreamExt;
use lazy_static::lazy_static;
use sequoia_ipc::assuan::Response;
use sequoia_ipc::gnupg::{Agent, Context};
use std::sync::Mutex;
use tokio::runtime::Runtime;

use openpgp_card::{CardCaps, CardTransaction, Error};

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
/// 22 characters are used to send "SCD APDU --exlen=abcd "
/// (So, as a defensive limit, 25 characters are subtracted).
///
/// In concrete terms, this limit means that some commands (with big
/// parameters) cannot be sent to the card, when the card doesn't support
/// command chaining (like the floss-shop "OpenPGP Smart Card 3.4").
///
/// In particular, uploading rsa4096 keys fails via scdaemon, with such cards.
const APDU_CMD_BYTES_MAX: usize = (ASSUAN_LINELENGTH - 25) / 2;

/// An implementation of the CardTransaction trait that uses GnuPG's scdaemon
/// (via GnuPG Agent) to access OpenPGP card devices.
pub struct ScdClient {
    agent: Agent,
    card_caps: Option<CardCaps>,
}

impl ScdClient {
    /// Open a CardApp that uses an scdaemon instance as its backend.
    /// The specific card with AID `serial` is requested from scdaemon.
    pub fn open_by_serial(
        agent: Option<Agent>,
        serial: &str,
    ) -> Result<Self, Error> {
        let mut card = ScdClient::new(agent, true)?;
        card.select_card(serial)?;

        <dyn CardTransaction>::initialize(&mut card)?;

        Ok(card)
    }

    /// Open a CardApp that uses an scdaemon instance as its backend.
    ///
    /// If multiple cards are available, scdaemon implicitly selects one.
    ///
    /// (NOTE: implicitly picking an unspecified card might be a bad idea.
    /// You might want to avoid using this function.)
    pub fn open_yolo(agent: Option<Agent>) -> Result<Self, Error> {
        let mut card = ScdClient::new(agent, true)?;

        <dyn CardTransaction>::initialize(&mut card)?;

        Ok(card)
    }

    /// Helper fn that shuts down scdaemon via GnuPG Agent.
    /// This may be useful to obtain access to a Smard card via PCSC.
    pub fn shutdown_scd(agent: Option<Agent>) -> Result<()> {
        let mut scdc = Self::new(agent, false)?;

        scdc.send("SCD RESTART")?;
        scdc.send("SCD BYE")?;

        Ok(())
    }

    /// Initialize an ScdClient object that is connected to an scdaemon
    /// instance via a GnuPG `agent` instance.
    ///
    /// If `agent` is None, a Context with the default GnuPG home directory
    /// is used.
    fn new(agent: Option<Agent>, init: bool) -> Result<Self> {
        let agent = if let Some(agent) = agent {
            agent
        } else {
            // Create and use a new Agent based on a default Context
            let ctx = Context::new()?;
            RT.lock().unwrap().block_on(Agent::connect(&ctx))?
        };

        let mut scdc = Self {
            agent,
            card_caps: None,
        };

        if init {
            scdc.serialno()?;
        }

        Ok(scdc)
    }

    /// Call "SCD SERIALNO", which causes scdaemon to be started by gpg
    /// agent (if it's not running yet).
    fn serialno(&mut self) -> Result<()> {
        let mut rt = RT.lock().unwrap();

        let send = "SCD SERIALNO";
        self.agent.send(send)?;

        while let Some(response) = rt.block_on(self.agent.next()) {
            log::debug!("init res: {:x?}", response);

            if let Ok(Response::Status { .. }) = response {
                // drop remaining lines
                while let Some(_drop) = rt.block_on(self.agent.next()) {
                    log::trace!("init drop: {:x?}", _drop);
                }

                return Ok(());
            }
        }

        Err(anyhow!("SCDC init() failed"))
    }

    /// Ask scdameon to switch to using a specific OpenPGP card, based on
    /// its `serial`.
    fn select_card(&mut self, serial: &str) -> Result<()> {
        let send = format!("SCD SERIALNO --demand={}", serial);
        self.agent.send(send)?;

        let mut rt = RT.lock().unwrap();

        while let Some(response) = rt.block_on(self.agent.next()) {
            log::debug!("select res: {:x?}", response);

            if response.is_err() {
                return Err(anyhow!("Card not found"));
            }

            if let Ok(Response::Status { .. }) = response {
                // drop remaining lines
                while let Some(_drop) = rt.block_on(self.agent.next()) {
                    log::debug!("select drop: {:x?}", _drop);
                }

                return Ok(());
            }
        }

        Err(anyhow!("Card not found"))
    }

    fn send(&mut self, cmd: &str) -> Result<()> {
        self.agent.send(cmd)?;

        let mut rt = RT.lock().unwrap();

        while let Some(response) = rt.block_on(self.agent.next()) {
            log::debug!("select res: {:x?}", response);

            if let Err(e) = response {
                return Err(anyhow!("Err {:?}", e));
            }

            if let Ok(..) = response {
                // drop remaining lines
                while let Some(_drop) = rt.block_on(self.agent.next()) {
                    log::debug!(" drop: {:x?}", _drop);
                }

                return Ok(());
            }
        }

        Err(anyhow!("Error sending command {}", cmd))
    }
}

impl CardTransaction for ScdClient {
    fn transmit(&mut self, cmd: &[u8], _: usize) -> Result<Vec<u8>, Error> {
        log::trace!("SCDC cmd len {}", cmd.len());

        let hex = hex::encode(cmd);

        // (Unwrap is ok here, not having a card_caps is fine)
        let ext = if self.card_caps.is_some()
            && self.card_caps.unwrap().ext_support()
        {
            // If we know about card_caps, and can do extended length we
            // set "exlen" accordingly ...
            format!("--exlen={} ", self.card_caps.unwrap().max_rsp_bytes())
        } else {
            // ... otherwise don't send "exlen" to scdaemon
            "".to_string()
        };

        let send = format!("SCD APDU {}{}\n", ext, hex);
        log::debug!("SCDC command: '{}'", send);

        if send.len() > ASSUAN_LINELENGTH {
            return Err(Error::InternalError(anyhow!(
                "APDU command is too long ({}) to send via Assuan",
                send.len()
            )));
        }

        self.agent.send(send)?;

        let mut rt = RT.lock().unwrap();

        while let Some(response) = rt.block_on(self.agent.next()) {
            log::debug!("res: {:x?}", response);
            if response.is_err() {
                return Err(Error::InternalError(anyhow!(
                    "Unexpected error response from SCD {:?}",
                    response
                )));
            }

            if let Ok(Response::Data { partial }) = response {
                let res = partial;

                // drop remaining lines
                while let Some(drop) = rt.block_on(self.agent.next()) {
                    log::trace!("drop: {:x?}", drop);
                }

                return Ok(res);
            }
        }

        Err(Error::InternalError(anyhow!("no response found")))
    }

    fn init_card_caps(&mut self, caps: CardCaps) {
        self.card_caps = Some(caps);
    }

    fn card_caps(&self) -> Option<&CardCaps> {
        self.card_caps.as_ref()
    }

    /// Return limit for APDU command size via scdaemon (based on Assuan
    /// maximum line length)
    fn max_cmd_len(&self) -> Option<usize> {
        Some(APDU_CMD_BYTES_MAX)
    }

    /// FIXME: not implemented yet
    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    /// FIXME: not implemented yet
    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    /// FIXME: not implemented yet
    fn pinpad_verify(&mut self, _id: u8) -> Result<Vec<u8>> {
        unimplemented!()
    }

    /// FIXME: not implemented yet
    fn pinpad_modify(&mut self, _id: u8) -> Result<Vec<u8>> {
        unimplemented!()
    }
}
