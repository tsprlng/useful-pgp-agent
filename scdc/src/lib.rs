// SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This crate implements the experimental `ScdBackend`/`ScdTransaction` backend for the
//! `openpgp-card` crate.
//! It uses GnuPG's scdaemon (via GnuPG Agent) to access smart cards (including OpenPGP cards).
//!
//! Note that (unlike `card-backend-pcsc`), this backend doesn't implement transaction guarantees.

use std::sync::Mutex;

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
use futures::StreamExt;
use lazy_static::lazy_static;
use sequoia_ipc::assuan::Response;
use sequoia_ipc::gnupg::{Agent, Context};
use tokio::runtime::Runtime;

lazy_static! {
    static ref RT: Mutex<Runtime> = Mutex::new(tokio::runtime::Runtime::new().unwrap());
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

/// The maximum number of bytes for a command that we can send to
/// scdaemon (via Assuan).
///
/// Each command byte gets sent via Assuan as a two-character hex string.
///
/// 17 characters are used to send "SCD APDU --exlen "
///
/// In concrete terms, this limit means that some commands (with big
/// parameters) cannot be sent to the card, when the card doesn't support
/// command chaining (like the floss-shop "OpenPGP Smart Card 3.4").
///
/// In particular, uploading rsa4096 keys fails via scdaemon, with such cards.
///
/// The value of "36" was experimentally determined:
/// This value results in the biggest APDU_CMD_BYTES_MAX that still allows
/// uploading an RSA4k key onto a YubiKey 5.
const APDU_CMD_BYTES_MAX: usize = (ASSUAN_LINELENGTH - 36) / 2;

/// An implementation of the CardBackend trait that uses GnuPG's scdaemon
/// (via GnuPG Agent) to access smart cards.
pub struct ScdBackend {
    agent: Agent,
}

/// Boxing helper (for easier consumption of PcscBackend in openpgp_card and openpgp_card_sequoia)
impl From<ScdBackend> for Box<dyn CardBackend + Sync + Send> {
    fn from(backend: ScdBackend) -> Box<dyn CardBackend + Sync + Send> {
        Box::new(backend)
    }
}

impl ScdBackend {
    /// Request card with AID `serial` from scdaemon, and return it as a ScdBackend.
    ///
    /// The client may provide a GnuPG `agent` to use.
    pub fn open_by_serial(agent: Option<Agent>, serial: &str) -> Result<Self, SmartcardError> {
        let mut card = ScdBackend::new(agent, true)?;
        card.select_by_serial(serial)?;

        Ok(card)
    }

    /// Open a CardApp that uses an scdaemon instance as its backend.
    ///
    /// If multiple cards are available, scdaemon implicitly selects one.
    ///
    /// (NOTE: implicitly picking an unspecified card might be a bad idea.
    /// You might want to avoid using this function, or check which card
    /// you received.)
    pub fn open_yolo(agent: Option<Agent>) -> Result<Self, SmartcardError> {
        let card = ScdBackend::new(agent, true)?;

        Ok(card)
    }

    /// Helper fn that shuts down scdaemon via GnuPG Agent.
    /// This may be useful to obtain access to a Smard card via PCSC.
    pub fn shutdown_scd(agent: Option<Agent>) -> Result<(), SmartcardError> {
        let mut scdc = Self::new(agent, false)?;

        scdc.execute("SCD RESTART")?;
        scdc.execute("SCD BYE")?;

        Ok(())
    }

    /// Initialize an ScdClient object that is connected to an scdaemon
    /// instance via a GnuPG `agent` instance.
    ///
    /// If `agent` is None, a Context with the default GnuPG home directory
    /// is used.
    fn new(agent: Option<Agent>, init: bool) -> Result<Self, SmartcardError> {
        let agent = agent.unwrap_or({
            let rt = RT.lock().unwrap();

            // Create and use a new Agent based on a default Context
            let ctx = Context::new()
                .map_err(|e| SmartcardError::Error(format!("Context::new failed {e}")))?;
            rt.block_on(Agent::connect(&ctx))
                .map_err(|e| SmartcardError::Error(format!("Agent::connect failed {e}")))?
        });

        let mut scdc = Self { agent };

        if init {
            scdc.serialno()?;
        }

        Ok(scdc)
    }

    /// Just send a command, without looking at the results at all
    fn send_cmd(&mut self, cmd: &str) -> Result<(), SmartcardError> {
        self.agent
            .send(cmd)
            .map_err(|e| SmartcardError::Error(format!("scdc agent send failed: {e}")))
    }

    /// Call "SCD SERIALNO", which causes scdaemon to be started by gpg-agent
    /// (if it's not running yet).
    fn serialno(&mut self) -> Result<(), SmartcardError> {
        let rt = RT.lock().unwrap();

        let cmd = "SCD SERIALNO";
        self.send_cmd(cmd)?;

        while let Some(response) = rt.block_on(self.agent.next()) {
            log::trace!("SCD SERIALNO res: {:x?}", response);

            if let Ok(Response::Status { .. }) = response {
                // drop remaining lines
                while let Some(_drop) = rt.block_on(self.agent.next()) {
                    log::trace!("init drop: {:x?}", _drop);
                }

                return Ok(());
            }
        }

        Err(SmartcardError::Error("SCDC init() failed".into()))
    }

    /// Ask scdaemon to switch to using a specific OpenPGP card, based on
    /// its `serial`.
    fn select_by_serial(&mut self, serial: &str) -> Result<(), SmartcardError> {
        let rt = RT.lock().unwrap();

        let send = format!("SCD SERIALNO --demand={serial}");
        self.send_cmd(&send)?;

        while let Some(response) = rt.block_on(self.agent.next()) {
            log::trace!("select res: {:x?}", response);

            if response.is_err() {
                return Err(SmartcardError::CardNotFound(serial.into()));
            }

            if let Ok(Response::Status { .. }) = response {
                // drop remaining lines
                while let Some(_drop) = rt.block_on(self.agent.next()) {
                    log::trace!("select drop: {:x?}", _drop);
                }

                return Ok(());
            }
        }

        Err(SmartcardError::CardNotFound(serial.into()))
    }

    fn execute(&mut self, cmd: &str) -> Result<(), SmartcardError> {
        let rt = RT.lock().unwrap();

        self.send_cmd(cmd)?;

        while let Some(response) = rt.block_on(self.agent.next()) {
            log::trace!("select res: {:x?}", response);

            if let Err(e) = response {
                return Err(SmartcardError::Error(format!("{e:?}")));
            }

            if response.is_ok() {
                // drop remaining lines
                while let Some(_drop) = rt.block_on(self.agent.next()) {
                    log::trace!(" drop: {:x?}", _drop);
                }

                return Ok(());
            }
        }

        Err(SmartcardError::Error(format!(
            "Error sending command {cmd}"
        )))
    }
}

impl CardBackend for ScdBackend {
    fn transaction(
        &mut self,
        _reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        Ok(Box::new(ScdTransaction { scd: self }))
    }
}

pub struct ScdTransaction<'a> {
    scd: &'a mut ScdBackend,
}

impl CardTransaction for ScdTransaction<'_> {
    fn transmit(&mut self, cmd: &[u8], _: usize) -> Result<Vec<u8>, SmartcardError> {
        log::trace!("SCDC cmd len {}", cmd.len());

        let hex = hex::encode(cmd);

        // Always set "--exlen" (without explicit parameter for length)
        //
        // FIXME: Does this ever cause problems?
        //
        // Hypothesis: this should be ok.
        // Allowing too big of a return value should not do any effective harm
        // (just maybe cause some slightly too large memory allocations).
        let ext = "--exlen ".to_string();

        let send = format!("SCD APDU {ext}{hex}");
        log::trace!("SCDC command: '{}'", send);

        if send.len() > ASSUAN_LINELENGTH {
            return Err(SmartcardError::Error(format!(
                "APDU command is too long ({}) to send via Assuan",
                send.len()
            )));
        }

        let rt = RT.lock().unwrap();

        self.scd.send_cmd(&send)?;

        while let Some(response) = rt.block_on(self.scd.agent.next()) {
            log::trace!("transmit res: {:x?}", response);
            if response.is_err() {
                return Err(SmartcardError::Error(format!(
                    "Unexpected error response from SCD {response:?}"
                )));
            }

            if let Ok(Response::Data { partial }) = response {
                let res = partial;

                // drop remaining lines
                while let Some(drop) = rt.block_on(self.scd.agent.next()) {
                    log::trace!("drop: {:x?}", drop);
                }

                return Ok(res);
            }
        }

        Err(SmartcardError::Error("no response found".into()))
    }

    /// Return limit for APDU command size via scdaemon (based on Assuan
    /// maximum line length)
    fn max_cmd_len(&self) -> Option<usize> {
        Some(APDU_CMD_BYTES_MAX)
    }

    /// Not implemented yet
    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    /// Not implemented yet
    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    /// Not implemented yet
    fn pinpad_verify(
        &mut self,
        _id: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        unimplemented!()
    }

    /// Not implemented yet
    fn pinpad_modify(
        &mut self,
        _id: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        unimplemented!()
    }
}
