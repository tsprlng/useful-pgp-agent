// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod command;
pub mod commands;
pub mod response;

use anyhow::{anyhow, Result};
use pcsc::Card;
use std::convert::TryFrom;

use crate::apdu::command::Command;
use crate::apdu::response::Response;
use crate::card;
use crate::card_app::CardApp;
use crate::errors::{OcErrorStatus, OpenpgpCardError, SmartcardError};
use crate::{CardBase, CardCaps, CardClient, CardClientBox};

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Le {
    None,
    Short,
    Long,
}

/// Send a Command and return the result as a Response.
///
/// If the reply is truncated, this fn assembles all the parts and returns
/// them as one aggregated Response.
pub(crate) fn send_command(
    card_client: &mut CardClientBox,
    cmd: Command,
    expect_reply: bool,
    card_caps: Option<&CardCaps>,
) -> Result<Response, OpenpgpCardError> {
    let mut resp = Response::try_from(send_command_low_level(
        card_client,
        cmd,
        expect_reply,
        card_caps,
    )?)?;

    while resp.status()[0] == 0x61 {
        // More data is available for this command from the card

        log::trace!(" response was truncated, getting more data");

        // Get additional data
        let next = Response::try_from(send_command_low_level(
            card_client,
            commands::get_response(),
            expect_reply,
            card_caps,
        )?)?;

        // FIXME: first check for 0x61xx or 0x9000?
        log::trace!(" appending {} bytes to response", next.raw_data().len());

        // Append new data to resp.data and overwrite status.
        resp.raw_mut_data().extend_from_slice(next.raw_data());
        resp.set_status(next.status());
    }

    log::trace!(" final response len: {}", resp.raw_data().len());

    Ok(resp)
}

/// Send the given Command (chained, if required) to the card and
/// return the response as a vector of `u8`.
///
/// If the response is chained, this fn only returns one chunk, the caller
/// needs take care of chained responses
fn send_command_low_level(
    card_client: &mut CardClientBox,
    cmd: Command,
    expect_reply: bool,
    card_caps: Option<&CardCaps>,
) -> Result<Vec<u8>, OpenpgpCardError> {
    let (ext_support, chaining_support, max_cmd_bytes) =
        if let Some(caps) = card_caps {
            log::trace!("found card caps data!");

            (
                caps.ext_support,
                caps.chaining_support,
                caps.max_cmd_bytes as usize,
            )
        } else {
            log::trace!("found NO card caps data!");

            // default settings
            (false, false, 255)
        };

    log::trace!(
        "ext le/lc {}, chaining {}, command chunk size {}",
        ext_support,
        chaining_support,
        max_cmd_bytes
    );

    // Set Le to 'long', if we're using an extended chunk size.
    //
    // According to the Card spec 3.4.1, pg 47,
    // 255 is the maximum value for 'Lc' in short mode:
    // "A short Lc field consists of one byte not set to '00' (1 to 255 dec.)"
    let ext = match (expect_reply, ext_support && max_cmd_bytes > 0xFF) {
        (false, _) => Le::None,
        (_, true) => Le::Long,
        _ => Le::Short,
    };

    log::trace!(" -> full APDU command: {:x?}", cmd);

    let buf_size = if !ext_support {
        pcsc::MAX_BUFFER_SIZE
    } else {
        pcsc::MAX_BUFFER_SIZE_EXTENDED
    };

    if chaining_support && !cmd.data.is_empty() {
        // Send command in chained mode

        log::trace!("chained command mode");

        // Break up payload into chunks that fit into one command, each
        let chunks: Vec<_> = cmd.data.chunks(max_cmd_bytes).collect();

        for (i, d) in chunks.iter().enumerate() {
            let last = i == chunks.len() - 1;
            let partial = Command {
                cla: if last { 0x00 } else { 0x10 },
                data: d.to_vec(),
                ..cmd
            };

            let serialized = partial
                .serialize(ext)
                .map_err(OpenpgpCardError::InternalError)?;
            log::trace!(" -> chunked APDU command: {:x?}", &serialized);

            let resp = card_client.transmit(&serialized, buf_size)?;

            log::trace!(" <- APDU chunk response: {:x?}", &resp);

            if resp.len() < 2 {
                return Err(OcErrorStatus::ResponseLength(resp.len()).into());
            }

            if !last {
                // check that the returned status is ok
                let sw1 = resp[resp.len() - 2];
                let sw2 = resp[resp.len() - 1];

                // ISO: "If SW1-SW2 is set to '6883', then the last
                // command of the chain is expected."
                if !((sw1 == 0x90 && sw2 == 0x00)
                    || (sw1 == 0x68 && sw2 == 0x83))
                {
                    // Unexpected status for a non-final chunked response
                    return Err(OcErrorStatus::from((sw1, sw2)).into());
                }

                // ISO: "If SW1-SW2 is set to '6884', then command
                // chaining is not supported."
            } else {
                // this is the last Response in the chain -> return
                return Ok(resp);
            }
        }
        unreachable!("This state should be unreachable");
    } else {
        let serialized = cmd.serialize(ext)?;

        let resp = card_client.transmit(&serialized, buf_size)?;

        log::trace!(" <- APDU response: {:x?}", resp);

        Ok(resp)
    }
}

pub struct PcscClient {
    card: Card,
}

impl PcscClient {
    fn new(card: Card) -> Self {
        Self { card }
    }

    pub fn list_cards() -> Result<Vec<PcscClient>> {
        Ok(card::get_cards()
            .map_err(|err| anyhow!(err))?
            .into_iter()
            .map(PcscClient::new)
            .collect())
    }

    /// Take a PCSC Card object and try to open the OpenPGP card applet.
    /// If successful, wrap and return the resulting CardClient as a
    /// CardBase object (which involves caching the "application related
    /// data").
    pub fn open(card: Card) -> Result<CardBase, OpenpgpCardError> {
        let card_client = PcscClient::new(card);
        let mut ccb = Box::new(card_client) as CardClientBox;

        let mut ca = CardApp::new(ccb);
        let resp = ca.select()?;

        if resp.is_ok() {
            CardBase::open_card(ca.take_card())
        } else {
            Err(anyhow!("Couldn't open OpenPGP application").into())
        }
    }
}

impl CardClient for PcscClient {
    fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>> {
        let mut resp_buffer = vec![0; buf_size];

        let resp = self.card.transmit(cmd, &mut resp_buffer).map_err(|e| {
            OpenpgpCardError::Smartcard(SmartcardError::Error(format!(
                "Transmit failed: {:?}",
                e
            )))
        })?;

        log::trace!(" <- APDU response: {:x?}", resp);

        Ok(resp.to_vec())
    }
}
