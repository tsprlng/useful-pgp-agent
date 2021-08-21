// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Commands and responses to commands ("Application Protocol Data Unit")

pub(crate) mod command;
pub(crate) mod commands;
pub mod response;

use anyhow::Result;
use std::convert::TryFrom;

use crate::apdu::command::Command;
use crate::apdu::response::RawResponse;
use crate::errors::{OcErrorStatus, OpenpgpCardError};
use crate::CardClientBox;

// "Maximum amount of bytes in a short APDU command or response" (from pcsc)
const MAX_BUFFER_SIZE: usize = 264;

#[derive(Clone, Copy, PartialEq, Debug)]
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
) -> Result<RawResponse, OpenpgpCardError> {
    let mut resp = RawResponse::try_from(send_command_low_level(
        card_client,
        cmd,
        expect_reply,
    )?)?;

    while resp.status().0 == 0x61 {
        // More data is available for this command from the card

        log::debug!(" response was truncated, getting more data");

        // Get additional data
        let next = RawResponse::try_from(send_command_low_level(
            card_client,
            commands::get_response(),
            expect_reply,
        )?)?;

        // FIXME: first check for 0x61xx or 0x9000?
        log::debug!(" appending {} bytes to response", next.raw_data().len());

        // Append new data to resp.data and overwrite status.
        resp.raw_mut_data().extend_from_slice(next.raw_data());
        resp.set_status(next.status());
    }

    log::debug!(" final response len: {}", resp.raw_data().len());

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
) -> Result<Vec<u8>, OpenpgpCardError> {
    let (ext_support, chaining_support, mut max_cmd_bytes, max_rsp_bytes) =
        if let Some(caps) = card_client.get_caps() {
            log::debug!("found card caps data!");

            (
                caps.ext_support,
                caps.chaining_support,
                caps.max_cmd_bytes as usize,
                caps.max_rsp_bytes as usize,
            )
        } else {
            log::debug!("found NO card caps data!");

            // default settings
            (false, false, 255, 255)
        };

    // If the CardClient implementation has an inherent limit for the cmd
    // size, take that limit into account.
    // (E.g. when using scdaemon as a CardClient backend, there is a
    // limitation to 1000 bytes length for Assuan commands, which
    // translates to maximum command length of a bit under 500 bytes)
    if let Some(max_cardclient_cmd_bytes) = card_client.max_cmd_len() {
        max_cmd_bytes = usize::min(max_cmd_bytes, max_cardclient_cmd_bytes);
    }

    log::debug!(
        "ext le/lc {}, chaining {}, max cmd {}, max rsp {}",
        ext_support,
        chaining_support,
        max_cmd_bytes,
        max_rsp_bytes
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

    log::debug!(" -> full APDU command: {:x?}", cmd);

    let buf_size = if !ext_support || ext == Le::Short {
        MAX_BUFFER_SIZE
    } else {
        max_rsp_bytes
    };

    log::trace!("buf_size {}", buf_size);

    if chaining_support && !cmd.data.is_empty() {
        // Send command in chained mode

        log::debug!("chained command mode");

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

            log::debug!(" -> chunked APDU command: {:x?}", &serialized);

            let resp = card_client.transmit(&serialized, buf_size)?;

            log::debug!(" <- APDU chunk response: {:x?}", &resp);

            if resp.len() < 2 {
                return Err(OpenpgpCardError::ResponseLength(resp.len()));
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

        // Can't send this command to the card, because it is too long and
        // the card doesn't support command chaining.
        if serialized.len() > max_cmd_bytes {
            return Err(OpenpgpCardError::CommandTooLong(serialized.len()));
        }

        log::debug!(" -> APDU command: {:x?}", &serialized);

        let resp = card_client.transmit(&serialized, buf_size)?;

        log::debug!(" <- APDU response: {:x?}", resp);

        Ok(resp)
    }
}
