// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! APDU "Application Protocol Data Unit"
//! Commands and responses to commands

pub(crate) mod command;
pub mod response;

use std::convert::TryFrom;

use card_backend::{CardCaps, CardTransaction};

use crate::ocard::apdu::command::{Command, Expect};
use crate::ocard::apdu::response::RawResponse;
use crate::ocard::commands;
use crate::ocard::StatusBytes;
use crate::Error;

/// "Maximum amount of bytes in a short APDU command or response" (from pcsc)
const MAX_BUFFER_SIZE: usize = 264;

/// Send a Command and return the result as a Response.
///
/// If the reply is truncated, this fn assembles all the parts and returns
/// them as one aggregated Response.
pub(crate) fn send_command<C>(
    card_tx: &mut C,
    cmd: Command,
    card_caps: Option<CardCaps>,
    expect_reply: bool,
) -> Result<RawResponse, Error>
where
    C: CardTransaction + ?Sized,
{
    log::debug!(" -> full APDU command: {:02x?}", cmd);

    let mut resp = RawResponse::try_from(send_command_low_level(
        card_tx,
        cmd.clone(),
        card_caps,
        if expect_reply {
            Expect::Some
        } else {
            Expect::Empty
        },
    )?)?;

    if let StatusBytes::UnknownStatus(0x6c, size) = resp.status() {
        resp = RawResponse::try_from(send_command_low_level(
            card_tx,
            cmd,
            card_caps,
            Expect::Short(size),
        )?)?;
    }

    while let StatusBytes::OkBytesAvailable(bytes) = resp.status() {
        // More data is available for this command from the card
        log::trace!(" chained response, getting more data");

        // Get next chunk of data
        let next = RawResponse::try_from(send_command_low_level(
            card_tx,
            commands::get_response(),
            card_caps,
            Expect::Short(bytes),
        )?)?;

        match next.status() {
            StatusBytes::OkBytesAvailable(_) | StatusBytes::Ok => {
                log::trace!(" appending {} bytes to response", next.raw_data().len());

                // Append new data to resp.data and overwrite status.
                resp.raw_mut_data().extend_from_slice(next.raw_data());
                resp.set_status(next.status());
            }
            error => return Err(error.into()),
        }
    }

    log::debug!(
        " <- APDU response [len {}]: {:02x?}",
        resp.raw_data().len(),
        resp
    );

    Ok(resp)
}

/// Send the given Command (chained, if required) to the card and
/// return the response as a vector of `u8`.
///
/// If the response is chained, this fn only returns one chunk, the caller
/// needs to re-assemble the chained response-parts.
fn send_command_low_level<C>(
    card_tx: &mut C,
    cmd: Command,
    card_caps: Option<CardCaps>,
    expect_response: Expect,
) -> Result<Vec<u8>, Error>
where
    C: CardTransaction + ?Sized,
{
    let (ext_support, chaining_support, max_cmd_bytes, max_rsp_bytes) =
        if let Some(caps) = card_caps {
            log::trace!("found card caps data!");

            (
                caps.ext_support(),
                caps.chaining_support(),
                caps.max_cmd_bytes() as usize,
                caps.max_rsp_bytes() as usize,
            )
        } else {
            log::trace!("found NO card caps data!");

            // default settings
            (false, false, 255, 255)
        };

    log::trace!(
        "ext le/lc {}, chaining {}, max cmd {}, max rsp {}",
        ext_support,
        chaining_support,
        max_cmd_bytes,
        max_rsp_bytes
    );

    // Decide if we want to use "extended length fields".
    //
    // Current approach: we only use extended length if the card supports it,
    // and only if the current command has more than 255 bytes of data.
    //
    // (This could be a problem with cards that don't support chained
    // responses, when a response if >255 bytes long - e.g. getting public
    // key data from cards?)
    let ext_len = ext_support && (max_cmd_bytes > 0xFF);

    let buf_size = if !ext_len {
        MAX_BUFFER_SIZE
    } else {
        max_rsp_bytes
    };

    log::trace!("buf_size {}", buf_size);

    if chaining_support && !cmd.data().is_empty() {
        // Send command in chained mode

        log::trace!("chained command mode");

        let cmd_chunk_size = if ext_support { max_cmd_bytes } else { 255 };

        // Break up payload into chunks that fit into one command, each
        let chunks: Vec<_> = cmd.data().chunks(cmd_chunk_size).collect();

        for (i, d) in chunks.iter().enumerate() {
            let last = i == chunks.len() - 1;

            let cla = if last { 0x00 } else { 0x10 };
            let partial = Command::new(cla, cmd.ins(), cmd.p1(), cmd.p2(), d.to_vec());

            let serialized = partial.serialize(ext_len, expect_response)?;

            log::trace!(" -> chained APDU command: {:02x?}", &serialized);

            let resp = card_tx.transmit(&serialized, buf_size)?;

            log::trace!(" <- APDU response: {:02x?}", &resp);

            if resp.len() < 2 {
                return Err(Error::ResponseLength(resp.len()));
            }

            if !last {
                // check that the returned status is ok
                let sw1 = resp[resp.len() - 2];
                let sw2 = resp[resp.len() - 1];

                let status = StatusBytes::from((sw1, sw2));

                // ISO: "If SW1-SW2 is set to '6883', then the last
                // command of the chain is expected."
                if !(status == StatusBytes::Ok || status == StatusBytes::LastCommandOfChainExpected)
                {
                    // Unexpected status for a non-final chunked response
                    return Err(status.into());
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
        let serialized = cmd.serialize(ext_len, expect_response)?;

        // Can't send this command to the card, because it is too long and
        // the card doesn't support command chaining.
        if serialized.len() > max_cmd_bytes {
            return Err(Error::CommandTooLong(serialized.len()));
        }

        log::trace!(" -> APDU command: {:02x?}", &serialized);

        let resp = card_tx.transmit(&serialized, buf_size)?;

        log::trace!(" <- APDU response: {:02x?}", resp);

        Ok(resp)
    }
}
