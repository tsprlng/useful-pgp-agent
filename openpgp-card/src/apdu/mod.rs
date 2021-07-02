// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod command;
pub mod commands;
pub mod response;

use pcsc::Card;
use std::convert::TryFrom;

use crate::apdu::command::Command;
use crate::apdu::response::Response;
use crate::errors::{OcErrorStatus, OpenpgpCardError, SmartcardError};
use crate::CardBase;

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
    card: &Card,
    cmd: Command,
    ext: Le,
    oc: Option<&CardBase>,
) -> Result<Response, OpenpgpCardError> {
    let mut resp =
        Response::try_from(send_command_low_level(&card, cmd, ext, oc)?)?;

    while resp.status()[0] == 0x61 {
        // More data is available for this command from the card

        log::trace!(" response was truncated, getting more data");

        // Get additional data
        let next = Response::try_from(send_command_low_level(
            &card,
            commands::get_response(),
            ext,
            oc,
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
    card: &Card,
    cmd: Command,
    ext: Le,
    oc: Option<&CardBase>,
) -> Result<Vec<u8>, OpenpgpCardError> {
    log::trace!(" -> full APDU command: {:x?}", cmd);
    log::trace!("    serialized: {:x?}", cmd.serialize(ext));

    // default settings
    let mut ext_support = false;
    let mut chaining_support = false;
    let mut chunk_size = 255;

    // Get feature configuration from card metadata
    if let Some(oc) = oc {
        if let Ok(hist) = oc.get_historical() {
            if let Some(cc) = hist.get_card_capabilities() {
                chaining_support = cc.get_command_chaining();
                ext_support = cc.get_extended_lc_le();
            }
        }

        if let Ok(Some(eli)) = oc.get_extended_length_information() {
            chunk_size = eli.max_command_bytes as usize;
        }
    }

    log::trace!(
        "ext le/lc {}, chaining {}, command chunk size {}",
        ext_support,
        chaining_support,
        chunk_size
    );

    // update Le setting to 'long', if we're using a larger chunk size
    let ext = match (ext, chunk_size > 0xff) {
        (Le::None, _) => Le::None,
        (_, true) => Le::Long,
        _ => ext,
    };

    let buf_size = if !ext_support {
        pcsc::MAX_BUFFER_SIZE
    } else {
        pcsc::MAX_BUFFER_SIZE_EXTENDED
    };

    let mut resp_buffer = vec![0; buf_size];

    if chaining_support && !cmd.data.is_empty() {
        // Send command in chained mode

        log::trace!("chained command mode");

        // Break up payload into chunks that fit into one command, each
        let chunks: Vec<_> = cmd.data.chunks(chunk_size).collect();

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

            let resp =
                card.transmit(&serialized, &mut resp_buffer).map_err(|e| {
                    OpenpgpCardError::Smartcard(SmartcardError::Error(
                        format!("Transmit failed: {:?}", e),
                    ))
                })?;

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
                return Ok(resp.to_vec());
            }
        }
        unreachable!("This state should be unreachable");
    } else {
        let serialized = cmd.serialize(ext)?;

        let resp =
            card.transmit(&serialized, &mut resp_buffer).map_err(|e| {
                OpenpgpCardError::Smartcard(SmartcardError::Error(format!(
                    "Transmit failed: {:?}",
                    e
                )))
            })?;

        log::trace!(" <- APDU response: {:x?}", resp);

        Ok(resp.to_vec())
    }
}
