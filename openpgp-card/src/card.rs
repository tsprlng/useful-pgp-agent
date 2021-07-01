// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use pcsc::{Card, Context, Error, Protocols, Scope, ShareMode};

use crate::errors;

pub fn get_cards() -> Result<Vec<Card>, errors::SmartcardError> {
    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            return Err(errors::SmartcardError::ContextError(err.to_string()))
        }
    };

    // List available readers.
    let mut readers_buf = [0; 2048];
    let readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            return Err(errors::SmartcardError::ReaderError(err.to_string()));
        }
    };

    let mut found_reader = false;

    let mut cards = vec![];

    // Find a reader with a SmartCard.
    for reader in readers {
        // We've seen at least one smartcard reader
        found_reader = true;

        // Try connecting to card in this reader
        let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY)
        {
            Ok(card) => card,
            Err(Error::NoSmartcard) => {
                continue; // try next reader
            }
            Err(err) => {
                return Err(errors::SmartcardError::SmartCardConnectionError(
                    err.to_string(),
                ));
            }
        };

        cards.push(card);
    }

    if !found_reader {
        Err(errors::SmartcardError::NoReaderFoundError)
    } else {
        Ok(cards)
    }
}
