// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use pcsc::{Card, Context, Error, Protocols, Scope, ShareMode};

use openpgp_card::card_app::CardApp;
use openpgp_card::errors::{OpenpgpCardError, SmartcardError};
use openpgp_card::{CardCaps, CardClient, CardClientBox};

pub struct PcscClient {
    card: Card,
    card_caps: Option<CardCaps>,
}

impl PcscClient {
    fn new(card: Card) -> Self {
        Self {
            card,
            card_caps: None,
        }
    }

    /// Opened PCSC Cards without selecting the OpenPGP card application
    fn pcsc_cards() -> Result<Vec<Card>, SmartcardError> {
        let ctx = match Context::establish(Scope::User) {
            Ok(ctx) => ctx,
            Err(err) => {
                return Err(SmartcardError::ContextError(err.to_string()))
            }
        };

        // List available readers.
        let mut readers_buf = [0; 2048];
        let readers = match ctx.list_readers(&mut readers_buf) {
            Ok(readers) => readers,
            Err(err) => {
                return Err(SmartcardError::ReaderError(err.to_string()));
            }
        };

        let mut found_reader = false;

        let mut cards = vec![];

        // Find a reader with a SmartCard.
        for reader in readers {
            // We've seen at least one smartcard reader
            found_reader = true;

            // Try connecting to card in this reader
            let card =
                match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
                    Ok(card) => card,
                    Err(Error::NoSmartcard) => {
                        continue; // try next reader
                    }
                    Err(err) => {
                        return Err(SmartcardError::SmartCardConnectionError(
                            err.to_string(),
                        ));
                    }
                };

            cards.push(card);
        }

        if !found_reader {
            Err(SmartcardError::NoReaderFoundError)
        } else {
            Ok(cards)
        }
    }

    /// All PCSC cards, wrapped as PcscClient
    fn unopened_cards() -> Result<Vec<PcscClient>> {
        Ok(Self::pcsc_cards()
            .map_err(|err| anyhow!(err))?
            .into_iter()
            .map(PcscClient::new)
            .collect())
    }

    /// Return all cards on which the OpenPGP application could be selected.
    pub fn list_cards() -> Result<Vec<CardClientBox>> {
        let cards = Self::unopened_cards()?
            .into_iter()
            .map(Self::select)
            .map(|res| res.ok())
            .flatten()
            .map(|ca| ca.take_card())
            .collect();

        Ok(cards)
    }

    /// Try to select the OpenPGP application on a card
    fn select(card_client: PcscClient) -> Result<CardApp, OpenpgpCardError> {
        let ccb = Box::new(card_client) as CardClientBox;

        let mut ca = CardApp::new(ccb);
        if ca.select().is_ok() {
            Ok(ca)
        } else {
            Err(OpenpgpCardError::Smartcard(
                SmartcardError::SelectOpenPGPCardFailed,
            ))
        }
    }

    /// Returns the first OpenPGP card, with the OpenPGP application selected.
    ///
    /// If multiple cards are connected, this will effectively be a random
    /// pick. You should consider using `open_by_ident` instead.
    pub fn open_yolo() -> Result<CardClientBox, OpenpgpCardError> {
        for card in Self::unopened_cards()? {
            if let Ok(ca) = Self::select(card) {
                return Ok(ca.take_card());
            }
        }

        Err(OpenpgpCardError::Smartcard(SmartcardError::CardNotFound(
            "No OpenPGP card found".to_string(),
        )))
    }

    /// Get application related data from the card and check if 'ident'
    /// matches
    fn match_by_ident(
        mut ca: CardApp,
        ident: &str,
    ) -> Result<Option<CardClientBox>, OpenpgpCardError> {
        let ard = ca.get_app_data()?;
        let aid = CardApp::get_aid(&ard)?;

        if aid.ident() == ident {
            Ok(Some(ca.take_card()))
        } else {
            Ok(None)
        }
    }

    /// Returns the OpenPGP card that matches `ident`, if it is available.
    /// The OpenPGP application of the `CardClientBox` has been selected.
    pub fn open_by_ident(
        ident: &str,
    ) -> Result<CardClientBox, OpenpgpCardError> {
        for card in Self::unopened_cards()? {
            if let Ok(ca) = Self::select(card) {
                if let Some(matched_card) =
                    PcscClient::match_by_ident(ca, ident)?
                {
                    return Ok(matched_card);
                }
            }
        }

        Err(OpenpgpCardError::Smartcard(SmartcardError::CardNotFound(
            ident.to_string(),
        )))
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

        log::debug!(" <- APDU response: {:x?}", resp);

        Ok(resp.to_vec())
    }

    fn init_caps(&mut self, caps: CardCaps) {
        self.card_caps = Some(caps);
    }

    fn get_caps(&self) -> Option<&CardCaps> {
        self.card_caps.as_ref()
    }
}
