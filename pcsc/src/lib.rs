// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use pcsc::{Card, Context, Protocols, Scope, ShareMode};

use openpgp_card::{CardApp, CardCaps, CardClient, Error, SmartcardError};

pub struct PcscClient {
    card: Card,
    card_caps: Option<CardCaps>,
}

impl PcscClient {
    /// Return all cards on which the OpenPGP application could be selected.
    ///
    /// Each card has the OpenPGP application selected, CardCaps have been
    /// initialized.
    pub fn cards() -> Result<Vec<CardApp>> {
        let mut cards = vec![];

        for mut card in Self::unopened_cards()? {
            if Self::select(&mut card).is_ok() {
                if let Ok(ca) = card.into_card_app() {
                    cards.push(ca);
                }
            }
        }

        Ok(cards)
    }

    /// Returns the OpenPGP card that matches `ident`, if it is available.
    /// A fully initialized CardApp is returned: the OpenPGP application has
    /// been selected, CardCaps have been set.
    pub fn open_by_ident(ident: &str) -> Result<CardApp, Error> {
        for mut card in Self::unopened_cards()? {
            if Self::select(&mut card).is_ok() {
                let mut ca = card.into_card_app()?;

                let ard = ca.get_application_related_data()?;
                let aid = ard.get_application_id()?;

                if aid.ident() == ident.to_ascii_uppercase() {
                    return Ok(ca);
                }
            }
        }

        Err(Error::Smartcard(SmartcardError::CardNotFound(
            ident.to_string(),
        )))
    }

    fn new(card: Card) -> Self {
        Self {
            card,
            card_caps: None,
        }
    }

    /// Make an initialized CardApp from a PcscClient
    fn into_card_app(self) -> Result<CardApp> {
        CardApp::initialize(Box::new(self))
    }

    /// A list of "raw" opened PCSC Cards (without selecting the OpenPGP card
    /// application)
    fn raw_pcsc_cards() -> Result<Vec<Card>, SmartcardError> {
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
                    Err(pcsc::Error::NoSmartcard) => {
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
        Ok(Self::raw_pcsc_cards()
            .map_err(|err| anyhow!(err))?
            .into_iter()
            .map(PcscClient::new)
            .collect())
    }

    /// Try to select the OpenPGP application on a card
    fn select(card_client: &mut PcscClient) -> Result<(), Error> {
        if <dyn CardClient>::select(card_client).is_ok() {
            Ok(())
        } else {
            Err(Error::Smartcard(SmartcardError::SelectOpenPGPCardFailed))
        }
    }
}

impl CardClient for PcscClient {
    fn transmit(
        &mut self,
        cmd: &[u8],
        buf_size: usize,
    ) -> Result<Vec<u8>, Error> {
        let mut resp_buffer = vec![0; buf_size];

        let resp =
            self.card.transmit(cmd, &mut resp_buffer).map_err(
                |e| match e {
                    pcsc::Error::NotTransacted => {
                        Error::Smartcard(SmartcardError::NotTransacted)
                    }
                    _ => Error::Smartcard(SmartcardError::Error(format!(
                        "Transmit failed: {:?}",
                        e
                    ))),
                },
            )?;

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
