// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This crate implements the `PcscClient` backend for the `openpgp-card`
//! crate, which uses the PCSC lite middleware to access the OpenPGP
//! application on smart cards.

use anyhow::{anyhow, Result};
use iso7816_tlv::simple::Tlv;
use pcsc::{Card, Context, Protocols, Scope, ShareMode, Transaction};
use std::collections::HashMap;
use std::convert::TryInto;

use openpgp_card::card_do::ApplicationRelatedData;
use openpgp_card::{CardApp, CardCaps, CardClient, Error, SmartcardError};

const FEATURE_VERIFY_PIN_DIRECT: u8 = 0x06;
const FEATURE_MODIFY_PIN_DIRECT: u8 = 0x07;

#[macro_export]
macro_rules! start_tx {
    ($card:expr, $reselect:expr) => {{
        use pcsc::{Disposition, Protocols, ShareMode};

        let mut was_reset = false;

        loop {
            let res = $card.transaction();

            match res {
                Ok(mut tx) => {
                    // A transaction has been successfully started

                    if was_reset {
                        log::debug!(
                            "start_tx: card was reset, select() openpgp"
                        );

                        let mut txc = PcscTxClient::new(&mut tx, None);
                        if $reselect {
                            PcscTxClient::select(&mut txc)?;
                        }
                    }

                    break Ok(tx);
                }
                Err(pcsc::Error::ResetCard) => {
                    // Card was reset, need to reconnect
                    was_reset = true;

                    drop(res);

                    log::debug!("start_tx: do reconnect");

                    {
                        $card
                            .reconnect(
                                ShareMode::Shared,
                                Protocols::ANY,
                                Disposition::ResetCard,
                            )
                            .map_err(|e| {
                                Error::Smartcard(SmartcardError::Error(
                                    format!("Reconnect failed: {:?}", e),
                                ))
                            })?;
                    }

                    log::debug!("start_tx: reconnected.");

                    // -> try opening a transaction again
                }
                Err(e) => {
                    log::debug!("start_tx: error {:?}", e);
                    break Err(Error::Smartcard(SmartcardError::Error(
                        format!("Error: {:?}", e),
                    )));
                }
            };
        }
    }};
}

/// An implementation of the CardClient trait that uses the PCSC lite
/// middleware to access the OpenPGP card application on smart cards.
pub struct PcscClient {
    card: Card,
    card_caps: Option<CardCaps>,
    reader_caps: HashMap<u8, Tlv>,
}

pub struct PcscTxClient<'a, 'b> {
    tx: &'a mut Transaction<'b>,
    card_caps: Option<CardCaps>,
}

impl<'a, 'b> PcscTxClient<'a, 'b> {
    pub fn new(
        tx: &'a mut Transaction<'b>,
        card_caps: Option<CardCaps>,
    ) -> Self {
        PcscTxClient { tx, card_caps }
    }
}

impl<'a, 'b> PcscTxClient<'a, 'b> {
    /// Try to select the OpenPGP application on a card
    pub fn select(card_client: &'a mut PcscTxClient) -> Result<(), Error> {
        if <dyn CardClient>::select(card_client).is_ok() {
            Ok(())
        } else {
            Err(Error::Smartcard(SmartcardError::SelectOpenPGPCardFailed))
        }
    }

    /// Get application_related_data from card
    fn application_related_data(
        card_client: &mut PcscTxClient,
    ) -> Result<ApplicationRelatedData, Error> {
        <dyn CardClient>::application_related_data(card_client).map_err(|e| {
            Error::Smartcard(SmartcardError::Error(format!(
                "TxClient: failed to get application_related_data {:x?}",
                e
            )))
        })
    }
}

impl CardClient for PcscTxClient<'_, '_> {
    fn transmit(
        &mut self,
        cmd: &[u8],
        buf_size: usize,
    ) -> Result<Vec<u8>, Error> {
        let mut resp_buffer = vec![0; buf_size];

        let resp =
            self.tx
                .transmit(cmd, &mut resp_buffer)
                .map_err(|e| match e {
                    pcsc::Error::NotTransacted => {
                        Error::Smartcard(SmartcardError::NotTransacted)
                    }
                    _ => Error::Smartcard(SmartcardError::Error(format!(
                        "Transmit failed: {:?}",
                        e
                    ))),
                })?;

        log::debug!(" <- APDU response: {:x?}", resp);

        Ok(resp.to_vec())
    }

    fn init_card_caps(&mut self, caps: CardCaps) {
        self.card_caps = Some(caps);
    }

    fn card_caps(&self) -> Option<&CardCaps> {
        self.card_caps.as_ref()
    }

    fn feature_pinpad_verify(&self) -> bool {
        todo!()
    }

    fn feature_pinpad_modify(&self) -> bool {
        todo!()
    }

    fn pinpad_verify(&mut self, _id: u8) -> Result<Vec<u8>> {
        todo!()
    }

    fn pinpad_modify(&mut self, _id: u8) -> Result<Vec<u8>> {
        todo!()
    }
}

impl PcscClient {
    pub fn card(&mut self) -> &mut Card {
        &mut self.card
    }

    /// A list of "raw" opened PCSC Cards (without selecting the OpenPGP card
    /// application)
    fn raw_pcsc_cards() -> Result<Vec<Card>, SmartcardError> {
        let ctx = match Context::establish(Scope::User) {
            Ok(ctx) => ctx,
            Err(err) => {
                log::debug!("Context::establish failed: {:?}", err);
                return Err(SmartcardError::ContextError(err.to_string()));
            }
        };

        // List available readers.
        let mut readers_buf = [0; 2048];
        let readers = match ctx.list_readers(&mut readers_buf) {
            Ok(readers) => readers,
            Err(err) => {
                log::debug!("list_readers failed: {:?}", err);
                return Err(SmartcardError::ReaderError(err.to_string()));
            }
        };

        log::debug!("readers: {:?}", readers);

        let mut found_reader = false;

        let mut cards = vec![];

        // Find a reader with a SmartCard.
        for reader in readers {
            // We've seen at least one smartcard reader
            found_reader = true;

            log::debug!("Checking reader: {:?}", reader);

            // Try connecting to card in this reader
            let card =
                match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
                    Ok(card) => card,
                    Err(pcsc::Error::NoSmartcard) => {
                        log::debug!("No Smartcard");

                        continue; // try next reader
                    }
                    Err(err) => {
                        log::warn!(
                            "Error connecting to card in reader: {:x?}",
                            err
                        );

                        continue;
                    }
                };

            log::debug!("Found card");

            cards.push(card);
        }

        if !found_reader {
            Err(SmartcardError::NoReaderFoundError)
        } else {
            Ok(cards)
        }
    }

    fn cards_filter(ident: Option<&str>) -> Result<Vec<PcscClient>, Error> {
        let mut cas: Vec<PcscClient> = vec![];

        for mut card in
            Self::raw_pcsc_cards().map_err(|sce| Error::Smartcard(sce))?
        {
            log::debug!("cards_filter: next card");

            let stat = card.status2_owned();
            log::debug!("cards_filter, status2: {:x?}", stat);

            let mut store_card = false;
            {
                // start transaction
                log::debug!("1");
                let mut tx: Transaction = start_tx!(card, false)?;

                let mut txc = PcscTxClient::new(&mut tx, None);
                log::debug!("3");
                {
                    if let Err(e) = PcscTxClient::select(&mut txc) {
                        log::debug!("4a");
                        log::debug!(
                            "cards_filter: error during select: {:?}",
                            e
                        );
                    } else {
                        log::debug!(
                            "4b: opened the OpenPGP application, will read ARD"
                        );
                        // successfully opened the OpenPGP application

                        // -- debug: status --
                        drop(txc);
                        let stat = tx.status2_owned().map_err(|e| {
                            Error::Smartcard(SmartcardError::Error(format!(
                                "{:?}",
                                e
                            )))
                        })?;
                        log::debug!("4b card status: {:x?}", stat);
                        let mut txc = PcscTxClient::new(&mut tx, None);
                        // -- /debug: status --

                        if let Some(ident) = ident {
                            if let Ok(ard) =
                                PcscTxClient::application_related_data(
                                    &mut txc,
                                )
                            {
                                let aid = ard.application_id()?;

                                if aid.ident() == ident.to_ascii_uppercase() {
                                    // FIXME: handle multiple cards with matching ident
                                    log::debug!(
                                    "open_by_ident: Opened and selected {:?}",
                                    ident
                                );

                                    // we want to return this one card
                                    store_card = true;
                                } else {
                                    log::debug!(
                                    "open_by_ident: Found, but won't use {:?}",
                                    aid.ident()
                                );

                                    // FIXME: end transaction
                                    // txc.end();
                                }
                            } else {
                                // couldn't read ARD for this card ...
                                // ignore and move on
                                continue;
                            }
                        } else {
                            // we want to return all cards
                            store_card = true;
                        }
                    }
                }

                // transaction ends
                // drop(txc);
                // drop(tx);
            }

            if store_card {
                let pcsc = PcscClient::new(card);
                cas.push(pcsc.initialize_card()?);
            }
        }

        log::debug!("cards_filter: found {} cards", cas.len());

        Ok(cas)
    }

    /// Return all cards on which the OpenPGP application could be selected.
    ///
    /// Each card has the OpenPGP application selected, CardCaps have been
    /// initialized.
    pub fn cards() -> Result<Vec<PcscClient>, Error> {
        Self::cards_filter(None)
    }

    /// Returns the OpenPGP card that matches `ident`, if it is available.
    /// A fully initialized CardApp is returned: the OpenPGP application has
    /// been selected, CardCaps have been set.
    pub fn open_by_ident(ident: &str) -> Result<PcscClient, Error> {
        log::debug!("open_by_ident for {:?}", ident);

        let mut cards = Self::cards_filter(Some(ident))?;

        if !cards.is_empty() {
            // FIXME: handle >1 cards found

            Ok(cards.pop().unwrap())
        } else {
            Err(Error::Smartcard(SmartcardError::CardNotFound(
                ident.to_string(),
            )))
        }
    }

    fn new(card: Card) -> Self {
        Self {
            card,
            card_caps: None,
            reader_caps: HashMap::new(),
        }
    }

    /// Make an initialized CardApp from a PcscClient.
    /// Obtain and store feature lists from reader (pinpad functionality).
    fn initialize_card(mut self) -> Result<Self> {
        log::debug!("pcsc initialize_card");

        // Get Features from reader (pinpad verify/modify)
        if let Ok(feat) = self.features() {
            for tlv in feat {
                log::debug!("Found reader feature {:?}", tlv);
                self.reader_caps.insert(tlv.tag().into(), tlv);
            }
        }

        // Get initalized CardApp
        CardApp::initialize(&mut self)?;

        Ok(self)
    }

    /// Get the minimum pin length for pin_id.
    fn min_pin_len(&self, pin_id: u8) -> Result<u8> {
        match pin_id {
            0x81 | 0x82 => Ok(6),
            0x83 => Ok(8),
            _ => Err(anyhow!("Unexpected pin_id {}", pin_id)),
        }
    }
    /// Get the maximum pin length for pin_id.
    fn max_pin_len(&self, pin_id: u8) -> Result<u8> {
        if let Some(card_caps) = self.card_caps {
            match pin_id {
                0x81 | 0x82 => Ok(card_caps.pw1_max_len()),
                0x83 => Ok(card_caps.pw3_max_len()),
                _ => Err(anyhow!("Unexpected pin_id {}", pin_id)),
            }
        } else {
            Err(anyhow!("card_caps is None"))
        }
    }

    /// GET_FEATURE_REQUEST
    /// (see http://pcscworkgroup.com/Download/Specifications/pcsc10_v2.02.09.pdf)
    fn features(&mut self) -> Result<Vec<Tlv>, Error> {
        let mut recv = vec![0; 1024];

        let cm_ioctl_get_feature_request = pcsc::ctl_code(3400);
        let res = self
            .card
            .control(cm_ioctl_get_feature_request, &[], &mut recv)
            .map_err(|e| {
                Error::Smartcard(SmartcardError::Error(format!(
                    "GET_FEATURE_REQUEST control call failed: {:?}",
                    e
                )))
            })?;

        Ok(Tlv::parse_all(res))
    }

    pub fn card_caps(&self) -> Option<CardCaps> {
        self.card_caps
    }
}

impl CardClient for PcscClient {
    fn transmit(
        &mut self,
        cmd: &[u8],
        buf_size: usize,
    ) -> Result<Vec<u8>, Error> {
        let stat = self.card.status2_owned();
        log::debug!("PcscClient transmit - status2: {:x?}", stat);

        let mut tx: Transaction = start_tx!(self.card, true)?;

        log::debug!("PcscClient transmit 2");
        let mut txc = PcscTxClient::new(&mut tx, self.card_caps);
        log::debug!("PcscClient transmit 3 (got TxClient!)");

        let res = txc.transmit(cmd, buf_size);

        log::debug!("PcscClient transmit res {:x?}", res);

        res
    }

    fn init_card_caps(&mut self, caps: CardCaps) {
        self.card_caps = Some(caps);
    }

    fn card_caps(&self) -> Option<&CardCaps> {
        self.card_caps.as_ref()
    }

    fn feature_pinpad_verify(&self) -> bool {
        self.reader_caps.contains_key(&FEATURE_VERIFY_PIN_DIRECT)
    }

    fn feature_pinpad_modify(&self) -> bool {
        self.reader_caps.contains_key(&FEATURE_MODIFY_PIN_DIRECT)
    }

    fn pinpad_verify(&mut self, pin_id: u8) -> Result<Vec<u8>> {
        let pin_min_size = self.min_pin_len(pin_id)?;
        let pin_max_size = self.max_pin_len(pin_id)?;

        // Default to varlen, for now.
        // (NOTE: Some readers don't support varlen, and need explicit length
        // information. Also see https://wiki.gnupg.org/CardReader/PinpadInput)
        let fixedlen: u8 = 0;

        // APDU: 00 20 00 pin_id <len> (ff)*
        let mut ab_data = vec![
            0x00,     /* CLA */
            0x20,     /* INS: VERIFY */
            0x00,     /* P1 */
            pin_id,   /* P2 */
            fixedlen, /* Lc: 'fixedlen' data bytes */
        ];
        ab_data.extend([0xff].repeat(fixedlen as usize));

        // PC/SC v2.02.05 Part 10 PIN verification data structure
        let mut send: Vec<u8> = vec![
            // 0 bTimeOut BYTE timeout in seconds (00 means use default
            // timeout)
            0x00,
            // 1 bTimeOut2 BYTE timeout in seconds after first key stroke
            0x00,
            // 2 bmFormatString BYTE formatting options USB_CCID_PIN_FORMAT_xxx
            0x82,
            // 3 bmPINBlockString BYTE
            // bits 7-4 bit size of PIN length in APDU
            // bits 3-0 PIN block size in bytes after justification and formatting
            fixedlen,
            // 4 bmPINLengthFormat BYTE
            // bits 7-5 RFU, bit 4 set if system units are bytes clear if
            // system units are bits,
            // bits 3-0 PIN length position in system units
            0x00,
            // 5 wPINMaxExtraDigit USHORT XXYY, where XX is minimum PIN size
            // in digits, YY is maximum
            pin_max_size,
            pin_min_size,
            // 7 bEntryValidationCondition BYTE Conditions under which PIN
            // entry should be considered complete.
            //
            // table for bEntryValidationCondition:
            // 0x01: Max size reached
            // 0x02: Validation key pressed
            // 0x04: Timeout occurred
            0x07,
            // 8 bNumberMessage BYTE Number of messages to display for PIN
            // verification
            0x01,
            // 9 wLangIdU SHORT Language for messages
            0x04,
            0x09, // US english
            // 11 bMsgIndex BYTE Message index (should be 00)
            0x00,
            // 12 bTeoPrologue BYTE[3] T=1 I-block prologue field to use (fill with 00)
            0x00,
            0x00,
            0x00,
        ];

        // 15 ulDataLength ULONG length of Data to be sent to the ICC
        send.extend(&(ab_data.len() as u32).to_le_bytes());

        // 19 abData BYTE[] Data to send to the ICC
        send.extend(ab_data);

        log::debug!("pcsc pinpad_verify send: {:x?}", send);

        let mut recv = vec![0xAA; 256];

        let verify_ioctl: [u8; 4] = self
            .reader_caps
            .get(&FEATURE_VERIFY_PIN_DIRECT)
            .ok_or_else(|| anyhow!("no reader_capability"))?
            .value()
            .try_into()?;

        let res = self.card.control(
            u32::from_be_bytes(verify_ioctl).into(),
            &send,
            &mut recv,
        )?;

        log::debug!(" <- pcsc pinpad_verify result: {:x?}", res);

        Ok(res.to_vec())
    }

    fn pinpad_modify(&mut self, pin_id: u8) -> Result<Vec<u8>> {
        let pin_min_size = self.min_pin_len(pin_id)?;
        let pin_max_size = self.max_pin_len(pin_id)?;

        // Default to varlen, for now.
        // (NOTE: Some readers don't support varlen, and need explicit length
        // information. Also see https://wiki.gnupg.org/CardReader/PinpadInput)
        let fixedlen: u8 = 0;

        // APDU: 00 24 00 pin_id <len> [(ff)* x2]
        let mut ab_data = vec![
            0x00,         /* CLA */
            0x24,         /* INS: CHANGE_REFERENCE_DATA */
            0x00,         /* P1 */
            pin_id,       /* P2 */
            fixedlen * 2, /* Lc: 'fixedlen' data bytes */
        ];
        ab_data.extend([0xff].repeat(fixedlen as usize * 2));

        // PC/SC v2.02.05 Part 10 PIN modification data structure
        let mut send: Vec<u8> = vec![
            // 0 bTimeOut BYTE timeout in seconds (00 means use default
            // timeout)
            0x00,
            // 1 bTimeOut2 BYTE timeout in seconds after first key stroke
            0x00,
            // 2 bmFormatString BYTE formatting options USB_CCID_PIN_FORMAT_xxx
            0x82,
            // 3 bmPINBlockString BYTE
            // bits 7-4 bit size of PIN length in APDU
            // bits 3-0 PIN block size in bytes after justification and formatting
            fixedlen,
            // 4 bmPINLengthFormat BYTE
            // bits 7-5 RFU, bit 4 set if system units are bytes clear if
            // system units are bits,
            // bits 3-0 PIN length position in system units
            0x00,
            // 5 bInsertionOffsetOld BYTE Insertion position offset in bytes for
            // the current PIN
            0x00,
            // 6 bInsertionOffsetNew BYTE Insertion position offset in bytes for
            // the new PIN
            fixedlen,
            // 7 wPINMaxExtraDigit USHORT XXYY, where XX is minimum PIN size
            // in digits, YY is maximum
            pin_max_size,
            pin_min_size,
            // 9 bConfirmPIN
            0x03, // TODO check?
            // 10 bEntryValidationCondition BYTE Conditions under which PIN
            // entry should be considered complete.
            //
            // table for bEntryValidationCondition:
            // 0x01: Max size reached
            // 0x02: Validation key pressed
            // 0x04: Timeout occurred
            0x07,
            // 11 bNumberMessage BYTE Number of messages to display for PIN
            // verification
            0x03, // TODO check? (match with bConfirmPIN?)
            // 12 wLangId USHORT Language for messages
            0x04,
            0x09, // US english
            // 14 bMsgIndex1-3
            0x00,
            0x01,
            0x02,
            // 17 bTeoPrologue BYTE[3] T=1 I-block prologue field to use (fill with 00)
            0x00,
            0x00,
            0x00,
        ];

        // 15 ulDataLength ULONG length of Data to be sent to the ICC
        send.extend(&(ab_data.len() as u32).to_le_bytes());

        // 19 abData BYTE[] Data to send to the ICC
        send.extend(ab_data);

        log::debug!("pcsc pinpad_modify send: {:x?}", send);

        let mut recv = vec![0xAA; 256];

        let modify_ioctl: [u8; 4] = self
            .reader_caps
            .get(&FEATURE_MODIFY_PIN_DIRECT)
            .ok_or_else(|| anyhow!("no reader_capability"))?
            .value()
            .try_into()?;

        let res = self.card.control(
            u32::from_be_bytes(modify_ioctl).into(),
            &send,
            &mut recv,
        )?;

        log::debug!(" <- pcsc pinpad_modify result: {:x?}", res);

        Ok(res.to_vec())
    }
}
