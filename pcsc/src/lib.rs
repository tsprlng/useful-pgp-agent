// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use iso7816_tlv::simple::Tlv;
use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use std::collections::HashMap;
use std::convert::TryInto;

use openpgp_card::{CardApp, CardCaps, CardClient, Error, SmartcardError};

const FEATURE_VERIFY_PIN_DIRECT: u8 = 0x06;
const FEATURE_MODIFY_PIN_DIRECT: u8 = 0x07;

pub struct PcscClient {
    card: Card,
    card_caps: Option<CardCaps>,
    reader_caps: HashMap<u8, Tlv>,
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

                let ard = ca.application_related_data()?;
                let aid = ard.application_id()?;

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
            reader_caps: HashMap::new(),
        }
    }

    /// Make an initialized CardApp from a PcscClient.
    /// Obtain and store feature lists from reader (pinpad functionality).
    fn into_card_app(mut self) -> Result<CardApp> {
        // Get Features from reader (pinpad verify/modify)
        let feat = self.features()?;
        for tlv in feat {
            log::debug!("Found reader feature {:?}", tlv);
            self.reader_caps.insert(tlv.tag().into(), tlv);
        }

        // Get initalized CardApp
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
                        log::warn!(
                            "Error connecting to card in reader: {:x?}",
                            err
                        );

                        continue;
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

        let cm_ioctl_get_feature_request = 0x42000000 + 3400;
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
            u32::from_be_bytes(verify_ioctl) as u64,
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
            u32::from_be_bytes(modify_ioctl) as u64,
            &send,
            &mut recv,
        )?;

        log::debug!(" <- pcsc pinpad_modify result: {:x?}", res);

        Ok(res.to_vec())
    }
}
