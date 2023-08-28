// SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This crate implements the traits [CardBackend] and [CardTransaction].
//! It uses the PCSC middleware to access smart cards.
//!
//! This crate is mainly intended for use by the `openpgp-card` crate.

use std::collections::HashMap;
use std::convert::TryInto;

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
use iso7816_tlv::simple::Tlv;
use pcsc::Disposition;

const FEATURE_VERIFY_PIN_DIRECT: u8 = 0x06;
const FEATURE_MODIFY_PIN_DIRECT: u8 = 0x07;

/// An opened PCSC Card (without open transaction).
/// Note: No application is `select`-ed on the card while setting up a PcscCard object.
///
/// This struct can be used to hold on to a Card, even while no operations
/// are performed on the Card. To perform operations on the card, a
/// [PcscTransaction] object needs to be obtained (via [PcscBackend::transaction]).
pub struct PcscBackend {
    card: pcsc::Card,
    mode: pcsc::ShareMode,
    reader_caps: HashMap<u8, Tlv>,
}

/// Boxing helper (for easier consumption of PcscBackend in openpgp_card and openpgp_card_sequoia)
impl From<PcscBackend> for Box<dyn CardBackend + Sync + Send> {
    fn from(backend: PcscBackend) -> Box<dyn CardBackend + Sync + Send> {
        Box::new(backend)
    }
}

/// An implementation of the CardTransaction trait that uses the PCSC lite
/// middleware to access the OpenPGP card application on smart cards, via a
/// PCSC "transaction".
///
/// This struct is created from a PcscCard by opening a transaction, using
/// PcscCard::transaction().
///
/// Transactions on a card cannot be opened and left idle
/// (e.g. Microsoft documents that on Windows, they will be closed after
/// 5s without a command:
/// <https://docs.microsoft.com/en-us/windows/win32/api/winscard/nf-winscard-scardbegintransaction?redirectedfrom=MSDN#remarks>)
pub struct PcscTransaction<'b> {
    tx: pcsc::Transaction<'b>,
    reader_caps: HashMap<u8, Tlv>, // FIXME: gets manually cloned
    was_reset: bool,
}

impl<'b> PcscTransaction<'b> {
    /// Start a transaction on `card`.
    ///
    /// If `reselect_application` is set, the application is SELECTed,
    /// if the card reports having been reset.
    fn new(
        card: &'b mut PcscBackend,
        reselect_application: Option<&[u8]>,
    ) -> Result<Self, SmartcardError> {
        log::trace!("Start a transaction");

        let mut was_reset = false;

        let mode = card.mode;
        let reader_caps = card.reader_caps.clone();

        let mut c = &mut card.card;

        loop {
            match c.transaction2() {
                Ok(tx) => {
                    // A pcsc transaction has been successfully started

                    let mut pt = Self {
                        tx,
                        reader_caps,
                        was_reset: false,
                    };

                    if was_reset {
                        log::trace!("Card was reset");

                        pt.was_reset = true;

                        // If the caller expects that an application on the
                        // card has been selected, re-select the application
                        // here.
                        //
                        // When initially opening a card, we don't do this
                        // (freshly opened cards don't have an application
                        // "SELECT"ed).
                        if let Some(app) = reselect_application {
                            log::trace!("Will re-select an application after card reset");

                            let mut res = CardTransaction::select(&mut pt, app)?;
                            log::trace!("select res: {:0x?}", res);

                            // Drop any bytes before the status code.
                            //
                            // e.g. SELECT on Basic Card 3.4 returns:
                            // [6f, 1d,
                            //  62, 15, 84, 10, d2, 76, 0, 1, 24, 1, 3, 4, 0, 5, 0, 0, a8, 35, 0, 0, 8a, 1, 5, 64, 4, 53, 2, c4, 41,
                            //  90, 0]
                            if res.len() > 2 {
                                res.drain(0..res.len() - 2);
                            }

                            if res != [0x90, 0x00] {
                                break Err(SmartcardError::Error(format!(
                                        "Error while attempting to (re-)select {:x?}, status code {:x?}",
                                        app, res
                                    )));
                            }

                            log::trace!("re-select ok");
                        }
                    }

                    break Ok(pt);
                }
                Err((c_, pcsc::Error::ResetCard)) => {
                    // Card was reset, need to reconnect
                    was_reset = true;

                    c = c_;

                    log::trace!("start_tx: do reconnect");

                    c.reconnect(mode, pcsc::Protocols::ANY, Disposition::ResetCard)
                        .map_err(|e| SmartcardError::Error(format!("Reconnect failed: {e:?}")))?;

                    log::trace!("start_tx: reconnected.");

                    // -> try opening a transaction again, in the next loop run
                }
                Err((_, e)) => {
                    log::trace!("start_tx: error {:?}", e);
                    break Err(SmartcardError::Error(format!("Error: {e:?}")));
                }
            };
        }
    }

    /// GET_FEATURE_REQUEST
    /// (see http://pcscworkgroup.com/Download/Specifications/pcsc10_v2.02.09.pdf)
    fn features(&mut self) -> Result<Vec<Tlv>, SmartcardError> {
        let mut recv = vec![0; 1024];

        let cm_ioctl_get_feature_request = pcsc::ctl_code(3400);
        let res = self
            .tx
            .control(cm_ioctl_get_feature_request, &[], &mut recv)
            .map_err(|e| {
                SmartcardError::Error(format!("GET_FEATURE_REQUEST control call failed: {e:?}"))
            })?;

        Ok(Tlv::parse_all(res))
    }

    /// Get the minimum pin length for pin_id.
    fn min_pin_len(&self, pin: PinType) -> u8 {
        match pin {
            PinType::User | PinType::Sign => 6,
            PinType::Admin => 8,
        }
    }

    /// Get the maximum pin length for pin_id.
    fn max_pin_len(
        &self,
        pin: PinType,
        card_caps: &Option<CardCaps>,
    ) -> Result<u8, SmartcardError> {
        if let Some(card_caps) = card_caps {
            match pin {
                PinType::User | PinType::Sign => Ok(card_caps.pw1_max_len()),
                PinType::Admin => Ok(card_caps.pw3_max_len()),
            }
        } else {
            Err(SmartcardError::Error("card_caps is None".into()))
        }
    }
}

impl CardTransaction for PcscTransaction<'_> {
    fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        let mut resp_buffer = vec![0; buf_size];

        let resp = self
            .tx
            .transmit(cmd, &mut resp_buffer)
            .map_err(|e| match e {
                pcsc::Error::NotTransacted => SmartcardError::NotTransacted,
                _ => SmartcardError::Error(format!("Transmit failed: {e:?}")),
            })?;

        Ok(resp.to_vec())
    }

    fn feature_pinpad_verify(&self) -> bool {
        self.reader_caps.contains_key(&FEATURE_VERIFY_PIN_DIRECT)
    }

    fn feature_pinpad_modify(&self) -> bool {
        self.reader_caps.contains_key(&FEATURE_MODIFY_PIN_DIRECT)
    }

    fn pinpad_verify(
        &mut self,
        pin: PinType,
        card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        let pin_min_size = self.min_pin_len(pin);
        let pin_max_size = self.max_pin_len(pin, card_caps)?;

        // Default to varlen, for now.
        // (NOTE: Some readers don't support varlen, and need explicit length
        // information. Also see https://wiki.gnupg.org/CardReader/PinpadInput)
        let fixedlen: u8 = 0;

        // APDU: 00 20 00 pin_id <len> (ff)*
        let mut ab_data = vec![
            0x00,     /* CLA */
            0x20,     /* INS: VERIFY */
            0x00,     /* P1 */
            pin.id(), /* P2 */
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
        send.extend((ab_data.len() as u32).to_le_bytes());

        // 19 abData BYTE[] Data to send to the ICC
        send.extend(ab_data);

        log::trace!("pcsc pinpad_verify send: {:x?}", send);

        let mut recv = vec![0xAA; 256];

        let verify_ioctl: [u8; 4] = self
            .reader_caps
            .get(&FEATURE_VERIFY_PIN_DIRECT)
            .ok_or_else(|| SmartcardError::Error("no reader_capability".into()))?
            .value()
            .try_into()
            .map_err(|e| SmartcardError::Error(format!("unexpected feature data: {e:?}")))?;

        let res = self
            .tx
            .control(u32::from_be_bytes(verify_ioctl).into(), &send, &mut recv)
            .map_err(|e: pcsc::Error| SmartcardError::Error(format!("pcsc Error: {e:?}")))?;

        log::trace!(" <- pcsc pinpad_verify result: {:x?}", res);

        Ok(res.to_vec())
    }

    fn pinpad_modify(
        &mut self,
        pin: PinType,
        card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        let pin_min_size = self.min_pin_len(pin);
        let pin_max_size = self.max_pin_len(pin, card_caps)?;

        // Default to varlen, for now.
        // (NOTE: Some readers don't support varlen, and need explicit length
        // information. Also see https://wiki.gnupg.org/CardReader/PinpadInput)
        let fixedlen: u8 = 0;

        // APDU: 00 24 00 pin_id <len> [(ff)* x2]
        let mut ab_data = vec![
            0x00,         /* CLA */
            0x24,         /* INS: CHANGE_REFERENCE_DATA */
            0x00,         /* P1 */
            pin.id(),     /* P2 */
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
        send.extend((ab_data.len() as u32).to_le_bytes());

        // 19 abData BYTE[] Data to send to the ICC
        send.extend(ab_data);

        log::trace!("pcsc pinpad_modify send: {:x?}", send);

        let mut recv = vec![0xAA; 256];

        let modify_ioctl: [u8; 4] = self
            .reader_caps
            .get(&FEATURE_MODIFY_PIN_DIRECT)
            .ok_or_else(|| SmartcardError::Error("no reader_capability".into()))?
            .value()
            .try_into()
            .map_err(|e| SmartcardError::Error(format!("unexpected feature data: {e:?}")))?;

        let res = self
            .tx
            .control(u32::from_be_bytes(modify_ioctl).into(), &send, &mut recv)
            .map_err(|e: pcsc::Error| SmartcardError::Error(format!("pcsc Error: {e:?}")))?;

        log::trace!(" <- pcsc pinpad_modify result: {:x?}", res);

        Ok(res.to_vec())
    }

    fn was_reset(&self) -> bool {
        self.was_reset
    }
}

impl PcscBackend {
    /// A list of "raw" opened PCSC Cards (without selecting any application)
    fn raw_pcsc_cards(mode: pcsc::ShareMode) -> Result<Vec<pcsc::Card>, SmartcardError> {
        log::trace!("raw_pcsc_cards start");

        let ctx = match pcsc::Context::establish(pcsc::Scope::User) {
            Ok(ctx) => ctx,
            Err(err) => {
                log::trace!("Context::establish failed: {:?}", err);
                return Err(SmartcardError::ContextError(err.to_string()));
            }
        };

        log::trace!("raw_pcsc_cards got context");

        // List available readers.
        let mut readers_buf = [0; 2048];
        let readers = match ctx.list_readers(&mut readers_buf) {
            Ok(readers) => readers,
            Err(err) => {
                log::trace!("list_readers failed: {:?}", err);
                return Err(SmartcardError::ReaderError(err.to_string()));
            }
        };

        log::trace!(" readers: {:?}", readers);

        let mut found_reader = false;

        let mut cards = vec![];

        // Find a reader with a SmartCard.
        for reader in readers {
            // We've seen at least one smartcard reader
            found_reader = true;

            log::trace!("Checking reader: {:?}", reader);

            // Try connecting to card in this reader
            let card = match ctx.connect(reader, mode, pcsc::Protocols::ANY) {
                Ok(card) => card,
                Err(pcsc::Error::NoSmartcard) => {
                    log::trace!("No Smartcard");

                    continue; // try next reader
                }
                Err(err) => {
                    log::warn!("Error connecting to card in reader: {:x?}", err);

                    continue;
                }
            };

            log::trace!("Found card");

            cards.push(card);
        }

        if !found_reader {
            Err(SmartcardError::NoReaderFoundError)
        } else {
            Ok(cards)
        }
    }

    /// Returns an Iterator over Smart Cards that are accessible via PCSC.
    ///
    /// No application is SELECTed on the cards.
    /// You can not assume that any particular application is available on the cards.
    pub fn cards(
        mode: Option<pcsc::ShareMode>,
    ) -> Result<impl Iterator<Item = Result<Self, SmartcardError>>, SmartcardError> {
        let mode = mode.unwrap_or(pcsc::ShareMode::Shared);

        let cards = Self::raw_pcsc_cards(mode)?;

        Ok(cards.into_iter().map(move |card| {
            let backend = PcscBackend {
                card,
                mode,
                reader_caps: Default::default(),
            };

            backend.initialize_card()
        }))
    }

    /// Returns an Iterator over Smart Cards that are accessible via PCSC.
    /// Like [Self::cards], but returns the cards as [CardBackend].
    pub fn card_backends(
        mode: Option<pcsc::ShareMode>,
    ) -> Result<
        impl Iterator<Item = Result<Box<dyn CardBackend + Send + Sync>, SmartcardError>>,
        SmartcardError,
    > {
        let cards = PcscBackend::cards(mode)?;

        Ok(cards.map(|c| match c {
            Ok(c) => Ok(Box::new(c) as Box<dyn CardBackend + Send + Sync>),
            Err(e) => Err(e),
        }))
    }

    /// Initialize this PcscBackend (obtains and stores feature lists from reader,
    /// to determine if the reader offers PIN pad functionality).
    fn initialize_card(mut self) -> Result<Self, SmartcardError> {
        log::trace!("pcsc initialize_card");

        let mut h: HashMap<u8, Tlv> = HashMap::default();

        let mut txc = PcscTransaction::new(&mut self, None)?;

        // Get Features from reader (pinpad verify/modify)
        if let Ok(feat) = txc.features() {
            for tlv in feat {
                log::trace!(" Found reader feature {:?}", tlv);
                h.insert(tlv.tag().into(), tlv);
            }
        }

        drop(txc);

        for (a, b) in h {
            self.reader_caps.insert(a, b);
        }

        Ok(self)
    }
}

impl CardBackend for PcscBackend {
    /// Get a CardTransaction for this PcscBackend (this starts a transaction)
    fn transaction(
        &mut self,
        reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        Ok(Box::new(PcscTransaction::new(self, reselect_application)?))
    }
}
