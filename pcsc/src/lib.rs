// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This crate implements the `CardBackend`/`CardTransaction` backend for
//! `openpgp-card`. It uses the PCSC middleware to access the OpenPGP
//! application on smart cards.

use std::collections::HashMap;
use std::convert::TryInto;

use iso7816_tlv::simple::Tlv;
use openpgp_card::card_do::ApplicationRelatedData;
use openpgp_card::{CardBackend, CardCaps, CardTransaction, Error, PinType, SmartcardError};

const FEATURE_VERIFY_PIN_DIRECT: u8 = 0x06;
const FEATURE_MODIFY_PIN_DIRECT: u8 = 0x07;

fn default_mode(mode: Option<pcsc::ShareMode>) -> pcsc::ShareMode {
    if let Some(mode) = mode {
        mode
    } else {
        pcsc::ShareMode::Shared
    }
}

/// An opened PCSC Card (without open transaction).
/// The OpenPGP application on the card is `select`-ed while setting up a PcscCard object.
///
/// This struct can be used to hold on to a Card, even while no operations
/// are performed on the Card. To perform operations on the card, a
/// `TxClient` object needs to be obtained (via PcscCard::transaction()).
pub struct PcscBackend {
    card: pcsc::Card,
    mode: pcsc::ShareMode,
    card_caps: Option<CardCaps>,
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
    card_caps: Option<CardCaps>,   // FIXME: manual copy from PcscCard
    reader_caps: HashMap<u8, Tlv>, // FIXME: manual copy from PcscCard
}

impl<'b> PcscTransaction<'b> {
    /// Start a transaction on `card`.
    ///
    /// `reselect` set to `false` is only used internally in this crate,
    /// during initial setup of cards. Otherwise it must be `true`, to
    /// cause a select() call on cards that have been reset.
    fn new(card: &'b mut PcscBackend, reselect: bool) -> Result<Self, Error> {
        use pcsc::Disposition;

        let mut was_reset = false;

        let card_caps = card.card_caps();
        let reader_caps = card.reader_caps();
        let mode = card.mode();

        let mut c = card.card();

        loop {
            match c.transaction2() {
                Ok(mut tx) => {
                    // A transaction has been successfully started

                    if was_reset {
                        log::trace!("start_tx: card was reset, select!");

                        let mut txc = Self {
                            tx,
                            card_caps,
                            reader_caps: reader_caps.clone(),
                        };

                        // In contexts where the caller of this fn
                        // expects that the card has already been opened,
                        // re-open the card here.
                        // For initial card-opening, we don't do this, then
                        // the caller always expects a card that has not
                        // been "select"ed yet.
                        if reselect {
                            PcscTransaction::select(&mut txc)?;
                        }

                        tx = txc.tx;
                    }

                    let txc = Self {
                        tx,
                        card_caps,
                        reader_caps,
                    };

                    break Ok(txc);
                }
                Err((c_, pcsc::Error::ResetCard)) => {
                    // Card was reset, need to reconnect
                    was_reset = true;

                    // drop(res);

                    c = c_;

                    log::trace!("start_tx: do reconnect");

                    {
                        c.reconnect(mode, pcsc::Protocols::ANY, Disposition::ResetCard)
                            .map_err(|e| {
                                Error::Smartcard(SmartcardError::Error(format!(
                                    "Reconnect failed: {:?}",
                                    e
                                )))
                            })?;
                    }

                    log::trace!("start_tx: reconnected.");

                    // -> try opening a transaction again
                }
                Err((_, e)) => {
                    log::trace!("start_tx: error {:?}", e);
                    break Err(Error::Smartcard(SmartcardError::Error(format!(
                        "Error: {:?}",
                        e
                    ))));
                }
            };
        }
    }

    /// Try to select the OpenPGP application on a card
    fn select(card_tx: &mut PcscTransaction) -> Result<(), Error> {
        if <dyn CardTransaction>::select(card_tx).is_ok() {
            Ok(())
        } else {
            Err(Error::Smartcard(SmartcardError::SelectOpenPGPCardFailed))
        }
    }

    /// Get application_related_data from card
    fn application_related_data(
        card_tx: &mut PcscTransaction,
    ) -> Result<ApplicationRelatedData, Error> {
        <dyn CardTransaction>::application_related_data(card_tx).map_err(|e| {
            Error::Smartcard(SmartcardError::Error(format!(
                "TxClient: failed to get application_related_data {:x?}",
                e
            )))
        })
    }

    /// GET_FEATURE_REQUEST
    /// (see http://pcscworkgroup.com/Download/Specifications/pcsc10_v2.02.09.pdf)
    fn features(&mut self) -> Result<Vec<Tlv>, Error> {
        let mut recv = vec![0; 1024];

        let cm_ioctl_get_feature_request = pcsc::ctl_code(3400);
        let res = self
            .tx
            .control(cm_ioctl_get_feature_request, &[], &mut recv)
            .map_err(|e| {
                Error::Smartcard(SmartcardError::Error(format!(
                    "GET_FEATURE_REQUEST control call failed: {:?}",
                    e
                )))
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
    fn max_pin_len(&self, pin: PinType) -> Result<u8, Error> {
        if let Some(card_caps) = self.card_caps {
            match pin {
                PinType::User | PinType::Sign => Ok(card_caps.pw1_max_len()),
                PinType::Admin => Ok(card_caps.pw3_max_len()),
            }
        } else {
            Err(Error::InternalError("card_caps is None".into()))
        }
    }
}

impl CardTransaction for PcscTransaction<'_> {
    fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>, Error> {
        let mut resp_buffer = vec![0; buf_size];

        let resp = self
            .tx
            .transmit(cmd, &mut resp_buffer)
            .map_err(|e| match e {
                pcsc::Error::NotTransacted => Error::Smartcard(SmartcardError::NotTransacted),
                _ => Error::Smartcard(SmartcardError::Error(format!("Transmit failed: {:?}", e))),
            })?;

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

    fn pinpad_verify(&mut self, pin: PinType) -> Result<Vec<u8>, Error> {
        let pin_min_size = self.min_pin_len(pin);
        let pin_max_size = self.max_pin_len(pin)?;

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
            .ok_or_else(|| Error::Smartcard(SmartcardError::Error("no reader_capability".into())))?
            .value()
            .try_into()
            .map_err(|e| Error::ParseError(format!("unexpected feature data: {:?}", e)))?;

        let res = self
            .tx
            .control(u32::from_be_bytes(verify_ioctl).into(), &send, &mut recv)
            .map_err(|e: pcsc::Error| {
                Error::Smartcard(SmartcardError::Error(format!("pcsc Error: {:?}", e)))
            })?;

        log::trace!(" <- pcsc pinpad_verify result: {:x?}", res);

        Ok(res.to_vec())
    }

    fn pinpad_modify(&mut self, pin: PinType) -> Result<Vec<u8>, Error> {
        let pin_min_size = self.min_pin_len(pin);
        let pin_max_size = self.max_pin_len(pin)?;

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
            .ok_or_else(|| Error::Smartcard(SmartcardError::Error("no reader_capability".into())))?
            .value()
            .try_into()
            .map_err(|e| Error::ParseError(format!("unexpected feature data: {:?}", e)))?;

        let res = self
            .tx
            .control(u32::from_be_bytes(modify_ioctl).into(), &send, &mut recv)
            .map_err(|e: pcsc::Error| {
                Error::Smartcard(SmartcardError::Error(format!("pcsc Error: {:?}", e)))
            })?;

        log::trace!(" <- pcsc pinpad_modify result: {:x?}", res);

        Ok(res.to_vec())
    }
}

impl PcscBackend {
    fn card(&mut self) -> &mut pcsc::Card {
        &mut self.card
    }

    fn mode(&self) -> pcsc::ShareMode {
        self.mode
    }

    /// A list of "raw" opened PCSC Cards (without selecting the OpenPGP card
    /// application)
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

    /// Starts from a list of all pcsc cards, then compares their OpenPGP
    /// application identity with `ident` (if `ident` is None, all Cards are
    /// returned). Returns fully initialized PcscCard structs for all matching
    /// cards.
    fn cards_filter(ident: Option<&str>, mode: pcsc::ShareMode) -> Result<Vec<Self>, Error> {
        let mut cards: Vec<Self> = vec![];

        for mut card in Self::raw_pcsc_cards(mode).map_err(Error::Smartcard)? {
            log::trace!("cards_filter: next card");
            log::trace!(" status: {:x?}", card.status2_owned());

            let mut store_card = false;
            {
                // start transaction
                let mut p = PcscBackend::new(card, mode);
                let mut txc = PcscTransaction::new(&mut p, false)?;

                {
                    if let Err(e) = PcscTransaction::select(&mut txc) {
                        log::trace!(" select error: {:?}", e);
                    } else {
                        // successfully opened the OpenPGP application
                        log::trace!(" select ok, will read ARD");
                        log::trace!(" status: {:x?}", txc.tx.status2_owned());

                        if let Some(ident) = ident {
                            if let Ok(ard) = PcscTransaction::application_related_data(&mut txc) {
                                let aid = ard.application_id()?;

                                if aid.ident() == ident.to_ascii_uppercase() {
                                    // FIXME: handle multiple cards with matching ident
                                    log::info!(" found card: {:?} (will use)", ident);

                                    // we want to return this one card
                                    store_card = true;
                                } else {
                                    log::info!(" found card: {:?} (won't use)", aid.ident());
                                }
                            } else {
                                // couldn't read ARD for this card.
                                // ignore and move on
                                continue;
                            }
                        } else {
                            // we want to return all cards
                            store_card = true;
                        }
                    }
                }

                drop(txc);
                card = p.card;
            }

            if store_card {
                let pcsc = PcscBackend::new(card, mode);
                cards.push(pcsc.initialize_card()?);
            }
        }

        log::trace!("cards_filter: found {} cards", cards.len());

        Ok(cards)
    }

    /// Return all cards on which the OpenPGP application could be selected.
    ///
    /// Each card has the OpenPGP application selected, card_caps and reader_caps have been
    /// initialized.
    pub fn cards(mode: Option<pcsc::ShareMode>) -> Result<Vec<Self>, Error> {
        Self::cards_filter(None, default_mode(mode))
    }

    /// Returns the OpenPGP card that matches `ident`, if it is available.
    /// A fully initialized PcscCard is returned: the OpenPGP application has
    /// been selected, card_caps and reader_caps have been initialized.
    pub fn open_by_ident(ident: &str, mode: Option<pcsc::ShareMode>) -> Result<Self, Error> {
        log::trace!("open_by_ident for {:?}", ident);

        let mut cards = Self::cards_filter(Some(ident), default_mode(mode))?;

        if !cards.is_empty() {
            // FIXME: handle >1 cards found

            Ok(cards.pop().unwrap())
        } else {
            Err(Error::Smartcard(SmartcardError::CardNotFound(
                ident.to_string(),
            )))
        }
    }

    fn new(card: pcsc::Card, mode: pcsc::ShareMode) -> Self {
        Self {
            card,
            mode,
            card_caps: None,
            reader_caps: HashMap::new(),
        }
    }

    /// Initialized a PcscCard:
    /// - Obtain and store feature lists from reader (pinpad functionality).
    /// - Get ARD from card, set CardCaps based on ARD.
    fn initialize_card(mut self) -> Result<Self, Error> {
        log::trace!("pcsc initialize_card");

        let mut h: HashMap<u8, Tlv> = HashMap::default();

        let mut txc = PcscTransaction::new(&mut self, true)?;

        // Get Features from reader (pinpad verify/modify)
        if let Ok(feat) = txc.features() {
            for tlv in feat {
                log::trace!(" Found reader feature {:?}", tlv);
                h.insert(tlv.tag().into(), tlv);
            }
        }

        // Initialize CardTransaction (set CardCaps from ARD)
        <dyn CardTransaction>::initialize(&mut txc)?;

        let cc = txc.card_caps().cloned();

        drop(txc);

        self.card_caps = cc;

        for (a, b) in h {
            self.reader_caps.insert(a, b);
        }

        Ok(self)
    }

    fn card_caps(&self) -> Option<CardCaps> {
        self.card_caps
    }
    fn reader_caps(&self) -> HashMap<u8, Tlv> {
        self.reader_caps.clone()
    }
}

impl CardBackend for PcscBackend {
    /// Get a TxClient for this PcscCard (this starts a transaction)
    fn transaction(&mut self) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, Error> {
        Ok(Box::new(PcscTransaction::new(self, true)?))
    }
}
