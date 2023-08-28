// SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A thin abstraction layer for accessing smart cards, including, but not
//! limited to, [openpgp-card](https://gitlab.com/openpgp-card/openpgp-card)
//! devices.

/// This trait defines a connection with a smart card via a
/// backend implementation (e.g. via the pcsc backend in the crate
/// [card-backend-pcsc](https://crates.io/crates/card-backend-pcsc)).
///
/// A [CardBackend] is only used to get access to a [CardTransaction] object,
/// which supports transmitting commands to the card.
pub trait CardBackend {
    fn transaction(
        &mut self,
        reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError>;
}

/// The CardTransaction trait defines communication with a smart card via a
/// backend implementation (e.g. the pcsc backend in the crate
/// [card-backend-pcsc](https://crates.io/crates/card-backend-pcsc)),
/// after opening a transaction from a CardBackend.
pub trait CardTransaction {
    /// Transmit the command data in `cmd` to the card.
    ///
    /// `buf_size` is a hint to the backend (the backend may ignore it)
    /// indicating the expected maximum response size.
    fn transmit(&mut self, cmd: &[u8], buf_size: usize) -> Result<Vec<u8>, SmartcardError>;

    /// Select `application` on the card
    fn select(&mut self, application: &[u8]) -> Result<Vec<u8>, SmartcardError> {
        let mut cmd = vec![0x00, 0xa4, 0x04, 0x00]; // CLA, INS, P1, P2
        cmd.push(application.len() as u8); // Lc
        cmd.extend_from_slice(application); // Data
        cmd.push(0x00); // Le

        self.transmit(&cmd, 254)
    }

    /// If a CardTransaction implementation introduces an additional,
    /// backend-specific limit for maximum number of bytes per command,
    /// this fn can indicate that limit by returning `Some(max_cmd_len)`.
    fn max_cmd_len(&self) -> Option<usize> {
        None
    }

    /// Does the reader support FEATURE_VERIFY_PIN_DIRECT?
    fn feature_pinpad_verify(&self) -> bool;

    /// Does the reader support FEATURE_MODIFY_PIN_DIRECT?
    fn feature_pinpad_modify(&self) -> bool;

    /// Verify the PIN `pin` via the reader pinpad
    fn pinpad_verify(
        &mut self,
        pin: PinType,
        card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError>;

    /// Modify the PIN `pin` via the reader pinpad
    fn pinpad_modify(
        &mut self,
        pin: PinType,
        card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError>;

    /// Has a reset been detected while starting this transaction?
    ///
    /// (Backends may choose to always return false)
    fn was_reset(&self) -> bool;
}

/// Information about the capabilities of a card.
///
/// CardCaps is used to signal capabilities (chaining, extended length support, max
/// command/response sizes, max PIN lengths) of the current card to backends.
///
/// CardCaps is not intended for users of this library.
///
/// (The information is gathered from the "Card Capabilities", "Extended length information" and
/// "PWStatus" DOs)
#[derive(Clone, Copy, Debug)]
pub struct CardCaps {
    ext_support: bool,
    chaining_support: bool,
    max_cmd_bytes: u16,
    max_rsp_bytes: u16,
    pw1_max_len: u8,
    pw3_max_len: u8,
}

impl CardCaps {
    pub fn new(
        ext_support: bool,
        chaining_support: bool,
        max_cmd_bytes: u16,
        max_rsp_bytes: u16,
        pw1_max_len: u8,
        pw3_max_len: u8,
    ) -> Self {
        Self {
            ext_support,
            chaining_support,
            max_cmd_bytes,
            max_rsp_bytes,
            pw1_max_len,
            pw3_max_len,
        }
    }

    /// Does the card support extended Lc and Le fields?
    pub fn ext_support(&self) -> bool {
        self.ext_support
    }

    /// Does the card support command chaining?
    pub fn chaining_support(&self) -> bool {
        self.chaining_support
    }

    /// Maximum number of bytes in a command APDU
    pub fn max_cmd_bytes(&self) -> u16 {
        self.max_cmd_bytes
    }

    /// Maximum number of bytes in a response APDU
    pub fn max_rsp_bytes(&self) -> u16 {
        self.max_rsp_bytes
    }

    /// Maximum length of PW1
    pub fn pw1_max_len(&self) -> u8 {
        self.pw1_max_len
    }

    /// Maximum length of PW3
    pub fn pw3_max_len(&self) -> u8 {
        self.pw3_max_len
    }
}

/// Specify a PIN to *verify* (distinguishes between `Sign`, `User` and `Admin`).
///
/// (Note that for PIN *management*, in particular changing a PIN, "signing and user" are
/// not distinguished. They always share the same PIN value `PW1`)
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PinType {
    /// Verify PW1 in mode P2=81 (for the PSO:CDS operation)
    Sign,

    /// Verify PW1 in mode P2=82 (for all other User operations)
    User,

    /// Verify PW3 (for Admin operations)
    Admin,
}

impl PinType {
    pub fn id(&self) -> u8 {
        match self {
            PinType::Sign => 0x81,
            PinType::User => 0x82,
            PinType::Admin => 0x83,
        }
    }
}

/// Errors on the smartcard/reader layer
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum SmartcardError {
    #[error("Failed to create a pcsc smartcard context {0}")]
    ContextError(String),

    #[error("Failed to list readers: {0}")]
    ReaderError(String),

    #[error("No reader found.")]
    NoReaderFoundError,

    #[error("The requested card '{0}' was not found.")]
    CardNotFound(String),

    #[error("Failed to connect to the card: {0}")]
    SmartCardConnectionError(String),

    #[error("Smart card status: [{0}, {1}]")]
    SmartCardStatus(u8, u8),

    #[error("NotTransacted (SCARD_E_NOT_TRANSACTED)")]
    NotTransacted,

    #[error("Generic SmartCard Error: {0}")]
    Error(String),
}
