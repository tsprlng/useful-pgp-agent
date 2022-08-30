// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types used by this crate.
//!
//! [`Error`] is a wrapper enum for all error types that are used.
//!
//! The two main classes of errors are:
//! - [`SmartcardError`], for problems on the reader/smartcard layer
//! - [`StatusBytes`], which models error statuses reported by the OpenPGP
//! card application

/// Enum wrapper for the different error types of this crate
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Error interacting with smartcard: {0}")]
    Smartcard(SmartcardError),

    #[error("OpenPGP card error status: {0}")]
    CardStatus(StatusBytes),

    #[error("Command too long ({0} bytes)")]
    CommandTooLong(usize),

    #[error("Unexpected response length: {0}")]
    ResponseLength(usize),

    #[error("Data not found: {0}")]
    NotFound(String),

    #[error("Couldn't parse data: {0}")]
    ParseError(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgo(String),

    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),

    // FIXME: placeholder, remove again later?
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<StatusBytes> for Error {
    fn from(oce: StatusBytes) -> Self {
        Error::CardStatus(oce)
    }
}

/// OpenPGP card "Status Bytes" (ok statuses and errors)
#[derive(thiserror::Error, Debug, PartialEq, Eq, Copy, Clone)]
#[non_exhaustive]
pub enum StatusBytes {
    #[error("Command correct")]
    Ok,

    #[error("Command correct, [{0}] bytes available in response")]
    OkBytesAvailable(u8),

    #[error("Selected file or DO in termination state")]
    TerminationState,

    #[error("Password not checked, {0} allowed retries")]
    PasswordNotChecked(u8),

    #[error("Triggering by the card {0}")]
    TriggeringByCard(u8),

    #[error("Memory failure")]
    MemoryFailure,

    #[error("Security-related issues (reserved for UIF in this application)")]
    SecurityRelatedIssues,

    #[error("Wrong length (Lc and/or Le)")]
    WrongLength,

    #[error("Logical channel not supported")]
    LogicalChannelNotSupported,

    #[error("Secure messaging not supported")]
    SecureMessagingNotSupported,

    #[error("Last command of the chain expected")]
    LastCommandOfChainExpected,

    #[error("Command chaining not supported")]
    CommandChainingNotSupported,

    #[error("Security status not satisfied")]
    SecurityStatusNotSatisfied,

    #[error("Authentication method blocked")]
    AuthenticationMethodBlocked,

    #[error("Condition of use not satisfied")]
    ConditionOfUseNotSatisfied,

    #[error("Expected secure messaging DOs missing (e. g. SM-key)")]
    ExpectedSecureMessagingDOsMissing,

    #[error("SM data objects incorrect (e. g. wrong TLV-structure in command data)")]
    SMDataObjectsIncorrect,

    #[error("Incorrect parameters in the command data field")]
    IncorrectParametersCommandDataField,

    #[error("File or application not found")]
    FileOrApplicationNotFound,

    #[error("Referenced data, reference data or DO not found")]
    ReferencedDataNotFound,

    #[error("Wrong parameters P1-P2")]
    WrongParametersP1P2,

    #[error("Instruction code (INS) not supported or invalid")]
    INSNotSupported,

    #[error("Class (CLA) not supported")]
    CLANotSupported,

    #[error("No precise diagnosis")]
    NoPreciseDiagnosis,

    #[error("Unknown OpenPGP card status: [{0:x}, {1:x}]")]
    UnknownStatus(u8, u8),
}

impl From<(u8, u8)> for StatusBytes {
    fn from(status: (u8, u8)) -> Self {
        match (status.0, status.1) {
            (0x90, 0x00) => StatusBytes::Ok,
            (0x61, bytes) => StatusBytes::OkBytesAvailable(bytes),

            (0x62, 0x85) => StatusBytes::TerminationState,
            (0x63, 0xC0..=0xCF) => StatusBytes::PasswordNotChecked(status.1 & 0xf),
            (0x64, 0x02..=0x80) => StatusBytes::TriggeringByCard(status.1),
            (0x65, 0x01) => StatusBytes::MemoryFailure,
            (0x66, 0x00) => StatusBytes::SecurityRelatedIssues,
            (0x67, 0x00) => StatusBytes::WrongLength,
            (0x68, 0x81) => StatusBytes::LogicalChannelNotSupported,
            (0x68, 0x82) => StatusBytes::SecureMessagingNotSupported,
            (0x68, 0x83) => StatusBytes::LastCommandOfChainExpected,
            (0x68, 0x84) => StatusBytes::CommandChainingNotSupported,
            (0x69, 0x82) => StatusBytes::SecurityStatusNotSatisfied,
            (0x69, 0x83) => StatusBytes::AuthenticationMethodBlocked,
            (0x69, 0x85) => StatusBytes::ConditionOfUseNotSatisfied,
            (0x69, 0x87) => StatusBytes::ExpectedSecureMessagingDOsMissing,
            (0x69, 0x88) => StatusBytes::SMDataObjectsIncorrect,
            (0x6A, 0x80) => StatusBytes::IncorrectParametersCommandDataField,
            (0x6A, 0x82) => StatusBytes::FileOrApplicationNotFound,
            (0x6A, 0x88) => StatusBytes::ReferencedDataNotFound,
            (0x6B, 0x00) => StatusBytes::WrongParametersP1P2,
            (0x6D, 0x00) => StatusBytes::INSNotSupported,
            (0x6E, 0x00) => StatusBytes::CLANotSupported,
            (0x6F, 0x00) => StatusBytes::NoPreciseDiagnosis,
            _ => StatusBytes::UnknownStatus(status.0, status.1),
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

    #[error("Couldn't select the OpenPGP card application")]
    SelectOpenPGPCardFailed,

    #[error("Failed to connect to the card: {0}")]
    SmartCardConnectionError(String),

    #[error("NotTransacted (SCARD_E_NOT_TRANSACTED)")]
    NotTransacted,

    #[error("Generic SmartCard Error: {0}")]
    Error(String),
}
