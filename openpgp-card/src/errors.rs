// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Error types used by this crate.
//!
//! [`Error`] is a wrapper enum for all error types that are used.
//!
//! The two main classes of errors are:
//! - [`SmartcardError`], for problems on the reader/smartcard layer
//! - [`StatusByte`], which models error statuses reported by the OpenPGP
//! card application

/// Enum wrapper for the different error types of this crate
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("Error interacting with smartcard: {0}")]
    Smartcard(SmartcardError),

    #[error("OpenPGP card error status: {0}")]
    CardStatus(StatusByte),

    #[error("Command too long ({0} bytes)")]
    CommandTooLong(usize),

    #[error("Unexpected response length: {0}")]
    ResponseLength(usize),

    #[error("Internal error: {0}")]
    InternalError(anyhow::Error),
}

impl From<StatusByte> for Error {
    fn from(oce: StatusByte) -> Self {
        Error::CardStatus(oce)
    }
}

impl From<anyhow::Error> for Error {
    fn from(ae: anyhow::Error) -> Self {
        Error::InternalError(ae)
    }
}

/// OpenPGP card "Status Byte" errors
#[derive(thiserror::Error, Debug, PartialEq)]
#[non_exhaustive]
pub enum StatusByte {
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
    CommandChainingUnsupported,

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

    #[error("Unknown OpenPGP card status: [{0}, {1}]")]
    UnknownStatus(u8, u8),
}

impl From<(u8, u8)> for StatusByte {
    fn from(status: (u8, u8)) -> Self {
        match (status.0, status.1) {
            (0x62, 0x85) => StatusByte::TerminationState,
            (0x63, 0xC0..=0xCF) => {
                StatusByte::PasswordNotChecked(status.1 & 0xf)
            }
            (0x64, 0x02..=0x80) => StatusByte::TriggeringByCard(status.1),
            (0x65, 0x01) => StatusByte::MemoryFailure,
            (0x66, 0x00) => StatusByte::SecurityRelatedIssues,
            (0x67, 0x00) => StatusByte::WrongLength,
            (0x68, 0x81) => StatusByte::LogicalChannelNotSupported,
            (0x68, 0x82) => StatusByte::SecureMessagingNotSupported,
            (0x68, 0x83) => StatusByte::LastCommandOfChainExpected,
            (0x68, 0x84) => StatusByte::CommandChainingUnsupported,
            (0x69, 0x82) => StatusByte::SecurityStatusNotSatisfied,
            (0x69, 0x83) => StatusByte::AuthenticationMethodBlocked,
            (0x69, 0x85) => StatusByte::ConditionOfUseNotSatisfied,
            (0x69, 0x87) => StatusByte::ExpectedSecureMessagingDOsMissing,
            (0x69, 0x88) => StatusByte::SMDataObjectsIncorrect,
            (0x6A, 0x80) => StatusByte::IncorrectParametersCommandDataField,
            (0x6A, 0x82) => StatusByte::FileOrApplicationNotFound,
            (0x6A, 0x88) => StatusByte::ReferencedDataNotFound,
            (0x6B, 0x00) => StatusByte::WrongParametersP1P2,
            (0x6D, 0x00) => StatusByte::INSNotSupported,
            (0x6E, 0x00) => StatusByte::CLANotSupported,
            (0x6F, 0x00) => StatusByte::NoPreciseDiagnosis,
            _ => StatusByte::UnknownStatus(status.0, status.1),
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

    #[error("Generic SmartCard Error: {0}")]
    Error(String),
}
