// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OpenpgpCardError {
    #[error("Error interacting with smartcard {0}")]
    Smartcard(SmartcardError),

    #[error("OpenPGP card error status {0}")]
    OcStatus(OcErrorStatus),

    #[error("Internal error {0}")]
    InternalError(anyhow::Error),
}

impl From<OcErrorStatus> for OpenpgpCardError {
    fn from(oce: OcErrorStatus) -> Self {
        OpenpgpCardError::OcStatus(oce)
    }
}

impl From<anyhow::Error> for OpenpgpCardError {
    fn from(ae: anyhow::Error) -> Self {
        OpenpgpCardError::InternalError(ae)
    }
}

#[derive(Error, Debug)]
pub enum OcErrorStatus {
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

    #[error("Unexpected response length: {0}")]
    ResponseLength(usize),
}

impl From<(u8, u8)> for OcErrorStatus {
    fn from(status: (u8, u8)) -> Self {
        match (status.0, status.1) {
            (0x62, 0x85) => OcErrorStatus::TerminationState,
            (0x63, 0xC0..=0xCF) => {
                OcErrorStatus::PasswordNotChecked(status.1 & 0xf)
            }
            (0x64, 0x02..=0x80) => OcErrorStatus::TriggeringByCard(status.1),
            (0x65, 0x01) => OcErrorStatus::MemoryFailure,
            (0x66, 0x00) => OcErrorStatus::SecurityRelatedIssues,
            (0x67, 0x00) => OcErrorStatus::WrongLength,
            (0x68, 0x81) => OcErrorStatus::LogicalChannelNotSupported,
            (0x68, 0x82) => OcErrorStatus::SecureMessagingNotSupported,
            (0x68, 0x83) => OcErrorStatus::LastCommandOfChainExpected,
            (0x68, 0x84) => OcErrorStatus::CommandChainingUnsupported,
            (0x69, 0x82) => OcErrorStatus::SecurityStatusNotSatisfied,
            (0x69, 0x83) => OcErrorStatus::AuthenticationMethodBlocked,
            (0x69, 0x85) => OcErrorStatus::ConditionOfUseNotSatisfied,
            (0x69, 0x87) => OcErrorStatus::ExpectedSecureMessagingDOsMissing,
            (0x69, 0x88) => OcErrorStatus::SMDataObjectsIncorrect,
            (0x6A, 0x80) => OcErrorStatus::IncorrectParametersCommandDataField,
            (0x6A, 0x82) => OcErrorStatus::FileOrApplicationNotFound,
            (0x6A, 0x88) => OcErrorStatus::ReferencedDataNotFound,
            (0x6B, 0x00) => OcErrorStatus::WrongParametersP1P2,
            (0x6D, 0x00) => OcErrorStatus::INSNotSupported,
            (0x6E, 0x00) => OcErrorStatus::CLANotSupported,
            (0x6F, 0x00) => OcErrorStatus::NoPreciseDiagnosis,
            _ => OcErrorStatus::UnknownStatus(status.0, status.1),
        }
    }
}

#[derive(Error, Debug)]
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

    #[error("Generic SmartCard Error: {0}")]
    Error(String),
}
