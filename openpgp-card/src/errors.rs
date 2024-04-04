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

use card_backend::SmartcardError;

use crate::openpgp::StatusBytes;

/// Enum wrapper for the error types of this crate
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

impl From<SmartcardError> for Error {
    fn from(sce: SmartcardError) -> Self {
        Error::Smartcard(sce)
    }
}
