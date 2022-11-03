// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::OutputVersion;

#[derive(Debug, thiserror::Error)]
pub enum OpgpCardError {
    #[error("unknown output version {0}")]
    UnknownVersion(OutputVersion),

    #[error("failed to serialize JSON output with serde_json")]
    SerdeJson(#[source] serde_json::Error),

    #[error("failed to serialize YAML output with serde_yaml")]
    SerdeYaml(#[source] serde_yaml::Error),
}

mod list;
pub use list::List;

mod status;
pub use status::{KeySlotInfo, Status};

mod info;
pub use info::Info;

mod ssh;
pub use ssh::Ssh;

mod pubkey;
pub use pubkey::PublicKey;

mod generate;
pub use generate::AdminGenerate;

mod attest;
pub use attest::AttestationCert;
