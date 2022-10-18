// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::output::OpgpCardError;
use crate::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

#[derive(Debug, Default, Serialize)]
pub struct PublicKey {
    ident: String,
    public_key: String,
}

impl PublicKey {
    pub fn ident(&mut self, ident: String) {
        self.ident = ident;
    }

    pub fn public_key(&mut self, key: String) {
        self.public_key = key;
    }

    fn text(&self) -> Result<String, OpgpCardError> {
        Ok(format!(
            "OpenPGP card {}\n\n{}\n",
            self.ident, self.public_key
        ))
    }

    fn v1(&self) -> Result<PublicKeyV0, OpgpCardError> {
        Ok(PublicKeyV0 {
            schema_version: PublicKeyV0::VERSION,
            ident: self.ident.clone(),
            public_key: self.public_key.clone(),
        })
    }
}

impl OutputBuilder for PublicKey {
    type Err = OpgpCardError;

    fn print(&self, format: OutputFormat, version: OutputVersion) -> Result<String, Self::Err> {
        match format {
            OutputFormat::Json => {
                let result = if PublicKeyV0::VERSION.is_acceptable_for(&version) {
                    self.v1()?.json()
                } else {
                    return Err(Self::Err::UnknownVersion(version));
                };
                result.map_err(Self::Err::SerdeJson)
            }
            OutputFormat::Yaml => {
                let result = if PublicKeyV0::VERSION.is_acceptable_for(&version) {
                    self.v1()?.yaml()
                } else {
                    return Err(Self::Err::UnknownVersion(version));
                };
                result.map_err(Self::Err::SerdeYaml)
            }
            OutputFormat::Text => Ok(self.text()?),
        }
    }
}

#[derive(Debug, Serialize)]
struct PublicKeyV0 {
    schema_version: OutputVersion,
    ident: String,
    public_key: String,
}

impl OutputVariant for PublicKeyV0 {
    const VERSION: OutputVersion = OutputVersion::new(0, 9, 0);
}
