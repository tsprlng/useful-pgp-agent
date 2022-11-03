// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::output::OpgpCardError;
use crate::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

#[derive(Debug, Default, Serialize)]
pub struct AdminGenerate {
    ident: String,
    algorithm: String,
    public_key: String,
}

impl AdminGenerate {
    pub fn ident(&mut self, ident: String) {
        self.ident = ident;
    }

    pub fn algorithm(&mut self, algorithm: String) {
        self.algorithm = algorithm;
    }

    pub fn public_key(&mut self, key: String) {
        self.public_key = key;
    }

    fn text(&self) -> Result<String, OpgpCardError> {
        // Do not print ident, as the file with the public_key must not contain anything else
        Ok(self.public_key.to_string())
    }

    fn v1(&self) -> Result<AdminGenerateV0, OpgpCardError> {
        Ok(AdminGenerateV0 {
            schema_version: AdminGenerateV0::VERSION,
            ident: self.ident.clone(),
            algorithm: self.algorithm.clone(),
            public_key: self.public_key.clone(),
        })
    }
}

impl OutputBuilder for AdminGenerate {
    type Err = OpgpCardError;

    fn print(&self, format: OutputFormat, version: OutputVersion) -> Result<String, Self::Err> {
        match format {
            OutputFormat::Json => {
                let result = if AdminGenerateV0::VERSION.is_acceptable_for(&version) {
                    self.v1()?.json()
                } else {
                    return Err(Self::Err::UnknownVersion(version));
                };
                result.map_err(Self::Err::SerdeJson)
            }
            OutputFormat::Yaml => {
                let result = if AdminGenerateV0::VERSION.is_acceptable_for(&version) {
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
struct AdminGenerateV0 {
    schema_version: OutputVersion,
    ident: String,
    algorithm: String,
    public_key: String,
}

impl OutputVariant for AdminGenerateV0 {
    const VERSION: OutputVersion = OutputVersion::new(0, 9, 0);
}
