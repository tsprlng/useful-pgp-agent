// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::output::OpgpCardError;
use crate::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

#[derive(Debug, Default, Serialize)]
pub struct AttestationCert {
    ident: String,
    attestation_cert: String,
}

impl AttestationCert {
    pub fn ident(&mut self, ident: String) {
        self.ident = ident;
    }

    pub fn attestation_cert(&mut self, cert: String) {
        self.attestation_cert = cert;
    }

    fn text(&self) -> Result<String, OpgpCardError> {
        Ok(format!(
            "OpenPGP card {}\n\n{}\n",
            self.ident, self.attestation_cert,
        ))
    }

    fn v1(&self) -> Result<AttestationCertV0, OpgpCardError> {
        Ok(AttestationCertV0 {
            schema_version: AttestationCertV0::VERSION,
            ident: self.ident.clone(),
            attestation_cert: self.attestation_cert.clone(),
        })
    }
}

impl OutputBuilder for AttestationCert {
    type Err = OpgpCardError;

    fn print(&self, format: OutputFormat, version: OutputVersion) -> Result<String, Self::Err> {
        match format {
            OutputFormat::Json => {
                let result = if AttestationCertV0::VERSION.is_acceptable_for(&version) {
                    self.v1()?.json()
                } else {
                    return Err(Self::Err::UnknownVersion(version));
                };
                result.map_err(Self::Err::SerdeJson)
            }
            OutputFormat::Yaml => {
                let result = if AttestationCertV0::VERSION.is_acceptable_for(&version) {
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
struct AttestationCertV0 {
    schema_version: OutputVersion,
    ident: String,
    attestation_cert: String,
}

impl OutputVariant for AttestationCertV0 {
    const VERSION: OutputVersion = OutputVersion::new(0, 9, 0);
}
