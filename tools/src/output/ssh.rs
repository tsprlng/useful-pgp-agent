// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::output::OpgpCardError;
use crate::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

#[derive(Debug, Default, Serialize)]
pub struct Ssh {
    ident: String,
    authentication_key_fingerprint: Option<String>,
    ssh_public_key: Option<String>,
}

impl Ssh {
    pub fn ident(&mut self, ident: String) {
        self.ident = ident;
    }

    pub fn authentication_key_fingerprint(&mut self, fp: String) {
        self.authentication_key_fingerprint = Some(fp);
    }

    pub fn ssh_public_key(&mut self, key: String) {
        self.ssh_public_key = Some(key);
    }

    fn text(&self) -> Result<String, OpgpCardError> {
        let mut s = format!("OpenPGP card {}\n\n", self.ident);

        if let Some(fp) = &self.authentication_key_fingerprint {
            s.push_str(&format!("Authentication key fingerprint:\n{}\n\n", fp));
        }
        if let Some(key) = &self.ssh_public_key {
            s.push_str(&format!("SSH public key:\n{}\n", key));
        }

        Ok(s)
    }

    fn v1(&self) -> Result<SshV0, OpgpCardError> {
        Ok(SshV0 {
            schema_version: SshV0::VERSION,
            ident: self.ident.clone(),
            authentication_key_fingerprint: self.authentication_key_fingerprint.clone(),
            ssh_public_key: self.ssh_public_key.clone(),
        })
    }
}

impl OutputBuilder for Ssh {
    type Err = OpgpCardError;

    fn print(&self, format: OutputFormat, version: OutputVersion) -> Result<String, Self::Err> {
        match format {
            OutputFormat::Json => {
                let result = if SshV0::VERSION.is_acceptable_for(&version) {
                    self.v1()?.json()
                } else {
                    return Err(Self::Err::UnknownVersion(version));
                };
                result.map_err(Self::Err::SerdeJson)
            }
            OutputFormat::Yaml => {
                let result = if SshV0::VERSION.is_acceptable_for(&version) {
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
struct SshV0 {
    schema_version: OutputVersion,
    ident: String,
    authentication_key_fingerprint: Option<String>,
    ssh_public_key: Option<String>,
}

impl OutputVariant for SshV0 {
    const VERSION: OutputVersion = OutputVersion::new(0, 9, 0);
}
