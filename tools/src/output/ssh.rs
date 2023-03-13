// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::output::OpgpCardError;
use crate::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

#[derive(Debug, Default, Serialize)]
pub struct Ssh {
    key_only: bool, // only print ssh public key, in text mode
    ident: String,
    authentication_key_fingerprint: Option<String>,
    ssh_public_key: Option<String>,
}

impl Ssh {
    pub fn key_only(&mut self, ssh_key_only: bool) {
        self.key_only = ssh_key_only;
    }

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
        if !self.key_only {
            let mut s = format!("OpenPGP card {}\n\n", self.ident);

            if let Some(fp) = &self.authentication_key_fingerprint {
                s.push_str(&format!("Authentication key fingerprint:\n{fp}\n\n"));
            }
            if let Some(key) = &self.ssh_public_key {
                s.push_str(&format!("SSH public key:\n{key}\n"));
            }

            Ok(s)
        } else {
            Ok(self.ssh_public_key.clone().unwrap_or("".to_string()))
        }
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
