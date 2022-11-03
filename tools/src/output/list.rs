// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::output::OpgpCardError;
use crate::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

#[derive(Default, Debug, Serialize)]
pub struct List {
    idents: Vec<String>,
}

impl List {
    pub fn push(&mut self, idnet: String) {
        self.idents.push(idnet);
    }

    fn text(&self) -> Result<String, OpgpCardError> {
        let s = if self.idents.is_empty() {
            "No OpenPGP cards found.".into()
        } else {
            let mut s = "Available OpenPGP cards:\n".to_string();
            for id in self.idents.iter() {
                s.push_str(&format!("  {}\n", id));
            }
            s
        };
        Ok(s)
    }

    fn v1(&self) -> Result<ListV0, OpgpCardError> {
        Ok(ListV0 {
            schema_version: ListV0::VERSION,
            idents: self.idents.clone(),
        })
    }
}

impl OutputBuilder for List {
    type Err = OpgpCardError;

    fn print(&self, format: OutputFormat, version: OutputVersion) -> Result<String, Self::Err> {
        match format {
            OutputFormat::Json => {
                let result = if ListV0::VERSION.is_acceptable_for(&version) {
                    self.v1()?.json()
                } else {
                    return Err(Self::Err::UnknownVersion(version));
                };
                result.map_err(Self::Err::SerdeJson)
            }
            OutputFormat::Yaml => {
                let result = if ListV0::VERSION.is_acceptable_for(&version) {
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
struct ListV0 {
    schema_version: OutputVersion,
    idents: Vec<String>,
}

impl OutputVariant for ListV0 {
    const VERSION: OutputVersion = OutputVersion::new(0, 9, 0);
}
