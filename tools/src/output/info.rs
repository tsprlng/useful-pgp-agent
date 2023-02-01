// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::output::OpgpCardError;
use crate::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

#[derive(Debug, Default, Serialize)]
pub struct Info {
    ident: String,
    card_version: String,
    application_id: String,
    manufacturer_id: String,
    manufacturer_name: String,
    card_capabilities: Vec<String>,
    card_service_data: Vec<String>,
    extended_length_info: Vec<String>,
    extended_capabilities: Vec<String>,
    algorithms: Option<Vec<String>>,
    firmware_version: Option<String>,
}

impl Info {
    pub fn ident(&mut self, ident: String) {
        self.ident = ident;
    }

    pub fn card_version(&mut self, version: String) {
        self.card_version = version;
    }

    pub fn application_id(&mut self, id: String) {
        self.application_id = id;
    }

    pub fn manufacturer_id(&mut self, id: String) {
        self.manufacturer_id = id;
    }

    pub fn manufacturer_name(&mut self, name: String) {
        self.manufacturer_name = name;
    }

    pub fn card_capability(&mut self, capability: String) {
        self.card_capabilities.push(capability);
    }

    pub fn card_service_data(&mut self, data: String) {
        self.card_service_data.push(data);
    }

    pub fn extended_length_info(&mut self, info: String) {
        self.extended_length_info.push(info);
    }

    pub fn extended_capability(&mut self, capability: String) {
        self.extended_capabilities.push(capability);
    }

    pub fn algorithm(&mut self, algorithm: String) {
        if let Some(ref mut algos) = self.algorithms {
            algos.push(algorithm);
        } else {
            self.algorithms = Some(vec![algorithm]);
        }
    }

    pub fn firmware_version(&mut self, version: String) {
        self.firmware_version = Some(version);
    }

    fn text(&self) -> Result<String, OpgpCardError> {
        let mut s = format!("OpenPGP card {}\n\n", self.ident);

        s.push_str(&format!(
            "Application Identifier: {}\n",
            self.application_id
        ));
        s.push_str(&format!(
            "Manufacturer [{}]: {}\n\n",
            self.manufacturer_id, self.manufacturer_name
        ));

        if !self.card_capabilities.is_empty() {
            s.push_str("Card Capabilities:\n");
            for c in self.card_capabilities.iter() {
                s.push_str(&format!("- {c}\n"));
            }
            s.push('\n');
        }

        if !self.card_service_data.is_empty() {
            s.push_str("Card service data:\n");
            for c in self.card_service_data.iter() {
                s.push_str(&format!("- {c}\n"));
            }
            s.push('\n');
        }

        if !self.extended_length_info.is_empty() {
            s.push_str("Extended Length Info:\n");
            for c in self.extended_length_info.iter() {
                s.push_str(&format!("- {c}\n"));
            }
            s.push('\n');
        }

        s.push_str("Extended Capabilities:\n");
        for c in self.extended_capabilities.iter() {
            s.push_str(&format!("- {c}\n"));
        }
        s.push('\n');

        if let Some(algos) = &self.algorithms {
            s.push_str("Supported algorithms:\n");
            for c in algos.iter() {
                s.push_str(&format!("- {c}\n"));
            }
            s.push('\n');
        }

        if let Some(v) = &self.firmware_version {
            s.push_str(&format!("Firmware Version: {v}\n"));
        }

        Ok(s)
    }

    fn v1(&self) -> Result<InfoV0, OpgpCardError> {
        Ok(InfoV0 {
            schema_version: InfoV0::VERSION,
            ident: self.ident.clone(),
            card_version: self.card_version.clone(),
            application_id: self.application_id.clone(),
            manufacturer_id: self.manufacturer_id.clone(),
            manufacturer_name: self.manufacturer_name.clone(),
            card_capabilities: self.card_capabilities.clone(),
            card_service_data: self.card_service_data.clone(),
            extended_length_info: self.extended_length_info.clone(),
            extended_capabilities: self.extended_capabilities.clone(),
            algorithms: self.algorithms.clone(),
            firmware_version: self.firmware_version.clone(),
        })
    }
}

impl OutputBuilder for Info {
    type Err = OpgpCardError;

    fn print(&self, format: OutputFormat, version: OutputVersion) -> Result<String, Self::Err> {
        match format {
            OutputFormat::Json => {
                let result = if InfoV0::VERSION.is_acceptable_for(&version) {
                    self.v1()?.json()
                } else {
                    return Err(Self::Err::UnknownVersion(version));
                };
                result.map_err(Self::Err::SerdeJson)
            }
            OutputFormat::Yaml => {
                let result = if InfoV0::VERSION.is_acceptable_for(&version) {
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
struct InfoV0 {
    schema_version: OutputVersion,
    ident: String,
    card_version: String,
    application_id: String,
    manufacturer_id: String,
    manufacturer_name: String,
    card_capabilities: Vec<String>,
    card_service_data: Vec<String>,
    extended_length_info: Vec<String>,
    extended_capabilities: Vec<String>,
    algorithms: Option<Vec<String>>,
    firmware_version: Option<String>,
}

impl OutputVariant for InfoV0 {
    const VERSION: OutputVersion = OutputVersion::new(0, 9, 0);
}
