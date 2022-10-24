// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::output::OpgpCardError;
use crate::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

#[derive(Debug, Default, Serialize)]
pub struct Status {
    verbose: bool,
    ident: String,
    card_version: String,
    card_holder: Option<String>,
    url: Option<String>,
    language_preferences: Vec<String>,
    signature_key: KeySlotInfo,
    signature_count: u32,
    decryption_key: KeySlotInfo,
    authentication_key: KeySlotInfo,
    user_pin_remaining_attempts: u8,
    admin_pin_remaining_attempts: u8,
    reset_code_remaining_attempts: u8,
    card_touch_policy: String,
    card_touch_features: String,
    key_statuses: Vec<(u8, String)>,
    ca_fingerprints: Vec<String>,
}

impl Status {
    pub fn verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    pub fn ident(&mut self, ident: String) {
        self.ident = ident;
    }

    pub fn card_version(&mut self, card_version: String) {
        self.card_version = card_version;
    }

    pub fn card_holder(&mut self, card_holder: String) {
        self.card_holder = Some(card_holder);
    }

    pub fn url(&mut self, url: String) {
        self.url = Some(url);
    }

    pub fn language_preference(&mut self, pref: String) {
        self.language_preferences.push(pref);
    }

    pub fn signature_key(&mut self, key: KeySlotInfo) {
        self.signature_key = key;
    }

    pub fn signature_count(&mut self, count: u32) {
        self.signature_count = count;
    }

    pub fn decryption_key(&mut self, key: KeySlotInfo) {
        self.decryption_key = key;
    }

    pub fn authentication_key(&mut self, key: KeySlotInfo) {
        self.authentication_key = key;
    }

    pub fn user_pin_remaining_attempts(&mut self, count: u8) {
        self.user_pin_remaining_attempts = count;
    }

    pub fn admin_pin_remaining_attempts(&mut self, count: u8) {
        self.admin_pin_remaining_attempts = count;
    }

    pub fn reset_code_remaining_attempts(&mut self, count: u8) {
        self.reset_code_remaining_attempts = count;
    }

    pub fn card_touch_policy(&mut self, policy: String) {
        self.card_touch_policy = policy;
    }

    pub fn card_touch_features(&mut self, features: String) {
        self.card_touch_features = features;
    }

    pub fn key_status(&mut self, keyref: u8, status: String) {
        self.key_statuses.push((keyref, status));
    }

    pub fn ca_fingerprint(&mut self, fingerprint: String) {
        self.ca_fingerprints.push(fingerprint);
    }

    fn text(&self) -> Result<String, OpgpCardError> {
        let mut s = String::new();

        s.push_str(&format!(
            "OpenPGP card {} (card version {})\n\n",
            self.ident, self.card_version
        ));

        let mut nl = false;
        if let Some(name) = &self.card_holder {
            if !name.is_empty() {
                s.push_str(&format!("Cardholder: {}\n", name));
                nl = true;
            }
        }

        if let Some(url) = &self.url {
            if !url.is_empty() {
                s.push_str(&format!("URL: {}\n", url));
                nl = true;
            }
        }

        if !self.language_preferences.is_empty() {
            let prefs = self.language_preferences.to_vec().join(", ");
            if !prefs.is_empty() {
                s.push_str(&format!("Language preferences: '{}'\n", prefs));
                nl = true;
            }
        }

        if nl {
            s.push('\n');
        }

        s.push_str("Signature key:\n");
        for line in self.signature_key.format(self.verbose) {
            s.push_str(&format!("  {}\n", line));
        }
        s.push_str(&format!("  Signatures made: {}\n", self.signature_count));
        s.push('\n');

        s.push_str("Decryption key:\n");
        for line in self.decryption_key.format(self.verbose) {
            s.push_str(&format!("  {}\n", line));
        }
        s.push('\n');

        s.push_str("Authentication key:\n");
        for line in self.authentication_key.format(self.verbose) {
            s.push_str(&format!("  {}\n", line));
        }
        s.push('\n');

        s.push_str(&format!(
            "Remaining PIN attempts: User: {}, Admin: {}, Reset Code: {}\n",
            self.user_pin_remaining_attempts,
            self.admin_pin_remaining_attempts,
            self.reset_code_remaining_attempts
        ));

        if self.verbose {
            s.push_str(&format!(
                "Touch policy attestation: {}\n",
                self.card_touch_policy
            ));

            for (keyref, status) in self.key_statuses.iter() {
                s.push_str(&format!("Key status (#{}): {}\n", keyref, status));
            }
        }

        Ok(s)
    }

    fn v1(&self) -> Result<StatusV0, OpgpCardError> {
        Ok(StatusV0 {
            schema_version: StatusV0::VERSION,
            ident: self.ident.clone(),
            card_version: self.card_version.clone(),
            card_holder: self.card_holder.clone(),
            url: self.url.clone(),
            language_preferences: self.language_preferences.clone(),
            signature_key: self.signature_key.clone(),
            signature_count: self.signature_count,
            decryption_key: self.decryption_key.clone(),
            authentication_key: self.authentication_key.clone(),
            user_pin_remaining_attempts: self.user_pin_remaining_attempts,
            admin_pin_remaining_attempts: self.admin_pin_remaining_attempts,
            reset_code_remaining_attempts: self.reset_code_remaining_attempts,
            card_touch_policy: self.card_touch_policy.clone(),
            card_touch_features: self.card_touch_features.clone(),
            key_statuses: self.key_statuses.clone(),
            ca_fingerprints: self.ca_fingerprints.clone(),
        })
    }
}

impl OutputBuilder for Status {
    type Err = OpgpCardError;

    fn print(&self, format: OutputFormat, version: OutputVersion) -> Result<String, Self::Err> {
        match format {
            OutputFormat::Json => {
                let result = if StatusV0::VERSION.is_acceptable_for(&version) {
                    self.v1()?.json()
                } else {
                    return Err(Self::Err::UnknownVersion(version));
                };
                result.map_err(Self::Err::SerdeJson)
            }
            OutputFormat::Yaml => {
                let result = if StatusV0::VERSION.is_acceptable_for(&version) {
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
pub struct StatusV0 {
    schema_version: OutputVersion,
    ident: String,
    card_version: String,
    card_holder: Option<String>,
    url: Option<String>,
    language_preferences: Vec<String>,
    signature_key: KeySlotInfo,
    signature_count: u32,
    decryption_key: KeySlotInfo,
    authentication_key: KeySlotInfo,
    user_pin_remaining_attempts: u8,
    admin_pin_remaining_attempts: u8,
    reset_code_remaining_attempts: u8,
    card_touch_policy: String,
    card_touch_features: String,
    key_statuses: Vec<(u8, String)>,
    ca_fingerprints: Vec<String>,
}

impl OutputVariant for StatusV0 {
    const VERSION: OutputVersion = OutputVersion::new(0, 9, 0);
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct KeySlotInfo {
    fingerprint: Option<String>,
    algorithm: Option<String>,
    created: Option<String>,
    touch_policy: Option<String>,
    touch_features: Option<String>,
    status: Option<String>,
    pin_valid_once: bool,
    public_key_material: Option<String>,
}

impl KeySlotInfo {
    pub fn fingerprint(&mut self, fingerprint: String) {
        self.fingerprint = Some(fingerprint);
    }

    pub fn algorithm(&mut self, algorithm: String) {
        self.algorithm = Some(algorithm);
    }

    pub fn created(&mut self, created: String) {
        self.created = Some(created);
    }

    pub fn touch_policy(&mut self, policy: String) {
        self.touch_policy = Some(policy);
    }

    pub fn touch_features(&mut self, features: String) {
        self.touch_features = Some(features);
    }

    pub fn status(&mut self, status: String) {
        self.status = Some(status);
    }

    pub fn pin_valid_once(&mut self) {
        self.pin_valid_once = true;
    }

    pub fn public_key_material(&mut self, material: String) {
        self.public_key_material = Some(material);
    }

    fn format(&self, verbose: bool) -> Vec<String> {
        let mut lines = vec![];

        if let Some(fp) = &self.fingerprint {
            lines.push(format!("Fingerprint: {}", fp));
        }
        if let Some(a) = &self.algorithm {
            lines.push(format!("Algorithm: {}", a));
        }
        if let Some(ts) = &self.created {
            lines.push(format!("Created: {}", ts));
        }

        if verbose {
            if let Some(policy) = &self.touch_policy {
                if let Some(features) = &self.touch_features {
                    lines.push(format!("Touch policy: {} (features: {})", policy, features));
                }
            }
            if let Some(status) = &self.status {
                lines.push(format!("Key Status: {}", status));
            }
            if self.pin_valid_once {
                lines.push("User PIN presentation valid for one signature".into());
            } else {
                lines.push("User PIN presentation valid for unlimited signatures".into());
            }
        }
        if let Some(material) = &self.public_key_material {
            lines.push(format!("Public key material: {}", material));
        }

        lines
    }
}
