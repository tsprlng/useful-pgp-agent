// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::Serialize;

use crate::output::OpgpCardError;
use crate::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

#[derive(Debug, Default, Serialize)]
pub struct Status {
    verbose: bool, // show verbose text output?
    pkm: bool,     // include public key material in text output?
    ident: String,
    card_version: String,
    cardholder_name: Option<String>,
    language_preferences: Vec<String>,
    certificate_url: Option<String>,
    signature_key: KeySlotInfo,
    signature_count: u32,
    user_pin_valid_for_only_one_signature: bool,
    decryption_key: KeySlotInfo,
    authentication_key: KeySlotInfo,
    attestation_key: Option<KeySlotInfo>,
    user_pin_remaining_attempts: u8,
    admin_pin_remaining_attempts: u8,
    reset_code_remaining_attempts: u8,
    additional_key_statuses: Vec<(u8, String)>,
    ca_fingerprints: Vec<String>,
}

impl Status {
    pub fn verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    pub fn pkm(&mut self, pkm: bool) {
        self.pkm = pkm;
    }

    pub fn ident(&mut self, ident: String) {
        self.ident = ident;
    }

    pub fn card_version(&mut self, card_version: String) {
        self.card_version = card_version;
    }

    pub fn cardholder_name(&mut self, card_holder: String) {
        self.cardholder_name = Some(card_holder);
    }

    pub fn language_preference(&mut self, pref: String) {
        self.language_preferences.push(pref);
    }

    pub fn certificate_url(&mut self, url: String) {
        self.certificate_url = Some(url);
    }

    pub fn signature_key(&mut self, key: KeySlotInfo) {
        self.signature_key = key;
    }

    pub fn signature_count(&mut self, count: u32) {
        self.signature_count = count;
    }

    pub fn user_pin_valid_for_only_one_signature(&mut self, sign_pin_valid_once: bool) {
        self.user_pin_valid_for_only_one_signature = sign_pin_valid_once;
    }

    pub fn decryption_key(&mut self, key: KeySlotInfo) {
        self.decryption_key = key;
    }

    pub fn authentication_key(&mut self, key: KeySlotInfo) {
        self.authentication_key = key;
    }

    pub fn attestation_key(&mut self, key: KeySlotInfo) {
        self.attestation_key = Some(key);
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

    pub fn additional_key_status(&mut self, keyref: u8, status: String) {
        self.additional_key_statuses.push((keyref, status));
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
        if let Some(name) = &self.cardholder_name {
            if !name.is_empty() {
                s.push_str(&format!("Cardholder: {}\n", name));
                nl = true;
            }
        }

        if let Some(url) = &self.certificate_url {
            if !url.is_empty() {
                s.push_str(&format!("Certificate URL: {}\n", url));
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
        for line in self.signature_key.format(self.verbose, self.pkm) {
            s.push_str(&format!("  {}\n", line));
        }
        if self.verbose {
            if self.user_pin_valid_for_only_one_signature {
                s.push_str("  User PIN presentation is valid for only one signature\n");
            } else {
                s.push_str("  User PIN presentation is valid for unlimited signatures\n");
            }
        }
        s.push_str(&format!("  Signatures made: {}\n", self.signature_count));
        s.push('\n');

        s.push_str("Decryption key:\n");
        for line in self.decryption_key.format(self.verbose, self.pkm) {
            s.push_str(&format!("  {}\n", line));
        }
        s.push('\n');

        s.push_str("Authentication key:\n");
        for line in self.authentication_key.format(self.verbose, self.pkm) {
            s.push_str(&format!("  {}\n", line));
        }
        s.push('\n');

        if self.verbose {
            if let Some(attestation_key) = &self.attestation_key {
                if attestation_key.touch_policy.is_some() || attestation_key.algorithm.is_some() {
                    s.push_str("Attestation key:\n");
                    for line in attestation_key.format(self.verbose, self.pkm) {
                        s.push_str(&format!("  {}\n", line));
                    }
                    s.push('\n');
                }
            }
        }

        s.push_str(&format!(
            "Remaining PIN attempts: User: {}, Admin: {}, Reset Code: {}\n",
            self.user_pin_remaining_attempts,
            self.admin_pin_remaining_attempts,
            self.reset_code_remaining_attempts
        ));

        if self.verbose {
            for (keyref, status) in self.additional_key_statuses.iter() {
                s.push_str(&format!(
                    "Additional key status (#{}): {}\n",
                    keyref, status
                ));
            }
        }

        Ok(s)
    }

    fn v1(&self) -> Result<StatusV0, OpgpCardError> {
        Ok(StatusV0 {
            schema_version: StatusV0::VERSION,
            ident: self.ident.clone(),
            card_version: self.card_version.clone(),
            cardholder_name: self.cardholder_name.clone(),
            language_preferences: self.language_preferences.clone(),
            certificate_url: self.certificate_url.clone(),
            signature_key: self.signature_key.clone(),
            signature_count: self.signature_count,
            decryption_key: self.decryption_key.clone(),
            authentication_key: self.authentication_key.clone(),
            attestation_key: self.attestation_key.clone(),
            user_pin_valid_for_only_one_signature: self.user_pin_valid_for_only_one_signature,
            user_pin_remaining_attempts: self.user_pin_remaining_attempts,
            admin_pin_remaining_attempts: self.admin_pin_remaining_attempts,
            reset_code_remaining_attempts: self.reset_code_remaining_attempts,
            additional_key_statuses: self.additional_key_statuses.clone(),
            // ca_fingerprints: self.ca_fingerprints.clone(),
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
    cardholder_name: Option<String>,
    language_preferences: Vec<String>,
    certificate_url: Option<String>,
    signature_key: KeySlotInfo,
    signature_count: u32,
    user_pin_valid_for_only_one_signature: bool,
    decryption_key: KeySlotInfo,
    authentication_key: KeySlotInfo,
    attestation_key: Option<KeySlotInfo>,
    user_pin_remaining_attempts: u8,
    admin_pin_remaining_attempts: u8,
    reset_code_remaining_attempts: u8,
    additional_key_statuses: Vec<(u8, String)>,
    // ca_fingerprints: Vec<String>, // TODO: add to JSON output after clarifying the content
}

impl OutputVariant for StatusV0 {
    const VERSION: OutputVersion = OutputVersion::new(0, 9, 0);
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct KeySlotInfo {
    fingerprint: Option<String>,
    creation_time: Option<String>,
    algorithm: Option<String>,
    touch_policy: Option<String>,
    touch_features: Option<String>,
    status: Option<String>,
    public_key_material: Option<String>,
}

impl KeySlotInfo {
    pub fn fingerprint(&mut self, fingerprint: String) {
        self.fingerprint = Some(fingerprint);
    }

    pub fn algorithm(&mut self, algorithm: String) {
        self.algorithm = Some(algorithm);
    }

    pub fn creation_time(&mut self, created: String) {
        self.creation_time = Some(created);
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

    pub fn public_key_material(&mut self, material: String) {
        self.public_key_material = Some(material);
    }

    fn format(&self, verbose: bool, pkm: bool) -> Vec<String> {
        let mut lines = vec![];

        if let Some(fp) = &self.fingerprint {
            lines.push(format!("Fingerprint: {}", fp));
        } else {
            lines.push("Fingerprint: [unset]".to_string());
        }
        if let Some(ts) = &self.creation_time {
            lines.push(format!("Creation Time: {}", ts));
        }
        if let Some(a) = &self.algorithm {
            lines.push(format!("Algorithm: {}", a));
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
        }
        if pkm {
            if let Some(material) = &self.public_key_material {
                lines.push(format!("Public key material: {}", material));
            }
        }

        lines
    }
}
