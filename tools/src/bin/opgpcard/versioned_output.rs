// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::ValueEnum;
use semver::Version;
use serde::{Serialize, Serializer};
use std::str::FromStr;

#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Text,
    Yaml,
}

#[derive(Debug, Clone)]
pub struct OutputVersion {
    version: Version,
}

impl OutputVersion {
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            version: Version::new(major, minor, patch),
        }
    }

    /// Does this version fulfill the needs of the version that is requested?
    pub fn is_acceptable_for(&self, wanted: &Self) -> bool {
        self.version.major == wanted.version.major
            && (self.version.minor > wanted.version.minor
                || (self.version.minor == wanted.version.minor
                    && self.version.patch >= wanted.version.patch))
    }
}

impl std::fmt::Display for OutputVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.version)
    }
}

impl FromStr for OutputVersion {
    type Err = semver::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = Version::parse(s)?;
        Ok(Self::new(v.major, v.minor, v.patch))
    }
}

impl PartialEq for &OutputVersion {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl Serialize for OutputVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub trait OutputBuilder {
    type Err;

    fn print(&self, format: OutputFormat, version: OutputVersion) -> Result<String, Self::Err>;
}

pub trait OutputVariant: Serialize {
    const VERSION: OutputVersion;
    fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    fn yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}
