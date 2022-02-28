// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wrapping of cards for tests. Open a list of cards, based on a
//! TestConfig configuration file

use anyhow::Result;
use pcsc::ShareMode;
use serde_derive::Deserialize;
use std::collections::BTreeMap;

use openpgp_card::{CardBackend, Error};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_scdc::ScdBackend;

const SHARE_MODE: Option<ShareMode> = Some(ShareMode::Shared);

#[derive(Debug, Deserialize)]
pub struct TestConfig {
    card: BTreeMap<String, Card>,
}

#[derive(Debug, Deserialize)]
pub struct Card {
    backend: BTreeMap<String, String>,
    config: Config,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub keygen: Option<Vec<String>>,
    pub import: Option<Vec<String>>,
}

/// An "opened" card, via one particular backend, with test-metadata
#[derive(Debug)]
pub struct TestCardData {
    name: String,
    tc: TestCard,
    config: Config,
}

impl TestCardData {
    pub(crate) fn get_card(&self) -> Result<Box<dyn CardBackend + Send + Sync>> {
        self.tc.open()
    }

    pub fn get_config(&self) -> &Config {
        &self.config
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }
}

impl TestConfig {
    pub fn load(file: &str) -> Result<Self> {
        let config_file = std::fs::read_to_string(file)?;

        let config: Self = toml::from_str(&config_file)?;
        Ok(config)
    }

    pub fn into_cardapps(self) -> Vec<TestCardData> {
        let mut cards = vec![];

        for (name, card) in self.card {
            for (backend, id) in &card.backend {
                let tc: TestCard = match backend.as_str() {
                    "pcsc" => TestCard::Pcsc(id.to_string()),
                    "scdc" => TestCard::Scdc(id.to_string()),
                    _ => panic!("unexpected backend {}", backend),
                };

                cards.push(TestCardData {
                    name: name.clone(),
                    tc,
                    config: card.config.clone(),
                })
            }
        }

        cards
    }
}

#[derive(Debug)]
pub enum TestCard {
    Pcsc(String),
    Scdc(String),
}

impl TestCard {
    pub fn open(&self) -> Result<Box<dyn CardBackend + Send + Sync>> {
        match self {
            Self::Pcsc(ident) => {
                // Attempt to shutdown SCD, if it is running.
                // Ignore any errors that occur during that shutdown attempt.
                let res = ScdBackend::shutdown_scd(None);
                log::trace!(" Attempt to shutdown scd: {:?}", res);

                // Make three attempts to open the card before failing
                // (this can be useful in ShareMode::Exclusive)
                let mut i = 1;
                let card: Result<Box<dyn CardBackend + Send + Sync>, Error> = loop {
                    let res = PcscBackend::open_by_ident(ident, SHARE_MODE);

                    if i == 3 {
                        if let Ok(res) = res {
                            break Ok(Box::new(res));
                        }
                    }

                    // sleep for 100ms
                    std::thread::sleep(std::time::Duration::from_millis(100));

                    i += 1;
                };

                Ok(card?)
            }
            Self::Scdc(serial) => Ok(Box::new(ScdBackend::open_by_serial(None, serial)?)),
        }
    }
}
