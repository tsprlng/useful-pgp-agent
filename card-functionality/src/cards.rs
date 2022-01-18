// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wrapping of cards for tests. Open a list of cards, based on a
//! TestConfig configuration file

use anyhow::Result;
use serde_derive::Deserialize;
use std::collections::BTreeMap;

use openpgp_card_pcsc::PcscCard;
use openpgp_card_scdc::ScdClient;

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
    pub(crate) fn get_card(&self) -> Result<Box<PcscCard>> {
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
    pub fn open(&self) -> Result<Box<PcscCard>> {
        match self {
            Self::Pcsc(ident) => {
                // Attempt to shutdown SCD, if it is running.
                // Ignore any errors that occur during that shutdown attempt.
                let res = ScdClient::shutdown_scd(None);
                log::trace!(" Attempt to shutdown scd: {:?}", res);

                Ok(Box::new(PcscCard::open_by_ident(ident)?))
            }
            Self::Scdc(serial) => {
                unimplemented!();
                println!("open scdc card {}", serial);
                // Ok(Box::new(ScdClient::open_by_serial(None, serial)?))
            }
        }
    }
}
