// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wrapping of cards for tests. Open a list of cards, based on a
//! TestConfig configuration file

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;
use std::collections::BTreeMap;

use openpgp_card::apdu::PcscClient;
use openpgp_card::card_app::CardApp;
use openpgp_card::CardClientBox;
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
    pub keygen: Vec<String>,
}

/// An "opened" card, via one particular backend, with test-metadata
#[derive(Debug)]
pub struct TestCardApp {
    name: String,
    tc: TestCard,
    config: Config,
}

impl TestCardApp {
    pub(crate) fn get_card_app(&mut self) -> Result<CardApp> {
        self.tc.open()
    }

    pub fn get_config(&self) -> &Config {
        &self.config
    }
}

impl TestConfig {
    pub fn load(file: &str) -> Result<Self> {
        let config_file = std::fs::read_to_string(file)?;

        let config: Self = toml::from_str(&config_file)?;
        Ok(config)
    }

    pub fn get_cards(self) -> Vec<TestCardApp> {
        let mut cards = vec![];

        for (name, card) in self.card {
            for (backend, id) in &card.backend {
                let tc: TestCard = match backend.as_str() {
                    "pcsc" => TestCard::Pcsc(id.to_string()),
                    "scdc" => TestCard::Scdc(id.to_string()),
                    _ => panic!("unexpected backend {}", backend),
                };

                cards.push(TestCardApp {
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
    pub fn open(&self) -> Result<CardApp> {
        match self {
            Self::Pcsc(ident) => {
                // Attempt to shutdown SCD, if it is running.
                // Ignore any errors that occur during that shutdown attempt.
                let res = ScdClient::shutdown_scd(None);
                log::trace!(" Attempt to shutdown scd: {:?}", res);

                for card in PcscClient::list_cards()? {
                    let card_client = Box::new(card) as CardClientBox;
                    let mut ca = CardApp::new(card_client);

                    // Select OpenPGP applet
                    let res = ca.select()?;
                    res.check_ok()?;

                    // Set Card Capabilities (chaining, command length, ..)
                    let ard = ca.get_app_data()?;
                    let app_id = CardApp::get_aid(&ard)?;

                    if app_id.ident().as_str() == ident {
                        ca.init_caps(&ard)?;

                        // println!("opened pcsc card {}", ident);

                        return Ok(ca);
                    }
                }

                Err(anyhow!("Pcsc card {} not found", ident))
            }
            Self::Scdc(serial) => {
                let card_client = ScdClient::open_by_serial(None, serial)?;
                let mut ca = CardApp::new(card_client);

                // Set Card Capabilities (chaining, command length, ..)
                let ard = ca.get_app_data()?;
                ca.init_caps(&ard)?;

                // println!("opened scdc card {}", serial);

                Ok(ca)
            }
        }
    }
}
