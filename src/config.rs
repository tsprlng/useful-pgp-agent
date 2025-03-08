use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use crate::*;

pub type CardNickname = String;

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Config {
    pub cards: HashMap<CardNickname, CardConfig>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Clone)]
pub struct CardConfig {
    pub ident: CardIdent,
    pub common_pin: Option<String>,
    pub priority: Option<u32>,
}

pub fn load_config() -> Config {
    serde_yaml::from_reader(File::open("./config.yml").expect("config file")).expect("serde")
}

impl Config {
    pub fn init_known_cards(&self) -> Vec<Card>{
        let mut cards = Vec::new();
        for (name, config) in self.cards.iter() {
            cards.push(Card {
                nickname: Some(name.clone()),
                pcsc_address: None,
                ident: Some(config.ident.clone()),
                config: Some(config.clone()),
                state: CardState::Unavailable,
            });
        }
        cards
    }
}
