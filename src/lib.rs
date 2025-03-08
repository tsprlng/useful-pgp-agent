pub mod config;
pub mod decryption;
pub mod identification;
pub mod monitoring;

/// GPG "application identity" of the card, which we use as our main ID to join configuration with reality
pub type CardIdent = String;

#[derive(Debug, PartialEq, Eq)]
pub enum CardState {
    Unidentified,
    Unavailable,
    Ready,
}

#[derive(Debug)]
pub struct Card {
    pub nickname: Option<config::CardNickname>,
    pub pcsc_address: Option<monitoring::PcscReaderName>,
    pub ident: Option<CardIdent>,
    pub config: Option<config::CardConfig>,
    pub state: CardState,
}

impl Card {
    pub fn pin_cache_key(&self) -> &str {
        if let Some(config) = &self.config {
            if let Some(common_pin_name) = &config.common_pin {
                return &common_pin_name;
            }
        }
        return self.ident.as_ref().unwrap();
    }
}
