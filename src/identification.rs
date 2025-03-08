extern crate pcsc;
extern crate card_backend_pcsc;
extern crate openpgp_card;

use crate::*;
use pcsc::*;
use card_backend_pcsc::PcscBackend;
use openpgp_card::Card;
use thiserror::Error;
use std::ffi::CStr;

pub(crate) fn cstr_to_string(cstr: &CStr) -> String {
    String::from_utf8_lossy(cstr.to_bytes()).to_string()
}

#[derive(Error, Debug)]
pub enum IdentificationError {
    #[error("couldn't connect (pcsc)")]
    PcscConnectionFailed(#[from] pcsc::Error),
    #[error("couldn't connect (gpg)")]
    GpgConnectionFailed,
    #[error("couldn't get transaction")]
    TransactionAcquisitionFailed,
    #[error("couldn't get id")]
    IdentRequestFailed(#[from] openpgp_card::Error),
}

pub fn try_identify_card(ctx: &pcsc::Context, name: &CStr) -> Result<CardIdent, IdentificationError> {
    let card = ctx.connect(&name, ShareMode::Shared, Protocols::ANY)?;
    let gpg = PcscBackend {
        card: card,
        mode: ShareMode::Shared,
        reader_caps: Default::default(),
        reader_name: String::from_utf8_lossy(name.to_bytes()).to_string(),
    };
    let mut card = Card::new(gpg)?;
    let tx = card.transaction()?;
    let ident = &tx.application_identifier()?.ident();
    Ok(ident.to_string())
}
