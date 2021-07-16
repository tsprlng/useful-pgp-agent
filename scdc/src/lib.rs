// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use futures::StreamExt;
use lazy_static::lazy_static;
use sequoia_ipc::assuan::{Client, Response};
use std::sync::Mutex;
use tokio::runtime::Runtime;

use openpgp_card::errors::OpenpgpCardError;
use openpgp_card::{CardBase, CardClient, CardClientBox};

lazy_static! {
    pub(crate) static ref RT: Mutex<Runtime> =
        Mutex::new(tokio::runtime::Runtime::new().unwrap());
}

pub struct ScdClient {
    client: Client,
}

impl ScdClient {
    /// Create a CardBase object that uses an scdaemon instance as its
    /// backend.
    pub fn open_scdc(socket: &str) -> Result<CardBase, OpenpgpCardError> {
        let card_client = ScdClient::new(socket)?;
        let card_client_box = Box::new(card_client) as CardClientBox;

        CardBase::open_card(card_client_box)
    }

    /// Create a CardBase object that uses an scdaemon instance as its
    /// backend, asking for a specific card by `serial`.
    pub fn open_scdc_by_serial(
        socket: &str,
        serial: &str,
    ) -> Result<CardBase, OpenpgpCardError> {
        let mut card_client = ScdClient::new(socket)?;

        card_client.select_card(serial)?;

        let card_client_box = Box::new(card_client) as CardClientBox;

        CardBase::open_card(card_client_box)
    }

    pub fn new(socket: &str) -> Result<Self> {
        let client = RT.lock().unwrap().block_on(Client::connect(socket))?;
        Ok(Self { client })
    }

    fn select_card(&mut self, serial: &str) -> Result<()> {
        let send = format!("SERIALNO --demand={}\n", serial);
        self.client.send(send)?;

        let mut rt = RT.lock().unwrap();

        while let Some(response) = rt.block_on(self.client.next()) {
            if let Err(_) = response {
                return Err(anyhow!("Card not found"));
            }

            if let Ok(Response::Status { .. }) = response {
                // drop remaining lines
                while let Some(_drop) = rt.block_on(self.client.next()) {}

                return Ok(());
            }
        }

        Err(anyhow!("Card not found"))
    }
}

impl CardClient for ScdClient {
    fn transmit(&mut self, cmd: &[u8], _: usize) -> Result<Vec<u8>> {
        let hex = hex::encode(cmd);

        let send = format!("APDU {}\n", hex);
        println!("send: '{}'", send);
        self.client.send(send)?;

        let mut rt = RT.lock().unwrap();

        while let Some(response) = rt.block_on(self.client.next()) {
            log::trace!("res: {:x?}", response);
            if let Err(_) = response {
                unimplemented!();
            }

            if let Ok(Response::Data { partial }) = response {
                let res = partial;

                // drop remaining lines
                while let Some(drop) = rt.block_on(self.client.next()) {
                    log::trace!("drop: {:x?}", drop);
                }

                return Ok(res);
            }
        }

        Err(anyhow!("no response found"))
    }
}
