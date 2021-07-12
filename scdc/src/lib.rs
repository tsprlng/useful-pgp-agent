use anyhow::{anyhow, Result};
use futures::StreamExt;
use lazy_static::lazy_static;
use sequoia_ipc::assuan::{Client, Response};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

use openpgp_card::errors::OpenpgpCardError;
use openpgp_card::{CardBase, CardClient, CardClientBox};

lazy_static! {
    pub(crate) static ref RT: Mutex<Runtime> =
        Mutex::new(tokio::runtime::Runtime::new().unwrap());
}

pub struct ScdClient {
    client: Arc<Mutex<Client>>,
}

impl ScdClient {
    /// Create a CardBase object that uses an scdaemon instance as its
    /// backend.
    pub fn open_scdc(socket: &str) -> Result<CardBase, OpenpgpCardError> {
        let card_client = ScdClient::new(socket)?;
        let card_client_box = Box::new(card_client) as CardClientBox;

        CardBase::open_card(card_client_box)
    }

    pub fn new(socket: &str) -> Result<Self> {
        let client = RT.lock().unwrap().block_on(Client::connect(socket))?;
        let client = Arc::new(Mutex::new(client));
        Ok(Self { client })
    }
}

impl CardClient for ScdClient {
    fn transmit(&mut self, cmd: &[u8], _: usize) -> Result<Vec<u8>> {
        let hex = hex::encode(cmd);

        let mut client = self.client.lock().unwrap();

        let send = format!("APDU {}\n", hex);
        println!("send: '{}'", send);
        client.send(send)?;

        let mut rt = RT.lock().unwrap();

        while let Some(response) = rt.block_on(client.next()) {
            println!("res: {:x?}", response);
            if let Err(_) = response {
                unimplemented!();
            }

            if let Ok(Response::Data { partial }) = response {
                let res = partial;

                // drop remaining lines
                while let Some(drop) = rt.block_on(client.next()) {
                    println!("drop: {:x?}", drop);
                }

                println!();

                return Ok(res);
            }
        }

        Err(anyhow!("no response found"))
    }
}
