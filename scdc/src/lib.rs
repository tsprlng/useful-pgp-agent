use anyhow::{anyhow, Result};
use futures::StreamExt;
use sequoia_ipc::assuan::{Client, Response};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

use lazy_static::lazy_static;
use openpgp_card::card_app::CardApp;
use openpgp_card::errors::OpenpgpCardError;
use openpgp_card::{CardBase, CardCaps, CardClient};

lazy_static! {
    pub(crate) static ref RT: Mutex<Runtime> =
        { Mutex::new(tokio::runtime::Runtime::new().unwrap()) };
}

pub struct ScdClient {
    client: Arc<Mutex<Client>>,
}

impl ScdClient {
    /// Create a CardBase object that uses an scdaemon instance as its
    /// backend.
    pub fn open_scdc(socket: &str) -> Result<CardBase, OpenpgpCardError> {
        println!("open_scdc");

        let card_client = ScdClient::new(socket)?;

        let ccb = Box::new(card_client) as Box<dyn CardClient + Send + Sync>;

        println!("get ard");

        // read and cache "application related data"
        let mut card_app = CardApp::new(ccb);
        let ard = card_app.get_app_data()?;

        println!("got ard");

        // Determine chaining/extended length support from card
        // metadata and cache this information in CardApp (as a
        // CardCaps)

        let mut ext_support = false;
        let mut chaining_support = false;

        if let Ok(hist) = CardApp::get_historical(&ard) {
            if let Some(cc) = hist.get_card_capabilities() {
                chaining_support = cc.get_command_chaining();
                ext_support = cc.get_extended_lc_le();
            }
        }

        let max_cmd_bytes = if let Ok(Some(eli)) =
            CardApp::get_extended_length_information(&ard)
        {
            eli.max_command_bytes
        } else {
            255
        };

        let caps = CardCaps::new(ext_support, chaining_support, max_cmd_bytes);
        let card_app = card_app.set_caps(caps);

        Ok(CardBase::new(card_app, ard))
    }

    pub fn new(socket: &str) -> Result<Self> {
        let client = RT.lock().unwrap().block_on(Client::connect(socket))?;
        let client = Arc::new(Mutex::new(client));
        Ok(Self { client })
    }

    async fn transmit_async(&mut self, cmd: &[u8]) -> Result<Vec<u8>> {
        let hex = hex::encode(cmd);

        let mut client = self.client.lock().unwrap();

        let mut res = None;

        {
            let send = format!("APDU {}\n", hex);
            println!("send: '{}'", send);
            client.send(send)?;

            while let Some(response) = client.next().await {
                println!("res: {:?}", response);
                if let Ok(Response::Data { partial }) = response {
                    res = Some(partial);

                    // drop remaining lines
                    while let Some(_) = client.next().await {}

                    break;
                }
            }
        }

        match res {
            Some(s) => Ok(s),
            None => Err(anyhow!("no response found")),
        }
    }
}

impl CardClient for ScdClient {
    fn transmit(&mut self, cmd: &[u8], _buf_size: usize) -> Result<Vec<u8>> {
        let mut res = None;

        {
            res = Some(RT.lock().unwrap().block_on(self.transmit_async(cmd)));
        }

        res.unwrap()
    }
}
