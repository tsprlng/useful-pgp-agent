// SPDX-FileCopyrightText: 2021 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-License-Identifier: MIT OR Apache-2.0

use openpgp_card_pcsc::PcscClient;

use openpgp_card_sequoia::card::Open;

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Message, Signer};
use openpgp::Cert;
use sequoia_openpgp as openpgp;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() < 3 {
        eprintln!("Usage: detach-sign card-ident pin-file cert-file");
        return Ok(());
    }

    let card_ident = &args[0];
    let pin_file = &args[1];
    let cert_file = &args[2];

    let mut ca = PcscClient::open_by_ident(&card_ident)?.into();
    let mut open = Open::open(&mut ca)?;

    let pin = std::fs::read_to_string(pin_file)?;

    open.verify_user_for_signing(&pin)?;

    let mut user = open.signing_card().unwrap();

    let p = StandardPolicy::new();
    let cert = Cert::from_file(cert_file)?;
    let s = user.signer(&cert, &p)?;

    let stdout = std::io::stdout();

    let message = Message::new(stdout);

    let message = Armorer::new(message).build()?;

    let signer = Signer::new(message, s);

    let mut signer = signer.detached().build()?;

    std::io::copy(&mut std::io::stdin(), &mut signer)?;

    signer.finalize()?;

    Ok(())
}
