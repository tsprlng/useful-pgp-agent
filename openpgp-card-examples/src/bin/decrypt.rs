// SPDX-FileCopyrightText: 2021 Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-License-Identifier: MIT OR Apache-2.0

use openpgp_card_pcsc::PcscClient;

use openpgp_card_sequoia::card::Open;

use openpgp::parse::{stream::DecryptorBuilder, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::Cert;
use sequoia_openpgp as openpgp;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();

    if args.len() < 3 {
        eprintln!("Usage: decrypt card-ident pin-file cert-file");
        return Ok(());
    }

    let card_ident = &args[0];
    let pin_file = &args[1];
    let cert_file = &args[2];

    let mut ca = PcscClient::open_by_ident(&card_ident)?.into();
    let mut open = Open::open(&mut ca)?;

    let pin = std::fs::read_to_string(pin_file)?;

    open.verify_user(&pin)?;

    let mut user = open.user_card().unwrap();

    let p = StandardPolicy::new();
    let cert = Cert::from_file(cert_file)?;
    let d = user.decryptor(&cert, &p)?;
    let stdin = std::io::stdin();

    let mut stdout = std::io::stdout();

    let db = DecryptorBuilder::from_reader(stdin)?;
    let mut decryptor = db.with_policy(&p, None, d)?;

    std::io::copy(&mut decryptor, &mut stdout)?;

    Ok(())
}
