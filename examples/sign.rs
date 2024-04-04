// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{self, SignatureConfig};
use pgp::types::{KeyTrait, KeyVersion};
use pgp::{ArmorOptions, StandaloneSignature};

fn main() -> testresult::TestResult {
    const DATA: &[u8] = b"Hello World";

    let pwd = &std::env::args().collect::<Vec<_>>()[1];
    eprintln!("with pwd = {pwd}");

    // -- set up card signer
    let card = PcscBackend::cards(None)
        .expect("cards")
        .next()
        .unwrap()
        .expect("card");
    let mut card = openpgp_card::ocard::OpenPGP::new(card).expect("card new");
    let mut tx = card.transaction().expect("tx");

    tx.verify_pw1_sign(pwd.as_bytes()).expect("Verify");

    let cs = CardSlot::init_from_card(tx, KeyType::Signing)?;

    // -- use card signer
    let signature = SignatureConfig::new_v4(
        packet::SignatureVersion::V4,
        packet::SignatureType::Binary,
        cs.public_key().algorithm(),
        HashAlgorithm::SHA2_256,
        vec![
            packet::Subpacket::regular(packet::SubpacketData::SignatureCreationTime(
                std::time::SystemTime::now().into(),
            )),
            packet::Subpacket::regular(packet::SubpacketData::Issuer(cs.key_id())),
            packet::Subpacket::regular(packet::SubpacketData::IssuerFingerprint(
                KeyVersion::V4,
                cs.fingerprint().into(),
            )),
        ],
        vec![],
    );

    let signature = signature.sign(&cs, String::new, DATA)?;

    let signature = StandaloneSignature { signature };
    signature
        .to_armored_writer(
            &mut std::fs::File::create("sig.asc").unwrap(),
            ArmorOptions::default(),
        )
        .unwrap();
    Ok(())
}
