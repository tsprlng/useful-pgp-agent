// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::PublicKeyTrait;
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
    let mut card = openpgp_card::Card::new(card).expect("card new");
    let mut tx = card.transaction().expect("tx");

    tx.card()
        .verify_pw1_sign(pwd.as_bytes().to_vec().into())
        .expect("Verify");

    let cs = CardSlot::init_from_card(&mut tx, KeyType::Signing, &|| {
        eprintln!("touch confirmation needed")
    })?;

    // -- use card signer
    let mut config = SignatureConfig::v4(
        SignatureType::Binary,
        cs.public_key().algorithm(),
        HashAlgorithm::SHA2_256,
    );

    config
        .hashed_subpackets
        .push(Subpacket::regular(SubpacketData::SignatureCreationTime(
            std::time::SystemTime::now().into(),
        )));
    config
        .hashed_subpackets
        .push(Subpacket::regular(SubpacketData::Issuer(cs.key_id())));
    config
        .hashed_subpackets
        .push(Subpacket::regular(SubpacketData::IssuerFingerprint(
            cs.fingerprint(),
        )));

    let signature = config.sign(&cs, String::new, DATA)?;

    let signature = StandaloneSignature { signature };
    signature
        .to_armored_writer(
            &mut std::fs::File::create("sig.asc").unwrap(),
            ArmorOptions::default(),
        )
        .unwrap();
    Ok(())
}
