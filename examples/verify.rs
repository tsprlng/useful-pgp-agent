// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use pgp::composed::signed_key::SignedPublicKey;
use pgp::composed::Deserializable;
use pgp::types::PublicKeyTrait;
use pgp::StandaloneSignature;

fn main() -> testresult::TestResult {
    const DATA: &[u8] = b"Hello World";

    let cert = &std::env::args().collect::<Vec<_>>()[1];
    eprintln!("with cert = {cert}");

    let key = SignedPublicKey::from_armor_single(std::fs::File::open(cert)?)?.0;

    let sig = StandaloneSignature::from_armor_single(std::fs::File::open("sig.asc")?)?.0;
    if let Ok(()) = sig.verify(&key, DATA) {
        eprintln!("Looks OK here: {:x}", key.key_id());
        return Ok(());
    }
    for subkey in key.public_subkeys {
        if let Ok(()) = sig.verify(&subkey, DATA) {
            eprintln!("Looks OK here: {:x}", subkey.key_id());
            return Ok(());
        }
    }

    panic!("no good signature found")
}
