
use pgp::composed::signed_key::SignedPublicKey;
use pgp::composed::Deserializable;
use pgp::types::KeyTrait;
use pgp::StandaloneSignature;

fn main() -> testresult::TestResult {
    const DATA: &[u8] = b"Hello World";

    let key = SignedPublicKey::from_armor_single(std::fs::File::open("key.asc")?)?.0;

    let sig = StandaloneSignature::from_armor_single(std::fs::File::open("sig.asc")?)?.0;
    if let Ok(()) = sig.verify(&key, DATA) {
        eprintln!("Looks OK here: {:x}", key.key_id());
    }
    for subkey in key.public_subkeys {
        if let Ok(()) = sig.verify(&subkey, DATA) {
            eprintln!("Looks OK here: {:x}", subkey.key_id());
        }
    }
    Ok(())
}
