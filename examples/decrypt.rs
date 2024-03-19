use std::fs::File;

use card_backend_pcsc::PcscBackend;
use openpgp_card::KeyType;
use openpgp_card_rpgp::CardSlot;
use pgp::{types::SecretKeyTrait, Deserializable, Esk, Message, PlainSessionKey};

fn main() -> testresult::TestResult {
    let card = PcscBackend::cards(None)?.next().unwrap()?;
    let mut card = openpgp_card::Card::new(card)?;
    let mut tx = card.transaction()?;

    let pwd = &std::env::args().collect::<Vec<_>>()[1];
    eprintln!("with pwd = {pwd}");

    tx.verify_pw1_user(pwd.as_bytes()).expect("Verify");

    let cs = CardSlot::init_from_card(tx, KeyType::Decryption)?;
    let (message, _headers) = Message::from_armor_single(File::open("message2.asc")?)?;
    eprintln!("message: {:?}", &message);

    //let (decrypted, _ids) = message.decrypt(|| String::new(), &[&decrypt_key])?;
    let Message::Encrypted { esk, edata } = message else {
        panic!("not encrypted");
    };

    let mpis = if let Esk::PublicKeyEncryptedSessionKey(ref k) = esk[0] {
        k.mpis()
    } else {
        panic!("whoops")
    };

    let (session_key, session_key_algorithm) =
        cs.unlock(|| String::new(), |priv_key| priv_key.decrypt(mpis))?;
    eprintln!("session key: {session_key:?}, {session_key_algorithm:?}");

    let plain_session_key = PlainSessionKey::V4 {
        key: session_key,
        sym_alg: session_key_algorithm,
    };

    let decrypted = edata.decrypt(plain_session_key)?;
    eprintln!("decrypted: {:?}", &decrypted);

    if let Message::Literal(data) = decrypted {
        println!("{}", String::from_utf8_lossy(&data.data()));
    }

    Ok(())
}
