use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use lazy_static::lazy_static;
use openpgp_card::{
    Card,
    ocard::KeyType,
    state::{Open, Transaction, User},
};
use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::io::Write;
use std::sync::Mutex;

use openpgp_card_rpgp::CardSlot;
use pgp::{Deserializable, types::SecretKeyTrait};
use pgp::{Esk, Message, PlainSessionKey};

use rpassword;
use secrecy::SecretString;
const ENTER_USER_PIN: &str = "Enther the Phin?:";

lazy_static! {
    static ref PIN_CACHE: Mutex<HashMap<String, SecretString>> = Mutex::new(HashMap::new());
}

pub fn get_card(card_info: &crate::Card) -> Result<Card<Open>> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("failed to establish context");
    let pcsc_reader_name = card_info.pcsc_address.as_ref().unwrap();
    let card = ctx.connect(pcsc_reader_name, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)?;
    let gpg = card_backend_pcsc::PcscBackend {
        card: card,
        mode: pcsc::ShareMode::Shared,
        reader_caps: Default::default(),
        reader_name: crate::identification::cstr_to_string(&pcsc_reader_name),
    };
    let open = Card::new(gpg)?;
    Ok(open)
}

fn get_pin(
    card: &mut Card<Transaction<'_>>,
    msg: &str,
) -> Result<Option<SecretString>> {
    if !card.feature_pinpad_verify() {
        let pin = rpassword::prompt_password(msg).context("Failed to read PIN")?;
        Ok(Some(pin.into()))
    } else {
        // we have a pinpad
        Ok(None)
    }
}

fn verify_to_user<'app, 'open>(
    card: &'open mut Card<Transaction<'app>>,
    pin: Option<SecretString>,
) -> Result<Card<User<'app, 'open>>, Box<dyn std::error::Error>> {
    if let Some(pin) = pin {
        card.verify_user_pin(pin)?;
    } else {
        if !card.feature_pinpad_verify() {
            return Err(anyhow!("No user PIN file provided, and no pinpad found").into());
        };

        card.verify_user_pinpad(&|| eprintln!("Enter user PIN on card reader pinpad."))?;
    }

    Ok(card.to_user_card(None)?)
}


pub fn get_tx<'a>(open: &'a mut Card<Open>, pin_cache_key: &'a str) -> Result<Card<Transaction<'a>>> {
    let mut tx = open.transaction().context("trans")?;
    let _ = tx.to_user_card(None);

    let mut cache = PIN_CACHE.lock().expect("pin cache lock");
    let cached_pin = cache.get(pin_cache_key);
    let user_pin = match cached_pin {
        Some(pin_ref) => Some(pin_ref.clone()),
        None => get_pin(&mut tx, ENTER_USER_PIN).context("phin")?,
    };

    let _ = verify_to_user(&mut tx, user_pin.clone()).unwrap();
    if let Some(pin) = user_pin {
        cache.insert(pin_cache_key.to_owned(), pin);
    }

    Ok(tx)
}

pub fn decrypt(tx: &mut Card<Transaction<'_>>, mut input: UnixStream) -> Result<(), Box<dyn std::error::Error>> {
    //let input = open_or_stdin(command.input.as_deref())?;
    let (message, _headers) = Message::from_reader_single(&mut input)?;

    eprintln!("{:?}", &message);
    eprintln!("{:?}", &_headers);

    eprintln!("doing card");


    eprintln!("got tx");
    eprintln!("{:?}", tx.fingerprints());

    if tx.fingerprints()?.decryption().is_none() {
        return Err(anyhow!("Can't decrypt: this card has no key in the decryption slot.").into());
    }

    eprintln!("card done");

    let cs = CardSlot::init_from_card(tx, KeyType::Decryption, &|| {
        eprintln!("Touch confirmation needed for decryption");
    })?;

    let Message::Encrypted { esk, edata } = message else {
        return Err(anyhow::anyhow!("message not encrypted").into());
    };

    eprintln!("{:?}", esk);

    // Try all ESK, until we can decrypt one
    for e in esk {
        // We only consider PKESK (OpenPGP card doesn't apply to SKESK)
        if let Esk::PublicKeyEncryptedSessionKey(pgp::packet::PublicKeyEncryptedSessionKey::V3 {
               ref values,
               ..
            }) = e {

            // Attempt to decrypt this PKESK with the card
            let res = cs.unlock(String::new, |priv_key| priv_key.decrypt(values));
            if let Ok((session_key, session_key_algorithm)) = res
            {
                // Session key decrypted! The card-related part of the operation is done.
                let plain_session_key = PlainSessionKey::V3_4 {
                    key: session_key,
                    sym_alg: session_key_algorithm,
                };

                // Symmetrically decrypt the edata
                let decrypted = edata.decrypt(plain_session_key)?;

                // Try to extract the pure plaintext from the decrypted inner message
                // (which could still be compressed and/or signed)
                let data = unpack_unencrypted_msg(&decrypted)?;

                // Write out the decrypted plaintext
                write!(input, "OK\n").expect("write");
                input.write_all(&data)?;
                write!(input, "\nEND\n").expect("write");

                return Ok(());
            }
            else
            {
                eprintln!("{:?}", res);
            }
        }
    }

    Err(anyhow::anyhow!("Couldn't decrypt message").into())
}

fn unpack_unencrypted_msg(msg: &Message) -> Result<Vec<u8>> {
    unpack_unencrypted_msg_int(msg, 0)
}

fn unpack_unencrypted_msg_int(msg: &Message, depth: usize) -> Result<Vec<u8>> {
    const MAX_RECURSION: usize = 10;
    if depth > MAX_RECURSION {
        return Err(anyhow::anyhow!("Excessive message nesting depth"));
    }

    match msg {
        Message::Compressed(cd) => {
            let payload = cd.decompress()?;
            let msg = Message::from_bytes(payload)?;
            unpack_unencrypted_msg_int(&msg, depth + 1)
        }
        Message::Encrypted { .. } => Err(anyhow::anyhow!(
            "error: decrypted message contains encrypted layer"
        )),
        Message::Literal(data) => Ok(data.data().to_vec()),
        Message::Signed { message, .. } => {
            if let Some(msg) = message {
                unpack_unencrypted_msg_int(msg, depth + 1)
            } else {
                Err(anyhow::anyhow!(
                    "error: no inner message found in signed message"
                ))
            }
        }
    }
}
