use libc::umask;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc,RwLock};
use std::thread;
use useful_pgp_agent::*;
use useful_pgp_agent::config;
use useful_pgp_agent::decryption;
use useful_pgp_agent::monitoring;

type CardStates = Vec<Card>;

#[derive(Debug)]
struct CardIdentified<'a>(#[allow(dead_code)] &'a monitoring::CardInfo);
#[derive(Debug)]
struct CardGone<'a>(#[allow(dead_code)] &'a monitoring::CardInfo);
#[derive(Debug)]
struct ConfigLoaded<'a>(#[allow(dead_code)] &'a config::Config);
#[derive(Debug)]
struct KnownCardsDerived<'a>(#[allow(dead_code)] &'a CardStates);
#[derive(Debug)]
struct StatusUpdated<'a>(#[allow(dead_code)] &'a CardStates);
#[derive(Debug)]
struct CardSelected<'a>(#[allow(dead_code)] &'a Option<&'a Card>);
#[derive(Debug)]
struct ConnectionReceived();

fn add_card(known_cards: &mut Vec<Card>, info: &monitoring::CardInfo){
    for card in known_cards.iter_mut() {
        if let Some(config) = &card.config {
            if config.ident == info.ident {
                card.state = CardState::Ready;
                card.pcsc_address = Some(info.pcsc_address.clone());
                break;
            }
        }
    }
    known_cards.retain(|c|{
        !(
            c.pcsc_address.as_ref() == Some(&info.pcsc_address)
                && c.config.as_ref().map(|c| &c.ident) != Some(&info.ident)
        )
    });
    println!("{:?}", StatusUpdated(&known_cards));
    println!("{:?}", CardSelected(&best_card_for_decrypt(&known_cards)));
}

fn remove_card(known_cards: &mut Vec<Card>, info: &monitoring::CardInfo){
    for card in known_cards.iter_mut() {
        if card.pcsc_address.as_ref() == Some(&info.pcsc_address) {
            card.state = CardState::Unavailable;
            break;
        }
    }
    println!("{:?}", StatusUpdated(&known_cards));
    println!("{:?}", CardSelected(&best_card_for_decrypt(&known_cards)));
}

fn best_card_for_decrypt(known_cards: &Vec<Card>) -> Option<&Card> {
    known_cards.iter().filter(|c| c.state == CardState::Ready).min_by_key(|c| c.config.as_ref().and_then(|conf| conf.priority).unwrap_or(999))
}


fn get_listener() -> UnixListener {
    let mut sock_path = dirs::home_dir().expect("home dir");
    sock_path.push("tmp.pgp.test.sock");
    let sock_path = &sock_path;

    if fs::exists(sock_path).expect("failed to existcheck") {
        let md = fs::metadata(sock_path).expect("failed to metadata");
        if md.file_type().is_socket() {
            fs::remove_file(sock_path);
        }
    }

    let old_umask;
    unsafe { old_umask = umask(0o077); }
    let sock = UnixListener::bind(sock_path).expect("hrm");
    unsafe { umask(old_umask); }
    sock
}

fn main() {
    let config = Arc::new(config::load_config());
    println!("{:?}", ConfigLoaded(&config));

    let known_cards = Arc::new(RwLock::new(config.init_known_cards()));
    println!("{:?}", KnownCardsDerived(&known_cards.read().expect("lock")));

    let known_cards_access_1 = known_cards.clone();
    let known_cards_access_2 = known_cards.clone();
    let _monitor = thread::spawn(move ||{
        let callbacks = monitoring::Callbacks {
            card_available: Box::new(move |info| {
                println!("{:?}", &CardIdentified(info));
                add_card(&mut known_cards_access_1.write().expect("lock"), info);
            }),
            card_unavailable: Box::new(move |info| {
                println!("{:?}", &CardGone(info));
                remove_card(&mut known_cards_access_2.write().expect("lock"), info);
            }),
        };
        monitoring::start(Some(callbacks));
    });


    let known_cards_access = known_cards.clone();
    let listener = get_listener();
    eprintln!("Session has begun; ready to decrypt :)");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("{:#?}", ConnectionReceived());
                let cards = known_cards_access.read().expect("lock");
                let best_card = best_card_for_decrypt(&cards).unwrap();
                let pin_cache_key = best_card.pin_cache_key();
                let mut open = decryption::get_card(best_card).expect("aaaaurght");
                let mut tx = decryption::get_tx(&mut open, pin_cache_key).expect("argh");

                decryption::decrypt(&mut tx, stream);
            }
            Err(err) => {break;}
        }
    }
    eprintln!("what");
}
