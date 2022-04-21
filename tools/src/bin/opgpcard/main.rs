// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::{Path, PathBuf};

use sequoia_openpgp::parse::{stream::DecryptorBuilder, Parse};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::Cert;

use openpgp_card::algorithm::AlgoSimple;
use openpgp_card::card_do::Sex;
use openpgp_card::{CardBackend, KeyType, OpenPgp};
use openpgp_card_sequoia::card::{Admin, Open};
use openpgp_card_sequoia::util::{
    make_cert, public_key_material_and_fp_to_key, public_key_material_to_key,
};
use openpgp_card_sequoia::{sq_util, PublicKey};

use crate::util::{load_pin, print_gnuk_note};
use sequoia_openpgp::types::{HashAlgorithm, SymmetricAlgorithm};
use std::io::Write;

mod cli;
mod util;

const ENTER_USER_PIN: &str = "Enter User PIN:";
const ENTER_ADMIN_PIN: &str = "Enter Admin PIN:";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let cli = cli::Cli::parse();

    match cli.cmd {
        cli::Command::List {} => {
            println!("Available OpenPGP cards:");
            list_cards()?;
        }
        cli::Command::Status { ident, verbose } => {
            print_status(ident, verbose)?;
        }
        cli::Command::Info { ident } => {
            print_info(ident)?;
        }
        cli::Command::Ssh { ident } => {
            print_ssh(ident)?;
        }
        cli::Command::Pubkey { ident, user_pin } => {
            print_pubkey(ident, user_pin)?;
        }
        cli::Command::SetIdentity { ident, id } => {
            set_identity(&ident, id)?;
        }
        cli::Command::Decrypt {
            ident,
            user_pin,
            cert_file,
            input,
        } => {
            decrypt(&ident, user_pin, &cert_file, input.as_deref())?;
        }
        cli::Command::Sign {
            ident,
            user_pin,
            cert_file,
            detached,
            input,
        } => {
            if detached {
                sign_detached(&ident, user_pin, &cert_file, input.as_deref())?;
            } else {
                return Err(
                    anyhow::anyhow!("Only detached signatures are supported for now").into(),
                );
            }
        }
        cli::Command::FactoryReset { ident } => {
            factory_reset(&ident)?;
        }
        cli::Command::Admin {
            ident,
            admin_pin,
            cmd,
        } => {
            let mut card = util::open_card(&ident)?;
            let mut pgp = OpenPgp::new(&mut card);

            let mut open = Open::new(pgp.transaction()?)?;
            let admin_pin = util::get_pin(&mut open, admin_pin, ENTER_ADMIN_PIN);

            match cmd {
                cli::AdminCommand::Name { name } => {
                    let mut admin = util::verify_to_admin(&mut open, admin_pin.as_deref())?;

                    let _ = admin.set_name(&name)?;
                }
                cli::AdminCommand::Url { url } => {
                    let mut admin = util::verify_to_admin(&mut open, admin_pin.as_deref())?;

                    let _ = admin.set_url(&url)?;
                }
                cli::AdminCommand::Import {
                    keyfile,
                    sig_fp,
                    dec_fp,
                    auth_fp,
                } => {
                    let key = Cert::from_file(keyfile)?;
                    let admin = util::verify_to_admin(&mut open, admin_pin.as_deref())?;

                    if (&sig_fp, &dec_fp, &auth_fp) == (&None, &None, &None) {
                        // If no fingerprint has been provided, we check if
                        // there is zero or one (sub)key for each keytype,
                        // and if so, import these keys to the card.
                        key_import_yolo(admin, &key)?;
                    } else {
                        key_import_explicit(admin, &key, sig_fp, dec_fp, auth_fp)?;
                    }
                }
                cli::AdminCommand::Generate {
                    user_pin,
                    output,
                    no_decrypt,
                    no_auth,
                    algo,
                } => {
                    let user_pin = util::get_pin(&mut open, user_pin, ENTER_USER_PIN);

                    generate_keys(
                        open,
                        admin_pin.as_deref(),
                        user_pin.as_deref(),
                        output,
                        !no_decrypt,
                        !no_auth,
                        algo,
                    )?;
                }
            }
        }
        cli::Command::Pin { ident, cmd } => {
            let mut card = util::open_card(&ident)?;
            let mut pgp = OpenPgp::new(&mut card);
            let pgpt = pgp.transaction()?;

            let pinpad_modify = pgpt.feature_pinpad_modify();

            let mut open = Open::new(pgpt)?;

            match cmd {
                cli::PinCommand::SetUser {
                    user_pin_old,
                    user_pin_new,
                } => {
                    let res = if !pinpad_modify {
                        // get current user pin
                        let user_pin1 = util::get_pin(&mut open, user_pin_old, ENTER_USER_PIN)
                            .expect("this should never be None");

                        // verify pin
                        open.verify_user(&user_pin1)?;
                        println!("PIN was accepted by the card.\n");

                        let pin_new = match user_pin_new {
                            None => {
                                // ask user for new user pin
                                util::input_pin_twice(
                                    "Enter new User PIN: ",
                                    "Repeat the new User PIN: ",
                                )?
                            }
                            Some(path) => load_pin(&path)?,
                        };

                        // set new user pin
                        open.change_user_pin(&user_pin1, &pin_new)
                    } else {
                        // set new user pin via pinpad
                        open.change_user_pin_pinpad(&|| {
                            println!(
                                "Enter old User PIN on card reader pinpad, then new User PIN (twice)."
                            )
                        })
                    };

                    if res.is_err() {
                        println!("\nFailed to change the User PIN!");
                        println!("{:?}", res);

                        if let Err(err) = res {
                            print_gnuk_note(err, &open)?;
                        }
                    } else {
                        println!("\nUser PIN has been set.");
                    }
                }
                cli::PinCommand::SetAdmin {
                    admin_pin_old,
                    admin_pin_new,
                } => {
                    if !pinpad_modify {
                        // get current admin pin
                        let admin_pin1 = util::get_pin(&mut open, admin_pin_old, ENTER_ADMIN_PIN)
                            .expect("this should never be None");

                        // verify pin
                        open.verify_admin(&admin_pin1)?;
                        println!("PIN was accepted by the card.\n");

                        let pin_new = match admin_pin_new {
                            None => {
                                // ask user for new admin pin
                                util::input_pin_twice(
                                    "Enter new Admin PIN: ",
                                    "Repeat the new Admin PIN: ",
                                )?
                            }
                            Some(path) => load_pin(&path)?,
                        };

                        // set new admin pin
                        open.change_admin_pin(&admin_pin1, &pin_new)?;
                    } else {
                        // set new admin pin via pinpad
                        open.change_admin_pin_pinpad(&|| {
                            println!(
                                "Enter old Admin PIN on card reader pinpad, then new Admin PIN (twice)."
                            )
                        })?;
                    };

                    println!("\nAdmin PIN has been set.");
                }

                cli::PinCommand::ResetUser {
                    admin_pin,
                    user_pin_new,
                } => {
                    // verify admin pin
                    match util::get_pin(&mut open, admin_pin, ENTER_ADMIN_PIN) {
                        Some(admin_pin) => {
                            // verify pin
                            open.verify_admin(&admin_pin)?;
                        }
                        None => {
                            open.verify_admin_pinpad(&|| println!("Enter Admin PIN on pinpad."))?;
                        }
                    }
                    println!("PIN was accepted by the card.\n");

                    // ask user for new user pin
                    let pin = match user_pin_new {
                        None => util::input_pin_twice(
                            "Enter new User PIN: ",
                            "Repeat the new User PIN: ",
                        )?,
                        Some(path) => load_pin(&path)?,
                    };

                    let res = if let Some(mut admin) = open.admin_card() {
                        admin.reset_user_pin(&pin)
                    } else {
                        return Err(anyhow::anyhow!("Failed to use card in admin-mode.").into());
                    };

                    if res.is_err() {
                        println!("\nFailed to change the User PIN!");
                        if let Err(err) = res {
                            print_gnuk_note(err, &open)?;
                        }
                    } else {
                        println!("\nUser PIN has been set.");
                    }
                }

                cli::PinCommand::SetReset {
                    admin_pin,
                    reset_code,
                } => {
                    // verify admin pin
                    match util::get_pin(&mut open, admin_pin, ENTER_ADMIN_PIN) {
                        Some(admin_pin) => {
                            // verify pin
                            open.verify_admin(&admin_pin)?;
                        }
                        None => {
                            open.verify_admin_pinpad(&|| println!("Enter Admin PIN on pinpad."))?;
                        }
                    }
                    println!("PIN was accepted by the card.\n");

                    // ask user for new resetting code
                    let code = match reset_code {
                        None => util::input_pin_twice(
                            "Enter new resetting code: ",
                            "Repeat the new resetting code: ",
                        )?,
                        Some(path) => load_pin(&path)?,
                    };

                    if let Some(mut admin) = open.admin_card() {
                        admin.set_resetting_code(&code)?;
                        println!("\nResetting code has been set.");
                    } else {
                        return Err(anyhow::anyhow!("Failed to use card in admin-mode.").into());
                    };
                }

                cli::PinCommand::ResetUserRc {
                    reset_code,
                    user_pin_new,
                } => {
                    // reset by presenting resetting code

                    let rst = if let Some(path) = reset_code {
                        // load resetting code from file
                        load_pin(&path)?
                    } else {
                        // input resetting code
                        rpassword::prompt_password("Enter resetting code: ")?
                            .as_bytes()
                            .to_vec()
                    };

                    // ask user for new user pin
                    let pin = match user_pin_new {
                        None => util::input_pin_twice(
                            "Enter new User PIN: ",
                            "Repeat the new User PIN: ",
                        )?,
                        Some(path) => load_pin(&path)?,
                    };

                    // reset to new user pin
                    match open.reset_user_pin(&rst, &pin) {
                        Err(err) => {
                            println!("\nFailed to change the User PIN!");
                            print_gnuk_note(err, &open)?;
                        }
                        Ok(_) => println!("\nUser PIN has been set."),
                    }
                }
            }
        }
    }

    Ok(())
}

fn list_cards() -> Result<()> {
    let cards = util::cards()?;
    if !cards.is_empty() {
        for mut card in cards {
            let mut pgp = OpenPgp::new(&mut card);
            let open = Open::new(pgp.transaction()?)?;
            println!(" {}", open.application_identifier()?.ident());
        }
    } else {
        println!("No OpenPGP cards found.");
    }
    Ok(())
}

fn set_identity(ident: &str, id: u8) -> Result<(), Box<dyn std::error::Error>> {
    let mut card = util::open_card(ident)?;
    let mut pgp = OpenPgp::new(&mut card);

    let mut pgpt = pgp.transaction()?;
    pgpt.set_identity(id)?;

    Ok(())
}

/// Return a card for a read operation. If `ident` is None, and exactly one card
/// is plugged in, that card is returned. (We don't This
fn pick_card_for_reading(ident: Option<String>) -> Result<Box<dyn CardBackend + Send + Sync>> {
    if let Some(ident) = ident {
        Ok(Box::new(util::open_card(&ident)?))
    } else {
        let mut cards = util::cards()?;
        if cards.len() == 1 {
            Ok(Box::new(cards.pop().unwrap()))
        } else if cards.is_empty() {
            return Err(anyhow::anyhow!("No cards found"));
        } else {
            println!("Found {} cards:", cards.len());
            list_cards()?;

            println!();
            println!("Specify which card to use with '--card <card ident>'");
            println!();

            return Err(anyhow::anyhow!("Specify card"));
        }
    }
}

fn print_status(ident: Option<String>, verbose: bool) -> Result<()> {
    let mut card = pick_card_for_reading(ident)?;

    let mut pgp = OpenPgp::new(&mut *card);
    let mut open = Open::new(pgp.transaction()?)?;

    print!("OpenPGP card {}", open.application_identifier()?.ident());

    let ai = open.application_identifier()?;
    let version = ai.version().to_be_bytes();
    println!(" (card version {}.{})\n", version[0], version[1]);

    // card / cardholder metadata
    let crd = open.cardholder_related_data()?;

    if let Some(name) = crd.name() {
        let name = String::from_utf8_lossy(name).to_string();

        print!("Cardholder: ");

        // This field is silly, maybe ignore it?!
        if let Some(sex) = crd.sex() {
            if sex == Sex::Male {
                print!("Mr. ");
            } else if sex == Sex::Female {
                print!("Mrs. ");
            }
        }

        // re-format name ("last<<first")
        let name: Vec<_> = name.split("<<").collect();
        let name = name.iter().cloned().rev().collect::<Vec<_>>().join(" ");

        println!("{}", name);
    }

    let url = open.url()?;
    if !url.is_empty() {
        println!("URL: {}", url);
    }

    if let Some(lang) = crd.lang() {
        let l = lang
            .iter()
            .map(|l| format!("{}", l))
            .collect::<Vec<_>>()
            .join(", ");
        println!("Language preferences: '{}'", l);
    }

    // information about subkeys

    let fps = open.fingerprints()?;
    let kgt = open.key_generation_times()?;

    println!();
    println!("Signature key");
    if let Some(fp) = fps.signature() {
        println!("  fingerprint: {}", fp.to_spaced_hex());
    }
    if let Some(kgt) = kgt.signature() {
        println! {"  created: {}", kgt.formatted()};
    }
    println! {"  algorithm: {}", open.algorithm_attributes(KeyType::Signing)?};
    if verbose {
        if let Ok(pkm) = open.public_key(KeyType::Signing) {
            println! {"  public key material: {}", pkm};
        }
    }

    println!();
    println!("Decryption key");
    if let Some(fp) = fps.decryption() {
        println!("  fingerprint: {}", fp.to_spaced_hex());
    }
    if let Some(kgt) = kgt.decryption() {
        println! {"  created: {}", kgt.formatted()};
    }
    println! {"  algorithm: {}", open.algorithm_attributes(KeyType::Decryption)?};
    if verbose {
        if let Ok(pkm) = open.public_key(KeyType::Decryption) {
            println! {"  public key material: {}", pkm};
        }
    }

    println!();
    println!("Authentication key");
    if let Some(fp) = fps.authentication() {
        println!("  fingerprint: {}", fp.to_spaced_hex());
    }
    if let Some(kgt) = kgt.authentication() {
        println! {"  created: {}", kgt.formatted()};
    }
    println! {"  algorithm: {}", open.algorithm_attributes(KeyType::Authentication)?};
    if verbose {
        if let Ok(pkm) = open.public_key(KeyType::Authentication) {
            println! {"  public key material: {}", pkm};
        }
    }

    // technical details about the card and its state

    println!();

    let sst = open.security_support_template()?;
    println!("Signature counter: {}", sst.signature_count());

    let pws = open.pw_status_bytes()?;

    println!(
        "Signature pin only valid once: {}",
        pws.pw1_cds_valid_once()
    );

    println!("Password validation retry count:");
    println!(
        "  user pw: {}, reset: {}, admin pw: {}",
        pws.err_count_pw1(),
        pws.err_count_rc(),
        pws.err_count_pw3(),
    );

    // FIXME: print "Login Data", "Key Information"

    Ok(())
}

/// print metadata information about a card
fn print_info(ident: Option<String>) -> Result<()> {
    let mut card = pick_card_for_reading(ident)?;

    let mut pgp = OpenPgp::new(&mut *card);
    let mut open = Open::new(pgp.transaction()?)?;

    let ai = open.application_identifier()?;

    print!("OpenPGP card {}", ai.ident());

    let version = ai.version().to_be_bytes();
    println!(" (card version {}.{})\n", version[0], version[1]);

    println!("Application Identifier: {}", ai);
    println!(
        "Manufacturer [{:04X}]: {}\n",
        ai.manufacturer(),
        ai.manufacturer_name()
    );

    if let Some(cc) = open.historical_bytes()?.card_capabilities() {
        println!("Card Capabilities:\n{}", cc);
    }
    if let Some(csd) = open.historical_bytes()?.card_service_data() {
        println!("Card service data:\n{}", csd);
    }

    if let Some(eli) = open.extended_length_information()? {
        println!("Extended Length Info:\n{}", eli);
    }

    let ec = open.extended_capabilities()?;
    println!("Extended Capabilities:\n{}", ec);

    // Algorithm information (list of supported algorithms)
    if let Ok(Some(ai)) = open.algorithm_information() {
        println!("Supported algorithms:");
        println!("{}", ai);
    }

    // FIXME: print KDF info

    // YubiKey specific (?) firmware version
    if let Ok(ver) = open.firmware_version() {
        let ver = ver.iter().map(u8::to_string).collect::<Vec<_>>().join(".");

        println!("Firmware Version: {}\n", ver);
    }

    Ok(())
}

fn print_ssh(ident: Option<String>) -> Result<()> {
    let mut card = pick_card_for_reading(ident)?;

    let mut pgp = OpenPgp::new(&mut *card);
    let mut open = Open::new(pgp.transaction()?)?;

    let ident = open.application_identifier()?.ident();

    println!("OpenPGP card {}", ident);

    // Print fingerprint of authentication subkey
    let fps = open.fingerprints()?;

    println!();
    if let Some(fp) = fps.authentication() {
        println!("Authentication key fingerprint:\n{}", fp);
    }

    // Show authentication subkey as openssh public key string
    if let Ok(pkm) = open.public_key(KeyType::Authentication) {
        if let Ok(ssh) = util::get_ssh_pubkey_string(&pkm, ident) {
            println!();
            println!("Authentication key as ssh public key:\n{}", ssh);
        }
    }

    Ok(())
}

fn print_pubkey(ident: Option<String>, user_pin: Option<PathBuf>) -> Result<()> {
    let mut card = pick_card_for_reading(ident)?;

    let mut pgp = OpenPgp::new(&mut *card);
    let mut open = Open::new(pgp.transaction()?)?;

    let ident = open.application_identifier()?.ident();

    println!("OpenPGP card {}", ident);

    let user_pin = util::get_pin(&mut open, user_pin, ENTER_USER_PIN);

    let pkm = open.public_key(KeyType::Signing)?;
    let times = open.key_generation_times()?;
    let fps = open.fingerprints()?;

    let key_sig = public_key_material_and_fp_to_key(
        &pkm,
        KeyType::Signing,
        times.signature().expect("Signature time is unset"),
        fps.signature().expect("Signature fingerprint is unset"),
    )?;

    let mut key_dec = None;
    if let Ok(pkm) = open.public_key(KeyType::Decryption) {
        if let Some(ts) = times.decryption() {
            key_dec = Some(public_key_material_and_fp_to_key(
                &pkm,
                KeyType::Decryption,
                ts,
                fps.decryption().expect("Decryption fingerprint is unset"),
            )?);
        }
    }

    let mut key_aut = None;
    if let Ok(pkm) = open.public_key(KeyType::Authentication) {
        if let Some(ts) = times.authentication() {
            key_aut = Some(public_key_material_and_fp_to_key(
                &pkm,
                KeyType::Authentication,
                ts,
                fps.authentication()
                    .expect("Authentication fingerprint is unset"),
            )?);
        }
    }

    let cert = get_cert(
        &mut open,
        key_sig,
        key_dec,
        key_aut,
        user_pin.as_deref(),
        &|| println!("Enter User PIN on card reader pinpad."),
    )?;

    let armored = String::from_utf8(cert.armored().to_vec()?)?;
    println!("{}", armored);

    Ok(())
}

fn decrypt(
    ident: &str,
    pin_file: Option<PathBuf>,
    cert_file: &Path,
    input: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let p = StandardPolicy::new();
    let cert = Cert::from_file(cert_file)?;

    let input = util::open_or_stdin(input)?;

    let mut card = util::open_card(ident)?;
    let mut pgp = OpenPgp::new(&mut card);

    let mut open = Open::new(pgp.transaction()?)?;

    let user_pin = util::get_pin(&mut open, pin_file, ENTER_USER_PIN);

    let mut user = util::verify_to_user(&mut open, user_pin.as_deref())?;
    let d = user.decryptor(&cert)?;

    let db = DecryptorBuilder::from_reader(input)?;
    let mut decryptor = db.with_policy(&p, None, d)?;

    std::io::copy(&mut decryptor, &mut std::io::stdout())?;

    Ok(())
}

fn sign_detached(
    ident: &str,
    pin_file: Option<PathBuf>,
    cert_file: &Path,
    input: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cert = Cert::from_file(cert_file)?;

    let mut input = util::open_or_stdin(input)?;

    let mut card = util::open_card(ident)?;
    let mut pgp = OpenPgp::new(&mut card);

    let mut open = Open::new(pgp.transaction()?)?;

    let user_pin = util::get_pin(&mut open, pin_file, ENTER_USER_PIN);

    let mut sign = util::verify_to_sign(&mut open, user_pin.as_deref())?;
    let s = sign.signer(&cert)?;

    let message = Armorer::new(Message::new(std::io::stdout())).build()?;
    let mut signer = Signer::new(message, s).detached().build()?;

    std::io::copy(&mut input, &mut signer)?;
    signer.finalize()?;

    Ok(())
}

fn factory_reset(ident: &str) -> Result<()> {
    println!("Resetting Card {}", ident);
    let mut card = util::open_card(ident)?;
    let mut pgp = OpenPgp::new(&mut card);

    let mut open = Open::new(pgp.transaction()?)?;
    open.factory_reset().map_err(|e| anyhow!(e))
}

fn key_import_yolo(mut admin: Admin, key: &Cert) -> Result<()> {
    let p = StandardPolicy::new();

    let sig = sq_util::subkey_by_type(key, &p, KeyType::Signing)?;

    let dec = sq_util::subkey_by_type(key, &p, KeyType::Decryption)?;

    let auth = sq_util::subkey_by_type(key, &p, KeyType::Authentication)?;

    if let Some(sig) = sig {
        println!("Uploading {} as signing key", sig.fingerprint());
        admin.upload_key(sig, KeyType::Signing, None)?;
    }
    if let Some(dec) = dec {
        println!("Uploading {} as decryption key", dec.fingerprint());
        admin.upload_key(dec, KeyType::Decryption, None)?;
    }
    if let Some(auth) = auth {
        println!("Uploading {} as authentication key", auth.fingerprint());
        admin.upload_key(auth, KeyType::Authentication, None)?;
    }

    Ok(())
}

fn key_import_explicit(
    mut admin: Admin,
    key: &Cert,
    sig_fp: Option<String>,
    dec_fp: Option<String>,
    auth_fp: Option<String>,
) -> Result<()> {
    let p = StandardPolicy::new();

    if let Some(sig_fp) = sig_fp {
        if let Some(sig) = sq_util::private_subkey_by_fingerprint(key, &p, &sig_fp)? {
            println!("Uploading {} as signing key", sig.fingerprint());
            admin.upload_key(sig, KeyType::Signing, None)?;
        } else {
            println!("ERROR: Couldn't find {} as signing key", sig_fp);
        }
    }

    if let Some(dec_fp) = dec_fp {
        if let Some(dec) = sq_util::private_subkey_by_fingerprint(key, &p, &dec_fp)? {
            println!("Uploading {} as decryption key", dec.fingerprint());
            admin.upload_key(dec, KeyType::Decryption, None)?;
        } else {
            println!("ERROR: Couldn't find {} as decryption key", dec_fp);
        }
    }

    if let Some(auth_fp) = auth_fp {
        if let Some(auth) = sq_util::private_subkey_by_fingerprint(key, &p, &auth_fp)? {
            println!("Uploading {} as authentication key", auth.fingerprint());
            admin.upload_key(auth, KeyType::Authentication, None)?;
        } else {
            println!("ERROR: Couldn't find {} as authentication key", auth_fp);
        }
    }

    Ok(())
}

fn get_cert(
    open: &mut Open,
    key_sig: PublicKey,
    key_dec: Option<PublicKey>,
    key_aut: Option<PublicKey>,
    user_pin: Option<&[u8]>,
    prompt: &dyn Fn(),
) -> Result<Cert> {
    if user_pin.is_none() && open.feature_pinpad_verify() {
        println!(
            "The public cert will now be generated.\n\n\
             You will need to enter your User PIN multiple times during this process.\n\n"
        );
    }

    make_cert(open, key_sig, key_dec, key_aut, user_pin, prompt)
}

fn generate_keys(
    mut open: Open,
    admin_pin: Option<&[u8]>,
    user_pin: Option<&[u8]>,
    output: Option<PathBuf>,
    decrypt: bool,
    auth: bool,
    algo: Option<String>,
) -> Result<()> {
    // 1) Interpret the user's choice of algorithm.
    //
    // Unset (None) means that the algorithm that is specified on the card
    // should remain unchanged.
    //
    // For RSA, different cards use different exact algorithm
    // specifications. In particular, the length of the value `e` differs
    // between cards. Some devices use 32 bit length for e, others use 17 bit.
    // In some cases, it's possible to get this information from the card,
    // but I believe this information is not obtainable in all cases.
    // Because of this, for generation of RSA keys, here we take the approach
    // of first trying one variant, and then if that fails, try the other.

    let a = match algo.as_deref() {
        None => None,
        Some("rsa2048") => Some(AlgoSimple::RSA2k),
        Some("rsa3072") => Some(AlgoSimple::RSA3k),
        Some("rsa4096") => Some(AlgoSimple::RSA4k),
        Some("nistp256") => Some(AlgoSimple::NIST256),
        Some("nistp384") => Some(AlgoSimple::NIST384),
        Some("nistp521") => Some(AlgoSimple::NIST521),
        Some("25519") => Some(AlgoSimple::Curve25519),
        _ => return Err(anyhow!("Unexpected algorithm")),
    };

    log::info!(" Key generation will be attempted with algo: {:?}", a);

    // 2) Then, generate keys on the card.
    // We need "admin" access to the card for this).
    let (key_sig, key_dec, key_aut) = {
        if let Ok(mut admin) = util::verify_to_admin(&mut open, admin_pin) {
            gen_subkeys(&mut admin, decrypt, auth, a)?
        } else {
            return Err(anyhow!("Failed to open card in admin mode."));
        }
    };

    // 3) Generate a Cert from the generated keys. For this, we
    // need "signing" access to the card (to make binding signatures within
    // the Cert).
    let cert = get_cert(&mut open, key_sig, key_dec, key_aut, user_pin, &|| {
        println!("Enter User PIN on card reader pinpad.")
    })?;

    let armored = String::from_utf8(cert.armored().to_vec()?)?;

    // Write armored certificate to the output file (or stdout)
    let mut output = util::open_or_stdout(output.as_deref())?;
    output.write_all(armored.as_bytes())?;

    Ok(())
}

fn gen_subkeys(
    admin: &mut Admin,
    decrypt: bool,
    auth: bool,
    algo: Option<AlgoSimple>,
) -> Result<(PublicKey, Option<PublicKey>, Option<PublicKey>)> {
    // We begin by generating the signing subkey, which is mandatory.
    println!(" Generate subkey for Signing");
    let (pkm, ts) = admin.generate_key_simple(KeyType::Signing, algo)?;
    let key_sig = public_key_material_to_key(&pkm, KeyType::Signing, &ts, None, None)?;

    // make decryption subkey (unless disabled), with the same algorithm as
    // the sig key
    let key_dec = if decrypt {
        println!(" Generate subkey for Decryption");
        let (pkm, ts) = admin.generate_key_simple(KeyType::Decryption, algo)?;
        Some(public_key_material_to_key(
            &pkm,
            KeyType::Decryption,
            &ts,
            Some(HashAlgorithm::SHA256),      // FIXME
            Some(SymmetricAlgorithm::AES128), // FIXME
        )?)
    } else {
        None
    };

    // make authentication subkey (unless disabled), with the same
    // algorithm as the sig key
    let key_aut = if auth {
        println!(" Generate subkey for Authentication");
        let (pkm, ts) = admin.generate_key_simple(KeyType::Authentication, algo)?;

        Some(public_key_material_to_key(
            &pkm,
            KeyType::Authentication,
            &ts,
            None,
            None,
        )?)
    } else {
        None
    };

    Ok((key_sig, key_dec, key_aut))
}
