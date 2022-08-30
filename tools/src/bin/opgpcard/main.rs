// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::{Path, PathBuf};

use sequoia_openpgp::cert::prelude::ValidErasedKeyAmalgamation;
use sequoia_openpgp::packet::key::{SecretParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::parse::{stream::DecryptorBuilder, Parse};
use sequoia_openpgp::policy::{Policy, StandardPolicy};
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{HashAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp::Cert;

use openpgp_card::algorithm::AlgoSimple;
use openpgp_card::card_do::{Sex, TouchPolicy};
use openpgp_card::{CardBackend, KeyType, OpenPgp};
use openpgp_card_sequoia::card::{Admin, Open};
use openpgp_card_sequoia::util::{
    make_cert, public_key_material_and_fp_to_key, public_key_material_to_key,
};
use openpgp_card_sequoia::{sq_util, PublicKey};

use crate::util::{load_pin, print_gnuk_note};
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
        cli::Command::Status {
            ident,
            verbose,
            pkm,
        } => {
            print_status(ident, verbose, pkm)?;
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
            input,
        } => {
            decrypt(&ident, user_pin, input.as_deref())?;
        }
        cli::Command::Sign {
            ident,
            user_pin,
            detached,
            input,
        } => {
            if detached {
                sign_detached(&ident, user_pin, input.as_deref())?;
            } else {
                return Err(
                    anyhow::anyhow!("Only detached signatures are supported for now").into(),
                );
            }
        }
        cli::Command::Attestation { cmd } => match cmd {
            cli::AttCommand::Cert { ident } => {
                let mut card = pick_card_for_reading(ident)?;

                let mut pgp = OpenPgp::new(&mut *card);
                let mut open = Open::new(pgp.transaction()?)?;

                if let Ok(ac) = open.attestation_certificate() {
                    let pem = util::pem_encode(ac);
                    println!("{}", pem);
                }
            }
            cli::AttCommand::Generate {
                ident,
                key,
                user_pin,
            } => {
                let mut card = util::open_card(&ident)?;
                let mut pgp = OpenPgp::new(&mut card);

                let mut open = Open::new(pgp.transaction()?)?;
                let user_pin = util::get_pin(&mut open, user_pin, ENTER_USER_PIN);

                let mut sign = util::verify_to_sign(&mut open, user_pin.as_deref())?;

                let kt = match key.as_str() {
                    "SIG" => KeyType::Signing,
                    "DEC" => KeyType::Decryption,
                    "AUT" => KeyType::Authentication,
                    _ => {
                        return Err(anyhow!("Unexpected Key Type {}", key).into());
                    }
                };
                sign.generate_attestation(kt, &|| {
                    println!("Touch confirmation needed to generate an attestation")
                })?;
            }
            cli::AttCommand::Statement { ident, key } => {
                let mut card = pick_card_for_reading(ident)?;

                let mut pgp = OpenPgp::new(&mut *card);
                let mut open = Open::new(pgp.transaction()?)?;

                // Get cardholder certificate from card.

                let mut select_data_workaround = false;
                // Use "select data" workaround if the card reports a
                // yk firmware version number >= 5 and <= 5.4.3
                if let Ok(version) = open.firmware_version() {
                    if version.len() == 3
                        && version[0] == 5
                        && (version[1] < 4 || (version[1] == 4 && version[2] <= 3))
                    {
                        select_data_workaround = true;
                    }
                }

                // Select cardholder certificate
                match key.as_str() {
                    "AUT" => open.select_data(0, &[0x7F, 0x21], select_data_workaround)?,
                    "DEC" => open.select_data(1, &[0x7F, 0x21], select_data_workaround)?,
                    "SIG" => open.select_data(2, &[0x7F, 0x21], select_data_workaround)?,

                    _ => {
                        return Err(anyhow!("Unexpected Key Type {}", key).into());
                    }
                };

                // Get DO "cardholder certificate" (returns the slot that was previously selected)
                let cert = open.cardholder_certificate()?;

                if !cert.is_empty() {
                    let pem = util::pem_encode(cert);
                    println!("{}", pem);
                } else {
                    println!("Cardholder certificate slot is empty");
                }
            }
        },
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

                    admin.set_name(&name)?;
                }
                cli::AdminCommand::Url { url } => {
                    let mut admin = util::verify_to_admin(&mut open, admin_pin.as_deref())?;

                    admin.set_url(&url)?;
                }
                cli::AdminCommand::Import {
                    keyfile,
                    sig_fp,
                    dec_fp,
                    auth_fp,
                } => {
                    let key = Cert::from_file(keyfile)?;

                    let p = StandardPolicy::new();

                    // select the (sub)keys to upload
                    let [sig, dec, auth] = match (&sig_fp, &dec_fp, &auth_fp) {
                        // No fingerprint has been provided, try to autoselect keys
                        // (this fails if there is more than one (sub)key for any keytype).
                        (&None, &None, &None) => keys_pick_yolo(&key, &p)?,

                        _ => keys_pick_explicit(&key, &p, sig_fp, dec_fp, auth_fp)?,
                    };

                    let mut pws: Vec<String> = vec![];

                    // helper: true, if `pw` decrypts `key`
                    let pw_ok = |key: &Key<SecretParts, UnspecifiedRole>, pw: &str| {
                        key.clone()
                            .decrypt_secret(&sequoia_openpgp::crypto::Password::from(pw))
                            .is_ok()
                    };

                    // helper: if any password in `pws` decrypts `key`, return that password
                    let find_pw = |key: &Key<SecretParts, UnspecifiedRole>, pws: &[String]| {
                        pws.iter().find(|pw| pw_ok(key, pw)).cloned()
                    };

                    // helper: check if we have the right password for `key` in `pws`,
                    // if so return it. otherwise ask the user for the password,
                    // add it to `pws` and return it.
                    let mut get_pw_for_key =
                        |key: &Option<ValidErasedKeyAmalgamation<SecretParts>>,
                         key_type: &str|
                         -> Result<Option<String>> {
                            if let Some(k) = key {
                                if !k.has_secret() {
                                    // key has no secret key material, it can't be imported
                                    return Err(anyhow!(
                                        "(Sub)Key {} contains no private key material",
                                        k.fingerprint()
                                    ));
                                }

                                if k.has_unencrypted_secret() {
                                    // key is unencrypted, we need no password
                                    return Ok(None);
                                }

                                // key is encrypted, we need the password

                                // do we already have the right password?
                                if let Some(pw) = find_pw(k, &pws) {
                                    return Ok(Some(pw));
                                }

                                // no, we need to get the password from user
                                let pw = rpassword::prompt_password(format!(
                                    "Enter password for {} (sub)key {}:",
                                    key_type,
                                    k.fingerprint()
                                ))?;

                                if pw_ok(k, &pw) {
                                    // remember pw for next subkeys
                                    pws.push(pw.clone());

                                    Ok(Some(pw))
                                } else {
                                    // this password doesn't work, error out
                                    Err(anyhow!(
                                        "Password not valid for (Sub)Key {}",
                                        k.fingerprint()
                                    ))
                                }
                            } else {
                                // we have no key for this slot, so we don't need a password
                                Ok(None)
                            }
                        };

                    // get passwords, if encrypted (try previous pw before asking for user input)
                    let sig_p = get_pw_for_key(&sig, "signing")?;
                    let dec_p = get_pw_for_key(&dec, "decryption")?;
                    let auth_p = get_pw_for_key(&auth, "authentication")?;

                    // upload keys to card
                    let mut admin = util::verify_to_admin(&mut open, admin_pin.as_deref())?;

                    if let Some(sig) = sig {
                        println!("Uploading {} as signing key", sig.fingerprint());
                        admin.upload_key(sig, KeyType::Signing, sig_p)?;
                    }
                    if let Some(dec) = dec {
                        println!("Uploading {} as decryption key", dec.fingerprint());
                        admin.upload_key(dec, KeyType::Decryption, dec_p)?;
                    }
                    if let Some(auth) = auth {
                        println!("Uploading {} as authentication key", auth.fingerprint());
                        admin.upload_key(auth, KeyType::Authentication, auth_p)?;
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
                cli::AdminCommand::Touch { key, policy } => {
                    let kt = match key.as_str() {
                        "SIG" => KeyType::Signing,
                        "DEC" => KeyType::Decryption,
                        "AUT" => KeyType::Authentication,
                        "ATT" => KeyType::Attestation,
                        _ => {
                            return Err(anyhow!("Unexpected Key Type {}", key).into());
                        }
                    };
                    let pol = match policy.as_str() {
                        "Off" => TouchPolicy::Off,
                        "On" => TouchPolicy::On,
                        "Fixed" => TouchPolicy::Fixed,
                        "Cached" => TouchPolicy::Cached,
                        "Cached-Fixed" => TouchPolicy::CachedFixed,
                        _ => {
                            return Err(anyhow!("Unexpected Policy {}", policy).into());
                        }
                    };

                    let mut admin = util::verify_to_admin(&mut open, admin_pin.as_deref())?;

                    admin.set_uif(kt, pol)?;
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
                        // (Verifying the PIN here fixes this class of problems:
                        // https://developers.yubico.com/PGP/PGP_PIN_Change_Behavior.html
                        // It is also just generally more user friendly than failing later)
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
            Err(anyhow::anyhow!("No cards found"))
        } else {
            println!("Found {} cards:", cards.len());
            list_cards()?;

            println!();
            println!("Specify which card to use with '--card <card ident>'");
            println!();

            Err(anyhow::anyhow!("Specify card"))
        }
    }
}

fn print_status(ident: Option<String>, verbose: bool, pkm: bool) -> Result<()> {
    let mut card = pick_card_for_reading(ident)?;

    let mut pgp = OpenPgp::new(&mut *card);
    let mut pgpt = pgp.transaction()?;

    let ard = pgpt.application_related_data()?;

    let mut open = Open::new(pgpt)?;

    print!("OpenPGP card {}", open.application_identifier()?.ident());

    let ai = open.application_identifier()?;
    let version = ai.version().to_be_bytes();
    println!(" (card version {}.{})\n", version[0], version[1]);

    // card / cardholder metadata
    let crd = open.cardholder_related_data()?;

    // Remember if any cardholder information is printed (if so, we print a newline later)
    let mut card_holder_output = false;

    if let Some(name) = crd.name() {
        // FIXME: decoding as utf8 is wrong (the spec defines this field as latin1 encoded)
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

        card_holder_output = true;
    }

    let url = open.url()?;
    if !url.is_empty() {
        println!("URL: {}", url);
        card_holder_output = true;
    }

    if let Some(lang) = crd.lang() {
        let l = lang
            .iter()
            .map(|l| format!("{}", l))
            .collect::<Vec<_>>()
            .join(", ");
        println!("Language preferences: '{}'", l);
        card_holder_output = true;
    }

    if card_holder_output {
        println!();
    }

    // key information (imported vs. generated on card)
    let ki = ard.key_information().ok().flatten();

    let pws = open.pw_status_bytes()?;

    // information about subkeys

    let fps = open.fingerprints()?;
    let kgt = open.key_generation_times()?;

    println!("Signature key");
    if let Some(fp) = fps.signature() {
        println!("  Fingerprint: {}", fp.to_spaced_hex());
    }
    println! {"  Algorithm: {}", open.algorithm_attributes(KeyType::Signing)?};
    if let Some(kgt) = kgt.signature() {
        println! {"  Created: {}", kgt.to_datetime()};
    }
    if verbose {
        if let Some(uif) = ard.uif_pso_cds()? {
            println!(
                "  Touch policy: {} [Features: {}]",
                uif.touch_policy(),
                uif.features()
            );
        }
        if let Some(ks) = ki.as_ref().map(|ki| ki.sig_status()) {
            println!("  Key Status: {}", ks);
        }
    }

    if verbose {
        if pws.pw1_cds_valid_once() {
            println!("  User PIN presentation valid for one signature");
        } else {
            println!("  User PIN presentation valid for unlimited signatures");
        }
    }

    let sst = open.security_support_template()?;
    println!("  Signatures made: {}", sst.signature_count());

    if pkm {
        if let Ok(pkm) = open.public_key(KeyType::Signing) {
            println! {"  Public key material: {}", pkm};
        }
    }

    println!();
    println!("Decryption key");
    if let Some(fp) = fps.decryption() {
        println!("  Fingerprint: {}", fp.to_spaced_hex());
    }
    println! {"  Algorithm: {}", open.algorithm_attributes(KeyType::Decryption)?};
    if let Some(kgt) = kgt.decryption() {
        println! {"  Created: {}", kgt.to_datetime()};
    }
    if verbose {
        if let Some(uif) = ard.uif_pso_dec()? {
            println!(
                "  Touch policy: {} [Features: {}]",
                uif.touch_policy(),
                uif.features()
            );
        }
        if let Some(ks) = ki.as_ref().map(|ki| ki.dec_status()) {
            println!("  Key Status: {}", ks);
        }
    }
    if pkm {
        if let Ok(pkm) = open.public_key(KeyType::Decryption) {
            println! {"  Public key material: {}", pkm};
        }
    }

    println!();
    println!("Authentication key");
    if let Some(fp) = fps.authentication() {
        println!("  Fingerprint: {}", fp.to_spaced_hex());
    }
    println! {"  Algorithm: {}", open.algorithm_attributes(KeyType::Authentication)?};
    if let Some(kgt) = kgt.authentication() {
        println! {"  Created: {}", kgt.to_datetime()};
    }
    if verbose {
        if let Some(uif) = ard.uif_pso_aut()? {
            println!(
                "  Touch policy: {} [Features: {}]",
                uif.touch_policy(),
                uif.features()
            );
        }
        if let Some(ks) = ki.as_ref().map(|ki| ki.aut_status()) {
            println!("  Key Status: {}", ks);
        }
    }
    if pkm {
        if let Ok(pkm) = open.public_key(KeyType::Authentication) {
            println! {"  public key material: {}", pkm};
        }
    }

    // technical details about the card's state

    println!();

    println!(
        "Remaining PIN attempts: User: {}, Admin: {}, Reset Code: {}",
        pws.err_count_pw1(),
        pws.err_count_pw3(),
        pws.err_count_rc(),
    );

    if verbose {
        println!();

        if let Some(uif) = ard.uif_attestation()? {
            println!(
                "Touch policy attestation: {} [Features: {}]",
                uif.touch_policy(),
                uif.features()
            );
            println!();
        }

        if let Some(ki) = ki {
            let num = ki.num_additional();
            for i in 0..num {
                println!(
                    "Key Status (#{}): {}",
                    ki.additional_ref(i),
                    ki.additional_status(i)
                );
            }

            if num > 0 {
                println!();
            }
        }

        if let Ok(fps) = ard.ca_fingerprints() {
            for (num, fp) in fps.iter().enumerate() {
                if let Some(fp) = fp {
                    println!("CA fingerprint {}: {:x?}", num + 1, fp);
                }
            }
        }
    }

    // FIXME: print "Login Data"

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
            println!("SSH public key:\n{}", ssh);
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
    input: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let p = StandardPolicy::new();

    let input = util::open_or_stdin(input)?;

    let mut card = util::open_card(ident)?;
    let mut pgp = OpenPgp::new(&mut card);

    let mut open = Open::new(pgp.transaction()?)?;

    let user_pin = util::get_pin(&mut open, pin_file, ENTER_USER_PIN);

    let mut user = util::verify_to_user(&mut open, user_pin.as_deref())?;
    let d = user.decryptor(&|| println!("Touch confirmation needed for decryption"))?;

    let db = DecryptorBuilder::from_reader(input)?;
    let mut decryptor = db.with_policy(&p, None, d)?;

    std::io::copy(&mut decryptor, &mut std::io::stdout())?;

    Ok(())
}

fn sign_detached(
    ident: &str,
    pin_file: Option<PathBuf>,
    input: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = util::open_or_stdin(input)?;

    let mut card = util::open_card(ident)?;
    let mut pgp = OpenPgp::new(&mut card);

    let mut open = Open::new(pgp.transaction()?)?;

    let user_pin = util::get_pin(&mut open, pin_file, ENTER_USER_PIN);

    let mut sign = util::verify_to_sign(&mut open, user_pin.as_deref())?;
    let s = sign.signer(&|| println!("Touch confirmation needed for signing"))?;

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

fn keys_pick_yolo<'a>(
    key: &'a Cert,
    policy: &'a dyn Policy,
) -> Result<[Option<ValidErasedKeyAmalgamation<'a, SecretParts>>; 3]> {
    let key_by_type = |kt| sq_util::subkey_by_type(key, policy, kt);

    Ok([
        key_by_type(KeyType::Signing)?,
        key_by_type(KeyType::Decryption)?,
        key_by_type(KeyType::Authentication)?,
    ])
}

fn keys_pick_explicit<'a>(
    key: &'a Cert,
    policy: &'a dyn Policy,
    sig_fp: Option<String>,
    dec_fp: Option<String>,
    auth_fp: Option<String>,
) -> Result<[Option<ValidErasedKeyAmalgamation<'a, SecretParts>>; 3]> {
    let key_by_fp = |fp: Option<String>| match fp {
        Some(fp) => sq_util::private_subkey_by_fingerprint(key, policy, &fp),
        None => Ok(None),
    };

    Ok([key_by_fp(sig_fp)?, key_by_fp(dec_fp)?, key_by_fp(auth_fp)?])
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

    make_cert(open, key_sig, key_dec, key_aut, user_pin, prompt, &|| {
        println!("Touch confirmation needed for signing")
    })
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
