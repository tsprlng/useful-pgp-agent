// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use clap::Parser;
use cli::BaseKeySlot;
use std::path::PathBuf;

use sequoia_openpgp::cert::prelude::ValidErasedKeyAmalgamation;
use sequoia_openpgp::packet::key::{SecretParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::{Policy, StandardPolicy};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{HashAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp::Cert;

use openpgp_card_sequoia::card::{Admin, Card, Open};
use openpgp_card_sequoia::types::{AlgoSimple, CardBackend, KeyType, TouchPolicy};
use openpgp_card_sequoia::util::{make_cert, public_key_material_to_key};
use openpgp_card_sequoia::{sq_util, PublicKey};

use crate::util::{load_pin, print_gnuk_note};
use std::io::Write;

mod cli;
mod commands;
mod output;
mod util;
mod versioned_output;

use cli::OUTPUT_VERSIONS;
use versioned_output::{OutputBuilder, OutputFormat, OutputVariant, OutputVersion};

const ENTER_USER_PIN: &str = "Enter User PIN:";
const ENTER_ADMIN_PIN: &str = "Enter Admin PIN:";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let cli = cli::Cli::parse();

    match cli.cmd {
        cli::Command::OutputVersions {} => {
            output_versions(cli.output_version);
        }
        cli::Command::List {} => {
            list_cards(cli.output_format, cli.output_version)?;
        }
        cli::Command::Status(cmd) => {
            commands::status::print_status(cli.output_format, cli.output_version, cmd)?;
        }
        cli::Command::Info(cmd) => {
            commands::info::print_info(cli.output_format, cli.output_version, cmd)?;
        }
        cli::Command::Ssh(cmd) => {
            commands::ssh::print_ssh(cli.output_format, cli.output_version, cmd)?;
        }
        cli::Command::Pubkey(cmd) => {
            commands::pubkey::print_pubkey(cli.output_format, cli.output_version, cmd)?;
        }
        cli::Command::SetIdentity(cmd) => {
            commands::set_identity::set_identity(cmd)?;
        }
        cli::Command::Decrypt(cmd) => {
            commands::decrypt::decrypt(cmd)?;
        }
        cli::Command::Sign(cmd) => {
            commands::sign::sign(cmd)?;
        }
        cli::Command::Attestation { cmd } => match cmd {
            cli::AttCommand::Cert { ident } => {
                let mut output = output::AttestationCert::default();

                let backend = pick_card_for_reading(ident)?;
                let mut card = Card::new(backend);
                let mut open = card.transaction()?;

                output.ident(open.application_identifier()?.ident());

                if let Ok(ac) = open.attestation_certificate() {
                    let pem = util::pem_encode(ac);
                    output.attestation_cert(pem);
                }

                println!("{}", output.print(cli.output_format, cli.output_version)?);
            }
            cli::AttCommand::Generate {
                ident,
                key,
                user_pin,
            } => {
                let backend = util::open_card(&ident)?;
                let mut card = Card::new(backend);
                let mut open = card.transaction()?;

                let user_pin = util::get_pin(&mut open, user_pin, ENTER_USER_PIN);

                let mut sign = util::verify_to_sign(&mut open, user_pin.as_deref())?;

                let kt = KeyType::from(key);
                sign.generate_attestation(kt, &|| {
                    println!("Touch confirmation needed to generate an attestation")
                })?;
            }
            cli::AttCommand::Statement { ident, key } => {
                let backend = pick_card_for_reading(ident)?;
                let mut card = Card::new(backend);
                let mut open = card.transaction()?;

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
                match key {
                    BaseKeySlot::Aut => {
                        open.select_data(0, &[0x7F, 0x21], select_data_workaround)?
                    }
                    BaseKeySlot::Dec => {
                        open.select_data(1, &[0x7F, 0x21], select_data_workaround)?
                    }
                    BaseKeySlot::Sig => {
                        open.select_data(2, &[0x7F, 0x21], select_data_workaround)?
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
        cli::Command::FactoryReset(cmd) => {
            commands::factory_reset::factory_reset(cmd)?;
        }
        cli::Command::Admin {
            ident,
            admin_pin,
            cmd,
        } => {
            let backend = util::open_card(&ident)?;
            let mut card = Card::new(backend);
            let mut open = card.transaction()?;

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
                    decrypt,
                    auth,
                    algo,
                    user_id,
                } => {
                    let user_pin = util::get_pin(&mut open, user_pin, ENTER_USER_PIN);

                    generate_keys(
                        cli.output_format,
                        cli.output_version,
                        open,
                        admin_pin.as_deref(),
                        user_pin.as_deref(),
                        output,
                        decrypt,
                        auth,
                        algo.map(AlgoSimple::from),
                        user_id,
                    )?;
                }
                cli::AdminCommand::Touch { key, policy } => {
                    let kt = KeyType::from(key);

                    let pol = TouchPolicy::from(policy);

                    let mut admin = util::verify_to_admin(&mut open, admin_pin.as_deref())?;

                    admin.set_uif(kt, pol)?;
                }
            }
        }
        cli::Command::Pin { ident, cmd } => {
            let backend = util::open_card(&ident)?;
            let mut card = Card::new(backend);
            let mut open = card.transaction()?;

            let pinpad_modify = open.feature_pinpad_modify();

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

fn output_versions(chosen: OutputVersion) {
    for v in OUTPUT_VERSIONS.iter() {
        if v == &chosen {
            println!("* {}", v);
        } else {
            println!("  {}", v);
        }
    }
}

fn list_cards(format: OutputFormat, output_version: OutputVersion) -> Result<()> {
    let cards = util::cards()?;
    let mut output = output::List::default();
    if !cards.is_empty() {
        for backend in cards {
            let mut card = Card::new(backend);
            let open = card.transaction()?;

            output.push(open.application_identifier()?.ident());
        }
    }
    println!("{}", output.print(format, output_version)?);
    Ok(())
}

/// Return a card for a read operation. If `ident` is None, and exactly one card
/// is plugged in, that card is returned. (We don't This
fn pick_card_for_reading(ident: Option<String>) -> Result<Box<dyn CardBackend + Send + Sync>> {
    if let Some(ident) = ident {
        Ok(util::open_card(&ident)?)
    } else {
        let mut cards = util::cards()?;
        if cards.len() == 1 {
            Ok(cards.pop().unwrap())
        } else if cards.is_empty() {
            Err(anyhow::anyhow!("No cards found"))
        } else {
            // The output version for OutputFormat::Text doesn't matter (it's ignored).
            list_cards(OutputFormat::Text, OutputVersion::new(0, 0, 0))?;

            println!("Specify which card to use with '--card <card ident>'\n");

            Err(anyhow::anyhow!("Found more than one card"))
        }
    }
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
    user_ids: &[String],
    prompt: &dyn Fn(),
) -> Result<Cert> {
    if user_pin.is_none() && open.feature_pinpad_verify() {
        println!(
            "The public cert will now be generated.\n\n\
             You will need to enter your User PIN multiple times during this process.\n\n"
        );
    }

    make_cert(
        open,
        key_sig,
        key_dec,
        key_aut,
        user_pin,
        prompt,
        &|| println!("Touch confirmation needed for signing"),
        user_ids,
    )
}

#[allow(clippy::too_many_arguments)]
fn generate_keys(
    format: OutputFormat,
    version: OutputVersion,
    mut open: Open,
    admin_pin: Option<&[u8]>,
    user_pin: Option<&[u8]>,
    output_file: Option<PathBuf>,
    decrypt: bool,
    auth: bool,
    algo: Option<AlgoSimple>,
    user_ids: Vec<String>,
) -> Result<()> {
    let mut output = output::AdminGenerate::default();
    output.ident(open.application_identifier()?.ident());

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

    log::info!(" Key generation will be attempted with algo: {:?}", algo);
    output.algorithm(format!("{:?}", algo));

    // 2) Then, generate keys on the card.
    // We need "admin" access to the card for this).
    let (key_sig, key_dec, key_aut) = {
        if let Ok(mut admin) = util::verify_to_admin(&mut open, admin_pin) {
            gen_subkeys(&mut admin, decrypt, auth, algo)?
        } else {
            return Err(anyhow!("Failed to open card in admin mode."));
        }
    };

    // 3) Generate a Cert from the generated keys. For this, we
    // need "signing" access to the card (to make binding signatures within
    // the Cert).
    let cert = get_cert(
        &mut open,
        key_sig,
        key_dec,
        key_aut,
        user_pin,
        &user_ids,
        &|| println!("Enter User PIN on card reader pinpad."),
    )?;

    let armored = String::from_utf8(cert.armored().to_vec()?)?;
    output.public_key(armored);

    // Write armored certificate to the output file (or stdout)
    let mut handle = util::open_or_stdout(output_file.as_deref())?;
    handle.write_all(output.print(format, version)?.as_bytes())?;
    let _ = handle.write(b"\n")?;

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
