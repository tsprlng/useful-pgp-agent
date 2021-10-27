// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use std::path::Path;
use structopt::StructOpt;

use sequoia_openpgp::parse::{stream::DecryptorBuilder, Parse};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};
use sequoia_openpgp::Cert;

use openpgp_card_sequoia::card::Admin;
use openpgp_card_sequoia::sq_util;

use openpgp_card::{card_do::Sex, KeyType};

mod cli;
mod util;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = cli::Cli::from_args();

    match cli.cmd {
        cli::Command::List {} => {
            list_cards()?;
        }
        cli::Command::Status { ident, verbose } => {
            print_status(ident, verbose)?;
        }
        cli::Command::Decrypt {
            ident,
            pin_file,
            cert_file,
            input,
        } => {
            decrypt(&ident, &pin_file, &cert_file, input.as_deref())?;
        }
        cli::Command::Sign {
            ident,
            pin_file,
            cert_file,
            detached,
            input,
        } => {
            if detached {
                sign_detached(
                    &ident,
                    &pin_file,
                    &cert_file,
                    input.as_deref(),
                )?;
            } else {
                return Err(anyhow::anyhow!(
                    "Only detached signatures are supported for now"
                )
                .into());
            }
        }
        cli::Command::FactoryReset { ident } => {
            factory_reset(&ident)?;
        }
        cli::Command::Admin {
            ident,
            pin_file,
            cmd,
        } => {
            let mut open = util::open_card(&ident)?;
            let mut admin = util::get_admin(&mut open, &pin_file)?;

            match cmd {
                cli::AdminCommand::Name { name } => {
                    let _ = admin.set_name(&name)?;
                }
                cli::AdminCommand::Url { url } => {
                    let _ = admin.set_url(&url)?;
                }
                cli::AdminCommand::Import {
                    keyfile,
                    sig_fp,
                    dec_fp,
                    auth_fp,
                } => {
                    let key = Cert::from_file(keyfile)?;

                    if (&sig_fp, &dec_fp, &auth_fp) == (&None, &None, &None) {
                        // If no fingerprint has been provided, we check if
                        // there is zero or one (sub)key for each keytype,
                        // and if so, import these keys to the card.
                        key_import_yolo(admin, &key)?;
                    } else {
                        key_import_explicit(
                            admin, &key, sig_fp, dec_fp, auth_fp,
                        )?;
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
        println!("Available OpenPGP cards:");

        for card in cards {
            println!(" {}", card.application_identifier()?.ident());
        }
    } else {
        println!("No OpenPGP cards found.");
    }
    Ok(())
}

fn print_status(ident: Option<String>, verbose: bool) -> Result<()> {
    let mut open = if let Some(ident) = ident {
        util::open_card(&ident)?
    } else {
        let mut cards = util::cards()?;
        if cards.len() == 1 {
            cards.pop().unwrap()
        } else {
            return Err(anyhow::anyhow!("Found {} cards", cards.len()).into());
        }
    };

    print!("OpenPGP card {}", open.application_identifier()?.ident());

    let ai = open.application_identifier()?;
    let version = ai.version().to_be_bytes();
    println!(" (card version {}.{})\n", version[0], version[1]);

    // card / cardholder metadata
    let crd = open.cardholder_related_data()?;

    if let Some(name) = crd.name() {
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
        let lang = lang
            .iter()
            .map(|lang| lang.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(", ");
        println!("Language preferences '{}'", lang);
    }

    // information about subkeys

    let fps = open.fingerprints()?;
    let kgt = open.key_generation_times()?;

    println!();
    println!(
        "Signature key ({})",
        open.algorithm_attributes(KeyType::Signing)?,
    );
    if let Some(fp) = fps.signature() {
        println!("  fingerprint: {}", fp.to_spaced_hex());
    }
    if let Some(kgt) = kgt.signature() {
        println! {"  created: {}",kgt.formatted()};
    }

    println!();
    println!(
        "Decryption key ({})",
        open.algorithm_attributes(KeyType::Decryption)?,
    );
    if let Some(fp) = fps.decryption() {
        println!("  fingerprint: {}", fp.to_spaced_hex());
    }
    if let Some(kgt) = kgt.decryption() {
        println! {"  created: {}",kgt.formatted()};
    }

    println!();
    println!(
        "Authentication key ({})",
        open.algorithm_attributes(KeyType::Authentication)?,
    );
    if let Some(fp) = fps.authentication() {
        println!("  fingerprint: {}", fp.to_spaced_hex());
    }
    if let Some(kgt) = kgt.authentication() {
        println! {"  created: {}",kgt.formatted()};
    }

    // technical details about the card and its state

    println!();

    let sst = open.security_support_template()?;
    println!("Signature counter: {}", sst.get_signature_count());

    let pws = open.pw_status_bytes()?;

    println!(
        "Signature pin only valid once: {}",
        pws.get_pw1_cds_valid_once()
    );

    println!("Password validation retry count:");
    println!(
        "  user pw: {}, reset: {}, admin pw: {}",
        pws.get_err_count_pw1(),
        pws.get_err_count_rst(),
        pws.get_err_count_pw3(),
    );

    // FIXME: add General key info; login data; KDF setting

    if verbose {
        if let Some(ai) = open.algorithm_information()? {
            println!();
            println!("Supported algorithms:");
            println!("{}", ai);
        }
    }

    Ok(())
}

fn decrypt(
    ident: &str,
    pin_file: &Path,
    cert_file: &Path,
    input: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let p = StandardPolicy::new();
    let cert = Cert::from_file(cert_file)?;

    let input = util::open_or_stdin(input.as_deref())?;

    let mut open = util::open_card(&ident)?;
    let mut user = util::get_user(&mut open, &pin_file)?;
    let d = user.decryptor(&cert, &p)?;

    let db = DecryptorBuilder::from_reader(input)?;
    let mut decryptor = db.with_policy(&p, None, d)?;

    std::io::copy(&mut decryptor, &mut std::io::stdout())?;

    Ok(())
}

fn sign_detached(
    ident: &str,
    pin_file: &Path,
    cert_file: &Path,
    input: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let p = StandardPolicy::new();
    let cert = Cert::from_file(cert_file)?;

    let mut input = util::open_or_stdin(input.as_deref())?;

    let mut open = util::open_card(&ident)?;
    let mut sign = util::get_sign(&mut open, &pin_file)?;
    let s = sign.signer(&cert, &p)?;

    let message = Armorer::new(Message::new(std::io::stdout())).build()?;
    let mut signer = Signer::new(message, s).detached().build()?;

    std::io::copy(&mut input, &mut signer)?;
    signer.finalize()?;

    Ok(())
}

fn factory_reset(ident: &str) -> Result<()> {
    println!("Resetting Card {}", ident);
    util::open_card(ident)?.factory_reset()
}

fn key_import_yolo(mut admin: Admin, key: &Cert) -> Result<()> {
    let p = StandardPolicy::new();

    let sig =
        openpgp_card_sequoia::sq_util::get_subkey(&key, &p, KeyType::Signing)?;

    let dec = openpgp_card_sequoia::sq_util::get_subkey(
        &key,
        &p,
        KeyType::Decryption,
    )?;

    let auth = openpgp_card_sequoia::sq_util::get_subkey(
        &key,
        &p,
        KeyType::Authentication,
    )?;

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
        if let Some(sig) =
            sq_util::get_subkey_by_fingerprint(&key, &p, &sig_fp)?
        {
            println!("Uploading {} as signing key", sig.fingerprint());
            admin.upload_key(sig, KeyType::Signing, None)?;
        } else {
            println!("ERROR: Couldn't find {} as signing key", sig_fp);
        }
    }

    if let Some(dec_fp) = dec_fp {
        if let Some(dec) =
            sq_util::get_subkey_by_fingerprint(&key, &p, &dec_fp)?
        {
            println!("Uploading {} as decryption key", dec.fingerprint());
            admin.upload_key(dec, KeyType::Decryption, None)?;
        } else {
            println!("ERROR: Couldn't find {} as decryption key", dec_fp);
        }
    }

    if let Some(auth_fp) = auth_fp {
        if let Some(auth) =
            sq_util::get_subkey_by_fingerprint(&key, &p, &auth_fp)?
        {
            println!("Uploading {} as authentication key", auth.fingerprint());
            admin.upload_key(auth, KeyType::Authentication, None)?;
        } else {
            println!("ERROR: Couldn't find {} as authentication key", auth_fp);
        }
    }

    Ok(())
}
