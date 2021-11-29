// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::Result;
use std::path::{Path, PathBuf};
use structopt::StructOpt;

use sequoia_openpgp::parse::{stream::DecryptorBuilder, Parse};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer};
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::Cert;

use openpgp_card_sequoia::card::{Admin, Open};
use openpgp_card_sequoia::util::{make_cert, public_key_material_to_key};
use openpgp_card_sequoia::{sq_util, PublicKey};

use openpgp_card::algorithm::AlgoSimple;
use openpgp_card::{card_do::Sex, KeyType};
use std::io::Write;

mod cli;
mod util;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let cli = cli::Cli::from_args();

    match cli.cmd {
        cli::Command::List {} => {
            list_cards()?;
        }
        cli::Command::Status { ident, verbose } => {
            print_status(ident, verbose)?;
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
            decrypt(&ident, &user_pin, &cert_file, input.as_deref())?;
        }
        cli::Command::Sign {
            ident,
            user_pin,
            cert_file,
            detached,
            input,
        } => {
            if detached {
                sign_detached(
                    &ident,
                    &user_pin,
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
            admin_pin,
            cmd,
        } => {
            let mut card = util::open_card(&ident)?;
            let mut open = Open::new(&mut card)?;

            match cmd {
                cli::AdminCommand::Name { name } => {
                    let mut admin = util::get_admin(&mut open, &admin_pin)?;

                    let _ = admin.set_name(&name)?;
                }
                cli::AdminCommand::Url { url } => {
                    let mut admin = util::get_admin(&mut open, &admin_pin)?;

                    let _ = admin.set_url(&url)?;
                }
                cli::AdminCommand::Import {
                    keyfile,
                    sig_fp,
                    dec_fp,
                    auth_fp,
                } => {
                    let admin = util::get_admin(&mut open, &admin_pin)?;
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
                cli::AdminCommand::Generate {
                    user_pin,
                    output,
                    no_decrypt,
                    no_auth,
                    algo,
                } => {
                    let pw3 = util::get_pin(&admin_pin)?;
                    let pw1 = util::get_pin(&user_pin)?;

                    generate_keys(
                        open,
                        &pw3,
                        &pw1,
                        output,
                        !no_decrypt,
                        !no_auth,
                        algo,
                    )?;
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

        for mut card in cards {
            let open = Open::new(&mut card)?;
            println!(" {}", open.application_identifier()?.ident());
        }
    } else {
        println!("No OpenPGP cards found.");
    }
    Ok(())
}

fn set_identity(
    ident: &str,
    id: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut card = util::open_card(ident)?;

    card.set_identity(id)?;

    Ok(())
}

fn print_status(ident: Option<String>, verbose: bool) -> Result<()> {
    let mut ca = if let Some(ident) = ident {
        util::open_card(&ident)?
    } else {
        let mut cards = util::cards()?;
        if cards.len() == 1 {
            cards.pop().unwrap()
        } else {
            return Err(anyhow::anyhow!("Found {} cards", cards.len()));
        }
    };
    let mut open = Open::new(&mut ca)?;

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
    if verbose {
        if let Ok(pkm) = open.get_pub_key(KeyType::Signing) {
            println! {"  public key material: {}", pkm};
        }
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
    if verbose {
        if let Ok(pkm) = open.get_pub_key(KeyType::Decryption) {
            println! {"  public key material: {}", pkm};
        }
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
    if verbose {
        if let Ok(pkm) = open.get_pub_key(KeyType::Authentication) {
            println! {"  public key material: {}", pkm};
        }
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
        // Algorithm information (list of supported algorithms)
        if let Ok(Some(ai)) = open.algorithm_information() {
            println!();
            println!("Supported algorithms:");
            println!("{}", ai);
        }

        // YubiKey specific (?) firmware version
        if let Ok(ver) = open.firmware_version() {
            let ver =
                ver.iter().map(u8::to_string).collect::<Vec<_>>().join(".");

            println!("Firmware Version: {}", ver);
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

    let mut card = util::open_card(ident)?;
    let mut open = Open::new(&mut card)?;

    let mut user = util::get_user(&mut open, pin_file)?;
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

    let mut card = util::open_card(ident)?;
    let mut open = Open::new(&mut card)?;

    let mut sign = util::get_sign(&mut open, pin_file)?;
    let s = sign.signer(&cert, &p)?;

    let message = Armorer::new(Message::new(std::io::stdout())).build()?;
    let mut signer = Signer::new(message, s).detached().build()?;

    std::io::copy(&mut input, &mut signer)?;
    signer.finalize()?;

    Ok(())
}

fn factory_reset(ident: &str) -> Result<()> {
    println!("Resetting Card {}", ident);
    let mut card = util::open_card(ident)?;
    Open::new(&mut card)?.factory_reset()
}

fn key_import_yolo(mut admin: Admin, key: &Cert) -> Result<()> {
    let p = StandardPolicy::new();

    let sig = sq_util::get_subkey_by_type(key, &p, KeyType::Signing)?;

    let dec = sq_util::get_subkey_by_type(key, &p, KeyType::Decryption)?;

    let auth = sq_util::get_subkey_by_type(key, &p, KeyType::Authentication)?;

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
            sq_util::get_priv_subkey_by_fingerprint(key, &p, &sig_fp)?
        {
            println!("Uploading {} as signing key", sig.fingerprint());
            admin.upload_key(sig, KeyType::Signing, None)?;
        } else {
            println!("ERROR: Couldn't find {} as signing key", sig_fp);
        }
    }

    if let Some(dec_fp) = dec_fp {
        if let Some(dec) =
            sq_util::get_priv_subkey_by_fingerprint(key, &p, &dec_fp)?
        {
            println!("Uploading {} as decryption key", dec.fingerprint());
            admin.upload_key(dec, KeyType::Decryption, None)?;
        } else {
            println!("ERROR: Couldn't find {} as decryption key", dec_fp);
        }
    }

    if let Some(auth_fp) = auth_fp {
        if let Some(auth) =
            sq_util::get_priv_subkey_by_fingerprint(key, &p, &auth_fp)?
        {
            println!("Uploading {} as authentication key", auth.fingerprint());
            admin.upload_key(auth, KeyType::Authentication, None)?;
        } else {
            println!("ERROR: Couldn't find {} as authentication key", auth_fp);
        }
    }

    Ok(())
}

fn generate_keys(
    mut open: Open,
    pw3: &str,
    pw1: &str,
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

    let algos = match algo.as_deref() {
        None => vec![],
        Some("rsa2048") => vec![AlgoSimple::RSA2k(32), AlgoSimple::RSA2k(17)],
        Some("rsa3072") => vec![AlgoSimple::RSA3k(32), AlgoSimple::RSA3k(17)],
        Some("rsa4096") => vec![AlgoSimple::RSA4k(32), AlgoSimple::RSA4k(17)],
        Some("nistp256") => vec![AlgoSimple::NIST256],
        Some("nistp384") => vec![AlgoSimple::NIST384],
        Some("nistp521") => vec![AlgoSimple::NIST521],
        Some("25519") => vec![AlgoSimple::Curve25519],
        _ => unimplemented!("unexpected algorithm"),
    };

    log::info!(
        " Key generation will be attempted with these algos: {:?}",
        algos
    );

    // 2) Then, generate keys on the card.
    // We need "admin" access to the card for this).

    open.verify_admin(pw3)?;

    let (key_sig, key_dec, key_aut) = {
        if let Some(mut admin) = open.admin_card() {
            gen_subkeys(&mut admin, decrypt, auth, algos)?
        } else {
            // FIXME: couldn't get admin mode
            unimplemented!()
        }
    };

    // 3) Generate a Cert from the generated keys. For this, we
    // need "signing" access to the card (to make binding signatures within
    // the Cert).

    let cert = make_cert(&mut open, key_sig, key_dec, key_aut, pw1)?;
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
    algos: Vec<AlgoSimple>,
) -> Result<(PublicKey, Option<PublicKey>, Option<PublicKey>)> {
    // We begin with the signing subkey, which is mandatory.
    // If there are multiple algorithms we should try (i.e. two rsa
    // variants), we'll attempt to make the signing subkey with each of
    // them, and continue with the first one that works, if any.

    println!(" Generate subkey for Signing");
    let (alg, key_sig) = if algos.is_empty() {
        // Handle unset algorithm from user (-> leave algo as is on the card)
        log::info!(" Running key generation with implicit algo");

        let (pkm, ts) = admin.generate_key_simple(KeyType::Signing, None)?;
        let key = public_key_material_to_key(&pkm, KeyType::Signing, ts)?;

        (None, key)
    } else {
        // Try list of algos until one works - or return list of all errors.

        let mut errors = vec![];

        let mut algo: Option<AlgoSimple> = None;
        let mut key_sig: Option<PublicKey> = None;

        // Check each algo while making key_sig.
        //
        // Return the result for the first one that works, and keep using
        // that algo.
        //
        // If none of them work, fail and return all errors

        for (n, alg) in algos.iter().enumerate() {
            let a = Some(*alg);

            log::info!(" Trying key generation with algo {:?}", alg);

            match admin.generate_key_simple(KeyType::Signing, a) {
                Ok((pkm, ts)) => {
                    // generated a valid key -> return it
                    let key = public_key_material_to_key(
                        &pkm,
                        KeyType::Signing,
                        ts,
                    )?;
                    algo = a;
                    key_sig = Some(key);
                    break;
                }
                Err(e) => match (n, n == algos.len() - 1) {
                    // there was only one algo, and it failed
                    (0, true) => return Err(e.into()),

                    // there was an error, but there are more algo to try
                    (_, false) => errors.push(e),

                    // there were multiple algo, there was an error, and
                    // this is the last algo
                    (_, true) => {
                        errors.push(e);

                        let err = anyhow::anyhow!(
                            "Key generation failed for all algorithm \
                            variants {:x?} ({:?})",
                            errors,
                            algos
                        );
                        return Err(err);
                    }
                },
            };
        }

        // Neither of these should be possible, but the compiler can't tell.
        assert!(algo.is_some());
        assert!(key_sig.is_some());

        (algo, key_sig.unwrap())
    };

    // make decryption subkey (unless disabled), with the same algorithm as
    // the sig key

    let key_dec = if decrypt {
        println!(" Generate subkey for Decryption");
        let (pkm, ts) = admin.generate_key_simple(KeyType::Decryption, alg)?;
        Some(public_key_material_to_key(&pkm, KeyType::Decryption, ts)?)
    } else {
        None
    };

    // make authentication subkey (unless disabled), with the same
    // algorithm as the sig key

    let key_aut = if auth {
        println!(" Generate subkey for Authentication");
        let (pkm, ts) =
            admin.generate_key_simple(KeyType::Authentication, alg)?;

        Some(public_key_material_to_key(
            &pkm,
            KeyType::Authentication,
            ts,
        )?)
    } else {
        None
    };

    Ok((key_sig, key_dec, key_aut))
}
