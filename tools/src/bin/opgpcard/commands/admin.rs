// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-FileCopyrightText: 2022 Nora Widdecke <mail@nora.pink>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use openpgp_card_sequoia::state::{Admin, Open, Transaction};
use openpgp_card_sequoia::util::public_key_material_to_key;
use sequoia_openpgp::types::{HashAlgorithm, SymmetricAlgorithm};

use std::path::PathBuf;

use openpgp_card_sequoia::{sq_util, PublicKey};

use sequoia_openpgp::cert::prelude::ValidErasedKeyAmalgamation;
use sequoia_openpgp::packet::key::{SecretParts, UnspecifiedRole};
use sequoia_openpgp::packet::Key;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::Cert;

use openpgp_card_sequoia::types::AlgoSimple;
use openpgp_card_sequoia::{types::KeyType, Card};

use crate::versioned_output::{OutputBuilder, OutputFormat, OutputVersion};
use crate::{output, util, ENTER_ADMIN_PIN, ENTER_USER_PIN};

#[derive(Parser, Debug)]
pub struct AdminCommand {
    #[clap(
        name = "card ident",
        short = 'c',
        long = "card",
        help = "Identifier of the card to use"
    )]
    pub ident: String,

    #[clap(
        name = "Admin PIN file",
        short = 'P',
        long = "admin-pin",
        help = "Optionally, get Admin PIN from a file"
    )]
    pub admin_pin: Option<PathBuf>,

    #[clap(subcommand)]
    pub cmd: AdminSubCommand,
}

#[derive(Parser, Debug)]
pub enum AdminSubCommand {
    /// Set cardholder name
    Name {
        #[clap(help = "cardholder name to set on the card")]
        name: String,
    },

    /// Set certificate URL
    Url {
        #[clap(help = "URL that provides the certificate for the key material on this card")]
        url: String,
    },

    /// Import a Key onto the card.
    ///
    /// Most keys can be imported without specifying subkey fingerprints. However, if the key
    /// contins more than one signing, decryption or authentication capable subkey, subkeys must be
    /// explicitly selected.
    ///
    /// If any of the options is given, only the selected subkeys are imported into the selected
    /// slots.
    ///
    /// Subkey capabilities must match the slot the key is imported into. The DEC slot can
    /// only be used for encryption capable subkeys. The SIG and AUT slots can be used for signing,
    /// certification and authentication capable subkeys.
    Import {
        #[clap(help = "File that contains the PGP private key")]
        keyfile: PathBuf,

        /// Optionally, select the subkey to import in the SIG slot
        #[clap(name = "SIG subkey fingerprint", short = 's', long = "sig-fp")]
        sig_fp: Option<String>,

        /// Optionally, select the subkey to import in the DEC slot
        #[clap(name = "DEC subkey fingerprint", short = 'd', long = "dec-fp")]
        dec_fp: Option<String>,

        /// Optionally, select the subkey to import in the AUT slot
        #[clap(name = "AUT subkey fingerprint", short = 'a', long = "aut-fp")]
        aut_fp: Option<String>,
    },

    /// Generate a Key on the card.
    ///
    /// A signing key is always created, decryption and authentication keys
    /// are optional.
    Generate(AdminGenerateCommand),

    /// Set the card's touch policy (if supported)
    ///
    /// A touch policy defines if cryptographic operations on the card require user interaction
    /// with the card, for example by touching a button on the card.
    ///
    /// Only some cards support this feature at all, not all cards support all policies.
    ///
    /// Caution: Setting the ATT slot to Fixed or Cached-Fixed is permanent. Even a factory reset does
    /// not undo this setting.
    Touch {
        /// Key slot to set the touch policy for
        #[clap(name = "Key slot", short = 'k', long = "key", value_enum)]
        key: BasePlusAttKeySlot,

        /// Touch policy to set on this key slot
        #[clap(
            name = "Policy",
            short = 'p',
            long = "policy",
            value_enum,
            long_help = "Touch policy to set on this key slot

Off: No touch confirmation required.
On: Touch confirmation required for each operation.
Fixed: Like 'On', but the policy can only be changed by a reset.
Cached: Like 'On', but touch confirmation is valid for 15 seconds.
Cached-Fixed: Combines 'Cached' and 'Fixed'."
        )]
        policy: TouchPolicy,
    },
}

#[derive(Parser, Debug)]
pub struct AdminGenerateCommand {
    /// Output file
    #[clap(name = "output", long = "output", short = 'o')]
    output_file: PathBuf,

    /// Do not create a key in the DEC slot
    #[clap(long = "no-dec", action = clap::ArgAction::SetFalse)]
    decrypt: bool,

    /// Do not create a key in the AUT slot
    #[clap(long = "no-aut", action = clap::ArgAction::SetFalse)]
    auth: bool,

    /// Choose the algorithm for the key material to generate on the card.
    ///
    /// If the parameter is not given, use the algorithm currently set on the card.
    ///
    /// Specific cards support a set of algorithms that can differ between models. On modern cards,
    /// use 'opgpcard info' to see the list of supported algorithms.
    #[clap(name = "algorithm", value_enum)]
    algo: Option<Algo>,

    /// User ID to add to the exported certificate representation
    #[clap(name = "User ID", short = 'u', long = "userid")]
    user_ids: Vec<String>,

    #[clap(
        name = "User PIN file",
        short = 'p',
        long = "user-pin",
        help = "Optionally, get User PIN from a file"
    )]
    user_pin: Option<PathBuf>,
}

#[derive(ValueEnum, Debug, Clone)]
#[clap(rename_all = "UPPER")]
pub enum BasePlusAttKeySlot {
    Sig,
    Dec,
    Aut,
    Att,
}

impl From<BasePlusAttKeySlot> for KeyType {
    fn from(ks: BasePlusAttKeySlot) -> Self {
        match ks {
            BasePlusAttKeySlot::Sig => KeyType::Signing,
            BasePlusAttKeySlot::Dec => KeyType::Decryption,
            BasePlusAttKeySlot::Aut => KeyType::Authentication,
            BasePlusAttKeySlot::Att => KeyType::Attestation,
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
pub enum TouchPolicy {
    #[clap(name = "Off")]
    Off,
    #[clap(name = "On")]
    On,
    #[clap(name = "Fixed")]
    Fixed,
    #[clap(name = "Cached")]
    Cached,
    #[clap(name = "Cached-Fixed")]
    CachedFixed,
}

impl From<TouchPolicy> for openpgp_card_sequoia::types::TouchPolicy {
    fn from(tp: TouchPolicy) -> Self {
        use openpgp_card_sequoia::types::TouchPolicy as OCTouchPolicy;
        match tp {
            TouchPolicy::On => OCTouchPolicy::On,
            TouchPolicy::Off => OCTouchPolicy::Off,
            TouchPolicy::Fixed => OCTouchPolicy::Fixed,
            TouchPolicy::Cached => OCTouchPolicy::Cached,
            TouchPolicy::CachedFixed => OCTouchPolicy::CachedFixed,
        }
    }
}

#[derive(ValueEnum, Debug, Clone)]
#[clap(rename_all = "lower")]
pub enum Algo {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Nistp256,
    Nistp384,
    Nistp521,
    Cv25519,
}

impl From<Algo> for AlgoSimple {
    fn from(a: Algo) -> Self {
        match a {
            Algo::Rsa2048 => AlgoSimple::RSA2k,
            Algo::Rsa3072 => AlgoSimple::RSA3k,
            Algo::Rsa4096 => AlgoSimple::RSA4k,
            Algo::Nistp256 => AlgoSimple::NIST256,
            Algo::Nistp384 => AlgoSimple::NIST384,
            Algo::Nistp521 => AlgoSimple::NIST521,
            Algo::Cv25519 => AlgoSimple::Curve25519,
        }
    }
}

pub fn admin(
    output_format: OutputFormat,
    output_version: OutputVersion,
    command: AdminCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let backend = util::open_card(&command.ident)?;
    let mut open: Card<Open> = backend.into();
    let mut card = open.transaction()?;

    let admin_pin = util::get_pin(&mut card, command.admin_pin, ENTER_ADMIN_PIN)?;

    match command.cmd {
        AdminSubCommand::Name { name } => {
            name_command(&name, card, admin_pin.as_deref())?;
        }
        AdminSubCommand::Url { url } => {
            url_command(&url, card, admin_pin.as_deref())?;
        }
        AdminSubCommand::Import {
            keyfile,
            sig_fp,
            dec_fp,
            aut_fp,
        } => {
            import_command(keyfile, sig_fp, dec_fp, aut_fp, card, admin_pin.as_deref())?;
        }
        AdminSubCommand::Generate(cmd) => {
            generate_command(
                output_format,
                output_version,
                card,
                admin_pin.as_deref(),
                cmd,
            )?;
        }
        AdminSubCommand::Touch { key, policy } => {
            touch_command(card, admin_pin.as_deref(), key, policy)?;
        }
    }
    Ok(())
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
    aut_fp: Option<String>,
) -> Result<[Option<ValidErasedKeyAmalgamation<'a, SecretParts>>; 3]> {
    let key_by_fp = |fp: Option<String>| match fp {
        Some(fp) => sq_util::private_subkey_by_fingerprint(key, policy, &fp),
        None => Ok(None),
    };

    Ok([key_by_fp(sig_fp)?, key_by_fp(dec_fp)?, key_by_fp(aut_fp)?])
}

fn gen_subkeys(
    admin: &mut Card<Admin>,
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

fn name_command(
    name: &str,
    mut card: Card<Transaction>,
    admin_pin: Option<&[u8]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut admin = util::verify_to_admin(&mut card, admin_pin)?;

    admin.set_name(name)?;
    Ok(())
}

fn url_command(
    url: &str,
    mut card: Card<Transaction>,
    admin_pin: Option<&[u8]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut admin = util::verify_to_admin(&mut card, admin_pin)?;

    admin.set_url(url)?;
    Ok(())
}

fn import_command(
    keyfile: PathBuf,
    sig_fp: Option<String>,
    dec_fp: Option<String>,
    aut_fp: Option<String>,
    mut card: Card<Transaction>,
    admin_pin: Option<&[u8]>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = Cert::from_file(keyfile)?;

    let p = StandardPolicy::new();

    // select the (sub)keys to upload
    let [sig, dec, auth] = match (&sig_fp, &dec_fp, &aut_fp) {
        // No fingerprint has been provided, try to autoselect keys
        // (this fails if there is more than one (sub)key for any keytype).
        (&None, &None, &None) => keys_pick_yolo(&key, &p)?,

        _ => keys_pick_explicit(&key, &p, sig_fp, dec_fp, aut_fp)?,
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
    let mut get_pw_for_key = |key: &Option<ValidErasedKeyAmalgamation<SecretParts>>,
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
    let mut admin = util::verify_to_admin(&mut card, admin_pin)?;

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
    Ok(())
}

fn generate_command(
    output_format: OutputFormat,
    output_version: OutputVersion,
    mut card: Card<Transaction>,

    admin_pin: Option<&[u8]>,

    cmd: AdminGenerateCommand,
) -> Result<()> {
    let user_pin = util::get_pin(&mut card, cmd.user_pin, ENTER_USER_PIN)?;

    let mut output = output::AdminGenerate::default();
    output.ident(card.application_identifier()?.ident());

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

    let algo = cmd.algo.map(AlgoSimple::from);
    log::info!(" Key generation will be attempted with algo: {:?}", algo);
    output.algorithm(format!("{:?}", algo));

    // 2) Then, generate keys on the card.
    // We need "admin" access to the card for this).
    let (key_sig, key_dec, key_aut) = {
        if let Ok(mut admin) = util::verify_to_admin(&mut card, admin_pin) {
            gen_subkeys(&mut admin, cmd.decrypt, cmd.auth, algo)?
        } else {
            return Err(anyhow!("Failed to open card in admin mode."));
        }
    };

    // 3) Generate a Cert from the generated keys. For this, we
    // need "signing" access to the card (to make binding signatures within
    // the Cert).
    let cert = crate::get_cert(
        &mut card,
        key_sig,
        key_dec,
        key_aut,
        user_pin.as_deref(),
        &cmd.user_ids,
        &|| println!("Enter User PIN on card reader pinpad."),
    )?;

    let armored = String::from_utf8(cert.armored().to_vec()?)?;
    output.public_key(armored);

    // Write armored certificate to the output file
    let mut handle = util::open_or_stdout(Some(&cmd.output_file))?;
    handle.write_all(output.print(output_format, output_version)?.as_bytes())?;
    let _ = handle.write(b"\n")?;

    Ok(())
}

fn touch_command(
    mut card: Card<Transaction>,
    admin_pin: Option<&[u8]>,
    key: BasePlusAttKeySlot,
    policy: TouchPolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    let kt = KeyType::from(key);

    let pol = openpgp_card_sequoia::types::TouchPolicy::from(policy);

    let mut admin = util::verify_to_admin(&mut card, admin_pin)?;

    admin.set_uif(kt, pol)?;
    Ok(())
}
