// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::card::{Admin, Open, Sign, User};
use openpgp_card_sequoia::types::{
    Algo, CardBackend, Curve, EccType, Error, PublicKeyMaterial, StatusBytes,
};

pub(crate) fn cards() -> Result<Vec<Box<dyn CardBackend + Send + Sync>>, Error> {
    PcscBackend::cards(None).map(|cards| cards.into_iter().map(|c| c.into()).collect())
}

pub(crate) fn open_card(ident: &str) -> Result<Box<dyn CardBackend + Send + Sync>, Error> {
    Ok(PcscBackend::open_by_ident(ident, None)?.into())
}

/// Get pin from file. Or via user input, if no file and no pinpad is available.
///
/// If a pinpad is available, return Null (the pinpad will be used to get access to the card).
///
/// `msg` is the message to show when asking the user to enter a PIN.
pub(crate) fn get_pin(open: &mut Open, pin_file: Option<PathBuf>, msg: &str) -> Option<Vec<u8>> {
    if let Some(path) = pin_file {
        // we have a pin file
        Some(load_pin(&path).ok()?)
    } else if !open.feature_pinpad_verify() {
        // we have no pin file and no pinpad
        let pin = rpassword::prompt_password(msg).ok()?;
        Some(pin.into_bytes())
    } else {
        // we have a pinpad
        None
    }
}

/// Let the user input a PIN twice, return PIN if both entries match, error otherwise
pub(crate) fn input_pin_twice(msg1: &str, msg2: &str) -> Result<Vec<u8>> {
    // get new user pin
    let newpin1 = rpassword::prompt_password(msg1)?;
    let newpin2 = rpassword::prompt_password(msg2)?;

    if newpin1 != newpin2 {
        Err(anyhow::anyhow!("PINs do not match."))
    } else {
        Ok(newpin1.as_bytes().to_vec())
    }
}

pub(crate) fn verify_to_user<'app, 'open>(
    open: &'open mut Open<'app>,
    pin: Option<&[u8]>,
) -> Result<User<'app, 'open>, Box<dyn std::error::Error>> {
    if let Some(pin) = pin {
        open.verify_user(pin)?;
    } else {
        if !open.feature_pinpad_verify() {
            return Err(anyhow!("No user PIN file provided, and no pinpad found").into());
        };

        open.verify_user_pinpad(&|| println!("Enter user PIN on card reader pinpad."))?;
    }

    open.user_card()
        .ok_or_else(|| anyhow!("Couldn't get user access").into())
}

pub(crate) fn verify_to_sign<'app, 'open>(
    open: &'open mut Open<'app>,
    pin: Option<&[u8]>,
) -> Result<Sign<'app, 'open>, Box<dyn std::error::Error>> {
    if let Some(pin) = pin {
        open.verify_user_for_signing(pin)?;
    } else {
        if !open.feature_pinpad_verify() {
            return Err(anyhow!("No user PIN file provided, and no pinpad found").into());
        }
        open.verify_user_for_signing_pinpad(&|| println!("Enter user PIN on card reader pinpad."))?;
    }
    open.signing_card()
        .ok_or_else(|| anyhow!("Couldn't get sign access").into())
}

pub(crate) fn verify_to_admin<'app, 'open>(
    open: &'open mut Open<'app>,
    pin: Option<&[u8]>,
) -> Result<Admin<'app, 'open>, Box<dyn std::error::Error>> {
    if let Some(pin) = pin {
        open.verify_admin(pin)?;
    } else {
        if !open.feature_pinpad_verify() {
            return Err(anyhow!("No admin PIN file provided, and no pinpad found").into());
        }

        open.verify_admin_pinpad(&|| println!("Enter admin PIN on card reader pinpad."))?;
    }
    open.admin_card()
        .ok_or_else(|| anyhow!("Couldn't get admin access").into())
}

pub(crate) fn load_pin(pin_file: &Path) -> Result<Vec<u8>> {
    let pin = std::fs::read_to_string(pin_file)?;
    Ok(pin.trim().as_bytes().to_vec())
}

pub(crate) fn open_or_stdin(f: Option<&Path>) -> Result<Box<dyn std::io::Read + Send + Sync>> {
    match f {
        Some(f) => Ok(Box::new(
            std::fs::File::open(f).context("Failed to open input file")?,
        )),
        None => Ok(Box::new(std::io::stdin())),
    }
}

pub(crate) fn open_or_stdout(f: Option<&Path>) -> Result<Box<dyn std::io::Write + Send + Sync>> {
    match f {
        Some(f) => Ok(Box::new(
            std::fs::File::create(f).context("Failed to open input file")?,
        )),
        None => Ok(Box::new(std::io::stdout())),
    }
}

fn get_ssh_pubkey(pkm: &PublicKeyMaterial, ident: String) -> Result<sshkeys::PublicKey> {
    let cardname = format!("opgpcard:{}", ident);

    let (key_type, kind) = match pkm {
        PublicKeyMaterial::R(rsa) => {
            let key_type = sshkeys::KeyType::from_name("ssh-rsa")?;

            let kind = sshkeys::PublicKeyKind::Rsa(sshkeys::RsaPublicKey {
                e: rsa.v().to_vec(),
                n: rsa.n().to_vec(),
            });

            Ok((key_type, kind))
        }
        PublicKeyMaterial::E(ecc) => {
            if let Algo::Ecc(ecc_attrs) = ecc.algo() {
                match ecc_attrs.ecc_type() {
                    EccType::EdDSA => {
                        let key_type = sshkeys::KeyType::from_name("ssh-ed25519")?;

                        let kind = sshkeys::PublicKeyKind::Ed25519(sshkeys::Ed25519PublicKey {
                            key: ecc.data().to_vec(),
                            sk_application: None,
                        });

                        Ok((key_type, kind))
                    }
                    EccType::ECDSA => {
                        let (curve, name) = match ecc_attrs.curve() {
                            Curve::NistP256r1 => Ok((
                                sshkeys::Curve::from_identifier("nistp256")?,
                                "ecdsa-sha2-nistp256",
                            )),
                            Curve::NistP384r1 => Ok((
                                sshkeys::Curve::from_identifier("nistp384")?,
                                "ecdsa-sha2-nistp384",
                            )),
                            Curve::NistP521r1 => Ok((
                                sshkeys::Curve::from_identifier("nistp521")?,
                                "ecdsa-sha2-nistp521",
                            )),
                            _ => Err(anyhow!("Unexpected ECDSA curve {:?}", ecc_attrs.curve())),
                        }?;

                        let key_type = sshkeys::KeyType::from_name(name)?;

                        let kind = sshkeys::PublicKeyKind::Ecdsa(sshkeys::EcdsaPublicKey {
                            curve,
                            key: ecc.data().to_vec(),
                            sk_application: None,
                        });

                        Ok((key_type, kind))
                    }
                    _ => Err(anyhow!("Unexpected EccType {:?}", ecc_attrs.ecc_type())),
                }
            } else {
                Err(anyhow!("Unexpected Algo in EccPub {:?}", ecc))
            }
        }
        _ => Err(anyhow!("Unexpected PublicKeyMaterial type {:?}", pkm)),
    }?;

    let pk = sshkeys::PublicKey {
        key_type,
        comment: Some(cardname),
        kind,
    };

    Ok(pk)
}

/// Return a String representation of an ssh public key, in a form like:
/// "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAuTuxILMTvzTIRvaRqqUM3aRDoEBgz/JAoWKsD1ECxy opgpcard:FFFE:43194240"
pub(crate) fn get_ssh_pubkey_string(pkm: &PublicKeyMaterial, ident: String) -> Result<String> {
    let pk = get_ssh_pubkey(pkm, ident)?;

    let mut v = vec![];
    pk.write(&mut v)?;

    let s = String::from_utf8_lossy(&v).to_string();

    Ok(s.trim().into())
}

/// Gnuk doesn't allow the User password (pw1) to be changed while no
/// private key material exists on the card.
///
/// This fn checks for Gnuk's Status code and the case that no keys exist
/// on the card, and prints a note to the user, pointing out that the
/// absence of keys on the card might be the reason for the error they get.
pub(crate) fn print_gnuk_note(err: Error, card: &Open) -> Result<()> {
    if matches!(
        err,
        Error::CardStatus(StatusBytes::ConditionOfUseNotSatisfied)
    ) {
        // check if no keys exist on the card
        let fps = card.fingerprints()?;
        if fps.signature() == None && fps.decryption() == None && fps.authentication() == None {
            println!(
                "\nNOTE: Some cards (e.g. Gnuk) don't allow \
                        User PIN change while no keys exist on the card."
            );
        }
    }
    Ok(())
}

pub(crate) fn pem_encode(data: Vec<u8>) -> String {
    const PEM_TAG: &str = "CERTIFICATE";

    let pem = pem::Pem {
        tag: String::from(PEM_TAG),
        contents: data,
    };

    pem::encode(&pem)
}
