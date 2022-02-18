// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};

use openpgp_card::algorithm::{Algo, Curve};
use openpgp_card::crypto_data::{EccType, PublicKeyMaterial};
use openpgp_card::{CardBackend, Error};
use openpgp_card_pcsc::PcscCard;
use openpgp_card_sequoia::card::{Admin, Open, Sign, User};

pub(crate) fn cards() -> Result<Vec<Box<dyn CardBackend>>, Error> {
    PcscCard::cards(None)
        .map(|cards| cards.into_iter().map(Into::into).collect())
}

pub(crate) fn open_card(ident: &str) -> Result<Box<dyn CardBackend>, Error> {
    PcscCard::open_by_ident(ident, None).map(Into::into)
}

pub(crate) fn verify_to_user<'app, 'open>(
    open: &'app mut Open<'app>,
    pin_file: Option<PathBuf>,
) -> Result<User<'app, 'open>, Box<dyn std::error::Error>> {
    if let Some(path) = pin_file {
        open.verify_user(&load_pin(&path)?)?;
    } else {
        if !open.feature_pinpad_verify() {
            return Err(anyhow!(
                "No user PIN file provided, and no pinpad found"
            )
            .into());
        };

        open.verify_user_pinpad(&|| {
            println!("Enter user PIN on card reader pinpad.")
        })?;
    }

    open.user_card()
        .ok_or_else(|| anyhow!("Couldn't get user access").into())
}

pub(crate) fn verify_to_sign<'app, 'open>(
    open: &'app mut Open<'app>,
    pin_file: Option<PathBuf>,
) -> Result<Sign<'app, 'open>, Box<dyn std::error::Error>> {
    if let Some(path) = pin_file {
        open.verify_user_for_signing(&load_pin(&path)?)?;
    } else {
        if !open.feature_pinpad_verify() {
            return Err(anyhow!(
                "No user PIN file provided, and no pinpad found"
            )
            .into());
        }
        open.verify_user_for_signing_pinpad(&|| {
            println!("Enter user PIN on card reader pinpad.")
        })?;
    }
    open.signing_card()
        .ok_or_else(|| anyhow!("Couldn't get sign access").into())
}

// pub fn admin_card<'b>(&'b mut self) -> Option<Admin<'a, 'b>> {

pub(crate) fn verify_to_admin<'app, 'open>(
    open: &'open mut Open<'app>,
    pin_file: Option<PathBuf>,
) -> Result<Admin<'app, 'open>, Box<dyn std::error::Error>> {
    if let Some(path) = pin_file {
        open.verify_admin(&load_pin(&path)?)?;
    } else {
        if !open.feature_pinpad_verify() {
            return Err(anyhow!(
                "No admin PIN file provided, and no pinpad found"
            )
            .into());
        }

        open.verify_admin_pinpad(&|| {
            println!("Enter admin PIN on card reader pinpad.")
        })?;
    }
    open.admin_card()
        .ok_or_else(|| anyhow!("Couldn't get admin access").into())
}

pub(crate) fn load_pin(pin_file: &Path) -> Result<String> {
    let pin = std::fs::read_to_string(pin_file)?;
    Ok(pin.trim().to_string())
}

pub(crate) fn open_or_stdin(
    f: Option<&Path>,
) -> Result<Box<dyn std::io::Read + Send + Sync>> {
    match f {
        Some(f) => Ok(Box::new(
            std::fs::File::open(f).context("Failed to open input file")?,
        )),
        None => Ok(Box::new(std::io::stdin())),
    }
}

pub(crate) fn open_or_stdout(
    f: Option<&Path>,
) -> Result<Box<dyn std::io::Write + Send + Sync>> {
    match f {
        Some(f) => Ok(Box::new(
            std::fs::File::create(f).context("Failed to open input file")?,
        )),
        None => Ok(Box::new(std::io::stdout())),
    }
}

fn get_ssh_pubkey(
    pkm: &PublicKeyMaterial,
    ident: String,
) -> Result<sshkeys::PublicKey> {
    let cardno = format!("cardno:{}", ident);

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
                        let key_type =
                            sshkeys::KeyType::from_name("ssh-ed25519")?;

                        let kind = sshkeys::PublicKeyKind::Ed25519(
                            sshkeys::Ed25519PublicKey {
                                key: ecc.data().to_vec(),
                                sk_application: None,
                            },
                        );

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
                            _ => Err(anyhow!(
                                "Unexpected ECDSA curve {:?}",
                                ecc_attrs.curve()
                            )),
                        }?;

                        let key_type = sshkeys::KeyType::from_name(name)?;

                        let kind = sshkeys::PublicKeyKind::Ecdsa(
                            sshkeys::EcdsaPublicKey {
                                curve,
                                key: ecc.data().to_vec(),
                                sk_application: None,
                            },
                        );

                        Ok((key_type, kind))
                    }
                    _ => Err(anyhow!(
                        "Unexpected EccType {:?}",
                        ecc_attrs.ecc_type()
                    )),
                }
            } else {
                Err(anyhow!("Unexpected Algo in EccPub {:?}", ecc))
            }
        }
        _ => Err(anyhow!("Unexpected PublicKeyMaterial type {:?}", pkm)),
    }?;

    let pk = sshkeys::PublicKey {
        key_type,
        comment: Some(cardno),
        kind,
    };

    Ok(pk)
}

/// Return a String representation of an ssh public key, in a form like:
/// "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAuTuxILMTvzTIRvaRqqUM3aRDoEBgz/JAoWKsD1ECxy cardno:FFFE:43194240"
pub(crate) fn get_ssh_pubkey_string(
    pkm: &PublicKeyMaterial,
    ident: String,
) -> Result<String> {
    let pk = get_ssh_pubkey(pkm, ident)?;

    let mut v = vec![];
    pk.write(&mut v)?;

    let s = String::from_utf8_lossy(&v).to_string();

    Ok(s.trim().into())
}
