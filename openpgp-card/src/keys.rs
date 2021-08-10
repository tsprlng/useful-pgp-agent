// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generate and import keys

use anyhow::{anyhow, Result};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::apdu::command::Command;
use crate::apdu::commands;
use crate::card_app::CardApp;
use crate::errors::OpenpgpCardError;
use crate::parse::algo_info::AlgoInfo;
use crate::tlv::{tag::Tag, Tlv, TlvEntry};
use crate::{apdu, Curve, EccPub, PublicKeyMaterial, RSAPub};
use crate::{
    tlv, Algo, CardUploadableKey, EccAttrs, EccKey, KeyType,
    PrivateKeyMaterial, RSAKey, RsaAttrs,
};

/// `gen_key_with_metadata` calculates the fingerprint for a public key
/// data object
pub(crate) fn gen_key_with_metadata(
    card_app: &mut CardApp,
    fp_from_pub: fn(
        &PublicKeyMaterial,
        SystemTime,
        KeyType,
        &Algo,
    ) -> Result<[u8; 20]>,
    key_type: KeyType,
    algo: Option<&Algo>,
) -> Result<(PublicKeyMaterial, u32), OpenpgpCardError> {
    // set algo on card if it's Some
    if let Some(algo) = algo {
        println!("set algo {:?}", algo);
        card_app
            .set_algorithm_attributes(key_type, algo)?
            .check_ok()?;
        println!("set algo done");
    }

    // algo
    let ard = card_app.get_app_data()?; // no caching, here!
    let algo = CardApp::get_algorithm_attributes(&ard, key_type)?;

    // generate key
    let tlv = gen_key(card_app, key_type)?;

    // derive pubkey
    let pubkey = tlv_to_pubkey(&tlv, &algo)?;

    log::trace!("public {:x?}", pubkey);

    // set creation time
    let time = SystemTime::now();

    // Store creation timestamp (unix time format, limited to u32)
    let ts = time
        .duration_since(UNIX_EPOCH)
        .map_err(|e| OpenpgpCardError::InternalError(anyhow!(e)))?
        .as_secs() as u32;

    card_app.set_creation_time(ts, key_type)?.check_ok()?;

    // calculate/store fingerprint
    let fp = fp_from_pub(&pubkey, time, key_type, &algo)?;
    card_app.set_fingerprint(fp, key_type)?.check_ok()?;

    Ok((pubkey, ts))
}

fn tlv_to_pubkey(tlv: &Tlv, algo: &Algo) -> Result<PublicKeyMaterial> {
    let n = tlv.find(&Tag::new(vec![0x81]));
    let v = tlv.find(&Tag::new(vec![0x82]));

    let ec = tlv.find(&Tag::new(vec![0x86]));

    match (n, v, ec) {
        (Some(n), Some(v), None) => {
            let rsa = RSAPub {
                n: n.serialize(),
                v: v.serialize(),
            };

            Ok(PublicKeyMaterial::R(rsa))
        }
        (None, None, Some(ec)) => {
            let data = ec.serialize();
            println!("EC --- len {}, data {:x?}", data.len(), data);

            Ok(PublicKeyMaterial::E(EccPub {
                data,
                algo: algo.clone(),
            }))
        }

        (_, _, _) => {
            unimplemented!()
        }
    }
}

pub(crate) fn gen_key(
    card_app: &mut CardApp,
    key_type: KeyType,
) -> Result<Tlv, OpenpgpCardError> {
    println!("gen key for {:?}", key_type);

    // generate key
    let crt = get_crt(key_type)?;
    let gen_key_cmd = commands::gen_key(crt.serialize().to_vec());

    let card_client = card_app.card();

    let resp = apdu::send_command(card_client, gen_key_cmd, true)?;
    resp.check_ok()?;

    let tlv = Tlv::try_from(resp.data()?)?;

    Ok(tlv)
}

pub(crate) fn get_pub_key(
    card_app: &mut CardApp,
    key_type: KeyType,
) -> Result<PublicKeyMaterial, OpenpgpCardError> {
    println!("get pub key for {:?}", key_type);

    // algo
    let ard = card_app.get_app_data()?; // FIXME: caching
    let algo = CardApp::get_algorithm_attributes(&ard, key_type)?;

    // get public key
    let crt = get_crt(key_type)?;
    let get_pub_key_cmd = commands::get_pub_key(crt.serialize().to_vec());

    let resp = apdu::send_command(card_app.card(), get_pub_key_cmd, true)?;
    resp.check_ok()?;

    let tlv = Tlv::try_from(resp.data()?)?;
    let pubkey = tlv_to_pubkey(&tlv, &algo)?;

    Ok(pubkey)
}

/// Upload an explicitly selected Key to the card as a specific KeyType.
///
/// The client needs to make sure that the key is suitable for `key_type`.
pub(crate) fn upload_key(
    card_app: &mut CardApp,
    key: Box<dyn CardUploadableKey>,
    key_type: KeyType,
    algo_list: Option<AlgoInfo>,
) -> Result<(), OpenpgpCardError> {
    let (algo, key_cmd) = match key.get_key()? {
        PrivateKeyMaterial::R(rsa_key) => {
            // RSA bitsize
            // (round up to 4-bytes, in case the key has 8+ leading zeros)
            let rsa_bits =
                (((rsa_key.get_n().len() * 8 + 31) / 32) * 32) as u16;

            // Get suitable algorithm from card's list, or try to derive it
            // from the current algo settings on the card
            let rsa_attrs = if let Some(algo_list) = algo_list {
                get_card_algo_rsa(algo_list, key_type, rsa_bits)
            } else {
                // Get current settings for this KeyType and adjust the bit
                // length.

                // FIXME: caching?
                let ard = card_app.get_app_data()?;

                let algo = CardApp::get_algorithm_attributes(&ard, key_type)?;

                if let Algo::Rsa(mut rsa) = algo {
                    rsa.len_n = rsa_bits;

                    rsa
                } else {
                    // We don't expect a card to support non-RSA algos when
                    // it can't provide an algorithm list.
                    unimplemented!("Unexpected: current algo is not RSA");
                }
            };

            let key_cmd = rsa_key_cmd(key_type, rsa_key, &rsa_attrs)?;

            (Algo::Rsa(rsa_attrs), key_cmd)
        }
        PrivateKeyMaterial::E(ecc_key) => {
            // Initially there were checks of the following form, here.
            // However, some cards seem to report erroneous
            // information about supported algorithms.
            // (e.g. Yk5 reports support of EdDSA over Cv25519/Ed25519,
            // but not ECDH).

            // if !check_card_algo_*(algo_list.unwrap(),
            //                       key_type, ecc_key.get_oid()) {
            //     // Error
            // }

            let algo = Algo::Ecc(EccAttrs {
                ecc_type: ecc_key.get_type(),
                curve: Curve::from(ecc_key.get_oid()).expect("unepected oid"),
                import_format: None,
            });

            let key_cmd = ecc_key_cmd(ecc_key, key_type)?;

            (algo, key_cmd)
        }
    };

    copy_key_to_card(
        card_app,
        key_type,
        key.get_ts(),
        key.get_fp(),
        &algo,
        key_cmd,
    )?;

    Ok(())
}

// FIXME: refactor, these checks currently pointlessly duplicate code
fn get_card_algo_rsa(
    algo_list: AlgoInfo,
    key_type: KeyType,
    rsa_bits: u16,
) -> RsaAttrs {
    // Find suitable algorithm parameters (from card's list of algorithms).
    // FIXME: handle "no list available" (older cards?)
    // (Current algo parameters of the key slot should be used, then (?))

    // Get Algos for this keytype
    let keytype_algos: Vec<_> = algo_list.get_by_keytype(key_type);
    // Get RSA algo attributes
    let rsa_algos: Vec<_> = keytype_algos
        .iter()
        .map(|a| if let Algo::Rsa(r) = a { Some(r) } else { None })
        .flatten()
        .collect();

    // Filter card algorithms by rsa bitlength of the key we want to upload
    let algo: Vec<_> =
        rsa_algos.iter().filter(|&a| a.len_n == rsa_bits).collect();

    // FIXME: handle error if no algo found
    let algo = *algo[0];

    algo.clone()
}

// FIXME: refactor, these checks currently pointlessly duplicate code
fn check_card_algo_ecdh(
    algo_list: AlgoInfo,
    key_type: KeyType,
    oid: &[u8],
) -> bool {
    // Find suitable algorithm parameters (from card's list of algorithms).
    // FIXME: handle "no list available" (older cards?)
    // (Current algo parameters of the key slot should be used, then (?))

    // Get Algos for this keytype
    let keytype_algos: Vec<_> = algo_list.get_by_keytype(key_type);

    // Get attributes
    let ecdh_algos: Vec<_> = keytype_algos
        .iter()
        .map(|a| if let Algo::Ecc(e) = a { Some(e) } else { None })
        .flatten()
        .collect();

    // Check if this OID exists in the supported algorithms
    ecdh_algos.iter().any(|e| e.oid() == oid)
}

// FIXME: refactor, these checks currently pointlessly duplicate code
fn check_card_algo_ecdsa(
    algo_list: AlgoInfo,
    key_type: KeyType,
    oid: &[u8],
) -> bool {
    // Find suitable algorithm parameters (from card's list of algorithms).
    // FIXME: handle "no list available" (older cards?)
    // (Current algo parameters of the key slot should be used, then (?))

    // Get Algos for this keytype
    let keytype_algos: Vec<_> = algo_list.get_by_keytype(key_type);

    // Get attributes
    let ecdsa_algos: Vec<_> = keytype_algos
        .iter()
        .map(|a| if let Algo::Ecc(e) = a { Some(e) } else { None })
        .flatten()
        .collect();

    // Check if this OID exists in the supported algorithms
    ecdsa_algos.iter().any(|e| e.oid() == oid)
}

// FIXME: refactor, these checks currently pointlessly duplicate code
fn check_card_algo_eddsa(
    algo_list: AlgoInfo,
    key_type: KeyType,
    oid: &[u8],
) -> bool {
    // Find suitable algorithm parameters (from card's list of algorithms).
    // FIXME: handle "no list available" (older cards?)
    // (Current algo parameters of the key slot should be used, then (?))

    // Get Algos for this keytype
    let keytype_algos: Vec<_> = algo_list.get_by_keytype(key_type);

    // Get attributes
    let eddsa_algos: Vec<_> = keytype_algos
        .iter()
        .map(|a| if let Algo::Ecc(e) = a { Some(e) } else { None })
        .flatten()
        .collect();

    // Check if this OID exists in the supported algorithms
    eddsa_algos.iter().any(|e| e.oid() == oid)
}

fn ecc_key_cmd(
    ecc_key: Box<dyn EccKey>,
    key_type: KeyType,
) -> Result<Command, OpenpgpCardError> {
    let scalar_data = ecc_key.get_scalar();
    let scalar_len = scalar_data.len() as u8;

    // 1) "Control Reference Template"
    let crt = get_crt(key_type)?;

    // 2) "Cardholder private key template" (7F48)
    let cpkt = Tlv(Tag(vec![0x7F, 0x48]), TlvEntry::S(vec![0x92, scalar_len]));

    // 3) "Cardholder private key" (5F48)
    let cpk = Tlv(Tag(vec![0x5F, 0x48]), TlvEntry::S(scalar_data.to_vec()));

    // "Extended header list (DO 4D)" (contains the three inner TLV)
    let ehl = Tlv(Tag(vec![0x4d]), TlvEntry::C(vec![crt, cpkt, cpk]));

    // The key import uses a PUT DATA command with odd INS (DB) and an
    // Extended header list (DO 4D) as described in ISO 7816-8

    Ok(Command::new(
        0x00,
        0xDB,
        0x3F,
        0xFF,
        ehl.serialize().to_vec(),
    ))
}

fn get_crt(key_type: KeyType) -> Result<Tlv, OpenpgpCardError> {
    // "Control Reference Template" (0xB8 | 0xB6 | 0xA4)
    let tag = match key_type {
        KeyType::Decryption => 0xB8,
        KeyType::Signing => 0xB6,
        KeyType::Authentication => 0xA4,
        _ => {
            return Err(OpenpgpCardError::InternalError(anyhow!(
                "Unexpected KeyType"
            )))
        }
    };
    Ok(Tlv(Tag(vec![tag]), TlvEntry::S(vec![])))
}

fn rsa_key_cmd(
    key_type: KeyType,
    rsa_key: Box<dyn RSAKey>,
    algo_attrs: &RsaAttrs,
) -> Result<Command, OpenpgpCardError> {
    // Assemble key command, which contains three sub-TLV:

    // 1) "Control Reference Template"
    let crt = get_crt(key_type)?;

    // 2) "Cardholder private key template" (7F48)
    // "describes the input and the length of the content of the following DO"

    // collect the value for this DO
    let mut value = vec![];

    // Length of e in bytes, rounding up from the bit value in algo.
    let len_e_bytes = ((algo_attrs.len_e + 7) / 8) as u8;

    value.push(0x91);
    // len_e in bytes has a value of 3-4, it doesn't need TLV encoding
    value.push(len_e_bytes);

    // len_p and len_q are len_n/2 (value from card algorithm list).
    // transform unit from bits to bytes.
    let len_p_bytes: u16 = algo_attrs.len_n / 2 / 8;
    let len_q_bytes: u16 = algo_attrs.len_n / 2 / 8;

    value.push(0x92);
    // len p in bytes, TLV-encoded
    value.extend_from_slice(&tlv::tlv_encode_length(len_p_bytes));

    value.push(0x93);
    // len q in bytes, TLV-encoded
    value.extend_from_slice(&tlv::tlv_encode_length(len_q_bytes));

    let cpkt = Tlv(Tag(vec![0x7F, 0x48]), TlvEntry::S(value));

    // 3) "Cardholder private key" (5F48)
    //
    // "represents a concatenation of the key data elements according to
    // the definitions in DO '7F48'."
    let mut keydata = Vec::new();

    let e_as_bytes = rsa_key.get_e();

    // Push e, padded to length with zero bytes from the left
    for _ in e_as_bytes.len()..(len_e_bytes as usize) {
        keydata.push(0);
    }
    keydata.extend(e_as_bytes);

    // FIXME: do p/q need to be padded from the left when many leading
    // bits are zero?
    keydata.extend(rsa_key.get_p().iter());
    keydata.extend(rsa_key.get_q().iter());

    let cpk = Tlv(Tag(vec![0x5F, 0x48]), TlvEntry::S(keydata));

    // "Extended header list (DO 4D)"
    let ehl = Tlv(Tag(vec![0x4d]), TlvEntry::C(vec![crt, cpkt, cpk]));

    // The key import uses a PUT DATA command with odd INS (DB) and an
    // Extended header list (DO 4D) as described in ISO 7816-8

    Ok(Command::new(
        0x00,
        0xDB,
        0x3F,
        0xFF,
        ehl.serialize().to_vec(),
    ))
}

fn copy_key_to_card(
    card_app: &mut CardApp,
    key_type: KeyType,
    ts: u32,
    fp: [u8; 20],
    algo: &Algo,
    key_cmd: Command,
) -> Result<(), OpenpgpCardError> {
    // Send all the commands

    // FIXME: Only write algo attributes to the card if "extended
    // capabilities" show that they are changeable!
    card_app
        .set_algorithm_attributes(key_type, algo)?
        .check_ok()?;

    apdu::send_command(card_app.card(), key_cmd, false)?.check_ok()?;

    card_app.set_fingerprint(fp, key_type)?.check_ok()?;

    card_app.set_creation_time(ts, key_type)?.check_ok()?;

    Ok(())
}
