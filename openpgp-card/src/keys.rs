// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Generate and import keys

use anyhow::{anyhow, Result};
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::algorithm::{Algo, AlgoInfo, Curve, EccAttrs, RsaAttrs};
use crate::apdu::command::Command;
use crate::apdu::commands;
use crate::card_app::CardApp;
use crate::card_do::{
    ApplicationRelatedData, ExCapFeatures, Fingerprint, KeyGenerationTime,
};
use crate::crypto_data::{
    CardUploadableKey, EccKey, EccPub, PrivateKeyMaterial, PublicKeyMaterial,
    RSAKey, RSAPub,
};
use crate::tlv::{length::tlv_encode_length, value::Value, Tlv};
use crate::Error;
use crate::{apdu, KeyType};

/// Generate asymmetric key pair on the card.
///
/// This is a convenience wrapper around gen_key() that:
/// - sets algorithm attributes (if not None)
/// - generates a key pair on the card
/// - sets the creation time on the card to the current host time
/// - calculates fingerprint for the key and sets it on the card
///
/// `fp_from_pub` calculates the fingerprint for a public key data object and
/// creation timestamp
pub(crate) fn gen_key_with_metadata(
    card_app: &mut CardApp,
    fp_from_pub: fn(
        &PublicKeyMaterial,
        KeyGenerationTime,
        KeyType,
    ) -> Result<Fingerprint, Error>,
    key_type: KeyType,
    algo: Option<&Algo>,
) -> Result<(PublicKeyMaterial, KeyGenerationTime), Error> {
    // set algo on card if it's Some
    if let Some(algo) = algo {
        card_app.set_algorithm_attributes(key_type, algo)?;
    }

    // algo
    let ard = card_app.get_application_related_data()?; // no caching, here!
    let algo = ard.get_algorithm_attributes(key_type)?;

    // generate key
    let tlv = generate_asymmetric_key_pair(card_app, key_type)?;

    // derive pubkey
    let pubkey = tlv_to_pubkey(&tlv, &algo)?;

    log::trace!("public {:x?}", pubkey);

    // set creation time
    let time = SystemTime::now();

    // Store creation timestamp (unix time format, limited to u32)
    let ts = time
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::InternalError(anyhow!(e)))?
        .as_secs() as u32;

    let ts = ts.into();

    card_app.set_creation_time(ts, key_type)?;

    // calculate/store fingerprint
    let fp = fp_from_pub(&pubkey, ts, key_type)?;
    card_app.set_fingerprint(fp, key_type)?;

    Ok((pubkey, ts))
}

/// Transform a public key Tlv from the card into PublicKeyMaterial
fn tlv_to_pubkey(tlv: &Tlv, algo: &Algo) -> Result<PublicKeyMaterial> {
    let n = tlv.find(&[0x81].into());
    let v = tlv.find(&[0x82].into());

    let ec = tlv.find(&[0x86].into());

    match (n, v, ec) {
        (Some(n), Some(v), None) => {
            let rsa = RSAPub::new(n.serialize(), v.serialize());
            Ok(PublicKeyMaterial::R(rsa))
        }
        (None, None, Some(ec)) => {
            let data = ec.serialize();
            log::trace!("EC --- len {}, data {:x?}", data.len(), data);

            let ecc = EccPub::new(data, algo.clone());
            Ok(PublicKeyMaterial::E(ecc))
        }

        (_, _, _) => Err(anyhow!(
            "Unexpected public key material from card {:?}",
            tlv
        )),
    }
}

/// 7.2.14 GENERATE ASYMMETRIC KEY PAIR
///
/// This runs the low level key generation primitive on the card.
/// (This does not set algorithm attributes, creation time or fingerprint)
pub(crate) fn generate_asymmetric_key_pair(
    card_app: &mut CardApp,
    key_type: KeyType,
) -> Result<Tlv, Error> {
    // generate key
    let crt = get_crt(key_type)?;
    let gen_key_cmd = commands::gen_key(crt.serialize().to_vec());

    let card_client = card_app.get_card_client();

    let resp = apdu::send_command(card_client, gen_key_cmd, true)?;
    resp.check_ok()?;

    let tlv = Tlv::try_from(resp.data()?)?;

    Ok(tlv)
}

/// Get the public key material for a key from the card.
///
/// ("Returns the public key of an asymmetric key pair previously generated
/// in the card or imported")
///
/// (See 7.2.14 GENERATE ASYMMETRIC KEY PAIR)
pub(crate) fn get_pub_key(
    card_app: &mut CardApp,
    key_type: KeyType,
) -> Result<PublicKeyMaterial, Error> {
    // get current algo
    let ard = card_app.get_application_related_data()?; // FIXME: caching
    let algo = ard.get_algorithm_attributes(key_type)?;

    // get public key
    let crt = get_crt(key_type)?;
    let get_pub_key_cmd = commands::get_pub_key(crt.serialize().to_vec());

    let resp =
        apdu::send_command(card_app.get_card_client(), get_pub_key_cmd, true)?;
    resp.check_ok()?;

    let tlv = Tlv::try_from(resp.data()?)?;
    let pubkey = tlv_to_pubkey(&tlv, &algo)?;

    Ok(pubkey)
}

/// Import private key material to the card as a specific KeyType.
///
/// If the key is suitable for `key_type`, an Error is returned (either
/// caused by checks before attempting to upload the key to the card, or by
/// an error that the card reports during an attempt to upload the key).
pub(crate) fn key_import(
    card_app: &mut CardApp,
    key: Box<dyn CardUploadableKey>,
    key_type: KeyType,
    algo_list: Option<AlgoInfo>,
) -> Result<(), Error> {
    // FIXME: caching?
    let ard = card_app.get_application_related_data()?;

    let (algo, key_cmd) = match key.get_key()? {
        PrivateKeyMaterial::R(rsa_key) => {
            let rsa_attrs =
                determine_rsa_attrs(&ard, &*rsa_key, key_type, algo_list)?;

            let key_cmd = rsa_key_import_cmd(key_type, rsa_key, &rsa_attrs)?;

            (Algo::Rsa(rsa_attrs), key_cmd)
        }
        PrivateKeyMaterial::E(ecc_key) => {
            let ecc_attrs =
                determine_ecc_attrs(&*ecc_key, key_type, algo_list)?;

            let key_cmd = ecc_key_import_cmd(ecc_key, key_type)?;

            (Algo::Ecc(ecc_attrs), key_cmd)
        }
    };

    let fp = key.get_fp()?;

    // Now that we have marshalled all necessary information, perform all
    // set-operations on the card.

    // Only set algo attrs if "Extended Capabilities" lists the feature
    if ard
        .get_extended_capabilities()?
        .features()
        .contains(&ExCapFeatures::AlgoAttrsChangeable)
    {
        card_app.set_algorithm_attributes(key_type, &algo)?;
    }

    apdu::send_command(card_app.get_card_client(), key_cmd, false)?
        .check_ok()?;
    card_app.set_fingerprint(fp, key_type)?;
    card_app.set_creation_time(key.get_ts(), key_type)?;

    Ok(())
}

/// Derive RsaAttrs for `rsa_key`.
///
/// If available, via lookup in `algo_list`, otherwise the current
/// algorithm attributes are loaded and checked. If neither method yields a
/// result, we 'guess' the RsaAttrs setting.
fn determine_rsa_attrs(
    ard: &ApplicationRelatedData,
    rsa_key: &dyn RSAKey,
    key_type: KeyType,
    algo_list: Option<AlgoInfo>,
) -> Result<RsaAttrs> {
    // RSA bitsize
    // (round up to 4-bytes, in case the key has 8+ leading zeros)
    let rsa_bits = (((rsa_key.get_n().len() * 8 + 31) / 32) * 32) as u16;

    // Figure out suitable RSA algorithm parameters:

    // Does the card offer a list of algorithms?
    let rsa_attrs = if let Some(algo_list) = algo_list {
        // Yes -> Look up the parameters for key_type and rsa_bits.
        // (Or error, if the list doesn't have an entry for rsa_bits)
        get_card_algo_rsa(algo_list, key_type, rsa_bits)?
    } else {
        // No -> Get the current algorithm attributes for key_type.

        let algo = ard.get_algorithm_attributes(key_type)?;

        // Is the algorithm on the card currently set to RSA?
        if let Algo::Rsa(rsa) = algo {
            // If so, use the algorithm parameters from the card and
            // adjust the bit length based on the user-provided key.
            RsaAttrs::new(rsa_bits, rsa.len_e(), rsa.import_format())
        } else {
            // The card doesn't provide an algorithm list, and the
            // current algorithm on the card is not RSA.
            //
            // So we 'guess' a value for len_e (some cards only
            // support 17, others only support 32).

            // [If this approach turns out to be insufficient, we
            // need to determine the model of the card and use a
            // list of which RSA parameters that model of card
            // supports]

            RsaAttrs::new(rsa_bits, 32, 0)
        }
    };

    Ok(rsa_attrs)
}

/// Derive EccAttrs from `ecc_key`, check if the OID is listed in algo_list.
fn determine_ecc_attrs(
    ecc_key: &dyn EccKey,
    key_type: KeyType,
    algo_list: Option<AlgoInfo>,
) -> Result<EccAttrs> {
    // If we have an algo_list, refuse upload if oid is not listed
    if let Some(algo_list) = algo_list {
        let oid = ecc_key.get_oid();
        if !check_card_algo_ecc(algo_list, key_type, oid) {
            // If oid is not in algo_list, return error.
            return Err(anyhow!(
                "Oid {:?} unsupported according to algo_list",
                oid
            ));
        }
    }

    // (Precisely looking up ECC algorithms in the card's "Algorithm
    // Information" seems to do more harm than good, so we don't do it.
    // Some cards report erroneous information about supported algorithms
    // - e.g. Yubikey 5 reports support for EdDSA over Cv25519 and
    // Ed25519, but not ECDH).

    Ok(EccAttrs::new(
        ecc_key.get_type(),
        Curve::try_from(ecc_key.get_oid())?,
        None,
    ))
}

/// Look up RsaAttrs parameters in algo_list based on key_type and rsa_bits
fn get_card_algo_rsa(
    algo_list: AlgoInfo,
    key_type: KeyType,
    rsa_bits: u16,
) -> Result<RsaAttrs, Error> {
    // Find suitable algorithm parameters (from card's list of algorithms).

    // Get Algos for this keytype
    let keytype_algos: Vec<_> = algo_list.get_by_keytype(key_type);
    // Get RSA algo attributes
    let rsa_algos: Vec<_> = keytype_algos
        .iter()
        .map(|a| if let Algo::Rsa(r) = a { Some(r) } else { None })
        .flatten()
        .collect();

    // Filter card algorithms by rsa bitlength of the key we want to upload
    let algo: Vec<_> = rsa_algos
        .iter()
        .filter(|&a| a.len_n() == rsa_bits)
        .collect();

    // Did we find a suitable algorithm entry?
    if !algo.is_empty() {
        Ok((*algo[0]).clone())
    } else {
        // RSA with this bit length is not in algo_list
        return Err(anyhow!(
            "RSA {} unsupported according to algo_list",
            rsa_bits
        )
        .into());
    }
}

/// Check if `oid` is supported for `key_type` in algo_list.
fn check_card_algo_ecc(
    algo_list: AlgoInfo,
    key_type: KeyType,
    oid: &[u8],
) -> bool {
    // Find suitable algorithm parameters (from card's list of algorithms).

    // Get Algos for this keytype
    let keytype_algos: Vec<_> = algo_list.get_by_keytype(key_type);

    // Get attributes
    let ecc_algos: Vec<_> = keytype_algos
        .iter()
        .map(|a| if let Algo::Ecc(e) = a { Some(e) } else { None })
        .flatten()
        .collect();

    // Check if this OID exists in the algorithm information for key_type
    ecc_algos.iter().any(|e| e.oid() == oid)
}

/// Create command for RSA key import
fn rsa_key_import_cmd(
    key_type: KeyType,
    rsa_key: Box<dyn RSAKey>,
    rsa_attrs: &RsaAttrs,
) -> Result<Command, Error> {
    // Assemble key command, which contains three sub-TLV:

    // 1) "Control Reference Template"
    let crt = get_crt(key_type)?;

    // 2) "Cardholder private key template" (7F48)
    // "describes the input and the length of the content of the following DO"

    // collect the value for this DO
    let mut value = vec![];

    // Length of e in bytes, rounding up from the bit value in algo.
    let len_e_bytes = ((rsa_attrs.len_e() + 7) / 8) as u8;

    value.push(0x91);
    // len_e in bytes has a value of 3-4, it doesn't need TLV encoding
    value.push(len_e_bytes);

    // len_p and len_q are len_n/2 (value from card algorithm list).
    // transform unit from bits to bytes.
    let len_p_bytes: u16 = rsa_attrs.len_n() / 2 / 8;
    let len_q_bytes: u16 = rsa_attrs.len_n() / 2 / 8;

    value.push(0x92);
    // len p in bytes, TLV-encoded
    value.extend_from_slice(&tlv_encode_length(len_p_bytes));

    value.push(0x93);
    // len q in bytes, TLV-encoded
    value.extend_from_slice(&tlv_encode_length(len_q_bytes));

    let cpkt = Tlv::new([0x7F, 0x48], Value::S(value));

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

    let cpk = Tlv::new([0x5F, 0x48], Value::S(keydata));

    // "Extended header list (DO 4D)"
    let ehl = Tlv::new([0x4d], Value::C(vec![crt, cpkt, cpk]));

    // key import command
    Ok(commands::key_import(ehl.serialize().to_vec()))
}

/// Create command for ECC key import
fn ecc_key_import_cmd(
    ecc_key: Box<dyn EccKey>,
    key_type: KeyType,
) -> Result<Command, Error> {
    let scalar_data = ecc_key.get_scalar();
    let scalar_len = scalar_data.len() as u8;

    // 1) "Control Reference Template"
    let crt = get_crt(key_type)?;

    // 2) "Cardholder private key template" (7F48)
    let cpkt = Tlv::new([0x7F, 0x48], Value::S(vec![0x92, scalar_len]));

    // 3) "Cardholder private key" (5F48)
    let cpk = Tlv::new([0x5F, 0x48], Value::S(scalar_data.to_vec()));

    // "Extended header list (DO 4D)" (contains the three inner TLV)
    let ehl = Tlv::new([0x4d], Value::C(vec![crt, cpkt, cpk]));

    // key import command
    Ok(commands::key_import(ehl.serialize().to_vec()))
}

/// Get "Control Reference Template" Tlv for `key_type`
fn get_crt(key_type: KeyType) -> Result<Tlv, Error> {
    // "Control Reference Template" (0xB8 | 0xB6 | 0xA4)
    let tag = match key_type {
        KeyType::Decryption => 0xB8,
        KeyType::Signing => 0xB6,
        KeyType::Authentication => 0xA4,
        _ => return Err(Error::InternalError(anyhow!("Unexpected KeyType"))),
    };
    Ok(Tlv::new([tag], Value::S(vec![])))
}
