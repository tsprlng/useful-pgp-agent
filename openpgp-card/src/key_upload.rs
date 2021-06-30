// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Result};

use crate::{KeyType, OpenPGPCardAdmin, tlv,
            CardUploadableKey, EccKey, RSAKey, EccType, PrivateKeyMaterial};
use crate::apdu;
use crate::apdu::commands;
use crate::apdu::command::Command;
use crate::apdu::Le;
use crate::parse::algo_attrs::{Algo, RsaAttrs};
use crate::parse::algo_info::AlgoInfo;
use crate::tlv::{Tlv, TlvEntry, tag::Tag};
use crate::errors::OpenpgpCardError;


/// Upload an explicitly selected Key to the card as a specific KeyType.
///
/// The client needs to make sure that the key is suitable for `key_type`.
pub(crate) fn upload_key(
    oca: &OpenPGPCardAdmin,
    key: Box<dyn CardUploadableKey>,
    key_type: KeyType,
) -> Result<(), OpenpgpCardError> {
    // FIXME: the list of algorithms is retrieved multiple times, it should
    // be cached
    let algo_list = oca.list_supported_algo()?;

    let (algo_cmd, key_cmd) =
        match key.get_key()? {
            PrivateKeyMaterial::R(rsa_key) => {
                // RSA bitsize
                // (round up to 4-bytes, in case the key has 8+ leading zeros)
                let rsa_bits =
                    (((rsa_key.get_n().len() * 8 + 31) / 32) * 32) as u16;

                // FIXME: deal with absence of algo list (unwrap!)
                // Get suitable algorithm from card's list
                let algo = get_card_algo_rsa(algo_list.unwrap(), key_type, rsa_bits);

                let algo_cmd = rsa_algo_attrs_cmd(key_type, rsa_bits, &algo)?;
                let key_cmd = rsa_key_cmd(key_type, rsa_key, &algo)?;

                // Return commands
                (algo_cmd, key_cmd)
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

                let algo_cmd = ecc_algo_attrs_cmd(key_type,
                                                  ecc_key.get_oid(),
                                                  ecc_key.get_type());

                let key_cmd = ecc_key_cmd(ecc_key, key_type)?;

                (algo_cmd, key_cmd)
            }
        };

    copy_key_to_card(oca, key_type, key.get_ts(), key.get_fp(), algo_cmd,
                     key_cmd)?;

    Ok(())
}

// FIXME: refactor, these checks currently pointlessly duplicate code
fn get_card_algo_rsa(algo_list: AlgoInfo, key_type: KeyType, rsa_bits: u16)
                     -> RsaAttrs {

    // Find suitable algorithm parameters (from card's list of algorithms).
    // FIXME: handle "no list available" (older cards?)
    // (Current algo parameters of the key slot should be used, then (?))

    // Get Algos for this keytype
    let keytype_algos: Vec<_> = algo_list.get_by_keytype(key_type);
    // Get RSA algo attributes
    let rsa_algos: Vec<_> = keytype_algos.iter()
        .map(|a|
            {
                if let Algo::Rsa(r) = a {
                    Some(r)
                } else {
                    None
                }
            })
        .flatten()
        .collect();

    // Filter card algorithms by rsa bitlength of the key we want to upload
    let algo: Vec<_> = rsa_algos.iter()
        .filter(|&a| a.len_n == rsa_bits)
        .collect();

    // FIXME: handle error if no algo found
    let algo = *algo[0];

    algo.clone()
}

// FIXME: refactor, these checks currently pointlessly duplicate code
fn check_card_algo_ecdh(algo_list: AlgoInfo, key_type: KeyType, oid: &[u8]) -> bool {
    // Find suitable algorithm parameters (from card's list of algorithms).
    // FIXME: handle "no list available" (older cards?)
    // (Current algo parameters of the key slot should be used, then (?))

    // Get Algos for this keytype
    let keytype_algos: Vec<_> = algo_list.get_by_keytype(key_type);

    // Get attributes
    let ecdh_algos: Vec<_> = keytype_algos.iter()
        .map(|a|
            {
                if let Algo::Ecdh(e) = a {
                    Some(e)
                } else {
                    None
                }
            })
        .flatten()
        .collect();

    // Check if this OID exists in the supported algorithms
    ecdh_algos.iter().any(|e| e.oid == oid)
}

// FIXME: refactor, these checks currently pointlessly duplicate code
fn check_card_algo_ecdsa(algo_list: AlgoInfo,
                         key_type: KeyType, oid: &[u8]) -> bool {
    // Find suitable algorithm parameters (from card's list of algorithms).
    // FIXME: handle "no list available" (older cards?)
    // (Current algo parameters of the key slot should be used, then (?))

    // Get Algos for this keytype
    let keytype_algos: Vec<_> = algo_list.get_by_keytype(key_type);

    // Get attributes
    let ecdsa_algos: Vec<_> = keytype_algos.iter()
        .map(|a|
            {
                if let Algo::Ecdsa(e) = a {
                    Some(e)
                } else {
                    None
                }
            })
        .flatten()
        .collect();

    // Check if this OID exists in the supported algorithms
    ecdsa_algos.iter().any(|e| e.oid == oid)
}

// FIXME: refactor, these checks currently pointlessly duplicate code
fn check_card_algo_eddsa(algo_list: AlgoInfo,
                         key_type: KeyType, oid: &[u8]) -> bool {
    // Find suitable algorithm parameters (from card's list of algorithms).
    // FIXME: handle "no list available" (older cards?)
    // (Current algo parameters of the key slot should be used, then (?))

    // Get Algos for this keytype
    let keytype_algos: Vec<_> = algo_list.get_by_keytype(key_type);

    // Get attributes
    let eddsa_algos: Vec<_> = keytype_algos.iter()
        .map(|a|
            {
                if let Algo::Eddsa(e) = a {
                    Some(e)
                } else {
                    None
                }
            })
        .flatten()
        .collect();

    // Check if this OID exists in the supported algorithms
    eddsa_algos.iter().any(|e| e.oid == oid)
}

fn ecc_key_cmd(ecc_key: Box<dyn EccKey>, key_type: KeyType)
               -> Result<Command, OpenpgpCardError> {
    let scalar_data = ecc_key.get_scalar();
    let scalar_len = scalar_data.len() as u8;

    // 1) "Control Reference Template"
    let crt = get_crt(key_type)?;

    // 2) "Cardholder private key template" (7F48)
    let cpkt = Tlv(Tag(vec![0x7F, 0x48]),
                   TlvEntry::S(vec![0x92, scalar_len]));

    // 3) "Cardholder private key" (5F48)
    let cpk = Tlv(Tag(vec![0x5F, 0x48]), TlvEntry::S(scalar_data.to_vec()));


    // "Extended header list (DO 4D)" (contains the three inner TLV)
    let ehl = Tlv(Tag(vec![0x4d]),
                  TlvEntry::C(vec![crt, cpkt, cpk]));


    // The key import uses a PUT DATA command with odd INS (DB) and an
    // Extended header list (DO 4D) as described in ISO 7816-8

    Ok(Command::new(0x00, 0xDB, 0x3F, 0xFF,
                    ehl.serialize().to_vec()))
}

fn get_crt(key_type: KeyType) -> Result<Tlv, OpenpgpCardError> {
    // "Control Reference Template" (0xB8 | 0xB6 | 0xA4)
    let tag = match key_type {
        KeyType::Decryption => 0xB8,
        KeyType::Signing => 0xB6,
        KeyType::Authentication => 0xA4,
        _ => return Err(OpenpgpCardError::InternalError
            (anyhow!("Unexpected KeyType")))
    };
    Ok(Tlv(Tag(vec![tag]), TlvEntry::S(vec![])))
}

fn rsa_key_cmd(key_type: KeyType,
               rsa_key: Box<dyn RSAKey>,
               algo_attrs: &RsaAttrs) -> Result<Command, OpenpgpCardError> {

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

    Ok(Command::new(0x00, 0xDB, 0x3F, 0xFF,
                    ehl.serialize().to_vec()))
}

/// Set algorithm attributes [4.4.3.9 Algorithm Attributes]
fn rsa_algo_attrs_cmd(key_type: KeyType,
                      rsa_bits: u16,
                      algo_attrs: &RsaAttrs) ->
                      Result<Command> {

    // Algorithm ID (01 = RSA (Encrypt or Sign))
    let mut algo_attributes = vec![0x01];

    // Length of modulus n in bit
    algo_attributes.extend(rsa_bits.to_be_bytes());

    // Length of public exponent e in bit
    algo_attributes.push(0x00);
    algo_attributes.push(algo_attrs.len_e as u8);

    // Import-Format of private key
    // (This fn currently assumes import_format "00 = standard (e, p, q)")
    if algo_attrs.import_format != 0 {
        return Err(
            anyhow!("Unexpected RSA input format (only 0 is supported)"));
    }

    algo_attributes.push(algo_attrs.import_format);

    // Command to PUT the algorithm attributes
    Ok(commands::put_data(&[key_type.get_algorithm_tag()], algo_attributes))
}

/// Set algorithm attributes [4.4.3.9 Algorithm Attributes]
fn ecc_algo_attrs_cmd(key_type: KeyType, oid: &[u8], ecc_type: EccType)
                      -> Command {
    let algo_id = match ecc_type {
        EccType::EdDSA => 0x16,
        EccType::ECDH => 0x12,
        EccType::ECDSA => 0x13,
    };

    let mut algo_attributes = vec![algo_id];
    algo_attributes.extend(oid);
    // Leave Import-Format unset, for default (pg. 35)

    // Command to PUT the algorithm attributes
    commands::put_data(&[key_type.get_algorithm_tag()], algo_attributes)
}

fn copy_key_to_card(oca: &OpenPGPCardAdmin,
                    key_type: KeyType,
                    ts: u64,
                    fp: Vec<u8>,
                    algo_cmd: Command,
                    key_cmd: Command)
                    -> Result<(), OpenpgpCardError> {
    let fp_cmd =
        commands::put_data(&[key_type.get_fingerprint_put_tag()], fp);

    // Timestamp update
    let time_value: Vec<u8> = ts
        .to_be_bytes()
        .iter()
        .skip_while(|&&e| e == 0)
        .copied()
        .collect();

    let time_cmd =
        commands::put_data(&[key_type.get_timestamp_put_tag()], time_value);


    // Send all the commands

    let ext = Le::None; // FIXME?!

    // FIXME: Only write algo attributes to the card if "extended
    // capabilities" show that they are changeable!
    apdu::send_command(oca.card(), algo_cmd, ext, Some(oca))?.check_ok()?;

    apdu::send_command(oca.card(), key_cmd, ext, Some(oca))?.check_ok()?;
    apdu::send_command(oca.card(), fp_cmd, ext, Some(oca))?.check_ok()?;
    apdu::send_command(oca.card(), time_cmd, ext, Some(oca))?.check_ok()?;

    Ok(())
}
