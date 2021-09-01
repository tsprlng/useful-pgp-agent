// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CardApp exposes functionality of the "OpenPGP card" application.

use std::borrow::BorrowMut;
use std::convert::TryFrom;
use std::convert::TryInto;

use anyhow::{anyhow, Result};

use crate::algorithm::{Algo, AlgoInfo, AlgoSimple, RsaAttrs};
use crate::apdu::{commands, response::Response};
use crate::card_do::{
    ApplicationRelatedData, Cardholder, Fingerprint, KeyGenerationTime,
    PWStatus, SecuritySupportTemplate, Sex,
};
use crate::crypto_data::{
    CardUploadableKey, Cryptogram, EccType, Hash, PublicKeyMaterial,
};
use crate::errors::OpenpgpCardError;
use crate::tlv::{tag::Tag, value::Value, Tlv};
use crate::{apdu, keys, CardCaps, CardClientBox, KeyType};

/// Low-level access to OpenPGP card functionality.
///
/// Not many checks are performed here (e.g. for valid data lengths).
/// Such checks should be performed on a higher layer, if needed.
///
/// Also, no caching of data is done here. If necessary, caching should
/// be done on a higher layer.
pub struct CardApp {
    card_client: CardClientBox,
}

impl From<CardClientBox> for CardApp {
    fn from(card_client: CardClientBox) -> Self {
        Self { card_client }
    }
}

impl Into<CardClientBox> for CardApp {
    fn into(self) -> CardClientBox {
        self.card_client
    }
}

impl CardApp {
    /// Get the CardClient for this CardApp
    pub(crate) fn get_card_client(&mut self) -> &mut CardClientBox {
        &mut self.card_client
    }

    /// Initialize the CardCaps settings in the underlying CardClient
    /// from the data in `ard`.
    ///
    /// This should be done at an early point, soon after opening the card.
    pub fn init_caps(&mut self, ard: &ApplicationRelatedData) -> Result<()> {
        // Determine chaining/extended length support from card
        // metadata and cache this information in CardApp (as a
        // CardCaps)

        let mut ext_support = false;
        let mut chaining_support = false;

        if let Ok(hist) = ard.get_historical() {
            if let Some(cc) = hist.get_card_capabilities() {
                chaining_support = cc.get_command_chaining();
                ext_support = cc.get_extended_lc_le();
            }
        }

        let (max_cmd_bytes, max_rsp_bytes) =
            if let Ok(Some(eli)) = ard.get_extended_length_information() {
                (eli.max_command_bytes(), eli.max_response_bytes())
            } else {
                (255, 255)
            };

        let caps = CardCaps {
            ext_support,
            chaining_support,
            max_cmd_bytes,
            max_rsp_bytes,
        };

        self.card_client.init_caps(caps);

        Ok(())
    }

    // --- select ---

    /// Select the OpenPGP card application
    pub fn select(&mut self) -> Result<Response, OpenpgpCardError> {
        let select_openpgp = commands::select_openpgp();
        apdu::send_command(&mut self.card_client, select_openpgp, false)?
            .try_into()
    }

    // --- get data ---

    /// Get the "application related data" from the card.
    ///
    /// (This data should probably be cached in a higher layer. Some parts of
    /// it are needed regularly, and it does not usually change during
    /// normal use of a card.)
    pub fn get_app_data(&mut self) -> Result<ApplicationRelatedData> {
        let ad = commands::get_application_data();
        let resp = apdu::send_command(&mut self.card_client, ad, true)?;
        let value = Value::from(resp.data()?, true)?;

        log::debug!(" App data Value: {:x?}", value);

        Ok(ApplicationRelatedData(Tlv::new(Tag::from([0x6E]), value)))
    }

    /// Get data from "private use" DO.
    ///
    /// `num` must be between 1 and 4.
    pub fn get_private(&mut self, num: u8) -> Result<Vec<u8>> {
        assert!((1..=4).contains(&num));

        let cmd = commands::get_private_do(num);
        let resp = apdu::send_command(&mut self.card_client, cmd, true)?;

        Ok(resp.data()?.to_vec())
    }

    fn get_ca_fingerprints() {
        unimplemented!()
    }

    fn get_key_information() {
        unimplemented!()
    }

    fn get_uif_pso_cds() {
        unimplemented!()
    }

    fn get_uif_pso_dec() {
        unimplemented!()
    }

    fn get_uif_pso_aut() {
        unimplemented!()
    }

    fn get_uif_attestation() {
        unimplemented!()
    }

    // --- optional private DOs (0101 - 0104) ---

    // --- login data (5e) ---

    // --- URL (5f50) ---

    pub fn get_url(&mut self) -> Result<String> {
        let resp = apdu::send_command(
            &mut self.card_client,
            commands::get_url(),
            true,
        )?;

        Ok(String::from_utf8_lossy(resp.data()?).to_string())
    }

    // --- cardholder related data (65) ---
    pub fn get_cardholder_related_data(&mut self) -> Result<Cardholder> {
        let crd = commands::cardholder_related_data();
        let resp = apdu::send_command(&mut self.card_client, crd, true)?;
        resp.check_ok()?;

        Cardholder::try_from(resp.data()?)
    }

    // --- security support template (7a) ---
    pub fn get_security_support_template(
        &mut self,
    ) -> Result<SecuritySupportTemplate> {
        let sst = commands::get_security_support_template();
        let resp = apdu::send_command(&mut self.card_client, sst, true)?;
        resp.check_ok()?;

        let tlv = Tlv::try_from(resp.data()?)?;
        let res = tlv.find(&[0x93].into()).ok_or_else(|| {
            anyhow!("Couldn't get SecuritySupportTemplate DO")
        })?;

        if let Value::S(data) = res {
            let mut data = data.to_vec();
            assert_eq!(data.len(), 3);

            data.insert(0, 0); // prepend a zero
            let data: [u8; 4] = data.try_into().unwrap();

            let dsc: u32 = u32::from_be_bytes(data);
            Ok(SecuritySupportTemplate { dsc })
        } else {
            Err(anyhow!("Failed to process SecuritySupportTemplate"))
        }
    }

    /// Get cardholder certificate (each for AUT, DEC and SIG).
    ///
    /// Call select_data() before calling this fn, to select a particular
    /// certificate (if the card supports multiple certificates).
    pub fn get_cardholder_certificate(
        &mut self,
    ) -> Result<Response, OpenpgpCardError> {
        let cmd = commands::get_cardholder_certificate();
        apdu::send_command(&mut self.card_client, cmd, true)?.try_into()
    }

    /// DO "Algorithm Information"
    pub fn get_algo_info(&mut self) -> Result<Option<AlgoInfo>> {
        let resp = apdu::send_command(
            &mut self.card_client,
            commands::get_algo_list(),
            true,
        )?;
        resp.check_ok()?;

        let ai = AlgoInfo::try_from(resp.data()?)?;
        Ok(Some(ai))
    }

    /// SELECT DATA "select a DO in the current template"
    /// (e.g. for cardholder certificate)
    pub fn select_data(
        &mut self,
        num: u8,
        tag: &[u8],
    ) -> Result<Response, OpenpgpCardError> {
        let tlv = Tlv::new(
            [0x60],
            Value::C(vec![Tlv::new([0x5c], Value::S(tag.to_vec()))]),
        );

        let data = tlv.serialize();

        let cmd = commands::select_data(num, data);
        apdu::send_command(&mut self.card_client, cmd, true)?.try_into()
    }

    // ----------

    /// Reset all state on this OpenPGP card.
    ///
    /// Note: the "factory reset" operation is not directly offered by the
    /// card. It is implemented as a series of OpenPGP card commands:
    /// - send 4 bad requests to verify pw1
    /// - send 4 bad requests to verify pw3
    /// - terminate_df
    /// - activate_file
    pub fn factory_reset(&mut self) -> Result<()> {
        // send 4 bad requests to verify pw1
        // [apdu 00 20 00 81 08 40 40 40 40 40 40 40 40]
        for _ in 0..4 {
            let verify = commands::verify_pw1_81([0x40; 8].to_vec());
            let resp =
                apdu::send_command(&mut self.card_client, verify, false)?;
            if !(resp.status() == (0x69, 0x82)
                || resp.status() == (0x69, 0x83))
            {
                return Err(anyhow!("Unexpected status for reset, at pw1."));
            }
        }

        // send 4 bad requests to verify pw3
        // [apdu 00 20 00 83 08 40 40 40 40 40 40 40 40]
        for _ in 0..4 {
            let verify = commands::verify_pw3([0x40; 8].to_vec());
            let resp =
                apdu::send_command(&mut self.card_client, verify, false)?;

            if !(resp.status() == (0x69, 0x82)
                || resp.status() == (0x69, 0x83))
            {
                return Err(anyhow!("Unexpected status for reset, at pw3."));
            }
        }

        // terminate_df [apdu 00 e6 00 00]
        let term = commands::terminate_df();
        let resp = apdu::send_command(&mut self.card_client, term, false)?;
        resp.check_ok()?;

        // activate_file [apdu 00 44 00 00]
        let act = commands::activate_file();
        let resp = apdu::send_command(&mut self.card_client, act, false)?;
        resp.check_ok()?;

        // FIXME: does the connection need to be re-opened on some cards,
        // after reset?!

        Ok(())
    }

    /// Verify pw1 (user) for signing operation (mode 81) and set an
    /// appropriate access status.
    ///
    /// Depending on the PW1 status byte (see Extended Capabilities) this
    /// access condition is only valid for one PSO:CDS command or remains
    /// valid for several attempts.
    pub fn verify_pw1_for_signing(
        &mut self,
        pin: &str,
    ) -> Result<Response, OpenpgpCardError> {
        assert!(pin.len() >= 6); // FIXME: Err

        let verify = commands::verify_pw1_81(pin.as_bytes().to_vec());
        apdu::send_command(&mut self.card_client, verify, false)?.try_into()
    }

    /// Check the current access of PW1 for signing (mode 81).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note: some cards don't correctly implement this feature,
    /// e.g. yubikey 5)
    pub fn check_pw1_for_signing(
        &mut self,
    ) -> Result<Response, OpenpgpCardError> {
        let verify = commands::verify_pw1_81(vec![]);
        apdu::send_command(&mut self.card_client, verify, false)?.try_into()
    }

    /// Verify PW1 (user) and set an appropriate access status.
    /// (For operations except signing, mode 82).
    pub fn verify_pw1(
        &mut self,
        pin: &str,
    ) -> Result<Response, OpenpgpCardError> {
        assert!(pin.len() >= 6); // FIXME: Err

        let verify = commands::verify_pw1_82(pin.as_bytes().to_vec());
        apdu::send_command(&mut self.card_client, verify, false)?.try_into()
    }

    /// Check the current access of PW1.
    /// (For operations except signing, mode 82).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note: some cards don't correctly implement this feature,
    /// e.g. yubikey 5)
    pub fn check_pw1(&mut self) -> Result<Response, OpenpgpCardError> {
        let verify = commands::verify_pw1_82(vec![]);
        apdu::send_command(&mut self.card_client, verify, false)?.try_into()
    }

    /// Verify PW3 (admin) and set an appropriate access status.
    pub fn verify_pw3(
        &mut self,
        pin: &str,
    ) -> Result<Response, OpenpgpCardError> {
        assert!(pin.len() >= 8); // FIXME: Err

        let verify = commands::verify_pw3(pin.as_bytes().to_vec());
        apdu::send_command(&mut self.card_client, verify, false)?.try_into()
    }

    /// Check the current access of PW3 (admin).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note: some cards don't correctly implement this feature,
    /// e.g. yubikey 5)
    pub fn check_pw3(&mut self) -> Result<Response, OpenpgpCardError> {
        let verify = commands::verify_pw3(vec![]);
        apdu::send_command(&mut self.card_client, verify, false)?.try_into()
    }

    // --- decrypt ---

    /// Decrypt the ciphertext in `dm`, on the card.
    ///
    /// (This is a convenience wrapper around the low-level pso_decipher
    /// operation, it builds the required `data` field from `dm`)
    pub fn decrypt(
        &mut self,
        dm: Cryptogram,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        match dm {
            Cryptogram::RSA(message) => {
                let mut data = vec![0x0];
                data.extend_from_slice(message);

                // Call the card to decrypt `data`
                self.pso_decipher(data)
            }
            Cryptogram::ECDH(eph) => {
                // External Public Key
                let epk = Tlv::new([0x86], Value::S(eph.to_vec()));

                // Public Key DO
                let pkdo = Tlv::new([0x7f, 0x49], Value::C(vec![epk]));

                // Cipher DO
                let cdo = Tlv::new([0xa6], Value::C(vec![pkdo]));

                self.pso_decipher(cdo.serialize())
            }
        }
    }

    /// Run decryption operation on the smartcard (low level operation)
    /// (7.2.11 PSO: DECIPHER)
    fn pso_decipher(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        // The OpenPGP card is already connected and PW1 82 has been verified
        let dec_cmd = commands::decryption(data);
        let resp = apdu::send_command(&mut self.card_client, dec_cmd, true)?;
        resp.check_ok()?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }

    // --- sign ---

    /// Sign `hash`, on the card.
    ///
    /// (This is a convenience wrapper around the low-level
    /// pso_compute_digital_signature operation. It builds the required
    /// `data` field from `hash`)
    pub fn signature_for_hash(
        &mut self,
        hash: Hash,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        let data = match hash {
            Hash::SHA256(_) | Hash::SHA384(_) | Hash::SHA512(_) => {
                let tlv = Tlv::new(
                    [0x30],
                    Value::C(vec![
                        Tlv::new(
                            [0x30],
                            Value::C(vec![
                                Tlv::new(
                                    [0x06],
                                    // unwrapping is ok, for SHA*
                                    Value::S(hash.oid().unwrap().to_vec()),
                                ),
                                Tlv::new([0x05], Value::S(vec![])),
                            ]),
                        ),
                        Tlv::new([0x04], Value::S(hash.digest().to_vec())),
                    ]),
                );

                tlv.serialize()
            }
            Hash::EdDSA(d) => d.to_vec(),
            Hash::ECDSA(d) => d.to_vec(),
        };

        self.pso_compute_digital_signature(data)
    }

    /// Run signing operation on the smartcard (low level operation)
    /// (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)
    fn pso_compute_digital_signature(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        let dec_cmd = commands::signature(data);

        let resp = apdu::send_command(&mut self.card_client, dec_cmd, true)?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }

    // --- admin ---

    /// Set data of "private use" DO.
    ///
    /// `num` must be between 1 and 4.
    ///
    /// Access condition:
    /// - 1/3 need PW1 (82)
    /// - 2/4 need PW3
    pub fn set_private(&mut self, num: u8, data: Vec<u8>) -> Result<Vec<u8>> {
        assert!((1..=4).contains(&num));

        let cmd = commands::put_private_do(num, data);
        let resp = apdu::send_command(&mut self.card_client, cmd, true)?;

        Ok(resp.data()?.to_vec())
    }

    pub fn set_name(
        &mut self,
        name: &str,
    ) -> Result<Response, OpenpgpCardError> {
        let put_name = commands::put_name(name.as_bytes().to_vec());
        apdu::send_command(&mut self.card_client, put_name, false)?.try_into()
    }

    pub fn set_lang(
        &mut self,
        lang: &str,
    ) -> Result<Response, OpenpgpCardError> {
        let put_lang = commands::put_lang(lang.as_bytes().to_vec());
        apdu::send_command(self.card_client.borrow_mut(), put_lang, false)?
            .try_into()
    }

    pub fn set_sex(&mut self, sex: Sex) -> Result<Response, OpenpgpCardError> {
        let put_sex = commands::put_sex((&sex).into());
        apdu::send_command(self.card_client.borrow_mut(), put_sex, false)?
            .try_into()
    }

    pub fn set_url(
        &mut self,
        url: &str,
    ) -> Result<Response, OpenpgpCardError> {
        let put_url = commands::put_url(url.as_bytes().to_vec());
        apdu::send_command(&mut self.card_client, put_url, false)?.try_into()
    }

    pub fn set_creation_time(
        &mut self,
        time: KeyGenerationTime,
        key_type: KeyType,
    ) -> Result<Response, OpenpgpCardError> {
        // Timestamp update
        let time_value: Vec<u8> = time
            .get()
            .to_be_bytes()
            .iter()
            .skip_while(|&&e| e == 0)
            .copied()
            .collect();

        let time_cmd = commands::put_data(
            &[key_type.get_timestamp_put_tag()],
            time_value,
        );

        apdu::send_command(&mut self.card_client, time_cmd, false)?.try_into()
    }

    pub fn set_fingerprint(
        &mut self,
        fp: Fingerprint,
        key_type: KeyType,
    ) -> Result<Response, OpenpgpCardError> {
        let fp_cmd = commands::put_data(
            &[key_type.get_fingerprint_put_tag()],
            fp.as_bytes().to_vec(),
        );

        apdu::send_command(self.get_card_client(), fp_cmd, false)?.try_into()
    }

    /// Set PW Status Bytes.
    ///
    /// If `long` is false, send 1 byte to the card, otherwise 4.
    /// According to the spec, length information should not be changed.
    ///
    /// So, effectively, with 'long == false' the setting `pw1_cds_multi`
    /// can be changed.
    /// With 'long == true', the settings `pw1_pin_block` and `pw3_pin_block`
    /// can also be changed.
    ///
    /// (See OpenPGP card spec, pg. 28)
    pub fn set_pw_status_bytes(
        &mut self,
        pw_status: &PWStatus,
        long: bool,
    ) -> Result<Response, OpenpgpCardError> {
        let data = pw_status.serialize_for_put(long);

        let cmd = commands::put_pw_status(data);
        apdu::send_command(self.get_card_client(), cmd, false)?.try_into()
    }

    /// Set cardholder certificate (for AUT, DEC or SIG).
    ///
    /// Call select_data() before calling this fn, to select a particular
    /// certificate (if the card supports multiple certificates).
    pub fn set_cardholder_certificate(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Response, OpenpgpCardError> {
        let cmd = commands::put_cardholder_certificate(data);
        apdu::send_command(&mut self.card_client, cmd, false)?.try_into()
    }

    /// Set algorithm attributes
    /// (4.4.3.9 Algorithm Attributes)
    pub fn set_algorithm_attributes(
        &mut self,
        key_type: KeyType,
        algo: &Algo,
    ) -> Result<Response, OpenpgpCardError> {
        // FIXME: caching?
        let ard = self.get_app_data()?;

        // FIXME: Only write algo attributes to the card if "extended
        // capabilities" show that they are changeable!

        // FIXME: reuse "e" from card, if no algo list is available
        let _cur_algo = ard.get_algorithm_attributes(key_type)?;

        let data = match algo {
            Algo::Rsa(rsa) => Self::rsa_algo_attrs(rsa)?,
            Algo::Ecc(ecc) => Self::ecc_algo_attrs(ecc.oid(), ecc.ecc_type()),
            _ => {
                return Err(anyhow!("Unexpected Algo {:?}", algo).into());
            }
        };

        // Command to PUT the algorithm attributes
        let cmd = commands::put_data(&[key_type.get_algorithm_tag()], data);

        apdu::send_command(&mut self.card_client, cmd, false)?.try_into()
    }

    /// Helper: generate `data` for algorithm attributes with RSA
    fn rsa_algo_attrs(algo_attrs: &RsaAttrs) -> Result<Vec<u8>> {
        // Algorithm ID (01 = RSA (Encrypt or Sign))
        let mut algo_attributes = vec![0x01];

        // Length of modulus n in bit
        algo_attributes.extend(&algo_attrs.len_n().to_be_bytes());

        // Length of public exponent e in bit
        algo_attributes.push(0x00);
        algo_attributes.push(algo_attrs.len_e() as u8);

        // Import-Format of private key
        // (This fn currently assumes import_format "00 = standard (e, p, q)")
        if algo_attrs.import_format() != 0 {
            return Err(anyhow!(
                "Unexpected RSA input format (only 0 is supported)"
            ));
        }

        algo_attributes.push(algo_attrs.import_format());

        Ok(algo_attributes)
    }

    /// Helper: generate `data` for algorithm attributes with ECC
    fn ecc_algo_attrs(oid: &[u8], ecc_type: EccType) -> Vec<u8> {
        let algo_id = match ecc_type {
            EccType::EdDSA => 0x16,
            EccType::ECDH => 0x12,
            EccType::ECDSA => 0x13,
        };

        let mut algo_attributes = vec![algo_id];
        algo_attributes.extend(oid);
        // Leave Import-Format unset, for default (pg. 35)

        algo_attributes
    }

    /// Import an existing private key to the card.
    /// (This implicitly sets the algorithm info, fingerprint and timestamp)
    pub fn key_import(
        &mut self,
        key: Box<dyn CardUploadableKey>,
        key_type: KeyType,
    ) -> Result<(), OpenpgpCardError> {
        let algo_list = self.get_algo_info();

        // An error is ok - it's fine if a card doesn't offer a list of
        // supported algorithms
        let algo_list = algo_list.unwrap_or(None);

        keys::key_import(self, key, key_type, algo_list)
    }

    /// Generate a key on the card.
    /// (7.2.14 GENERATE ASYMMETRIC KEY PAIR)
    ///
    /// If the `algo` parameter is Some, then this algorithm will be set on
    /// the card for "key_type".
    pub fn generate_key(
        &mut self,
        fp_from_pub: fn(
            &PublicKeyMaterial,
            KeyGenerationTime,
            KeyType,
        ) -> Result<Fingerprint, OpenpgpCardError>,
        key_type: KeyType,
        algo: Option<&Algo>,
    ) -> Result<(PublicKeyMaterial, KeyGenerationTime), OpenpgpCardError> {
        keys::gen_key_with_metadata(self, fp_from_pub, key_type, algo)
    }

    /// Generate a key on the card.
    /// (7.2.14 GENERATE ASYMMETRIC KEY PAIR)
    ///
    /// This is a convenience wrapper around generate_key() which allows
    /// using the simplified `AlgoSimple` algorithm selector enum.
    pub fn generate_key_simple(
        &mut self,
        fp_from_pub: fn(
            &PublicKeyMaterial,
            KeyGenerationTime,
            KeyType,
        ) -> Result<Fingerprint, OpenpgpCardError>,
        key_type: KeyType,
        algo: AlgoSimple,
    ) -> Result<(PublicKeyMaterial, KeyGenerationTime), OpenpgpCardError> {
        let algo = algo.get_algo(key_type);
        self.generate_key(fp_from_pub, key_type, Some(&algo))
    }

    /// Get public key material from the card.
    ///
    /// Note: this fn returns an uninterpreted set of raw values (not an
    /// OpenPGP key data structure).
    /// This data from the card is insufficient to create a typical
    /// full public key.
    pub fn get_pub_key(
        &mut self,
        key_type: KeyType,
    ) -> Result<PublicKeyMaterial, OpenpgpCardError> {
        keys::get_pub_key(self, key_type)
    }
}
