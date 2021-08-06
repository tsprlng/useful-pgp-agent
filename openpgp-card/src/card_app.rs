// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Direct, low-level, access to OpenPGP card functionality.
//!
//! No checks are performed here (e.g. for valid data lengths).
//! Such checks should be performed on a higher layer, if needed.
//!
//! Also, no caching of data is done here. If necessary, caching should
//! be done on a higher layer.

use std::borrow::BorrowMut;
use std::convert::TryFrom;
use std::time::SystemTime;

use anyhow::{anyhow, Result};

use crate::apdu::{commands, response::Response};
use crate::errors::OpenpgpCardError;
use crate::parse::{
    algo_attrs::Algo, algo_info::AlgoInfo, application_id::ApplicationId,
    cardholder::CardHolder, extended_cap::ExtendedCap,
    extended_length_info::ExtendedLengthInfo, fingerprint,
    historical::Historical, key_generation_times, pw_status::PWStatus, KeySet,
};
use crate::tlv::{tag::Tag, Tlv, TlvEntry};
use crate::{
    apdu, keys, CardCaps, CardClientBox, CardUploadableKey, DecryptMe, Hash,
    KeyGeneration, KeyType, PublicKeyMaterial, Sex,
};

pub struct CardApp {
    card_client: CardClientBox,
}

impl CardApp {
    pub fn new(card_client: CardClientBox) -> Self {
        Self { card_client }
    }

    pub(crate) fn take_card(self) -> CardClientBox {
        self.card_client
    }

    /// Read capabilities from the card, and set them in the CardApp.
    ///
    /// Also initializes the underlying CardClient with the caps - some
    /// implementations may need this information.
    pub fn init_caps(&mut self, ard: &Tlv) -> Result<()> {
        // Determine chaining/extended length support from card
        // metadata and cache this information in CardApp (as a
        // CardCaps)

        let mut ext_support = false;
        let mut chaining_support = false;

        if let Ok(hist) = CardApp::get_historical(ard) {
            if let Some(cc) = hist.get_card_capabilities() {
                chaining_support = cc.get_command_chaining();
                ext_support = cc.get_extended_lc_le();
            }
        }

        let (max_cmd_bytes, max_rsp_bytes) = if let Ok(Some(eli)) =
            CardApp::get_extended_length_information(ard)
        {
            (eli.max_command_bytes, eli.max_response_bytes)
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

    pub fn card(&mut self) -> &mut CardClientBox {
        &mut self.card_client
    }

    // --- select ---

    /// "Select" the OpenPGP card application
    pub fn select(&mut self) -> Result<Response, OpenpgpCardError> {
        let select_openpgp = commands::select_openpgp();
        apdu::send_command(&mut self.card_client, select_openpgp, false)
    }

    // --- application data ---

    /// Load "application related data".
    ///
    /// This is done once, after opening the OpenPGP card applet
    /// (the data is stored in the OpenPGPCard object).
    pub fn get_app_data(&mut self) -> Result<Tlv> {
        let ad = commands::get_application_data();
        let resp = apdu::send_command(&mut self.card_client, ad, true)?;
        let entry = TlvEntry::from(resp.data()?, true)?;

        log::debug!(" App data TlvEntry: {:x?}", entry);

        Ok(Tlv(Tag::from([0x6E]), entry))
    }

    // --- pieces of application related data ---

    pub fn get_aid(ard: &Tlv) -> Result<ApplicationId, OpenpgpCardError> {
        // get from cached "application related data"
        let aid = ard.find(&Tag::from([0x4F]));

        if let Some(aid) = aid {
            Ok(ApplicationId::try_from(&aid.serialize()[..])?)
        } else {
            Err(anyhow!("Couldn't get Application ID.").into())
        }
    }

    pub fn get_historical(ard: &Tlv) -> Result<Historical, OpenpgpCardError> {
        // get from cached "application related data"
        let hist = ard.find(&Tag::from([0x5F, 0x52]));

        if let Some(hist) = hist {
            log::debug!("Historical bytes: {:x?}", hist);
            Historical::from(&hist.serialize())
        } else {
            Err(anyhow!("Failed to get historical bytes.").into())
        }
    }

    pub fn get_extended_length_information(
        ard: &Tlv,
    ) -> Result<Option<ExtendedLengthInfo>> {
        // get from cached "application related data"
        let eli = ard.find(&Tag::from([0x7F, 0x66]));

        log::debug!("Extended length information: {:x?}", eli);

        if let Some(eli) = eli {
            // The card has returned extended length information
            Ok(Some(ExtendedLengthInfo::from(&eli.serialize()[..])?))
        } else {
            // The card didn't return this (optional) DO. That is ok.
            Ok(None)
        }
    }

    pub fn get_general_feature_management() -> Option<bool> {
        unimplemented!()
    }

    pub fn get_discretionary_data_objects() {
        unimplemented!()
    }

    pub fn get_extended_capabilities(
        ard: &Tlv,
    ) -> Result<ExtendedCap, OpenpgpCardError> {
        // get from cached "application related data"
        let ecap = ard.find(&Tag::from([0xc0]));

        if let Some(ecap) = ecap {
            Ok(ExtendedCap::try_from(&ecap.serialize()[..])?)
        } else {
            Err(anyhow!("Failed to get extended capabilities.").into())
        }
    }

    pub fn get_algorithm_attributes(
        ard: &Tlv,
        key_type: KeyType,
    ) -> Result<Algo> {
        // get from cached "application related data"
        let aa = ard.find(&Tag::from([key_type.get_algorithm_tag()]));

        if let Some(aa) = aa {
            Algo::try_from(&aa.serialize()[..])
        } else {
            Err(anyhow!(
                "Failed to get algorithm attributes for {:?}.",
                key_type
            ))
        }
    }

    /// PW status Bytes
    pub fn get_pw_status_bytes(ard: &Tlv) -> Result<PWStatus> {
        // get from cached "application related data"
        let psb = ard.find(&Tag::from([0xc4]));

        if let Some(psb) = psb {
            let pws = PWStatus::try_from(&psb.serialize())?;

            log::debug!("PW Status: {:x?}", pws);

            Ok(pws)
        } else {
            Err(anyhow!("Failed to get PW status Bytes."))
        }
    }

    pub fn get_fingerprints(
        ard: &Tlv,
    ) -> Result<KeySet<fingerprint::Fingerprint>, OpenpgpCardError> {
        // Get from cached "application related data"
        let fp = ard.find(&Tag::from([0xc5]));

        if let Some(fp) = fp {
            let fp = fingerprint::from(&fp.serialize())?;

            log::debug!("Fp: {:x?}", fp);

            Ok(fp)
        } else {
            Err(anyhow!("Failed to get fingerprints.").into())
        }
    }

    // ---

    pub fn get_ca_fingerprints() {
        unimplemented!()
    }

    pub fn get_key_generation_times(
        ard: &Tlv,
    ) -> Result<KeySet<KeyGeneration>, OpenpgpCardError> {
        let kg = ard.find(&Tag::from([0xCD]));

        if let Some(kg) = kg {
            let kg = key_generation_times::from(&kg.serialize())?;

            log::debug!("Key generation: {:x?}", kg);

            Ok(kg)
        } else {
            Err(anyhow!("Failed to get key generation times.").into())
        }
    }

    pub fn get_key_information() {
        unimplemented!()
    }

    pub fn get_uif_pso_cds() {
        unimplemented!()
    }

    pub fn get_uif_pso_dec() {
        unimplemented!()
    }

    pub fn get_uif_pso_aut() {
        unimplemented!()
    }
    pub fn get_uif_attestation() {
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
    pub fn get_cardholder_related_data(&mut self) -> Result<CardHolder> {
        let crd = commands::cardholder_related_data();
        let resp = apdu::send_command(&mut self.card_client, crd, true)?;
        resp.check_ok()?;

        CardHolder::try_from(resp.data()?)
    }

    // --- security support template (7a) ---
    pub fn get_security_support_template(&mut self) -> Result<Tlv> {
        let sst = commands::get_security_support_template();
        let resp = apdu::send_command(&mut self.card_client, sst, true)?;
        resp.check_ok()?;

        Tlv::try_from(resp.data()?)
    }

    // DO "Algorithm Information" (0xFA)
    pub fn list_supported_algo(&mut self) -> Result<Option<AlgoInfo>> {
        let resp = apdu::send_command(
            &mut self.card_client,
            commands::get_algo_list(),
            true,
        )?;
        resp.check_ok()?;

        let ai = AlgoInfo::try_from(resp.data()?)?;
        Ok(Some(ai))
    }

    // ----------

    /// Delete all state on this OpenPGP card
    pub fn factory_reset(&mut self) -> Result<()> {
        // send 4 bad requests to verify pw1
        // [apdu 00 20 00 81 08 40 40 40 40 40 40 40 40]
        for _ in 0..4 {
            let verify = commands::verify_pw1_81([0x40; 8].to_vec());
            let resp =
                apdu::send_command(&mut self.card_client, verify, false)?;
            if !(resp.status() == [0x69, 0x82]
                || resp.status() == [0x69, 0x83])
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

            if !(resp.status() == [0x69, 0x82]
                || resp.status() == [0x69, 0x83])
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

    pub fn verify_pw1_for_signing(
        &mut self,
        pin: &str,
    ) -> Result<Response, OpenpgpCardError> {
        assert!(pin.len() >= 6); // FIXME: Err

        let verify = commands::verify_pw1_81(pin.as_bytes().to_vec());
        apdu::send_command(&mut self.card_client, verify, false)
    }

    pub fn check_pw1(&mut self) -> Result<Response, OpenpgpCardError> {
        let verify = commands::verify_pw1_82(vec![]);
        apdu::send_command(&mut self.card_client, verify, false)
    }

    pub fn verify_pw1(
        &mut self,
        pin: &str,
    ) -> Result<Response, OpenpgpCardError> {
        assert!(pin.len() >= 6); // FIXME: Err

        let verify = commands::verify_pw1_82(pin.as_bytes().to_vec());
        apdu::send_command(&mut self.card_client, verify, false)
    }

    pub fn check_pw3(&mut self) -> Result<Response, OpenpgpCardError> {
        let verify = commands::verify_pw3(vec![]);
        apdu::send_command(&mut self.card_client, verify, false)
    }

    pub fn verify_pw3(
        &mut self,
        pin: &str,
    ) -> Result<Response, OpenpgpCardError> {
        assert!(pin.len() >= 8); // FIXME: Err

        let verify = commands::verify_pw3(pin.as_bytes().to_vec());
        apdu::send_command(&mut self.card_client, verify, false)
    }

    // --- decrypt ---

    /// Decrypt the ciphertext in `dm`, on the card.
    pub fn decrypt(
        &mut self,
        dm: DecryptMe,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        match dm {
            DecryptMe::RSA(message) => {
                let mut data = vec![0x0];
                data.extend_from_slice(message);

                // Call the card to decrypt `data`
                self.pso_decipher(data)
            }
            DecryptMe::ECDH(eph) => {
                // External Public Key
                let epk = Tlv(Tag(vec![0x86]), TlvEntry::S(eph.to_vec()));

                // Public Key DO
                let pkdo = Tlv(Tag(vec![0x7f, 0x49]), TlvEntry::C(vec![epk]));

                // Cipher DO
                let cdo = Tlv(Tag(vec![0xa6]), TlvEntry::C(vec![pkdo]));

                self.pso_decipher(cdo.serialize())
            }
        }
    }

    /// Run decryption operation on the smartcard
    /// (7.2.11 PSO: DECIPHER)
    pub(crate) fn pso_decipher(
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

    /// Sign the message in `hash`, on the card.
    pub fn signature_for_hash(
        &mut self,
        hash: Hash,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        let data = match hash {
            Hash::SHA256(_) | Hash::SHA384(_) | Hash::SHA512(_) => {
                let tlv = Tlv(
                    Tag(vec![0x30]),
                    TlvEntry::C(vec![
                        Tlv(
                            Tag(vec![0x30]),
                            TlvEntry::C(vec![
                                Tlv(
                                    Tag(vec![0x06]),
                                    // unwrapping is ok, for SHA*
                                    TlvEntry::S(hash.oid().unwrap().to_vec()),
                                ),
                                Tlv(Tag(vec![0x05]), TlvEntry::S(vec![])),
                            ]),
                        ),
                        Tlv(
                            Tag(vec![0x04]),
                            TlvEntry::S(hash.digest().to_vec()),
                        ),
                    ]),
                );

                tlv.serialize()
            }
            Hash::EdDSA(d) => d.to_vec(),
            Hash::ECDSA(d) => d.to_vec(),
        };

        self.compute_digital_signature(data)
    }

    /// Run signing operation on the smartcard
    /// (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)
    pub(crate) fn compute_digital_signature(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        let dec_cmd = commands::signature(data);

        let resp = apdu::send_command(&mut self.card_client, dec_cmd, true)?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }

    // --- admin ---

    pub fn set_name(
        &mut self,
        name: &str,
    ) -> Result<Response, OpenpgpCardError> {
        let put_name = commands::put_name(name.as_bytes().to_vec());
        apdu::send_command(&mut self.card_client, put_name, false)
    }

    pub fn set_lang(
        &mut self,
        lang: &str,
    ) -> Result<Response, OpenpgpCardError> {
        let put_lang = commands::put_lang(lang.as_bytes().to_vec());
        apdu::send_command(self.card_client.borrow_mut(), put_lang, false)
    }

    pub fn set_sex(&mut self, sex: Sex) -> Result<Response, OpenpgpCardError> {
        let put_sex = commands::put_sex(sex.as_u8());
        apdu::send_command(self.card_client.borrow_mut(), put_sex, false)
    }

    pub fn set_url(
        &mut self,
        url: &str,
    ) -> Result<Response, OpenpgpCardError> {
        let put_url = commands::put_url(url.as_bytes().to_vec());
        apdu::send_command(&mut self.card_client, put_url, false)
    }

    pub fn set_creation_time(
        &mut self,
        time: u32,
        key_type: KeyType,
    ) -> Result<Response, OpenpgpCardError> {
        // Timestamp update
        let time_value: Vec<u8> = time
            .to_be_bytes()
            .iter()
            .skip_while(|&&e| e == 0)
            .copied()
            .collect();

        let time_cmd = commands::put_data(
            &[key_type.get_timestamp_put_tag()],
            time_value,
        );

        apdu::send_command(&mut self.card_client, time_cmd, false)
    }

    pub fn upload_key(
        &mut self,
        key: Box<dyn CardUploadableKey>,
        key_type: KeyType,
    ) -> Result<(), OpenpgpCardError> {
        let algo_list = self.list_supported_algo();

        let algo_list = if algo_list.is_ok() {
            algo_list.unwrap()
        } else {
            // An error is ok - it's fine if a card doesn't offer a list of
            // supported algorithms
            None
        };

        keys::upload_key(self, key, key_type, algo_list)
    }

    // FIXME: use subset of CardUploadableKey to specify algo?
    pub fn generate_key(
        &mut self,
        fp_from_pub: fn(&PublicKeyMaterial, SystemTime) -> Result<[u8; 20]>,
        key_type: KeyType,
    ) -> Result<(), OpenpgpCardError> {
        // FIXME: specify algo; pass in algo list?
        keys::gen_key_with_metadata(self, fp_from_pub, key_type)
    }
}
