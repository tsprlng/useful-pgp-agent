// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Access library for
//! [OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card)
//! devices (such as Gnuk, Yubikey, or Java smartcards running an OpenPGP
//! card application).
//!
//! This library aims to offer
//! - access to all features in the OpenPGP
//! [card specification](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf),
//! - without relying on a particular
//! [OpenPGP implementation](https://www.openpgp.org/software/developer/).
//!
//! This library can't directly access cards by itself. Instead, users
//! need to supply an implementation of the [`CardBackend`]
//! / [`CardTransaction`] traits, to access cards.
//!
//! The companion crate
//! [openpgp-card-pcsc](https://crates.io/crates/openpgp-card-pcsc)
//! offers a backend that uses [pcsclite](https://pcsclite.apdu.fr/) to
//! communicate with smartcards.
//!
//! The [openpgp-card-sequoia](https://crates.io/crates/openpgp-card-sequoia)
//! crate offers a higher level wrapper based on the
//! [Sequoia PGP](https://sequoia-pgp.org/) implementation.

pub mod algorithm;
pub(crate) mod apdu;
pub mod card_do;
pub mod crypto_data;
mod errors;
pub(crate) mod keys;
mod tlv;

pub use crate::apdu::response::Response;
pub use crate::errors::{Error, SmartcardError, StatusBytes};

use anyhow::{anyhow, Result};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::ops::{Deref, DerefMut};

use crate::algorithm::{Algo, AlgoInfo, AlgoSimple};
use crate::apdu::commands;
use crate::apdu::response::RawResponse;
use crate::card_do::{
    ApplicationRelatedData, CardholderRelatedData, Fingerprint,
    KeyGenerationTime, Lang, PWStatusBytes, SecuritySupportTemplate, Sex,
};
use crate::crypto_data::{
    CardUploadableKey, Cryptogram, Hash, PublicKeyMaterial,
};
use crate::tlv::tag::Tag;
use crate::tlv::value::Value;
use crate::tlv::Tlv;

/// The CardTransaction trait defines communication with an OpenPGP card via a
/// backend implementation (e.g. the pcsc backend in the crate
/// [openpgp-card-pcsc](https://crates.io/crates/openpgp-card-pcsc)),
/// after opening a transaction from a CardBackend.
///
/// CardTransaction exposes low-level access to OpenPGP card functionality.
pub trait CardTransaction {
    /// Transmit the command data in `cmd` to the card.
    ///
    /// `buf_size` is a hint to the backend (the backend may ignore it)
    /// indicating the expected maximum response size.
    fn transmit(
        &mut self,
        cmd: &[u8],
        buf_size: usize,
    ) -> Result<Vec<u8>, Error>;

    /// Set the card capabilities in the CardTransaction.
    ///
    /// Setting these capabilities is typically part of a bootstrapping
    /// process: the information about the card's capabilities is typically
    /// requested from the card using the same CardTransaction instance,
    /// before the card's capabilities have been initialized.
    fn init_card_caps(&mut self, caps: CardCaps);

    /// Request the card's capabilities
    ///
    /// (apdu serialization makes use of this information, e.g. to
    /// determine if extended length can be used)
    fn card_caps(&self) -> Option<&CardCaps>;

    /// If a CardTransaction implementation introduces an additional,
    /// backend-specific limit for maximum number of bytes per command,
    /// this fn can indicate that limit by returning `Some(max_cmd_len)`.
    fn max_cmd_len(&self) -> Option<usize> {
        None
    }

    /// Does the reader support FEATURE_VERIFY_PIN_DIRECT?
    fn feature_pinpad_verify(&self) -> bool;

    /// Does the reader support FEATURE_MODIFY_PIN_DIRECT?
    fn feature_pinpad_modify(&self) -> bool;

    /// Verify the PIN `id` via the reader pinpad
    fn pinpad_verify(&mut self, id: u8) -> Result<Vec<u8>>;

    /// Modify the PIN `id` via the reader pinpad
    fn pinpad_modify(&mut self, id: u8) -> Result<Vec<u8>>;

    /// Select the OpenPGP card application
    fn select(&mut self) -> Result<Response, Error> {
        let select_openpgp = commands::select_openpgp();
        apdu::send_command(self, select_openpgp, false)?.try_into()
    }

    /// Get a CardApp based on a CardTransaction.
    ///
    /// It is expected that SELECT has already been performed on the card
    /// beforehand.
    ///
    /// This fn initializes the CardCaps by requesting
    /// application_related_data from the card, and setting the
    /// capabilities accordingly.
    fn initialize(&mut self) -> Result<()> {
        let ard = self.application_related_data()?;

        // Determine chaining/extended length support from card
        // metadata and cache this information in the CardTransaction
        // implementation (as a CardCaps)
        let mut ext_support = false;
        let mut chaining_support = false;

        if let Ok(hist) = ard.historical_bytes() {
            if let Some(cc) = hist.card_capabilities() {
                chaining_support = cc.command_chaining();
                ext_support = cc.extended_lc_le();
            }
        }

        let ext_cap = ard.extended_capabilities()?;

        // Get max command/response byte sizes from card
        let (max_cmd_bytes, max_rsp_bytes) =
            if let Ok(Some(eli)) = ard.extended_length_information() {
                // In card 3.x, max lengths come from ExtendedLengthInfo
                (eli.max_command_bytes(), eli.max_response_bytes())
            } else if let (Some(cmd), Some(rsp)) =
                (ext_cap.max_cmd_len(), ext_cap.max_resp_len())
            {
                // In card 2.x, max lengths come from ExtendedCapabilities
                (cmd, rsp)
            } else {
                // Fallback: use 255 if we have no information from the card
                (255, 255)
            };

        let pw_status = ard.pw_status_bytes()?;
        let pw1_max = pw_status.pw1_max_len();
        let pw3_max = pw_status.pw3_max_len();

        let caps = CardCaps {
            ext_support,
            chaining_support,
            max_cmd_bytes,
            max_rsp_bytes,
            pw1_max_len: pw1_max,
            pw3_max_len: pw3_max,
        };

        log::debug!("init_card_caps to: {:x?}", caps);

        self.init_card_caps(caps);

        Ok(())
    }

    // --- get data ---

    /// Get the "application related data" from the card.
    ///
    /// (This data should probably be cached in a higher layer. Some parts of
    /// it are needed regularly, and it does not usually change during
    /// normal use of a card.)
    fn application_related_data(&mut self) -> Result<ApplicationRelatedData> {
        let ad = commands::application_related_data();
        let resp = apdu::send_command(self, ad, true)?;
        let value = Value::from(resp.data()?, true)?;

        log::debug!(" ARD value: {:x?}", value);

        Ok(ApplicationRelatedData(Tlv::new(Tag::from([0x6E]), value)))
    }

    // #[allow(dead_code)]
    // fn ca_fingerprints() {
    //     unimplemented!()
    // }
    //
    // #[allow(dead_code)]
    // fn key_information() {
    //     unimplemented!()
    // }
    //
    // #[allow(dead_code)]
    // fn uif_pso_cds() {
    //     unimplemented!()
    // }
    //
    // #[allow(dead_code)]
    // fn uif_pso_dec() {
    //     unimplemented!()
    // }
    //
    // #[allow(dead_code)]
    // fn uif_pso_aut() {
    //     unimplemented!()
    // }
    //
    // #[allow(dead_code)]
    // fn uif_attestation() {
    //     unimplemented!()
    // }

    // --- login data (5e) ---

    /// Get URL (5f50)
    fn url(&mut self) -> Result<Vec<u8>> {
        let resp = apdu::send_command(self, commands::url(), true)?;

        Ok(resp.data()?.to_vec())
    }

    /// Get cardholder related data (65)
    fn cardholder_related_data(&mut self) -> Result<CardholderRelatedData> {
        let crd = commands::cardholder_related_data();
        let resp = apdu::send_command(self, crd, true)?;
        resp.check_ok()?;

        CardholderRelatedData::try_from(resp.data()?)
    }

    /// Get security support template (7a)
    fn security_support_template(
        &mut self,
    ) -> Result<SecuritySupportTemplate> {
        let sst = commands::security_support_template();
        let resp = apdu::send_command(self, sst, true)?;
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
    #[allow(dead_code)]
    fn cardholder_certificate(&mut self) -> Result<Response, Error> {
        let cmd = commands::cardholder_certificate();
        apdu::send_command(self, cmd, true)?.try_into()
    }

    /// Get "Algorithm Information"
    fn algorithm_information(&mut self) -> Result<Option<AlgoInfo>> {
        let resp = apdu::send_command(self, commands::algo_info(), true)?;
        resp.check_ok()?;

        let ai = AlgoInfo::try_from(resp.data()?)?;
        Ok(Some(ai))
    }

    /// Firmware Version (YubiKey specific (?))
    fn firmware_version(&mut self) -> Result<Vec<u8>> {
        let resp =
            apdu::send_command(self, commands::firmware_version(), true)?;

        Ok(resp.data()?.into())
    }

    /// Set identity (Nitrokey Start specific (?)).
    /// [see:
    /// <https://docs.nitrokey.com/start/linux/multiple-identities.html>
    /// <https://github.com/Nitrokey/nitrokey-start-firmware/pull/33/>]
    fn set_identity(&mut self, id: u8) -> Result<Vec<u8>> {
        let resp = apdu::send_command(self, commands::set_identity(id), false);

        // Apparently it's normal to get "NotTransacted" from pcsclite when
        // the identity switch was successful.
        if let Err(Error::Smartcard(SmartcardError::NotTransacted)) = resp {
            Ok(vec![])
        } else {
            Ok(resp?.data()?.into())
        }
    }

    /// SELECT DATA ("select a DO in the current template",
    /// e.g. for cardholder certificate)
    fn select_data(&mut self, num: u8, tag: &[u8]) -> Result<Response, Error> {
        let tlv = Tlv::new(
            [0x60],
            Value::C(vec![Tlv::new([0x5c], Value::S(tag.to_vec()))]),
        );

        let data = tlv.serialize();

        let cmd = commands::select_data(num, data);
        apdu::send_command(self, cmd, true)?.try_into()
    }

    // --- optional private DOs (0101 - 0104) ---

    /// Get data from "private use" DO.
    ///
    /// `num` must be between 1 and 4.
    fn private_use_do(&mut self, num: u8) -> Result<Vec<u8>> {
        assert!((1..=4).contains(&num));

        let cmd = commands::private_use_do(num);
        let resp = apdu::send_command(self, cmd, true)?;

        Ok(resp.data()?.to_vec())
    }

    /// Set data of "private use" DO.
    ///
    /// `num` must be between 1 and 4.
    ///
    /// Access condition:
    /// - 1/3 need PW1 (82)
    /// - 2/4 need PW3
    fn set_private_use_do(
        &mut self,
        num: u8,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        assert!((1..=4).contains(&num));

        let cmd = commands::put_private_use_do(num, data);
        let resp = apdu::send_command(self, cmd, true)?;

        Ok(resp.data()?.to_vec())
    }

    // ----------

    /// Reset all state on this OpenPGP card.
    ///
    /// Note: the "factory reset" operation is not directly offered by the
    /// card spec. It is implemented as a series of OpenPGP card commands:
    /// - send 4 bad requests to verify pw1,
    /// - send 4 bad requests to verify pw3,
    /// - terminate_df,
    /// - activate_file.
    ///
    /// With most cards, this sequence of operations causes the card
    /// to revert to a "blank" state.
    ///
    /// (However, e.g. vanilla Gnuk doesn't support this functionality.
    /// Gnuk needs to be built with the `--enable-factory-reset`
    /// option to the `configure` script to enable this functionality).
    fn factory_reset(&mut self) -> Result<()> {
        // send 4 bad requests to verify pw1
        // [apdu 00 20 00 81 08 40 40 40 40 40 40 40 40]
        for _ in 0..4 {
            let verify = commands::verify_pw1_81([0x40; 8].to_vec());
            let resp = apdu::send_command(self, verify, false)?;
            if !(resp.status() == StatusBytes::SecurityStatusNotSatisfied
                || resp.status() == StatusBytes::AuthenticationMethodBlocked
                || matches!(resp.status(), StatusBytes::PasswordNotChecked(_)))
            {
                return Err(anyhow!("Unexpected status for reset, at pw1."));
            }
        }

        // send 4 bad requests to verify pw3
        // [apdu 00 20 00 83 08 40 40 40 40 40 40 40 40]
        for _ in 0..4 {
            let verify = commands::verify_pw3([0x40; 8].to_vec());
            let resp = apdu::send_command(self, verify, false)?;

            if !(resp.status() == StatusBytes::SecurityStatusNotSatisfied
                || resp.status() == StatusBytes::AuthenticationMethodBlocked
                || matches!(resp.status(), StatusBytes::PasswordNotChecked(_)))
            {
                return Err(anyhow!("Unexpected status for reset, at pw3."));
            }
        }

        // terminate_df [apdu 00 e6 00 00]
        let term = commands::terminate_df();
        let resp = apdu::send_command(self, term, false)?;
        resp.check_ok()?;

        // activate_file [apdu 00 44 00 00]
        let act = commands::activate_file();
        let resp = apdu::send_command(self, act, false)?;
        resp.check_ok()?;

        Ok(())
    }

    // --- verify/modify ---

    /// Verify pw1 (user) for signing operation (mode 81).
    ///
    /// Depending on the PW1 status byte (see Extended Capabilities) this
    /// access condition is only valid for one PSO:CDS command or remains
    /// valid for several attempts.
    fn verify_pw1_for_signing(
        &mut self,
        pin: &str,
    ) -> Result<Response, Error> {
        let verify = commands::verify_pw1_81(pin.as_bytes().to_vec());
        apdu::send_command(self, verify, false)?.try_into()
    }

    /// Verify pw1 (user) for signing operation (mode 81) using a
    /// pinpad on the card reader. If no usable pinpad is found, an error
    /// is returned.
    ///
    /// Depending on the PW1 status byte (see Extended Capabilities) this
    /// access condition is only valid for one PSO:CDS command or remains
    /// valid for several attempts.
    fn verify_pw1_for_signing_pinpad(&mut self) -> Result<Response, Error> {
        let res = self.pinpad_verify(0x81)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Check the current access of PW1 for signing (mode 81).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note: some cards don't correctly implement this feature,
    /// e.g. YubiKey 5)
    fn check_pw1_for_signing(&mut self) -> Result<Response, Error> {
        let verify = commands::verify_pw1_81(vec![]);
        apdu::send_command(self, verify, false)?.try_into()
    }

    /// Verify PW1 (user).
    /// (For operations except signing, mode 82).
    fn verify_pw1(&mut self, pin: &str) -> Result<Response, Error> {
        let verify = commands::verify_pw1_82(pin.as_bytes().to_vec());
        apdu::send_command(self, verify, false)?.try_into()
    }

    /// Verify PW1 (user) for operations except signing (mode 82),
    /// using a pinpad on the card reader. If no usable pinpad is found,
    /// an error is returned.

    fn verify_pw1_pinpad(&mut self) -> Result<Response, Error> {
        let res = self.pinpad_verify(0x82)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Check the current access of PW1.
    /// (For operations except signing, mode 82).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note: some cards don't correctly implement this feature,
    /// e.g. YubiKey 5)
    fn check_pw1(&mut self) -> Result<Response, Error> {
        let verify = commands::verify_pw1_82(vec![]);
        apdu::send_command(self, verify, false)?.try_into()
    }

    /// Verify PW3 (admin).
    fn verify_pw3(&mut self, pin: &str) -> Result<Response, Error> {
        let verify = commands::verify_pw3(pin.as_bytes().to_vec());
        apdu::send_command(self, verify, false)?.try_into()
    }

    /// Verify PW3 (admin) using a pinpad on the card reader. If no usable
    /// pinpad is found, an error is returned.
    fn verify_pw3_pinpad(&mut self) -> Result<Response, Error> {
        let res = self.pinpad_verify(0x83)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Check the current access of PW3 (admin).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note: some cards don't correctly implement this feature,
    /// e.g. YubiKey 5)
    fn check_pw3(&mut self) -> Result<Response, Error> {
        let verify = commands::verify_pw3(vec![]);
        apdu::send_command(self, verify, false)?.try_into()
    }

    /// Change the value of PW1 (user password).
    ///
    /// The current value of PW1 must be presented in `old` for authorization.
    fn change_pw1(&mut self, old: &str, new: &str) -> Result<Response, Error> {
        let mut data = vec![];
        data.extend(old.as_bytes());
        data.extend(new.as_bytes());

        let change = commands::change_pw1(data);
        apdu::send_command(self, change, false)?.try_into()
    }

    /// Change the value of PW1 (user password)  using a pinpad on the
    /// card reader. If no usable pinpad is found, an error is returned.
    fn change_pw1_pinpad(&mut self) -> Result<Response, Error> {
        let res = self.pinpad_modify(0x81)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Change the value of PW3 (admin password).
    ///
    /// The current value of PW3 must be presented in `old` for authorization.
    fn change_pw3(&mut self, old: &str, new: &str) -> Result<Response, Error> {
        let mut data = vec![];
        data.extend(old.as_bytes());
        data.extend(new.as_bytes());

        let change = commands::change_pw3(data);
        apdu::send_command(self, change, false)?.try_into()
    }

    /// Change the value of PW3 (admin password) using a pinpad on the
    /// card reader. If no usable pinpad is found, an error is returned.
    fn change_pw3_pinpad(&mut self) -> Result<Response, Error> {
        let res = self.pinpad_modify(0x83)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Reset the error counter for PW1 (user password) and set a new value
    /// for PW1.
    ///
    /// For authorization, either:
    /// - PW3 must have been verified previously,
    /// - secure messaging must be currently used,
    /// - the resetting_code must be presented.
    fn reset_retry_counter_pw1(
        &mut self,
        new_pw1: Vec<u8>,
        resetting_code: Option<Vec<u8>>,
    ) -> Result<Response, Error> {
        let reset = commands::reset_retry_counter_pw1(resetting_code, new_pw1);
        apdu::send_command(self, reset, false)?.try_into()
    }

    // --- decrypt ---

    /// Decrypt the ciphertext in `dm`, on the card.
    ///
    /// (This is a wrapper around the low-level pso_decipher
    /// operation, it builds the required `data` field from `dm`)
    fn decipher(&mut self, dm: Cryptogram) -> Result<Vec<u8>, Error> {
        match dm {
            Cryptogram::RSA(message) => {
                // "Padding indicator byte (00) for RSA" (pg. 69)
                let mut data = vec![0x0];
                data.extend_from_slice(message);

                // Call the card to decrypt `data`
                self.pso_decipher(data)
            }
            Cryptogram::ECDH(eph) => {
                // "In case of ECDH the card supports a partial decrypt
                // only. The input is a cipher DO with the following data:"
                // A6 xx Cipher DO
                //  -> 7F49 xx Public Key DO
                //    -> 86 xx External Public Key

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
    ///
    /// (consider using the `decipher()` method if you don't want to create
    /// the data field manually)
    fn pso_decipher(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        // The OpenPGP card is already connected and PW1 82 has been verified
        let dec_cmd = commands::decryption(data);
        let resp = apdu::send_command(self, dec_cmd, true)?;
        resp.check_ok()?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }

    // --- sign ---

    /// Sign `hash`, on the card.
    ///
    /// This is a wrapper around the low-level
    /// pso_compute_digital_signature operation.
    /// It builds the required `data` field from `hash`.
    ///
    /// For RSA, this means a "DigestInfo" data structure is generated.
    /// (see 7.2.10.2 DigestInfo for RSA).
    ///
    /// With ECC the hash data is processed as is, using
    /// pso_compute_digital_signature.
    fn signature_for_hash(&mut self, hash: Hash) -> Result<Vec<u8>, Error> {
        self.pso_compute_digital_signature(digestinfo(hash))
    }

    /// Run signing operation on the smartcard (low level operation)
    /// (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)
    ///
    /// (consider using the `signature_for_hash()` method if you don't
    /// want to create the data field manually)
    fn pso_compute_digital_signature(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let cds_cmd = commands::signature(data);

        let resp = apdu::send_command(self, cds_cmd, true)?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }

    // --- internal authenticate ---

    /// Auth-sign `hash`, on the card.
    ///
    /// This is a wrapper around the low-level
    /// internal_authenticate operation.
    /// It builds the required `data` field from `hash`.
    ///
    /// For RSA, this means a "DigestInfo" data structure is generated.
    /// (see 7.2.10.2 DigestInfo for RSA).
    ///
    /// With ECC the hash data is processed as is.
    fn authenticate_for_hash(&mut self, hash: Hash) -> Result<Vec<u8>, Error> {
        self.internal_authenticate(digestinfo(hash))
    }

    /// Run signing operation on the smartcard (low level operation)
    /// (7.2.13 INTERNAL AUTHENTICATE)
    ///
    /// (consider using the `authenticate_for_hash()` method if you don't
    /// want to create the data field manually)
    fn internal_authenticate(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let ia_cmd = commands::internal_authenticate(data);
        let resp = apdu::send_command(self, ia_cmd, true)?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }

    // --- admin ---

    fn set_name(&mut self, name: &[u8]) -> Result<Response, Error> {
        let put_name = commands::put_name(name.to_vec());
        apdu::send_command(self, put_name, false)?.try_into()
    }

    fn set_lang(&mut self, lang: &[Lang]) -> Result<Response, Error> {
        let bytes: Vec<u8> = lang
            .iter()
            .map(|&l| Into::<Vec<u8>>::into(l))
            .flatten()
            .collect();

        let put_lang = commands::put_lang(bytes);
        apdu::send_command(self, put_lang, false)?.try_into()
    }

    fn set_sex(&mut self, sex: Sex) -> Result<Response, Error> {
        let put_sex = commands::put_sex((&sex).into());
        apdu::send_command(self, put_sex, false)?.try_into()
    }

    fn set_url(&mut self, url: &[u8]) -> Result<Response, Error> {
        let put_url = commands::put_url(url.to_vec());
        apdu::send_command(self, put_url, false)?.try_into()
    }

    fn set_creation_time(
        &mut self,
        time: KeyGenerationTime,
        key_type: KeyType,
    ) -> Result<Response, Error> {
        // Timestamp update
        let time_value: Vec<u8> = time
            .get()
            .to_be_bytes()
            .iter()
            .skip_while(|&&e| e == 0)
            .copied()
            .collect();

        let time_cmd =
            commands::put_data(&[key_type.timestamp_put_tag()], time_value);

        apdu::send_command(self, time_cmd, false)?.try_into()
    }

    fn set_fingerprint(
        &mut self,
        fp: Fingerprint,
        key_type: KeyType,
    ) -> Result<Response, Error> {
        let fp_cmd = commands::put_data(
            &[key_type.fingerprint_put_tag()],
            fp.as_bytes().to_vec(),
        );

        apdu::send_command(self, fp_cmd, false)?.try_into()
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
    fn set_pw_status_bytes(
        &mut self,
        pw_status: &PWStatusBytes,
        long: bool,
    ) -> Result<Response, Error> {
        let data = pw_status.serialize_for_put(long);

        let cmd = commands::put_pw_status(data);
        apdu::send_command(self, cmd, false)?.try_into()
    }

    /// Set cardholder certificate (for AUT, DEC or SIG).
    ///
    /// Call select_data() before calling this fn, to select a particular
    /// certificate (if the card supports multiple certificates).
    fn set_cardholder_certificate(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Response, Error> {
        let cmd = commands::put_cardholder_certificate(data);
        apdu::send_command(self, cmd, false)?.try_into()
    }

    /// Set algorithm attributes
    /// (4.4.3.9 Algorithm Attributes)
    fn set_algorithm_attributes(
        &mut self,
        key_type: KeyType,
        algo: &Algo,
    ) -> Result<Response, Error> {
        // Command to PUT the algorithm attributes
        let cmd = commands::put_data(
            &[key_type.algorithm_tag()],
            algo.to_data_object()?,
        );

        apdu::send_command(self, cmd, false)?.try_into()
    }

    /// Set resetting code
    /// (4.3.4 Resetting Code)
    fn set_resetting_code(
        &mut self,
        resetting_code: Vec<u8>,
    ) -> Result<Response, Error> {
        let cmd = commands::put_data(&[0xd3], resetting_code);
        apdu::send_command(self, cmd, false)?.try_into()
    }

    /// Import an existing private key to the card.
    /// (This implicitly sets the algorithm info, fingerprint and timestamp)
    fn key_import(
        &mut self,
        key: Box<dyn CardUploadableKey>,
        key_type: KeyType,
    ) -> Result<(), Error> {
        let algo_info = self.algorithm_information();

        // An error is ok - it's fine if a card doesn't offer a list of
        // supported algorithms
        let algo_info = algo_info.unwrap_or(None);

        keys::key_import(self, key, key_type, algo_info)
    }

    /// Generate a key on the card.
    /// (7.2.14 GENERATE ASYMMETRIC KEY PAIR)
    ///
    /// If the `algo` parameter is Some, then this algorithm will be set on
    /// the card for "key_type".
    ///
    /// Note: `algo` needs to precisely specify the RSA bitsize of e (if
    /// applicable), and import format, with values that the current card
    /// supports.
    fn generate_key(
        &mut self,
        fp_from_pub: fn(
            &PublicKeyMaterial,
            KeyGenerationTime,
            KeyType,
        ) -> Result<Fingerprint, Error>,
        key_type: KeyType,
        algo: Option<&Algo>,
    ) -> Result<(PublicKeyMaterial, KeyGenerationTime), Error> {
        keys::gen_key_with_metadata(self, fp_from_pub, key_type, algo)
    }

    /// Generate a key on the card.
    /// (7.2.14 GENERATE ASYMMETRIC KEY PAIR)
    ///
    /// This is a wrapper around generate_key() which allows
    /// using the simplified `AlgoSimple` algorithm selector enum.
    ///
    /// Note: AlgoSimple doesn't specify card specific details (such as
    /// bitsize of e for RSA, and import format). This function determines
    /// these values based on information from the card.
    fn generate_key_simple(
        &mut self,
        fp_from_pub: fn(
            &PublicKeyMaterial,
            KeyGenerationTime,
            KeyType,
        ) -> Result<Fingerprint, Error>,
        key_type: KeyType,
        simple: AlgoSimple,
    ) -> Result<(PublicKeyMaterial, KeyGenerationTime), Error> {
        let ard = self.application_related_data()?;
        let algo_info = if let Ok(ai) = self.algorithm_information() {
            ai
        } else {
            None
        };

        let algo = simple.determine_algo(key_type, &ard, algo_info)?;

        Self::generate_key(self, fp_from_pub, key_type, Some(&algo))
    }

    /// Get public key material from the card.
    ///
    /// Note: this fn returns a set of raw public key data (not an
    /// OpenPGP data structure).
    ///
    /// Note also that the information from the card is insufficient to
    /// reconstruct a pre-existing OpenPGP public key that corresponds to
    /// the private key on the card.
    fn public_key(
        &mut self,
        key_type: KeyType,
    ) -> Result<PublicKeyMaterial, Error> {
        keys::public_key(self, key_type)
    }
}

impl<'a> Deref for dyn CardTransaction + Send + Sync + 'a {
    type Target = dyn CardTransaction + 'a;

    fn deref(&self) -> &Self::Target {
        self
    }
}
impl<'a> DerefMut for dyn CardTransaction + Send + Sync + 'a {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
    }
}

fn digestinfo(hash: Hash) -> Vec<u8> {
    match hash {
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
    }
}

/// Configuration of the capabilities of a card.
///
/// This configuration is used to determine e.g. if chaining or extended
/// length can be used when communicating with the card.
///
/// (This configuration is retrieved from card metadata, specifically from
/// "Card Capabilities", "Extended length information" and "PWStatus")
#[derive(Clone, Copy, Debug)]
pub struct CardCaps {
    /// Extended Lc and Le fields
    ext_support: bool,

    /// Command chaining
    chaining_support: bool,

    /// Maximum number of bytes in a command APDU
    max_cmd_bytes: u16,

    /// Maximum number of bytes in a response APDU
    max_rsp_bytes: u16,

    /// Maximum length of pw1
    pw1_max_len: u8,

    /// Maximum length of pw3
    pw3_max_len: u8,
}

impl CardCaps {
    pub fn ext_support(&self) -> bool {
        self.ext_support
    }

    pub fn max_rsp_bytes(&self) -> u16 {
        self.max_rsp_bytes
    }

    pub fn pw1_max_len(&self) -> u8 {
        self.pw1_max_len
    }

    pub fn pw3_max_len(&self) -> u8 {
        self.pw3_max_len
    }
}

/// Identify a Key slot on an OpenPGP card
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyType {
    Signing,
    Decryption,
    Authentication,
    Attestation,
}

impl KeyType {
    /// Get C1/C2/C3/DA values for this KeyTypes, to use as Tag
    fn algorithm_tag(&self) -> u8 {
        use KeyType::*;

        match self {
            Signing => 0xC1,
            Decryption => 0xC2,
            Authentication => 0xC3,
            Attestation => 0xDA,
        }
    }

    /// Get C7/C8/C9/DB values for this KeyTypes, to use as Tag.
    ///
    /// (NOTE: these Tags are only used for "PUT DO", but GETting
    /// fingerprint information from the card uses the combined Tag C5)
    fn fingerprint_put_tag(&self) -> u8 {
        use KeyType::*;

        match self {
            Signing => 0xC7,
            Decryption => 0xC8,
            Authentication => 0xC9,
            Attestation => 0xDB,
        }
    }

    /// Get CE/CF/D0/DD values for this KeyTypes, to use as Tag.
    ///
    /// (NOTE: these Tags are only used for "PUT DO", but GETting
    /// timestamp information from the card uses the combined Tag CD)
    fn timestamp_put_tag(&self) -> u8 {
        use KeyType::*;

        match self {
            Signing => 0xCE,
            Decryption => 0xCF,
            Authentication => 0xD0,
            Attestation => 0xDD,
        }
    }
}

/// A KeySet binds together a triple of information about each Key on a card
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySet<T> {
    signature: Option<T>,
    decryption: Option<T>,
    authentication: Option<T>,
}

impl<T> From<(Option<T>, Option<T>, Option<T>)> for KeySet<T> {
    fn from(tuple: (Option<T>, Option<T>, Option<T>)) -> Self {
        Self {
            signature: tuple.0,
            decryption: tuple.1,
            authentication: tuple.2,
        }
    }
}

impl<T> KeySet<T> {
    pub fn signature(&self) -> Option<&T> {
        self.signature.as_ref()
    }

    pub fn decryption(&self) -> Option<&T> {
        self.decryption.as_ref()
    }

    pub fn authentication(&self) -> Option<&T> {
        self.authentication.as_ref()
    }
}
