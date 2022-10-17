// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::{TryFrom, TryInto};

use crate::algorithm::{Algo, AlgoInfo, AlgoSimple};
use crate::apdu::commands;
use crate::apdu::response::RawResponse;
use crate::card_do::{
    ApplicationRelatedData, CardholderRelatedData, Fingerprint, KeyGenerationTime, Lang,
    PWStatusBytes, SecuritySupportTemplate, Sex, UIF,
};
use crate::crypto_data::{CardUploadableKey, Cryptogram, Hash, PublicKeyMaterial};
use crate::tlv::{value::Value, Tlv};
use crate::{
    apdu, keys, CardBackend, CardTransaction, Error, KeyType, PinType, SmartcardError, StatusBytes,
    Tag, Tags,
};

/// An OpenPGP card access object, backed by a CardBackend implementation.
///
/// Most users will probably want to use the `PcscCard` backend from the `openpgp-card-pcsc` crate.
///
/// Users of this crate can keep a long lived OpenPgp object. All operations must be performed on
/// a short lived `OpenPgpTransaction`.
pub struct OpenPgp {
    card: Box<dyn CardBackend + Send + Sync>,
}

impl OpenPgp {
    pub fn new<B>(backend: B) -> Self
    where
        B: Into<Box<dyn CardBackend + Send + Sync>>,
    {
        Self {
            card: backend.into(),
        }
    }

    /// Get an OpenPgpTransaction object. This starts a transaction on the underlying
    /// CardBackend.
    ///
    /// Note: transactions on the Card cannot be long running, they will be reset within seconds
    /// when idle.
    pub fn transaction(&mut self) -> Result<OpenPgpTransaction, Error> {
        Ok(OpenPgpTransaction {
            tx: self.card.transaction()?,
        })
    }
}

/// Low-level access to OpenPGP card functionality.
///
/// On backends that support transactions, operations are grouped together in transaction, while
/// an object of this type lives.
///
/// An OpenPgpTransaction on typical underlying card subsystems must be short lived. Typically,
/// smart cards can't be kept open for longer than a few seconds, before they are automatically
/// closed.
pub struct OpenPgpTransaction<'a> {
    tx: Box<dyn CardTransaction + Send + Sync + 'a>,
}

impl<'a> OpenPgpTransaction<'a> {
    pub(crate) fn tx(&mut self) -> &mut dyn CardTransaction {
        self.tx.as_mut()
    }

    // --- pinpad ---

    /// Does the reader support FEATURE_VERIFY_PIN_DIRECT?
    pub fn feature_pinpad_verify(&self) -> bool {
        self.tx.feature_pinpad_verify()
    }

    /// Does the reader support FEATURE_MODIFY_PIN_DIRECT?
    pub fn feature_pinpad_modify(&self) -> bool {
        self.tx.feature_pinpad_modify()
    }

    // --- get data ---

    /// Get the "application related data" from the card.
    ///
    /// (This data should probably be cached in a higher layer. Some parts of
    /// it are needed regularly, and it does not usually change during
    /// normal use of a card.)
    pub fn application_related_data(&mut self) -> Result<ApplicationRelatedData, Error> {
        log::info!("OpenPgpTransaction: application_related_data");

        self.tx.application_related_data()
    }

    // --- login data (5e) ---

    /// Get URL (5f50)
    pub fn url(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: url");

        let resp = apdu::send_command(self.tx(), commands::url(), true)?;

        Ok(resp.data()?.to_vec())
    }

    /// Get cardholder related data (65)
    pub fn cardholder_related_data(&mut self) -> Result<CardholderRelatedData, Error> {
        log::info!("OpenPgpTransaction: cardholder_related_data");

        let crd = commands::cardholder_related_data();
        let resp = apdu::send_command(self.tx(), crd, true)?;
        resp.check_ok()?;

        CardholderRelatedData::try_from(resp.data()?)
    }

    /// Get security support template (7a)
    pub fn security_support_template(&mut self) -> Result<SecuritySupportTemplate, Error> {
        log::info!("OpenPgpTransaction: security_support_template");

        let sst = commands::security_support_template();
        let resp = apdu::send_command(self.tx(), sst, true)?;
        resp.check_ok()?;

        let tlv = Tlv::try_from(resp.data()?)?;
        let res = tlv.find(Tag::from([0x93])).ok_or_else(|| {
            Error::NotFound("Couldn't get SecuritySupportTemplate DO".to_string())
        })?;

        if let Value::S(data) = res {
            let mut data = data.to_vec();
            if data.len() != 3 {
                return Err(Error::ParseError(format!(
                    "Unexpected length {} for 'Digital signature counter' DO",
                    data.len()
                )));
            }

            data.insert(0, 0); // prepend a zero
            let data: [u8; 4] = data.try_into().unwrap();

            let dsc: u32 = u32::from_be_bytes(data);
            Ok(SecuritySupportTemplate { dsc })
        } else {
            Err(Error::NotFound(
                "Failed to process SecuritySupportTemplate".to_string(),
            ))
        }
    }

    /// Get cardholder certificate (each for AUT, DEC and SIG).
    ///
    /// Call select_data() before calling this fn to select a particular
    /// certificate (if the card supports multiple certificates).
    ///
    /// According to the OpenPGP card specification:
    ///
    /// The cardholder certificate DOs are designed to store a certificate (e. g. X.509)
    /// for the keys in the card. They can be used to identify the card in a client-server
    /// authentication, where specific non-OpenPGP-certificates are needed, for S-MIME and
    /// other x.509 related functions.
    ///
    /// (See <https://support.nitrokey.com/t/nitrokey-pro-and-pkcs-11-support-on-linux/160/4>
    /// for some discussion of the `cardholder certificate` OpenPGP card feature)
    #[allow(dead_code)]
    pub fn cardholder_certificate(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: cardholder_certificate");

        let cmd = commands::cardholder_certificate();
        apdu::send_command(self.tx(), cmd, true)?.try_into()
    }

    /// Call "GET NEXT DATA" for the DO cardholder certificate.
    ///
    /// Cardholder certificate data for multiple slots can be read from the card by first calling
    /// cardholder_certificate(), followed by up to two calls to  next_cardholder_certificate().
    pub fn next_cardholder_certificate(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: next_cardholder_certificate");

        let cmd = commands::get_next_cardholder_certificate();
        apdu::send_command(self.tx(), cmd, true)?.try_into()
    }

    /// Get "Algorithm Information"
    pub fn algorithm_information(&mut self) -> Result<Option<AlgoInfo>, Error> {
        log::info!("OpenPgpTransaction: algorithm_information");

        let resp = apdu::send_command(self.tx(), commands::algo_info(), true)?;
        resp.check_ok()?;

        let ai = AlgoInfo::try_from(resp.data()?)?;
        Ok(Some(ai))
    }

    /// Get "Attestation Certificate (Yubico)"
    pub fn attestation_certificate(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: attestation_certificate");

        let resp = apdu::send_command(self.tx(), commands::attestation_certificate(), true)?;

        Ok(resp.data()?.into())
    }

    /// Firmware Version (YubiKey specific (?))
    pub fn firmware_version(&mut self) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: firmware_version");

        let resp = apdu::send_command(self.tx(), commands::firmware_version(), true)?;

        Ok(resp.data()?.into())
    }

    /// Set identity (Nitrokey Start specific (?)).
    /// [see:
    /// <https://docs.nitrokey.com/start/linux/multiple-identities.html>
    /// <https://github.com/Nitrokey/nitrokey-start-firmware/pull/33/>]
    pub fn set_identity(&mut self, id: u8) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: set_identity");

        let resp = apdu::send_command(self.tx(), commands::set_identity(id), false);

        // Apparently it's normal to get "NotTransacted" from pcsclite when
        // the identity switch was successful.
        if let Err(Error::Smartcard(SmartcardError::NotTransacted)) = resp {
            Ok(vec![])
        } else {
            Ok(resp?.data()?.into())
        }
    }

    /// SELECT DATA ("select a DO in the current template").
    ///
    /// This command currently only applies to
    /// [`cardholder_certificate`](OpenPgpTransaction::cardholder_certificate) and
    /// [`set_cardholder_certificate`](OpenPgpTransaction::set_cardholder_certificate)
    /// in OpenPGP card.
    ///
    /// `yk_workaround`: YubiKey 5 up to (and including) firmware version 5.4.3 need a workaround
    /// for this command. Set to `true` to apply this workaround.
    /// (When sending the SELECT DATA command as defined in the card spec, without enabling the
    /// workaround, bad YubiKey firmware versions (<= 5.4.3) return
    /// [`IncorrectParametersCommandDataField`](StatusBytes::IncorrectParametersCommandDataField))
    ///
    /// (This library leaves it up to consumers to decide on a strategy for dealing with this
    /// issue. Possible strategies include:
    /// - asking the card for its [`firmware_version`](OpenPgpTransaction::firmware_version)
    ///   and using the workaround if version <=5.4.3
    /// - trying this command first without the workaround, then with workaround if the card
    ///   returns
    ///   [`IncorrectParametersCommandDataField`](StatusBytes::IncorrectParametersCommandDataField)
    /// - for read operations: using
    ///   [`next_cardholder_certificate`](OpenPgpTransaction::next_cardholder_certificate)
    ///   instead of SELECT DATA)
    pub fn select_data(&mut self, num: u8, tag: &[u8], yk_workaround: bool) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: select_data");

        let tlv = Tlv::new(
            Tags::GeneralReference,
            Value::C(vec![Tlv::new(Tags::TagList, Value::S(tag.to_vec()))]),
        );

        let mut data = tlv.serialize();

        if yk_workaround {
            // Workaround for YubiKey 5.
            // This hack is needed <= 5.4.3 according to ykman sources
            // (see _select_certificate() in ykman/openpgp.py).

            assert!(data.len() <= 255); // catch blatant misuse: tags are 1-2 bytes long

            data.insert(0, data.len() as u8);
        }

        let cmd = commands::select_data(num, data);

        // Possible response data (Control Parameter = CP) don't need to be evaluated by the
        // application (See "7.2.5 SELECT DATA")
        apdu::send_command(self.tx(), cmd, true)?.try_into()?;

        Ok(())
    }

    // --- optional private DOs (0101 - 0104) ---

    /// Get data from "private use" DO.
    ///
    /// `num` must be between 1 and 4.
    pub fn private_use_do(&mut self, num: u8) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: private_use_do");

        assert!((1..=4).contains(&num));

        let cmd = commands::private_use_do(num);
        let resp = apdu::send_command(self.tx(), cmd, true)?;

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
    pub fn factory_reset(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: factory_reset");

        // send 4 bad requests to verify pw1
        // [apdu 00 20 00 81 08 40 40 40 40 40 40 40 40]
        for _ in 0..4 {
            log::info!("  verify_pw1_81");
            let verify = commands::verify_pw1_81([0x40; 8].to_vec());
            let resp = apdu::send_command(self.tx(), verify, false)?;
            if !(resp.status() == StatusBytes::SecurityStatusNotSatisfied
                || resp.status() == StatusBytes::AuthenticationMethodBlocked
                || matches!(resp.status(), StatusBytes::PasswordNotChecked(_)))
            {
                return Err(Error::InternalError(
                    "Unexpected status for reset, at pw1.".into(),
                ));
            }
        }

        // send 4 bad requests to verify pw3
        // [apdu 00 20 00 83 08 40 40 40 40 40 40 40 40]
        for _ in 0..4 {
            log::info!("  verify_pw3");
            let verify = commands::verify_pw3([0x40; 8].to_vec());
            let resp = apdu::send_command(self.tx(), verify, false)?;

            if !(resp.status() == StatusBytes::SecurityStatusNotSatisfied
                || resp.status() == StatusBytes::AuthenticationMethodBlocked
                || matches!(resp.status(), StatusBytes::PasswordNotChecked(_)))
            {
                return Err(Error::InternalError(
                    "Unexpected status for reset, at pw3.".into(),
                ));
            }
        }

        // terminate_df [apdu 00 e6 00 00]
        log::info!("  terminate_df");
        let term = commands::terminate_df();
        let resp = apdu::send_command(self.tx(), term, false)?;
        resp.check_ok()?;

        // activate_file [apdu 00 44 00 00]
        log::info!("  activate_file");
        let act = commands::activate_file();
        let resp = apdu::send_command(self.tx(), act, false)?;
        resp.check_ok()?;

        Ok(())
    }

    // --- verify/modify ---

    /// Verify pw1 (user) for signing operation (mode 81).
    ///
    /// Depending on the PW1 status byte (see Extended Capabilities) this
    /// access condition is only valid for one PSO:CDS command or remains
    /// valid for several attempts.
    pub fn verify_pw1_sign(&mut self, pin: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw1_sign");

        let verify = commands::verify_pw1_81(pin.to_vec());
        apdu::send_command(self.tx(), verify, false)?.try_into()
    }

    /// Verify pw1 (user) for signing operation (mode 81) using a
    /// pinpad on the card reader. If no usable pinpad is found, an error
    /// is returned.
    ///
    /// Depending on the PW1 status byte (see Extended Capabilities) this
    /// access condition is only valid for one PSO:CDS command or remains
    /// valid for several attempts.
    pub fn verify_pw1_sign_pinpad(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw1_sign_pinpad");

        let res = self.tx().pinpad_verify(PinType::Sign)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Check the current access of PW1 for signing (mode 81).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note:
    /// - some cards don't correctly implement this feature, e.g. YubiKey 5
    /// - some cards that don't support this instruction may decrease the pin's error count,
    ///   eventually requiring the user to reset the pin)
    pub fn check_pw1_sign(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: check_pw1_sign");

        let verify = commands::verify_pw1_81(vec![]);
        apdu::send_command(self.tx(), verify, false)?.try_into()
    }

    /// Verify PW1 (user).
    /// (For operations except signing, mode 82).
    pub fn verify_pw1_user(&mut self, pin: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw1_user");

        let verify = commands::verify_pw1_82(pin.to_vec());
        apdu::send_command(self.tx(), verify, false)?.try_into()
    }

    /// Verify PW1 (user) for operations except signing (mode 82),
    /// using a pinpad on the card reader. If no usable pinpad is found,
    /// an error is returned.

    pub fn verify_pw1_user_pinpad(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw1_user_pinpad");

        let res = self.tx().pinpad_verify(PinType::User)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Check the current access of PW1.
    /// (For operations except signing, mode 82).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note:
    /// - some cards don't correctly implement this feature, e.g. YubiKey 5
    /// - some cards that don't support this instruction may decrease the pin's error count,
    ///   eventually requiring the user to reset the pin)
    pub fn check_pw1_user(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: check_pw1_user");

        let verify = commands::verify_pw1_82(vec![]);
        apdu::send_command(self.tx(), verify, false)?.try_into()
    }

    /// Verify PW3 (admin).
    pub fn verify_pw3(&mut self, pin: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw3");

        let verify = commands::verify_pw3(pin.to_vec());
        apdu::send_command(self.tx(), verify, false)?.try_into()
    }

    /// Verify PW3 (admin) using a pinpad on the card reader. If no usable
    /// pinpad is found, an error is returned.
    pub fn verify_pw3_pinpad(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: verify_pw3_pinpad");

        let res = self.tx().pinpad_verify(PinType::Admin)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Check the current access of PW3 (admin).
    ///
    /// If verification is not required, an empty Ok Response is returned.
    ///
    /// (Note:
    /// - some cards don't correctly implement this feature, e.g. YubiKey 5
    /// - some cards that don't support this instruction may decrease the pin's error count,
    ///   eventually requiring the user to reset the pin)
    pub fn check_pw3(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: check_pw3");

        let verify = commands::verify_pw3(vec![]);
        apdu::send_command(self.tx(), verify, false)?.try_into()
    }

    /// Change the value of PW1 (user password).
    ///
    /// The current value of PW1 must be presented in `old` for authorization.
    pub fn change_pw1(&mut self, old: &[u8], new: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: change_pw1");

        let mut data = vec![];
        data.extend(old);
        data.extend(new);

        let change = commands::change_pw1(data);
        apdu::send_command(self.tx(), change, false)?.try_into()
    }

    /// Change the value of PW1 (0x81) using a pinpad on the
    /// card reader. If no usable pinpad is found, an error is returned.
    pub fn change_pw1_pinpad(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: change_pw1_pinpad");

        // Note: for change PW, only 0x81 and 0x83 are used!
        // 0x82 is implicitly the same as 0x81.
        let res = self.tx().pinpad_modify(PinType::Sign)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Change the value of PW3 (admin password).
    ///
    /// The current value of PW3 must be presented in `old` for authorization.
    pub fn change_pw3(&mut self, old: &[u8], new: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: change_pw3");

        let mut data = vec![];
        data.extend(old);
        data.extend(new);

        let change = commands::change_pw3(data);
        apdu::send_command(self.tx(), change, false)?.try_into()
    }

    /// Change the value of PW3 (admin password) using a pinpad on the
    /// card reader. If no usable pinpad is found, an error is returned.
    pub fn change_pw3_pinpad(&mut self) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: change_pw3_pinpad");

        let res = self.tx().pinpad_modify(PinType::Admin)?;
        RawResponse::try_from(res)?.try_into()
    }

    /// Reset the error counter for PW1 (user password) and set a new value
    /// for PW1.
    ///
    /// For authorization, either:
    /// - PW3 must have been verified previously,
    /// - secure messaging must be currently used,
    /// - the resetting_code must be presented.
    pub fn reset_retry_counter_pw1(
        &mut self,
        new_pw1: &[u8],
        resetting_code: Option<&[u8]>,
    ) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: reset_retry_counter_pw1");

        let reset = commands::reset_retry_counter_pw1(resetting_code, new_pw1);
        apdu::send_command(self.tx(), reset, false)?.try_into()
    }

    // --- decrypt ---

    /// Decrypt the ciphertext in `dm`, on the card.
    ///
    /// (This is a wrapper around the low-level pso_decipher
    /// operation, it builds the required `data` field from `dm`)
    pub fn decipher(&mut self, dm: Cryptogram) -> Result<Vec<u8>, Error> {
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
                let epk = Tlv::new(Tags::ExternalPublicKey, Value::S(eph.to_vec()));

                // Public Key DO
                let pkdo = Tlv::new(Tags::PublicKey, Value::C(vec![epk]));

                // Cipher DO
                let cdo = Tlv::new(Tags::Cipher, Value::C(vec![pkdo]));

                self.pso_decipher(cdo.serialize())
            }
        }
    }

    /// Run decryption operation on the smartcard (low level operation)
    /// (7.2.11 PSO: DECIPHER)
    ///
    /// (consider using the `decipher()` method if you don't want to create
    /// the data field manually)
    pub fn pso_decipher(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: pso_decipher");

        // The OpenPGP card is already connected and PW1 82 has been verified
        let dec_cmd = commands::decryption(data);
        let resp = apdu::send_command(self.tx(), dec_cmd, true)?;
        resp.check_ok()?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }

    /// Set the key to be used for the pso_decipher and the internal_authenticate commands.
    ///
    /// Valid until next reset of of the card or the next call to `select`
    /// The only keys that can be configured by this command are the `Decryption` and `Authentication` keys.
    ///
    /// The following first sets the *Authentication* key to be used for [pso_decipher](OpenPgpTransaction::pso_decipher)
    /// and then sets the *Decryption* key to be used for [internal_authenticate](OpenPgpTransaction::internal_authenticate).
    ///
    /// ```no_run
    /// # use openpgp_card::{KeyType, OpenPgpTransaction};
    /// # let mut tx: OpenPgpTransaction<'static> = panic!();
    /// tx.manage_security_environment(KeyType::Decryption, KeyType::Authentication)?;
    /// tx.manage_security_environment(KeyType::Authentication, KeyType::Decryption)?;
    /// # Result::<(), openpgp_card::Error>::Ok(())
    /// ```
    pub fn manage_security_environment(
        &mut self,
        for_operation: KeyType,
        key_ref: KeyType,
    ) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: manage_security_environment");

        if !matches!(for_operation, KeyType::Authentication | KeyType::Decryption)
            || !matches!(key_ref, KeyType::Authentication | KeyType::Decryption)
        {
            return Err(Error::UnsupportedAlgo("Only Decryption and Authentication keys can be manipulated by manage_security_environment".to_string()));
        }

        let cmd = commands::manage_security_environment(for_operation, key_ref);
        let resp = apdu::send_command(self.tx(), cmd, false)?;
        resp.check_ok()?;
        Ok(())
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
    pub fn signature_for_hash(&mut self, hash: Hash) -> Result<Vec<u8>, Error> {
        self.pso_compute_digital_signature(digestinfo(hash))
    }

    /// Run signing operation on the smartcard (low level operation)
    /// (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)
    ///
    /// (consider using the `signature_for_hash()` method if you don't
    /// want to create the data field manually)
    pub fn pso_compute_digital_signature(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: pso_compute_digital_signature");

        let cds_cmd = commands::signature(data);

        let resp = apdu::send_command(self.tx(), cds_cmd, true)?;

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
    pub fn authenticate_for_hash(&mut self, hash: Hash) -> Result<Vec<u8>, Error> {
        self.internal_authenticate(digestinfo(hash))
    }

    /// Run signing operation on the smartcard (low level operation)
    /// (7.2.13 INTERNAL AUTHENTICATE)
    ///
    /// (consider using the `authenticate_for_hash()` method if you don't
    /// want to create the data field manually)
    pub fn internal_authenticate(&mut self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: internal_authenticate");

        let ia_cmd = commands::internal_authenticate(data);
        let resp = apdu::send_command(self.tx(), ia_cmd, true)?;

        Ok(resp.data().map(|d| d.to_vec())?)
    }

    // --- PUT DO ---

    /// Set data of "private use" DO.
    ///
    /// `num` must be between 1 and 4.
    ///
    /// Access condition:
    /// - 1/3 need PW1 (82)
    /// - 2/4 need PW3
    pub fn set_private_use_do(&mut self, num: u8, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        log::info!("OpenPgpTransaction: set_private_use_do");

        assert!((1..=4).contains(&num));

        let cmd = commands::put_private_use_do(num, data);
        let resp = apdu::send_command(self.tx(), cmd, true)?;

        Ok(resp.data()?.to_vec())
    }

    pub fn set_name(&mut self, name: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_name");

        let put_name = commands::put_name(name.to_vec());
        apdu::send_command(self.tx(), put_name, false)?.try_into()
    }

    pub fn set_lang(&mut self, lang: &[Lang]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_lang");

        let bytes: Vec<u8> = lang
            .iter()
            .flat_map(|&l| Into::<Vec<u8>>::into(l))
            .collect();

        let put_lang = commands::put_lang(bytes);
        apdu::send_command(self.tx(), put_lang, false)?.try_into()
    }

    pub fn set_sex(&mut self, sex: Sex) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_sex");

        let put_sex = commands::put_sex((&sex).into());
        apdu::send_command(self.tx(), put_sex, false)?.try_into()
    }

    pub fn set_url(&mut self, url: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_url");

        let put_url = commands::put_url(url.to_vec());
        apdu::send_command(self.tx(), put_url, false)?.try_into()
    }

    /// Set cardholder certificate (for AUT, DEC or SIG).
    ///
    /// Call select_data() before calling this fn to select a particular
    /// certificate (if the card supports multiple certificates).
    pub fn set_cardholder_certificate(&mut self, data: Vec<u8>) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_cardholder_certificate");

        let cmd = commands::put_cardholder_certificate(data);
        apdu::send_command(self.tx(), cmd, false)?.try_into()
    }

    /// Set algorithm attributes
    /// (4.4.3.9 Algorithm Attributes)
    pub fn set_algorithm_attributes(
        &mut self,
        key_type: KeyType,
        algo: &Algo,
    ) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_algorithm_attributes");

        // Command to PUT the algorithm attributes
        let cmd = commands::put_data(key_type.algorithm_tag(), algo.to_data_object()?);

        apdu::send_command(self.tx(), cmd, false)?.try_into()
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
        pw_status: &PWStatusBytes,
        long: bool,
    ) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_pw_status_bytes");

        let data = pw_status.serialize_for_put(long);

        let cmd = commands::put_pw_status(data);
        apdu::send_command(self.tx(), cmd, false)?.try_into()
    }

    pub fn set_fingerprint(&mut self, fp: Fingerprint, key_type: KeyType) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_fingerprint");

        let fp_cmd = commands::put_data(key_type.fingerprint_put_tag(), fp.as_bytes().to_vec());

        apdu::send_command(self.tx(), fp_cmd, false)?.try_into()
    }

    pub fn set_ca_fingerprint_1(&mut self, fp: Fingerprint) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_ca_fingerprint_1");

        let fp_cmd = commands::put_data(Tags::CaFingerprint1, fp.as_bytes().to_vec());
        apdu::send_command(self.tx(), fp_cmd, false)?.try_into()
    }

    pub fn set_ca_fingerprint_2(&mut self, fp: Fingerprint) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_ca_fingerprint_2");

        let fp_cmd = commands::put_data(Tags::CaFingerprint2, fp.as_bytes().to_vec());
        apdu::send_command(self.tx(), fp_cmd, false)?.try_into()
    }

    pub fn set_ca_fingerprint_3(&mut self, fp: Fingerprint) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_ca_fingerprint_3");

        let fp_cmd = commands::put_data(Tags::CaFingerprint3, fp.as_bytes().to_vec());
        apdu::send_command(self.tx(), fp_cmd, false)?.try_into()
    }

    pub fn set_creation_time(
        &mut self,
        time: KeyGenerationTime,
        key_type: KeyType,
    ) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_creation_time");

        // Timestamp update
        let time_value: Vec<u8> = time
            .get()
            .to_be_bytes()
            .iter()
            .skip_while(|&&e| e == 0)
            .copied()
            .collect();

        let time_cmd = commands::put_data(key_type.timestamp_put_tag(), time_value);

        apdu::send_command(self.tx(), time_cmd, false)?.try_into()
    }

    // FIXME: optional DO SM-Key-ENC

    // FIXME: optional DO SM-Key-MAC

    /// Set resetting code
    /// (4.3.4 Resetting Code)
    pub fn set_resetting_code(&mut self, resetting_code: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_resetting_code");

        let cmd = commands::put_data(Tags::ResettingCode, resetting_code.to_vec());
        apdu::send_command(self.tx(), cmd, false)?.try_into()
    }

    /// Set AES key for symmetric decryption/encryption operations.
    ///
    /// Optional DO (announced in Extended Capabilities) for
    /// PSO:ENC/DEC with AES (32 bytes dec. in case of
    /// AES256, 16 bytes dec. in case of AES128).
    pub fn set_pso_enc_dec_key(&mut self, key: &[u8]) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_pso_enc_dec_key");

        let fp_cmd = commands::put_data(Tags::PsoEncDecKey, key.to_vec());

        apdu::send_command(self.tx(), fp_cmd, false)?.try_into()
    }

    // FIXME: optional DO for PSO:ENC/DEC with AES

    /// Set UIF for PSO:CDS
    pub fn set_uif_pso_cds(&mut self, uif: &UIF) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_uif_pso_cds");

        let cmd = commands::put_data(Tags::UifSig, uif.as_bytes().to_vec());
        apdu::send_command(self.tx(), cmd, false)?.try_into()
    }

    /// Set UIF for PSO:DEC
    pub fn set_uif_pso_dec(&mut self, uif: &UIF) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_uif_pso_dec");

        let cmd = commands::put_data(Tags::UifDec, uif.as_bytes().to_vec());
        apdu::send_command(self.tx(), cmd, false)?.try_into()
    }

    /// Set UIF for PSO:AUT
    pub fn set_uif_pso_aut(&mut self, uif: &UIF) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_uif_pso_aut");

        let cmd = commands::put_data(Tags::UifAuth, uif.as_bytes().to_vec());
        apdu::send_command(self.tx(), cmd, false)?.try_into()
    }

    /// Set UIF for Attestation key
    pub fn set_uif_attestation(&mut self, uif: &UIF) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: set_uif_attestation");

        let cmd = commands::put_data(Tags::UifAttestation, uif.as_bytes().to_vec());
        apdu::send_command(self.tx(), cmd, false)?.try_into()
    }

    /// Generate Attestation (Yubico)
    pub fn generate_attestation(&mut self, key_type: KeyType) -> Result<(), Error> {
        log::info!("OpenPgpTransaction: generate_attestation");

        let key = match key_type {
            KeyType::Signing => 0x01,
            KeyType::Decryption => 0x02,
            KeyType::Authentication => 0x03,
            _ => return Err(Error::InternalError("Unexpected KeyType".to_string())),
        };

        let cmd = commands::generate_attestation(key);
        apdu::send_command(self.tx(), cmd, false)?.try_into()
    }

    // FIXME: Attestation key algo attr, FP, CA-FP, creation time

    // FIXME: SM keys (ENC and MAC) with Tags D1 and D2

    // FIXME: KDF DO

    // FIXME: certificate used with secure messaging

    // FIXME: Attestation Certificate (Yubico)

    // -----------------

    /// Import an existing private key to the card.
    /// (This implicitly sets the algorithm info, fingerprint and timestamp)
    pub fn key_import(
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
    pub fn generate_key(
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
    pub fn generate_key_simple(
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
    pub fn public_key(&mut self, key_type: KeyType) -> Result<PublicKeyMaterial, Error> {
        keys::public_key(self, key_type)
    }
}

fn digestinfo(hash: Hash) -> Vec<u8> {
    match hash {
        Hash::SHA256(_) | Hash::SHA384(_) | Hash::SHA512(_) => {
            let tlv = Tlv::new(
                Tags::Sequence,
                Value::C(vec![
                    Tlv::new(
                        Tags::Sequence,
                        Value::C(vec![
                            Tlv::new(
                                Tags::ObjectIdentifier,
                                // unwrapping is ok, for SHA*
                                Value::S(hash.oid().unwrap().to_vec()),
                            ),
                            Tlv::new(Tags::Null, Value::S(vec![])),
                        ]),
                    ),
                    Tlv::new(Tags::OctetString, Value::S(hash.digest().to_vec())),
                ]),
            );

            tlv.serialize()
        }
        Hash::EdDSA(d) => d.to_vec(),
        Hash::ECDSA(d) => d.to_vec(),
    }
}
