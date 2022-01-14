// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Perform operations on a card. Different states of a card are modeled by
//! different types, such as `Open`, `User`, `Sign`, `Admin`.

use anyhow::{anyhow, Result};

use sequoia_openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use sequoia_openpgp::packet::key::SecretParts;
use sequoia_openpgp::Cert;

use openpgp_card::algorithm::{Algo, AlgoInfo, AlgoSimple};
use openpgp_card::card_do::{
    ApplicationIdentifier, ApplicationRelatedData, CardholderRelatedData,
    ExtendedCapabilities, ExtendedLengthInfo, Fingerprint, HistoricalBytes,
    KeyGenerationTime, PWStatusBytes, SecuritySupportTemplate, Sex,
};
use openpgp_card::{CardApp, CardClient, Error, KeySet, KeyType, Response};

use crate::decryptor::CardDecryptor;
use crate::signer::CardSigner;
use crate::util::{public_to_fingerprint, vka_as_uploadable_key};
use crate::PublicKey;
use openpgp_card::crypto_data::PublicKeyMaterial;

/// Representation of an opened OpenPGP card in its base state (i.e. no
/// passwords have been verified, default authorization applies).
pub struct Open<'a> {
    card_client: &'a mut (dyn CardClient + Send + Sync),

    // Cache of "application related data".
    //
    // FIXME: Should be invalidated when changing data on the card!
    // (e.g. uploading keys, etc)
    ard: ApplicationRelatedData,

    // verify status of pw1
    pw1: bool,

    // verify status of pw1 for signing
    pw1_sign: bool,

    // verify status of pw3
    pw3: bool,
}

impl<'a> Open<'a> {
    pub fn new(
        card_client: &'a mut (dyn CardClient + Send + Sync),
    ) -> Result<Self, Error> {
        let ard = CardApp::application_related_data(card_client)?;

        Ok(Self {
            card_client,
            ard,
            pw1: false,
            pw1_sign: false,
            pw3: false,
        })
    }
    pub fn feature_pinpad_verify(&mut self) -> bool {
        CardApp::feature_pinpad_verify(self.card_client)
    }

    pub fn feature_pinpad_modify(&mut self) -> bool {
        CardApp::feature_pinpad_modify(self.card_client)
    }

    pub fn verify_user(&mut self, pin: &str) -> Result<(), Error> {
        let _ = CardApp::verify_pw1(self.card_client, pin)?;
        self.pw1 = true;
        Ok(())
    }

    pub fn verify_user_pinpad(
        &mut self,
        prompt: &dyn Fn(),
    ) -> Result<(), Error> {
        prompt();

        let _ = CardApp::verify_pw1_pinpad(self.card_client)?;
        self.pw1 = true;
        Ok(())
    }

    pub fn verify_user_for_signing(&mut self, pin: &str) -> Result<(), Error> {
        let _ = CardApp::verify_pw1_for_signing(self.card_client, pin)?;

        // FIXME: depending on card mode, pw1_sign is only usable once

        self.pw1_sign = true;
        Ok(())
    }

    pub fn verify_user_for_signing_pinpad(
        &mut self,
        prompt: &dyn Fn(),
    ) -> Result<(), Error> {
        prompt();

        let _ = CardApp::verify_pw1_for_signing_pinpad(self.card_client)?;

        // FIXME: depending on card mode, pw1_sign is only usable once

        self.pw1_sign = true;
        Ok(())
    }

    pub fn verify_admin(&mut self, pin: &str) -> Result<(), Error> {
        let _ = CardApp::verify_pw3(self.card_client, pin)?;
        self.pw3 = true;
        Ok(())
    }

    pub fn verify_admin_pinpad(
        &mut self,
        prompt: &dyn Fn(),
    ) -> Result<(), Error> {
        prompt();

        let _ = CardApp::verify_pw3_pinpad(self.card_client)?;
        self.pw3 = true;
        Ok(())
    }

    /// Ask the card if the user password has been successfully verified.
    ///
    /// NOTE: on some cards this functionality seems broken.
    pub fn check_user_verified(&mut self) -> Result<Response, Error> {
        CardApp::check_pw1(self.card_client)
    }

    /// Ask the card if the admin password has been successfully verified.
    ///
    /// NOTE: on some cards this functionality seems broken.
    pub fn check_admin_verified(&mut self) -> Result<Response, Error> {
        CardApp::check_pw3(self.card_client)
    }

    pub fn change_user_pin(
        &mut self,
        old: &str,
        new: &str,
    ) -> Result<Response, Error> {
        CardApp::change_pw1(self.card_client, old, new)
    }

    pub fn change_user_pin_pinpad(
        &mut self,
        prompt: &dyn Fn(),
    ) -> Result<Response, Error> {
        prompt();
        CardApp::change_pw1_pinpad(self.card_client)
    }

    pub fn reset_user_pin(
        &mut self,
        rst: &str,
        new: &str,
    ) -> Result<Response, Error> {
        CardApp::reset_retry_counter_pw1(
            self.card_client,
            new.into(),
            Some(rst.into()),
        )
    }

    pub fn change_admin_pin(
        &mut self,
        old: &str,
        new: &str,
    ) -> Result<Response, Error> {
        CardApp::change_pw3(self.card_client, old, new)
    }

    pub fn change_admin_pin_pinpad(
        &mut self,
        prompt: &dyn Fn(),
    ) -> Result<Response, Error> {
        prompt();
        CardApp::change_pw3_pinpad(self.card_client)
    }

    /// Get a view of the card authenticated for "User" commands.
    pub fn user_card<'b>(&'a mut self) -> Option<User<'a, 'b>> {
        if self.pw1 {
            Some(User { oc: self })
        } else {
            None
        }
    }

    /// Get a view of the card authenticated for Signing.
    pub fn signing_card<'b>(&'b mut self) -> Option<Sign<'a, 'b>> {
        if self.pw1_sign {
            Some(Sign { oc: self })
        } else {
            None
        }
    }

    /// Get a view of the card authenticated for "Admin" commands.
    pub fn admin_card<'b>(&'b mut self) -> Option<Admin<'a, 'b>> {
        if self.pw3 {
            Some(Admin { oc: self })
        } else {
            None
        }
    }

    // --- application data ---

    pub fn application_identifier(
        &self,
    ) -> Result<ApplicationIdentifier, Error> {
        self.ard.application_id()
    }

    pub fn historical_bytes(&self) -> Result<HistoricalBytes, Error> {
        self.ard.historical_bytes()
    }

    pub fn extended_length_information(
        &self,
    ) -> Result<Option<ExtendedLengthInfo>> {
        self.ard.extended_length_information()
    }

    #[allow(dead_code)]
    fn general_feature_management() -> Option<bool> {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn discretionary_data_objects() {
        unimplemented!()
    }

    pub fn extended_capabilities(
        &self,
    ) -> Result<ExtendedCapabilities, Error> {
        self.ard.extended_capabilities()
    }

    pub fn algorithm_attributes(&self, key_type: KeyType) -> Result<Algo> {
        self.ard.algorithm_attributes(key_type)
    }

    /// PW status Bytes
    pub fn pw_status_bytes(&self) -> Result<PWStatusBytes> {
        self.ard.pw_status_bytes()
    }

    pub fn fingerprints(&self) -> Result<KeySet<Fingerprint>, Error> {
        self.ard.fingerprints()
    }

    #[allow(dead_code)]
    fn ca_fingerprints(&self) {
        unimplemented!()
    }

    pub fn key_generation_times(
        &self,
    ) -> Result<KeySet<KeyGenerationTime>, Error> {
        self.ard.key_generation_times()
    }

    #[allow(dead_code)]
    fn key_information() {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn uif_pso_cds() {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn uif_pso_dec() {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn uif_pso_aut() {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn uif_attestation() {
        unimplemented!()
    }

    // --- optional private DOs (0101 - 0104) ---

    // --- login data (5e) ---

    // --- URL (5f50) ---

    pub fn url(&mut self) -> Result<String> {
        CardApp::url(self.card_client)
    }

    // --- cardholder related data (65) ---
    pub fn cardholder_related_data(
        &mut self,
    ) -> Result<CardholderRelatedData> {
        CardApp::cardholder_related_data(self.card_client)
    }

    // --- security support template (7a) ---
    pub fn security_support_template(
        &mut self,
    ) -> Result<SecuritySupportTemplate> {
        CardApp::security_support_template(self.card_client)
    }

    // DO "Algorithm Information" (0xFA)
    pub fn algorithm_information(&mut self) -> Result<Option<AlgoInfo>> {
        // The DO "Algorithm Information" (Tag FA) shall be present if
        // Algorithm attributes can be changed
        let ec = self.extended_capabilities()?;
        if !ec.algo_attrs_changeable() {
            // Algorithm attributes can not be changed,
            // list_supported_algo is not supported
            return Ok(None);
        }

        CardApp::algorithm_information(self.card_client)
    }

    /// Firmware Version, YubiKey specific (?)
    pub fn firmware_version(&mut self) -> Result<Vec<u8>> {
        CardApp::firmware_version(self.card_client)
    }

    // ----------

    pub fn public_key(
        &mut self,
        key_type: KeyType,
    ) -> Result<PublicKeyMaterial> {
        CardApp::public_key(self.card_client, key_type).map_err(|e| e.into())
    }

    // ----------

    /// Delete all state on this OpenPGP card
    pub fn factory_reset(&mut self) -> Result<()> {
        CardApp::factory_reset(self.card_client)
    }
}

/// An OpenPGP card after successfully verifying PW1 in mode 82
/// (verification for user operations other than signing)
pub struct User<'app, 'open> {
    oc: &'open mut Open<'app>,
}

impl User<'_, '_> {
    pub fn decryptor(&mut self, cert: &Cert) -> Result<CardDecryptor, Error> {
        CardDecryptor::new(self.oc.card_client, cert)
    }
}

/// An OpenPGP card after successfully verifying PW1 in mode 81
/// (verification for signing)
pub struct Sign<'app, 'open> {
    oc: &'open mut Open<'app>,
}

impl Sign<'_, '_> {
    pub fn signer(
        &mut self,
        cert: &Cert,
    ) -> std::result::Result<CardSigner, Error> {
        // FIXME: depending on the setting in "PW1 Status byte", only one
        // signature can be made after verification for signing

        CardSigner::new(self.oc.card_client, cert)
    }

    pub fn signer_from_pubkey(&mut self, pubkey: PublicKey) -> CardSigner {
        // FIXME: depending on the setting in "PW1 Status byte", only one
        // signature can be made after verification for signing

        CardSigner::with_pubkey(self.oc.card_client, pubkey)
    }
}

/// An OpenPGP card after successful verification of PW3 ("Admin privileges")
pub struct Admin<'app, 'open> {
    oc: &'open mut Open<'app>,
}

impl<'app, 'open> Admin<'app, 'open> {
    pub fn as_open(&'_ mut self) -> &mut Open<'app> {
        self.oc
    }
}

impl Admin<'_, '_> {
    pub fn set_name(&mut self, name: &str) -> Result<Response, Error> {
        if name.len() >= 40 {
            return Err(anyhow!("name too long").into());
        }

        // All chars must be in ASCII7
        if name.chars().any(|c| !c.is_ascii()) {
            return Err(anyhow!("Invalid char in name").into());
        };

        CardApp::set_name(self.oc.card_client, name)
    }

    pub fn set_lang(&mut self, lang: &str) -> Result<Response, Error> {
        if lang.len() > 8 {
            return Err(anyhow!("lang too long").into());
        }

        CardApp::set_lang(self.oc.card_client, lang)
    }

    pub fn set_sex(&mut self, sex: Sex) -> Result<Response, Error> {
        CardApp::set_sex(self.oc.card_client, sex)
    }

    pub fn set_url(&mut self, url: &str) -> Result<Response, Error> {
        if url.chars().any(|c| !c.is_ascii()) {
            return Err(anyhow!("Invalid char in url").into());
        }

        // Check for max len
        let ec = self.oc.extended_capabilities()?;

        if ec.max_len_special_do() == None
            || url.len() <= ec.max_len_special_do().unwrap() as usize
        {
            // If we don't know the max length for URL ("special DO"),
            // or if it's within the acceptable length:
            // send the url update to the card.

            CardApp::set_url(self.oc.card_client, url)
        } else {
            Err(anyhow!("URL too long").into())
        }
    }

    pub fn set_resetting_code(
        &mut self,
        pin: &str,
    ) -> Result<Response, Error> {
        CardApp::set_resetting_code(self.oc.card_client, pin.into())
    }

    pub fn reset_user_pin(&mut self, new: &str) -> Result<Response, Error> {
        CardApp::reset_retry_counter_pw1(self.oc.card_client, new.into(), None)
    }

    /// Upload a ValidErasedKeyAmalgamation to the card as a specific KeyType.
    ///
    /// (The caller needs to make sure that `vka` is suitable as `key_type`)
    pub fn upload_key(
        &mut self,
        vka: ValidErasedKeyAmalgamation<SecretParts>,
        key_type: KeyType,
        password: Option<String>,
    ) -> Result<(), Error> {
        let key = vka_as_uploadable_key(vka, password);
        CardApp::key_import(self.oc.card_client, key, key_type)
    }

    pub fn generate_key_simple(
        &mut self,
        key_type: KeyType,
        algo: Option<AlgoSimple>,
    ) -> Result<(PublicKeyMaterial, KeyGenerationTime), Error> {
        match algo {
            Some(algo) => CardApp::generate_key_simple(
                self.oc.card_client,
                public_to_fingerprint,
                key_type,
                algo,
            ),
            None => CardApp::generate_key(
                self.oc.card_client,
                public_to_fingerprint,
                key_type,
                None,
            ),
        }
    }
}
