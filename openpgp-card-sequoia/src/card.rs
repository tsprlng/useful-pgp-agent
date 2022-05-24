// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Perform operations on a card. Different states of a card are modeled by
//! different types, such as `Open`, `User`, `Sign`, `Admin`.

use sequoia_openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use sequoia_openpgp::packet::key::SecretParts;
use sequoia_openpgp::types::{HashAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp::Cert;

use openpgp_card::algorithm::{Algo, AlgoInfo, AlgoSimple};
use openpgp_card::card_do::{
    ApplicationIdentifier, ApplicationRelatedData, CardholderRelatedData, ExtendedCapabilities,
    ExtendedLengthInfo, Fingerprint, HistoricalBytes, KeyGenerationTime, Lang, PWStatusBytes,
    SecuritySupportTemplate, Sex,
};
use openpgp_card::{Error, KeySet, KeyType, OpenPgpTransaction};

use crate::decryptor::CardDecryptor;
use crate::signer::CardSigner;
use crate::util::{public_to_fingerprint, vka_as_uploadable_key};
use crate::PublicKey;
use openpgp_card::crypto_data::PublicKeyMaterial;

/// Representation of an opened OpenPGP card in its base state (i.e. no
/// passwords have been verified, default authorization applies).
pub struct Open<'a> {
    opt: OpenPgpTransaction<'a>,

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
    pub fn new(mut ca: OpenPgpTransaction<'a>) -> Result<Self, Error> {
        let ard = ca.application_related_data()?;

        Ok(Self {
            opt: ca,
            ard,
            pw1: false,
            pw1_sign: false,
            pw3: false,
        })
    }

    pub fn feature_pinpad_verify(&mut self) -> bool {
        self.opt.feature_pinpad_verify()
    }

    pub fn feature_pinpad_modify(&mut self) -> bool {
        self.opt.feature_pinpad_modify()
    }

    pub fn verify_user(&mut self, pin: &[u8]) -> Result<(), Error> {
        let _ = self.opt.verify_pw1_user(pin)?;
        self.pw1 = true;
        Ok(())
    }

    pub fn verify_user_pinpad(&mut self, prompt: &dyn Fn()) -> Result<(), Error> {
        prompt();

        let _ = self.opt.verify_pw1_user_pinpad()?;
        self.pw1 = true;
        Ok(())
    }

    pub fn verify_user_for_signing(&mut self, pin: &[u8]) -> Result<(), Error> {
        let _ = self.opt.verify_pw1_sign(pin)?;

        // FIXME: depending on card mode, pw1_sign is only usable once

        self.pw1_sign = true;
        Ok(())
    }

    pub fn verify_user_for_signing_pinpad(&mut self, prompt: &dyn Fn()) -> Result<(), Error> {
        prompt();

        let _ = self.opt.verify_pw1_sign_pinpad()?;

        // FIXME: depending on card mode, pw1_sign is only usable once

        self.pw1_sign = true;
        Ok(())
    }

    pub fn verify_admin(&mut self, pin: &[u8]) -> Result<(), Error> {
        let _ = self.opt.verify_pw3(pin)?;
        self.pw3 = true;
        Ok(())
    }

    pub fn verify_admin_pinpad(&mut self, prompt: &dyn Fn()) -> Result<(), Error> {
        prompt();

        let _ = self.opt.verify_pw3_pinpad()?;
        self.pw3 = true;
        Ok(())
    }

    /// Ask the card if the user password has been successfully verified.
    ///
    /// NOTE: on some cards this functionality seems broken.
    pub fn check_user_verified(&mut self) -> Result<(), Error> {
        self.opt.check_pw1_user()
    }

    /// Ask the card if the admin password has been successfully verified.
    ///
    /// NOTE: on some cards this functionality seems broken.
    pub fn check_admin_verified(&mut self) -> Result<(), Error> {
        self.opt.check_pw3()
    }

    pub fn change_user_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), Error> {
        self.opt.change_pw1(old, new)
    }

    pub fn change_user_pin_pinpad(&mut self, prompt: &dyn Fn()) -> Result<(), Error> {
        prompt();
        self.opt.change_pw1_pinpad()
    }

    pub fn reset_user_pin(&mut self, rst: &[u8], new: &[u8]) -> Result<(), Error> {
        self.opt.reset_retry_counter_pw1(new, Some(rst))
    }

    pub fn change_admin_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), Error> {
        self.opt.change_pw3(old, new)
    }

    pub fn change_admin_pin_pinpad(&mut self, prompt: &dyn Fn()) -> Result<(), Error> {
        prompt();
        self.opt.change_pw3_pinpad()
    }

    /// Get a view of the card authenticated for "User" commands.
    pub fn user_card<'b>(&'b mut self) -> Option<User<'a, 'b>> {
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

    pub fn application_identifier(&self) -> Result<ApplicationIdentifier, Error> {
        self.ard.application_id()
    }

    pub fn historical_bytes(&self) -> Result<HistoricalBytes, Error> {
        self.ard.historical_bytes()
    }

    pub fn extended_length_information(&self) -> Result<Option<ExtendedLengthInfo>, Error> {
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

    pub fn extended_capabilities(&self) -> Result<ExtendedCapabilities, Error> {
        self.ard.extended_capabilities()
    }

    pub fn algorithm_attributes(&self, key_type: KeyType) -> Result<Algo, Error> {
        self.ard.algorithm_attributes(key_type)
    }

    /// PW status Bytes
    pub fn pw_status_bytes(&self) -> Result<PWStatusBytes, Error> {
        self.ard.pw_status_bytes()
    }

    pub fn fingerprints(&self) -> Result<KeySet<Fingerprint>, Error> {
        self.ard.fingerprints()
    }

    #[allow(dead_code)]
    fn ca_fingerprints(&self) {
        unimplemented!()
    }

    pub fn key_generation_times(&self) -> Result<KeySet<KeyGenerationTime>, Error> {
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

    pub fn url(&mut self) -> Result<String, Error> {
        Ok(String::from_utf8_lossy(&self.opt.url()?).to_string())
    }

    // --- cardholder related data (65) ---
    pub fn cardholder_related_data(&mut self) -> Result<CardholderRelatedData, Error> {
        self.opt.cardholder_related_data()
    }

    // --- security support template (7a) ---
    pub fn security_support_template(&mut self) -> Result<SecuritySupportTemplate, Error> {
        self.opt.security_support_template()
    }

    // DO "Algorithm Information" (0xFA)
    pub fn algorithm_information(&mut self) -> Result<Option<AlgoInfo>, Error> {
        // The DO "Algorithm Information" (Tag FA) shall be present if
        // Algorithm attributes can be changed
        let ec = self.extended_capabilities()?;
        if !ec.algo_attrs_changeable() {
            // Algorithm attributes can not be changed,
            // list_supported_algo is not supported
            return Ok(None);
        }

        self.opt.algorithm_information()
    }

    /// Get "Attestation Certificate (Yubico)"
    pub fn attestation_certificate(&mut self) -> Result<Vec<u8>, Error> {
        self.opt.attestation_certificate()
    }

    /// Firmware Version, YubiKey specific (?)
    pub fn firmware_version(&mut self) -> Result<Vec<u8>, Error> {
        self.opt.firmware_version()
    }

    // ----------

    pub fn public_key(&mut self, key_type: KeyType) -> Result<PublicKeyMaterial, Error> {
        self.opt.public_key(key_type)
    }

    // ----------

    /// Delete all state on this OpenPGP card
    pub fn factory_reset(&mut self) -> Result<(), Error> {
        self.opt.factory_reset()
    }
}

/// An OpenPGP card after successfully verifying PW1 in mode 82
/// (verification for user operations other than signing)
pub struct User<'app, 'open> {
    oc: &'open mut Open<'app>,
}

impl<'app, 'open> User<'app, 'open> {
    pub fn decryptor(&mut self, cert: &Cert) -> Result<CardDecryptor<'_, 'app>, Error> {
        CardDecryptor::new(&mut self.oc.opt, cert)
    }
}

/// An OpenPGP card after successfully verifying PW1 in mode 81
/// (verification for signing)
pub struct Sign<'app, 'open> {
    oc: &'open mut Open<'app>,
}

impl<'app, 'open> Sign<'app, 'open> {
    pub fn signer(&mut self, cert: &Cert) -> std::result::Result<CardSigner<'_, 'app>, Error> {
        // FIXME: depending on the setting in "PW1 Status byte", only one
        // signature can be made after verification for signing

        CardSigner::new(&mut self.oc.opt, cert)
    }

    pub fn signer_from_pubkey(&mut self, pubkey: PublicKey) -> CardSigner<'_, 'app> {
        // FIXME: depending on the setting in "PW1 Status byte", only one
        // signature can be made after verification for signing

        CardSigner::with_pubkey(&mut self.oc.opt, pubkey)
    }

    /// Generate Attestation (Yubico)
    pub fn generate_attestation(&mut self, key_type: KeyType) -> Result<(), Error> {
        self.oc.opt.generate_attestation(key_type)
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
    pub fn set_name(&mut self, name: &str) -> Result<(), Error> {
        if name.len() >= 40 {
            return Err(Error::InternalError("name too long".into()));
        }

        // All chars must be in ASCII7
        if name.chars().any(|c| !c.is_ascii()) {
            return Err(Error::InternalError("Invalid char in name".into()));
        };

        self.oc.opt.set_name(name.as_bytes())
    }

    pub fn set_lang(&mut self, lang: &[Lang]) -> Result<(), Error> {
        if lang.len() > 8 {
            return Err(Error::InternalError("lang too long".into()));
        }

        self.oc.opt.set_lang(lang)
    }

    pub fn set_sex(&mut self, sex: Sex) -> Result<(), Error> {
        self.oc.opt.set_sex(sex)
    }

    pub fn set_url(&mut self, url: &str) -> Result<(), Error> {
        if url.chars().any(|c| !c.is_ascii()) {
            return Err(Error::InternalError("Invalid char in url".into()));
        }

        // Check for max len
        let ec = self.oc.extended_capabilities()?;

        if ec.max_len_special_do() == None || url.len() <= ec.max_len_special_do().unwrap() as usize
        {
            // If we don't know the max length for URL ("special DO"),
            // or if it's within the acceptable length:
            // send the url update to the card.

            self.oc.opt.set_url(url.as_bytes())
        } else {
            Err(Error::InternalError("URL too long".into()))
        }
    }

    pub fn set_resetting_code(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.oc.opt.set_resetting_code(pin)
    }

    pub fn reset_user_pin(&mut self, new: &[u8]) -> Result<(), Error> {
        self.oc.opt.reset_retry_counter_pw1(new, None)
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
        self.oc.opt.key_import(key, key_type)
    }

    /// Wrapper fn for `public_to_fingerprint` that uses SHA256/AES128 as default parameters.
    ///
    /// FIXME: This is a hack.
    /// These parameters should probably be automatically determined based on the algorithm used?
    fn ptf(
        pkm: &PublicKeyMaterial,
        time: KeyGenerationTime,
        key_type: KeyType,
    ) -> Result<Fingerprint, Error> {
        public_to_fingerprint(
            pkm,
            &time,
            key_type,
            Some(HashAlgorithm::SHA256),
            Some(SymmetricAlgorithm::AES128),
        )
    }

    pub fn generate_key_simple(
        &mut self,
        key_type: KeyType,
        algo: Option<AlgoSimple>,
    ) -> Result<(PublicKeyMaterial, KeyGenerationTime), Error> {
        match algo {
            Some(algo) => self.oc.opt.generate_key_simple(Self::ptf, key_type, algo),
            None => self.oc.opt.generate_key(Self::ptf, key_type, None),
        }
    }
}
