// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Perform operations on a card. Different states of a card are modeled by
//! different types, such as `Open`, `User`, `Sign`, `Admin`.

use anyhow::{anyhow, Result};
use std::ops::{Deref, DerefMut};

use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::Cert;

use openpgp_card::algorithm::{Algo, AlgoInfo};
use openpgp_card::card_do::{
    ApplicationIdentifier, ApplicationRelatedData, CardholderRelatedData,
    ExCapFeatures, ExtendedCapabilities, ExtendedLengthInfo, Fingerprint,
    HistoricalBytes, PWStatusBytes, SecuritySupportTemplate, Sex,
};
use openpgp_card::crypto_data::CardUploadableKey;
use openpgp_card::{CardApp, CardClientBox, Error, KeySet, KeyType, Response};

use crate::decryptor::CardDecryptor;
use crate::signer::CardSigner;

/// Representation of an opened OpenPGP card in its base state (i.e. no
/// passwords have been verified, default authorization applies).
pub struct Open {
    card_app: CardApp,

    // Cache of "application related data".
    //
    // FIXME: Should be invalidated when changing data on the card!
    // (e.g. uploading keys, etc)
    ard: ApplicationRelatedData,
}

impl Open {
    /// Set up connection to a CardClient (read and cache "application
    /// related data").
    ///
    /// The OpenPGP applet must already be opened in the CardClient.
    pub fn open_card(ccb: CardClientBox) -> Result<Self, Error> {
        // read and cache "application related data"
        let mut card_app = CardApp::from(ccb);

        let ard = card_app.get_application_related_data()?;

        card_app.init_caps(&ard)?;

        Ok(Self { card_app, ard })
    }

    // --- application data ---

    /// Load "application related data".
    ///
    /// This is done once, after opening the OpenPGP card applet
    /// (the data is stored in the OpenPGPCard object).
    fn get_app_data(&mut self) -> Result<ApplicationRelatedData> {
        self.card_app.get_application_related_data()
    }

    pub fn get_application_id(&self) -> Result<ApplicationIdentifier, Error> {
        self.ard.get_application_id()
    }

    pub fn get_historical(&self) -> Result<HistoricalBytes, Error> {
        self.ard.get_historical()
    }

    pub fn get_extended_length_information(
        &self,
    ) -> Result<Option<ExtendedLengthInfo>> {
        self.ard.get_extended_length_information()
    }

    pub fn get_general_feature_management() -> Option<bool> {
        unimplemented!()
    }

    pub fn get_discretionary_data_objects() {
        unimplemented!()
    }

    pub fn get_extended_capabilities(
        &self,
    ) -> Result<ExtendedCapabilities, Error> {
        self.ard.get_extended_capabilities()
    }

    pub fn get_algorithm_attributes(&self, key_type: KeyType) -> Result<Algo> {
        self.ard.get_algorithm_attributes(key_type)
    }

    /// PW status Bytes
    pub fn get_pw_status_bytes(&self) -> Result<PWStatusBytes> {
        self.ard.get_pw_status_bytes()
    }

    pub fn get_fingerprints(&self) -> Result<KeySet<Fingerprint>, Error> {
        self.ard.get_fingerprints()
    }

    pub fn get_ca_fingerprints(&self) {
        unimplemented!()
    }

    pub fn get_key_generation_times() {
        unimplemented!()
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
        self.card_app.get_url()
    }

    // --- cardholder related data (65) ---
    pub fn get_cardholder_related_data(
        &mut self,
    ) -> Result<CardholderRelatedData> {
        self.card_app.get_cardholder_related_data()
    }

    // --- security support template (7a) ---
    pub fn get_security_support_template(
        &mut self,
    ) -> Result<SecuritySupportTemplate> {
        self.card_app.get_security_support_template()
    }

    // DO "Algorithm Information" (0xFA)
    pub fn list_supported_algo(&mut self) -> Result<Option<AlgoInfo>> {
        // The DO "Algorithm Information" (Tag FA) shall be present if
        // Algorithm attributes can be changed
        let ec = self.get_extended_capabilities()?;
        if !ec.features().contains(&ExCapFeatures::AlgoAttrsChangeable) {
            // Algorithm attributes can not be changed,
            // list_supported_algo is not supported
            return Ok(None);
        }

        self.card_app.get_algo_info()
    }

    // ----------

    /// Delete all state on this OpenPGP card
    pub fn factory_reset(&mut self) -> Result<()> {
        self.card_app.factory_reset()
    }

    pub fn verify_pw1_for_signing(mut self, pin: &str) -> Result<Sign, Open> {
        assert!(pin.len() >= 6); // FIXME: Err

        if self.card_app.verify_pw1_for_signing(pin).is_ok() {
            Ok(Sign { oc: self })
        } else {
            Err(self)
        }
    }

    pub fn check_pw1(&mut self) -> Result<Response, Error> {
        self.card_app.check_pw1()
    }

    pub fn verify_pw1(mut self, pin: &str) -> Result<User, Open> {
        assert!(pin.len() >= 6); // FIXME: Err

        if self.card_app.verify_pw1(pin).is_ok() {
            Ok(User { oc: self })
        } else {
            Err(self)
        }
    }

    pub fn check_pw3(&mut self) -> Result<Response, Error> {
        self.card_app.check_pw3()
    }

    pub fn verify_pw3(mut self, pin: &str) -> Result<Admin, Open> {
        assert!(pin.len() >= 8); // FIXME: Err

        if self.card_app.verify_pw3(pin).is_ok() {
            Ok(Admin { oc: self })
        } else {
            Err(self)
        }
    }
}

/// An OpenPGP card after successful verification of PW1 in mode 82
/// (verification for operations other than signing)
pub struct User {
    oc: Open,
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardUser.
impl Deref for User {
    type Target = Open;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

/// Allow access to fn of CardBase, through CardUser.
impl DerefMut for User {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.oc
    }
}

impl User {
    pub fn decryptor(
        &mut self,
        cert: &Cert,
        policy: &dyn Policy,
    ) -> Result<CardDecryptor, Error> {
        CardDecryptor::new(&mut self.card_app, cert, policy)
    }
}

/// An OpenPGP card after successful verification of PW1 in mode 81
/// (verification for signing)
pub struct Sign {
    oc: Open,
}

/// Allow access to fn of CardBase, through CardSign.
impl Deref for Sign {
    type Target = Open;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

/// Allow access to fn of CardBase, through CardSign.
impl DerefMut for Sign {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.oc
    }
}

// FIXME: depending on the setting in "PW1 Status byte", only one
// signature can be made after verification for signing
impl Sign {
    pub fn signer(
        &mut self,
        cert: &Cert,
        policy: &dyn Policy,
    ) -> std::result::Result<CardSigner, Error> {
        CardSigner::new(&mut self.card_app, cert, policy)
    }
}

/// An OpenPGP card after successful verification of PW3 ("Admin privileges")
pub struct Admin {
    oc: Open,
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardAdmin.
impl Deref for Admin {
    type Target = Open;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardAdmin.
impl DerefMut for Admin {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.oc
    }
}

impl Admin {
    pub fn set_name(&mut self, name: &str) -> Result<Response, Error> {
        if name.len() >= 40 {
            return Err(anyhow!("name too long").into());
        }

        // All chars must be in ASCII7
        if name.chars().any(|c| !c.is_ascii()) {
            return Err(anyhow!("Invalid char in name").into());
        };

        self.card_app.set_name(name)
    }

    pub fn set_lang(&mut self, lang: &str) -> Result<Response, Error> {
        if lang.len() > 8 {
            return Err(anyhow!("lang too long").into());
        }

        self.card_app.set_lang(lang)
    }

    pub fn set_sex(&mut self, sex: Sex) -> Result<Response, Error> {
        self.card_app.set_sex(sex)
    }

    pub fn set_url(&mut self, url: &str) -> Result<Response, Error> {
        if url.chars().any(|c| !c.is_ascii()) {
            return Err(anyhow!("Invalid char in url").into());
        }

        // Check for max len
        let ec = self.get_extended_capabilities()?;

        if url.len() < ec.max_len_special_do() as usize {
            self.card_app.set_url(url)
        } else {
            Err(anyhow!("URL too long").into())
        }
    }

    pub fn upload_key(
        &mut self,
        key: Box<dyn CardUploadableKey>,
        key_type: KeyType,
    ) -> Result<(), Error> {
        self.card_app.key_import(key, key_type)
    }
}
