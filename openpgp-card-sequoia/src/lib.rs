// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This crate offers ergonomic abstractions to use
//! [OpenPGP cards](https://en.wikipedia.org/wiki/OpenPGP_card).
//! The central abstraction is the [Card] type, which offers access to all card operations.
//!
//! A [Card] object is always in one of the possible [State]s. The [State] determines which
//! operations can be performed on the card.
//!
//! This crate is a convenient higher-level wrapper around the
//! [openpgp-card](https://crates.io/crates/openpgp-card) crate (which exposes low level access
//! to OpenPGP card functionality).
//! [sequoia-openpgp](https://crates.io/crates/sequoia-openpgp) is used to perform OpenPGP operations.
//!
//! # Backends
//!
//! To make use of this crate, you need to use a backend for communication
//! with cards. The suggested default backend is `openpgp-card-pcsc`.
//!
//! With `openpgp-card-pcsc` you can either open all available cards:
//!
//! ```no_run
//! use openpgp_card_pcsc::PcscBackend;
//! use openpgp_card_sequoia::{state::Open, Card};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! for backend in PcscBackend::cards(None)? {
//!     let mut card: Card<Open> = backend.into();
//!     let mut transaction = card.transaction()?;
//!     println!(
//!         "Found OpenPGP card with ident '{}'",
//!         transaction.application_identifier()?.ident()
//!     );
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Or you can open one particular card, by ident:
//!
//! ```no_run
//! use openpgp_card_pcsc::PcscBackend;
//! use openpgp_card_sequoia::{state::Open, Card};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let backend = PcscBackend::open_by_ident("abcd:01234567", None)?;
//! let mut card: Card<Open> = backend.into();
//! let mut transaction = card.transaction()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Use for cryptographic operations
//!
//! ## Decryption
//!
//! To use a card for decryption, it needs to be opened, user authorization
//! needs to be available. A `sequoia_openpgp::crypto::Decryptor`
//! implementation can then be obtained:
//!
//! ```no_run
//! use openpgp_card_pcsc::PcscBackend;
//! use openpgp_card_sequoia::{state::Open, Card};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Open card via PCSC
//! use sequoia_openpgp::policy::StandardPolicy;
//! let backend = PcscBackend::open_by_ident("abcd:01234567", None)?;
//! let mut card: Card<Open> = backend.into();
//! let mut transaction = card.transaction()?;
//!
//! // Get authorization for user access to the card with password
//! transaction.verify_user(b"123456")?;
//! let mut user = transaction.user_card().expect("This should not fail");
//!
//! // Get decryptor
//! let decryptor = user.decryptor(&|| println!("Touch confirmation needed for decryption"));
//!
//! // Perform decryption operation(s)
//! // ..
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Signing
//!
//! To use a card for signing, it needs to be opened, signing authorization
//! needs to be available. A `sequoia_openpgp::crypto::Signer`
//! implementation can then be obtained.
//!
//! (Note that by default, some OpenPGP Cards will only allow one signing
//! operation to be performed after the password has been presented for
//! signing. Depending on the card's configuration you need to present the
//! user password before each signing operation!)
//!
//! ```no_run
//! use openpgp_card_pcsc::PcscBackend;
//! use openpgp_card_sequoia::{state::Open, Card};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Open card via PCSC
//! let backend = PcscBackend::open_by_ident("abcd:01234567", None)?;
//! let mut card: Card<Open> = backend.into();
//! let mut transaction = card.transaction()?;
//!
//! // Get authorization for signing access to the card with password
//! transaction.verify_user_for_signing(b"123456")?;
//! let mut user = transaction.signing_card().expect("This should not fail");
//!
//! // Get signer
//! let signer = user.signer(&|| println!("Touch confirmation needed for signing"));
//!
//! // Perform signing operation(s)
//! // ..
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Setting up and configuring a card
//!
//! ```no_run
//! use openpgp_card_pcsc::PcscBackend;
//! use openpgp_card_sequoia::{state::Open, Card};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Open card via PCSC
//! let backend = PcscBackend::open_by_ident("abcd:01234567", None)?;
//! let mut card: Card<Open> = backend.into();
//! let mut transaction = card.transaction()?;
//!
//! // Get authorization for admin access to the card with password
//! transaction.verify_admin(b"12345678")?;
//! let mut admin = transaction.admin_card().expect("This should not fail");
//!
//! // Set the Name and URL fields on the card
//! admin.set_name("Alice Adams")?;
//! admin.set_url("https://example.org/openpgp.asc")?;
//!
//! # Ok(())
//! # }
//! ```

use openpgp_card::algorithm::{Algo, AlgoInfo, AlgoSimple};
use openpgp_card::card_do::{
    ApplicationIdentifier, CardholderRelatedData, ExtendedCapabilities, ExtendedLengthInfo,
    Fingerprint, HistoricalBytes, KeyGenerationTime, KeyInformation, Lang, PWStatusBytes,
    SecuritySupportTemplate, Sex, TouchPolicy, UIF,
};
use openpgp_card::crypto_data::PublicKeyMaterial;
use openpgp_card::{CardBackend, Error, KeySet, KeyType, OpenPgp, OpenPgpTransaction};
use sequoia_openpgp::cert::prelude::ValidErasedKeyAmalgamation;
use sequoia_openpgp::packet::key::SecretParts;
use sequoia_openpgp::packet::{key, Key};
use sequoia_openpgp::types::{HashAlgorithm, SymmetricAlgorithm};

use crate::decryptor::CardDecryptor;
use crate::signer::CardSigner;
use crate::state::{Admin, Open, Sign, State, Transaction, User};
use crate::util::{
    public_key_material_and_fp_to_key, public_to_fingerprint, vka_as_uploadable_key,
};

mod decryptor;
mod privkey;
mod signer;
pub mod sq_util;
pub mod state;
pub mod types;
pub mod util;

/// Shorthand for Sequoia public key data (a single public (sub)key)
pub type PublicKey = Key<key::PublicParts, key::UnspecifiedRole>;

/// Representation of an OpenPGP card.
///
/// A card transitions between `State`s by starting a transaction (that groups together a number
/// of operations into an atomic sequence) and via PIN presentation.
///
/// Depending on the `State` of the card, and the access privileges that are associated with that
/// state, different operations can be performed. In many cases, client software will want to
/// transition between states while performing one activity for the user.
pub struct Card<S>
where
    S: State,
{
    state: S,
}

impl<B> From<B> for Card<Open>
where
    B: Into<Box<dyn CardBackend + Send + Sync>>,
{
    fn from(backend: B) -> Self {
        let pgp = OpenPgp::new(backend.into());

        Card::<Open> {
            state: Open { pgp },
        }
    }
}

impl Card<Open> {
    pub fn transaction(&mut self) -> Result<Card<Transaction>, Error> {
        let opt = self.state.pgp.transaction()?;

        Card::<Transaction>::new(opt)
    }
}

impl<'a> Card<Transaction<'a>> {
    /// Do not use!
    ///
    /// FIXME: this interface is currently used in `card-functionality`, for testing.
    /// It will be removed.
    pub fn new(mut opt: OpenPgpTransaction<'a>) -> Result<Self, Error> {
        let ard = opt.application_related_data()?;

        Ok(Self {
            state: Transaction {
                opt,
                ard,
                pw1: false,
                pw1_sign: false,
                pw3: false,
            },
        })
    }

    /// Replace cached "application related data" in this instance of Open
    /// with the current data on the card.
    ///
    /// This is needed e.g. after importing or generating keys on a card, to
    /// see these changes reflected in `self.ard`.
    pub fn reload_ard(&mut self) -> Result<(), Error> {
        // FIXME: this should be implemented internally, transparent to users
        self.state.ard = self.state.opt.application_related_data()?;
        Ok(())
    }

    pub fn feature_pinpad_verify(&mut self) -> bool {
        self.state.opt.feature_pinpad_verify()
    }

    pub fn feature_pinpad_modify(&mut self) -> bool {
        self.state.opt.feature_pinpad_modify()
    }

    pub fn verify_user(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.state.opt.verify_pw1_user(pin)?;
        self.state.pw1 = true;
        Ok(())
    }

    pub fn verify_user_pinpad(&mut self, pinpad_prompt: &dyn Fn()) -> Result<(), Error> {
        pinpad_prompt();

        self.state.opt.verify_pw1_user_pinpad()?;
        self.state.pw1 = true;
        Ok(())
    }

    pub fn verify_user_for_signing(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.state.opt.verify_pw1_sign(pin)?;

        // FIXME: depending on card mode, pw1_sign is only usable once

        self.state.pw1_sign = true;
        Ok(())
    }

    pub fn verify_user_for_signing_pinpad(
        &mut self,
        pinpad_prompt: &dyn Fn(),
    ) -> Result<(), Error> {
        pinpad_prompt();

        self.state.opt.verify_pw1_sign_pinpad()?;

        // FIXME: depending on card mode, pw1_sign is only usable once

        self.state.pw1_sign = true;
        Ok(())
    }

    pub fn verify_admin(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.state.opt.verify_pw3(pin)?;
        self.state.pw3 = true;
        Ok(())
    }

    pub fn verify_admin_pinpad(&mut self, pinpad_prompt: &dyn Fn()) -> Result<(), Error> {
        pinpad_prompt();

        self.state.opt.verify_pw3_pinpad()?;
        self.state.pw3 = true;
        Ok(())
    }

    /// Ask the card if the user password has been successfully verified.
    ///
    /// NOTE: on some cards this functionality seems broken.
    pub fn check_user_verified(&mut self) -> Result<(), Error> {
        self.state.opt.check_pw1_user()
    }

    /// Ask the card if the admin password has been successfully verified.
    ///
    /// NOTE: on some cards this functionality seems broken.
    pub fn check_admin_verified(&mut self) -> Result<(), Error> {
        self.state.opt.check_pw3()
    }

    pub fn change_user_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), Error> {
        self.state.opt.change_pw1(old, new)
    }

    pub fn change_user_pin_pinpad(&mut self, pinpad_prompt: &dyn Fn()) -> Result<(), Error> {
        pinpad_prompt();
        self.state.opt.change_pw1_pinpad()
    }

    pub fn reset_user_pin(&mut self, rst: &[u8], new: &[u8]) -> Result<(), Error> {
        self.state.opt.reset_retry_counter_pw1(new, Some(rst))
    }

    pub fn change_admin_pin(&mut self, old: &[u8], new: &[u8]) -> Result<(), Error> {
        self.state.opt.change_pw3(old, new)
    }

    pub fn change_admin_pin_pinpad(&mut self, pinpad_prompt: &dyn Fn()) -> Result<(), Error> {
        pinpad_prompt();
        self.state.opt.change_pw3_pinpad()
    }

    /// Get a view of the card authenticated for "User" commands.
    pub fn user_card<'b>(&'b mut self) -> Option<Card<User<'a, 'b>>> {
        Some(Card::<User> {
            state: User { tx: self },
        })
    }

    /// Get a view of the card authenticated for Signing.
    pub fn signing_card<'b>(&'b mut self) -> Option<Card<Sign<'a, 'b>>> {
        Some(Card::<Sign> {
            state: Sign { tx: self },
        })
    }

    /// Get a view of the card authenticated for "Admin" commands.
    pub fn admin_card<'b>(&'b mut self) -> Option<Card<Admin<'a, 'b>>> {
        Some(Card::<Admin> {
            state: Admin { tx: self },
        })
    }

    // --- application data ---

    pub fn application_identifier(&self) -> Result<ApplicationIdentifier, Error> {
        self.state.ard.application_id()
    }

    pub fn historical_bytes(&self) -> Result<HistoricalBytes, Error> {
        self.state.ard.historical_bytes()
    }

    pub fn extended_length_information(&self) -> Result<Option<ExtendedLengthInfo>, Error> {
        self.state.ard.extended_length_information()
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
        self.state.ard.extended_capabilities()
    }

    pub fn algorithm_attributes(&self, key_type: KeyType) -> Result<Algo, Error> {
        self.state.ard.algorithm_attributes(key_type)
    }

    /// PW status Bytes
    pub fn pw_status_bytes(&self) -> Result<PWStatusBytes, Error> {
        self.state.ard.pw_status_bytes()
    }

    pub fn fingerprints(&self) -> Result<KeySet<Fingerprint>, Error> {
        self.state.ard.fingerprints()
    }

    pub fn ca_fingerprints(&self) -> Result<[Option<Fingerprint>; 3], Error> {
        self.state.ard.ca_fingerprints()
    }

    pub fn key_generation_times(&self) -> Result<KeySet<KeyGenerationTime>, Error> {
        self.state.ard.key_generation_times()
    }

    pub fn key_information(&self) -> Result<Option<KeyInformation>, Error> {
        self.state.ard.key_information()
    }

    pub fn uif_signing(&self) -> Result<Option<UIF>, Error> {
        self.state.ard.uif_pso_cds()
    }

    pub fn uif_decryption(&self) -> Result<Option<UIF>, Error> {
        self.state.ard.uif_pso_dec()
    }

    pub fn uif_authentication(&self) -> Result<Option<UIF>, Error> {
        self.state.ard.uif_pso_aut()
    }

    pub fn uif_attestation(&self) -> Result<Option<UIF>, Error> {
        self.state.ard.uif_attestation()
    }

    // --- optional private DOs (0101 - 0104) ---

    // --- login data (5e) ---

    // --- URL (5f50) ---

    /// Get "hardholder" URL from the card.
    ///
    /// "The URL should contain a link to a set of public keys in OpenPGP format, related to
    /// the card."
    pub fn url(&mut self) -> Result<String, Error> {
        Ok(String::from_utf8_lossy(&self.state.opt.url()?).to_string())
    }

    // --- cardholder related data (65) ---
    pub fn cardholder_related_data(&mut self) -> Result<CardholderRelatedData, Error> {
        self.state.opt.cardholder_related_data()
    }

    // Unicode codepoints are a superset of iso-8859-1 characters
    fn latin1_to_string(s: &[u8]) -> String {
        s.iter().map(|&c| c as char).collect()
    }

    /// Get cardholder name as a String (this also normalizes the "<" and "<<" filler chars)
    pub fn cardholder_name(&mut self) -> Result<Option<String>, Error> {
        let crd = self.state.opt.cardholder_related_data()?;
        if let Some(name) = crd.name() {
            let name = Self::latin1_to_string(name);

            // re-format name ("last<<first")
            let name: Vec<_> = name.split("<<").collect();
            let name = name.iter().cloned().rev().collect::<Vec<_>>().join(" ");

            // replace item separators with spaces
            let name = name.replace('<', " ");

            Ok(Some(name))
        } else {
            Ok(None)
        }
    }

    // --- security support template (7a) ---
    pub fn security_support_template(&mut self) -> Result<SecuritySupportTemplate, Error> {
        self.state.opt.security_support_template()
    }

    /// SELECT DATA ("select a DO in the current template").
    pub fn select_data(&mut self, num: u8, tag: &[u8], yk_workaround: bool) -> Result<(), Error> {
        self.state.opt.select_data(num, tag, yk_workaround)
    }

    /// Get cardholder certificate.
    ///
    /// Call select_data() before calling this fn to select a particular
    /// certificate (if the card supports multiple certificates).
    pub fn cardholder_certificate(&mut self) -> Result<Vec<u8>, Error> {
        self.state.opt.cardholder_certificate()
    }

    /// "GET NEXT DATA" for the DO cardholder certificate.
    ///
    /// Cardholder certificate data for multiple slots can be read from the card by first calling
    /// cardholder_certificate(), followed by up to two calls to  next_cardholder_certificate().
    pub fn next_cardholder_certificate(&mut self) -> Result<Vec<u8>, Error> {
        self.state.opt.next_cardholder_certificate()
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

        self.state.opt.algorithm_information()
    }

    /// "MANAGE SECURITY ENVIRONMENT"
    /// Make `key_ref` usable for the operation normally done by the key designated by `for_operation`
    pub fn manage_security_environment(
        &mut self,
        for_operation: KeyType,
        key_ref: KeyType,
    ) -> Result<(), Error> {
        self.state
            .opt
            .manage_security_environment(for_operation, key_ref)
    }

    // ----------

    /// Get "Attestation Certificate (Yubico)"
    pub fn attestation_certificate(&mut self) -> Result<Vec<u8>, Error> {
        self.state.opt.attestation_certificate()
    }

    pub fn attestation_key_fingerprint(&mut self) -> Result<Option<Fingerprint>, Error> {
        self.state.ard.attestation_key_fingerprint()
    }

    pub fn attestation_key_algorithm_attributes(&mut self) -> Result<Option<Algo>, Error> {
        self.state.ard.attestation_key_algorithm_attributes()
    }

    pub fn attestation_key_generation_time(&mut self) -> Result<Option<KeyGenerationTime>, Error> {
        self.state.ard.attestation_key_generation_time()
    }

    /// Firmware Version, YubiKey specific (?)
    pub fn firmware_version(&mut self) -> Result<Vec<u8>, Error> {
        self.state.opt.firmware_version()
    }

    /// Set "identity", Nitrokey Start specific (possible values: 0, 1, 2).
    /// <https://docs.nitrokey.com/start/windows/multiple-identities.html>
    ///
    /// A Nitrokey Start can present as 3 different virtual OpenPGP cards.
    /// This command enables one of those virtual cards.
    ///
    /// Each virtual card identity behaves like a separate, independent OpenPGP card.
    pub fn set_identity(&mut self, id: u8) -> Result<(), Error> {
        // FIXME: what is in the returned data - is it ever useful?
        let _ = self.state.opt.set_identity(id)?;

        Ok(())
    }

    // ----------

    pub fn public_key_material(&mut self, key_type: KeyType) -> Result<PublicKeyMaterial, Error> {
        self.state.opt.public_key(key_type)
    }

    // ----------

    /// Delete all state on this OpenPGP card
    pub fn factory_reset(&mut self) -> Result<(), Error> {
        self.state.opt.factory_reset()
    }

    // -- higher level abstractions

    /// Get PublicKey representation for a key slot on the card
    pub fn public_key(&mut self, kt: KeyType) -> Result<Option<PublicKey>, Error> {
        // FIXME: only read these once, if multiple subkeys are retrieved from the card
        let times = self.key_generation_times()?;
        let fps = self.fingerprints()?;

        match kt {
            KeyType::Signing => {
                if let Ok(pkm) = self.public_key_material(KeyType::Signing) {
                    if let Some(ts) = times.signature() {
                        return Ok(Some(public_key_material_and_fp_to_key(
                            &pkm,
                            KeyType::Signing,
                            ts,
                            fps.signature().expect("Signature fingerprint is unset"),
                        )?));
                    }
                }
                Ok(None)
            }
            KeyType::Decryption => {
                if let Ok(pkm) = self.public_key_material(KeyType::Decryption) {
                    if let Some(ts) = times.decryption() {
                        return Ok(Some(public_key_material_and_fp_to_key(
                            &pkm,
                            KeyType::Decryption,
                            ts,
                            fps.decryption().expect("Decryption fingerprint is unset"),
                        )?));
                    }
                }
                Ok(None)
            }
            KeyType::Authentication => {
                if let Ok(pkm) = self.public_key_material(KeyType::Authentication) {
                    if let Some(ts) = times.authentication() {
                        return Ok(Some(public_key_material_and_fp_to_key(
                            &pkm,
                            KeyType::Authentication,
                            ts,
                            fps.authentication()
                                .expect("Authentication fingerprint is unset"),
                        )?));
                    }
                }
                Ok(None)
            }
            _ => unimplemented!(),
        }
    }
}

impl<'app, 'open> Card<User<'app, 'open>> {
    /// Helper fn to easily access underlying openpgp_card object
    fn card(&mut self) -> &mut OpenPgpTransaction<'app> {
        &mut self.state.tx.state.opt
    }

    pub fn decryptor(
        &mut self,
        touch_prompt: &'open (dyn Fn() + Send + Sync),
    ) -> Result<CardDecryptor<'_, 'app>, Error> {
        let pk = self
            .state
            .tx
            .public_key(KeyType::Decryption)?
            .expect("Couldn't get decryption pubkey from card");

        Ok(CardDecryptor::with_pubkey(self.card(), pk, touch_prompt))
    }

    pub fn decryptor_from_public(
        &mut self,
        pubkey: PublicKey,
        touch_prompt: &'open (dyn Fn() + Send + Sync),
    ) -> CardDecryptor<'_, 'app> {
        CardDecryptor::with_pubkey(self.card(), pubkey, touch_prompt)
    }

    pub fn authenticator(
        &mut self,
        touch_prompt: &'open (dyn Fn() + Send + Sync),
    ) -> Result<CardSigner<'_, 'app>, Error> {
        let pk = self
            .state
            .tx
            .public_key(KeyType::Authentication)?
            .expect("Couldn't get authentication pubkey from card");

        Ok(CardSigner::with_pubkey_for_auth(
            self.card(),
            pk,
            touch_prompt,
        ))
    }
    pub fn authenticator_from_public(
        &mut self,
        pubkey: PublicKey,
        touch_prompt: &'open (dyn Fn() + Send + Sync),
    ) -> CardSigner<'_, 'app> {
        CardSigner::with_pubkey_for_auth(self.card(), pubkey, touch_prompt)
    }
}

impl<'app, 'open> Card<Sign<'app, 'open>> {
    /// Helper fn to easily access underlying openpgp_card object
    fn card(&mut self) -> &mut OpenPgpTransaction<'app> {
        &mut self.state.tx.state.opt
    }

    pub fn signer(
        &mut self,
        touch_prompt: &'open (dyn Fn() + Send + Sync),
    ) -> Result<CardSigner<'_, 'app>, Error> {
        // FIXME: depending on the setting in "PW1 Status byte", only one
        // signature can be made after verification for signing

        let pk = self
            .state
            .tx
            .public_key(KeyType::Signing)?
            .expect("Couldn't get signing pubkey from card");

        Ok(CardSigner::with_pubkey(self.card(), pk, touch_prompt))
    }

    pub fn signer_from_public(
        &mut self,
        pubkey: PublicKey,
        touch_prompt: &'open (dyn Fn() + Send + Sync),
    ) -> CardSigner<'_, 'app> {
        // FIXME: depending on the setting in "PW1 Status byte", only one
        // signature can be made after verification for signing

        CardSigner::with_pubkey(self.card(), pubkey, touch_prompt)
    }

    /// Generate Attestation (Yubico)
    pub fn generate_attestation(
        &mut self,
        key_type: KeyType,
        touch_prompt: &'open (dyn Fn() + Send + Sync),
    ) -> Result<(), Error> {
        // Touch is required if:
        // - the card supports the feature
        // - and the policy is set to a value other than 'Off'
        if let Some(uif) = self.state.tx.state.ard.uif_attestation()? {
            if uif.touch_policy().touch_required() {
                (touch_prompt)();
            }
        }

        self.card().generate_attestation(key_type)
    }
}

impl<'app, 'open> Card<Admin<'app, 'open>> {
    pub fn as_open(&'_ mut self) -> &mut Card<Transaction<'app>> {
        self.state.tx
    }

    /// Helper fn to easily access underlying openpgp_card object
    fn card(&mut self) -> &mut OpenPgpTransaction<'app> {
        &mut self.state.tx.state.opt
    }
}

impl Card<Admin<'_, '_>> {
    pub fn set_name(&mut self, name: &str) -> Result<(), Error> {
        // All chars must be in ASCII7
        if name.chars().any(|c| !c.is_ascii()) {
            return Err(Error::InternalError("Invalid char in name".into()));
        };

        // FIXME: encode spaces and do ordering

        if name.len() >= 40 {
            return Err(Error::InternalError("name too long".into()));
        }

        self.card().set_name(name.as_bytes())
    }

    pub fn set_lang(&mut self, lang: &[Lang]) -> Result<(), Error> {
        if lang.len() > 8 {
            return Err(Error::InternalError("lang too long".into()));
        }

        self.card().set_lang(lang)
    }

    pub fn set_sex(&mut self, sex: Sex) -> Result<(), Error> {
        self.card().set_sex(sex)
    }

    /// Set "hardholder" URL on the card.
    ///
    /// "The URL should contain a link to a set of public keys in OpenPGP format, related to
    /// the card."
    pub fn set_url(&mut self, url: &str) -> Result<(), Error> {
        if url.chars().any(|c| !c.is_ascii()) {
            return Err(Error::InternalError("Invalid char in url".into()));
        }

        // Check for max len
        let ec = self.state.tx.extended_capabilities()?;

        if ec.max_len_special_do().is_none()
            || url.len() <= ec.max_len_special_do().unwrap() as usize
        {
            // If we don't know the max length for URL ("special DO"),
            // or if it's within the acceptable length:
            // send the url update to the card.

            self.card().set_url(url.as_bytes())
        } else {
            Err(Error::InternalError("URL too long".into()))
        }
    }

    pub fn set_uif(&mut self, key: KeyType, policy: TouchPolicy) -> Result<(), Error> {
        let uif = match key {
            KeyType::Signing => self.state.tx.state.ard.uif_pso_cds()?,
            KeyType::Decryption => self.state.tx.state.ard.uif_pso_dec()?,
            KeyType::Authentication => self.state.tx.state.ard.uif_pso_aut()?,
            KeyType::Attestation => self.state.tx.state.ard.uif_attestation()?,
            _ => unimplemented!(),
        };

        if let Some(mut uif) = uif {
            uif.set_touch_policy(policy);

            match key {
                KeyType::Signing => self.card().set_uif_pso_cds(&uif)?,
                KeyType::Decryption => self.card().set_uif_pso_dec(&uif)?,
                KeyType::Authentication => self.card().set_uif_pso_aut(&uif)?,
                KeyType::Attestation => self.card().set_uif_attestation(&uif)?,
                _ => unimplemented!(),
            }
        } else {
            return Err(Error::UnsupportedFeature(
                "User Interaction Flag not available".into(),
            ));
        };

        Ok(())
    }

    pub fn set_resetting_code(&mut self, pin: &[u8]) -> Result<(), Error> {
        self.card().set_resetting_code(pin)
    }

    pub fn set_pso_enc_dec_key(&mut self, key: &[u8]) -> Result<(), Error> {
        self.card().set_pso_enc_dec_key(key)
    }

    pub fn reset_user_pin(&mut self, new: &[u8]) -> Result<(), Error> {
        self.card().reset_retry_counter_pw1(new, None)
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
        self.card().key_import(key, key_type)
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
            Some(algo) => self.card().generate_key_simple(Self::ptf, key_type, algo),
            None => self.card().generate_key(Self::ptf, key_type, None),
        }
    }
}
