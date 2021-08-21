// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This library supports using openpgp-card functionality with
//! sequoia_openpgp data structures.

use anyhow::{anyhow, Context, Result};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::error::Error;
use std::io;
use std::ops::{Deref, DerefMut};
use std::time::SystemTime;

use openpgp::armor;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::crypto::mpi;
use openpgp::crypto::mpi::{ProtectedMPI, MPI};
use openpgp::packet::key::KeyRole;
use openpgp::packet::key::{Key4, PublicParts};
use openpgp::packet::key::{PrimaryRole, SubordinateRole};
use openpgp::packet::key::{SecretParts, UnspecifiedRole};
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::UserID;
use openpgp::packet::{key, Key};
use openpgp::parse::{stream::DecryptorBuilder, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Message, Signer};
use openpgp::types::Timestamp;
use openpgp::types::{KeyFlags, PublicKeyAlgorithm, SignatureType};
use openpgp::{Cert, Packet};
use sequoia_openpgp as openpgp;

use openpgp_card::algorithm::{Algo, AlgoInfo, Curve};
use openpgp_card::card_do::{
    ApplicationId, ApplicationRelatedData, Cardholder, ExtendedCap,
    ExtendedLengthInfo, Features, Fingerprint, Historical, KeySet, PWStatus,
    SecuritySupportTemplate, Sex,
};
use openpgp_card::crypto_data::{
    CardUploadableKey, Cryptogram, EccKey, EccType, Hash, PrivateKeyMaterial,
    PublicKeyMaterial, RSAKey,
};
use openpgp_card::{
    errors::OpenpgpCardError, CardApp, CardClientBox, KeyType, Response,
};

use crate::signer::CardSigner;

mod decryptor;
pub mod signer;

/// Shorthand for public key data
pub(crate) type PublicKey = Key<key::PublicParts, key::UnspecifiedRole>;

/// A SequoiaKey represents the private cryptographic key material of an
/// OpenPGP (sub)key to be uploaded to an OpenPGP card.
struct SequoiaKey {
    key: openpgp::packet::Key<SecretParts, UnspecifiedRole>,
    public: mpi::PublicKey,
    password: Option<String>,
}

impl SequoiaKey {
    /// A `SequoiaKey` wraps a Sequoia PGP private (sub)key data
    /// (i.e. a ValidErasedKeyAmalgamation) in a form that can be uploaded
    /// by the openpgp-card crate.
    fn new(
        vka: ValidErasedKeyAmalgamation<SecretParts>,
        password: Option<String>,
    ) -> Self {
        let public = vka.parts_as_public().mpis().clone();

        Self {
            key: vka.key().clone(),
            public,
            password,
        }
    }
}

/// Helper fn: get a CardUploadableKey for a ValidErasedKeyAmalgamation
pub fn vka_as_uploadable_key(
    vka: ValidErasedKeyAmalgamation<SecretParts>,
    password: Option<String>,
) -> Box<dyn CardUploadableKey> {
    let sqk = SequoiaKey::new(vka, password);
    Box::new(sqk)
}

/// Helper fn: get a Key<PublicParts, UnspecifiedRole> for a PublicKeyMaterial
pub fn public_key_material_to_key(
    pkm: &PublicKeyMaterial,
    key_type: KeyType,
    time: SystemTime,
) -> Result<Key<PublicParts, UnspecifiedRole>> {
    match pkm {
        PublicKeyMaterial::R(rsa) => {
            let k4 = Key4::import_public_rsa(&rsa.v, &rsa.n, Some(time))?;

            Ok(k4.into())
        }
        PublicKeyMaterial::E(ecc) => {
            let algo = ecc.algo.clone(); // FIXME?
            if let Algo::Ecc(algo_ecc) = algo {
                let curve = match algo_ecc.curve {
                    Curve::NistP256r1 => openpgp::types::Curve::NistP256,
                    Curve::NistP384r1 => openpgp::types::Curve::NistP384,
                    Curve::NistP521r1 => openpgp::types::Curve::NistP521,
                    Curve::Ed25519 => openpgp::types::Curve::Ed25519,
                    Curve::Cv25519 => openpgp::types::Curve::Cv25519,
                    c => unimplemented!("unhandled curve: {:?}", c),
                };

                match key_type {
                    KeyType::Authentication | KeyType::Signing => {
                        if algo_ecc.curve == Curve::Ed25519 {
                            // EdDSA
                            let k4 =
                                Key4::import_public_ed25519(&ecc.data, time)?;

                            Ok(Key::from(k4))
                        } else {
                            // ECDSA
                            let k4 = Key4::new(
                                time,
                                PublicKeyAlgorithm::ECDSA,
                                mpi::PublicKey::ECDSA {
                                    curve,
                                    q: mpi::MPI::new(&ecc.data),
                                },
                            )?;

                            Ok(k4.into())
                        }
                    }
                    KeyType::Decryption => {
                        if algo_ecc.curve == Curve::Cv25519 {
                            // EdDSA
                            let k4 = Key4::import_public_cv25519(
                                &ecc.data, None, None, time,
                            )?;

                            Ok(k4.into())
                        } else {
                            // FIXME: just defining `hash` and `sym` is not
                            // ok when a cert already exists

                            // ECDH
                            let k4 = Key4::new(
                                time,
                                PublicKeyAlgorithm::ECDH,
                                mpi::PublicKey::ECDH {
                                    curve,
                                    q: mpi::MPI::new(&ecc.data),
                                    hash: Default::default(),
                                    sym: Default::default(),
                                },
                            )?;

                            Ok(k4.into())
                        }
                    }
                    _ => unimplemented!("Unsupported KeyType"),
                }
            } else {
                panic!("unexpected algo {:?}", algo);
            }
        }
    }
}

/// Create a Cert from the three subkeys on a card.
/// (Calling this multiple times will result in different Certs!)
///
/// FIXME: make dec/auth keys optional
///
/// FIXME: accept optional metadata for user_id(s)?
pub fn make_cert(
    ca: &mut CardApp,
    key_sig: Key<PublicParts, UnspecifiedRole>,
    key_dec: Key<PublicParts, UnspecifiedRole>,
    key_aut: Key<PublicParts, UnspecifiedRole>,
) -> Result<Cert> {
    let mut pp = vec![];

    // 1) use the signing key as primary key
    let pri = PrimaryRole::convert_key(key_sig.clone());
    pp.push(Packet::from(pri));

    // 2) add decryption key as subkey
    let sub_dec = SubordinateRole::convert_key(key_dec);
    pp.push(Packet::from(sub_dec.clone()));

    // Temporary version of the cert
    let cert = Cert::try_from(pp.clone())?;

    // 3) make binding, sign with card -> add
    {
        let signing_builder =
            SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(SystemTime::now())?
                .set_key_validity_period(std::time::Duration::new(0, 0))?
                .set_key_flags(
                    KeyFlags::empty()
                        .set_storage_encryption()
                        .set_transport_encryption(),
                )?;

        // Allow signing on the card
        ca.verify_pw1_for_signing("123456")?;

        // Card-backed signer for bindings
        let mut card_signer = CardSigner::with_pubkey(ca, key_sig.clone());

        let signing_bsig: Packet = sub_dec
            .bind(&mut card_signer, &cert, signing_builder)?
            .into();

        pp.push(signing_bsig);
    }

    // 4) add auth subkey
    let sub_aut = SubordinateRole::convert_key(key_aut);
    pp.push(Packet::from(sub_aut.clone()));

    // 5) make, sign binding -> add
    {
        let signing_builder =
            SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(SystemTime::now())?
                .set_key_validity_period(std::time::Duration::new(0, 0))?
                .set_key_flags(KeyFlags::empty().set_authentication())?;

        // Allow signing on the card
        ca.verify_pw1_for_signing("123456")?;

        // Card-backed signer for bindings
        let mut card_signer = CardSigner::with_pubkey(ca, key_sig.clone());

        let signing_bsig: Packet = sub_aut
            .bind(&mut card_signer, &cert, signing_builder)?
            .into();

        pp.push(signing_bsig);
    }

    // 6) add user id from name / email
    let cardholder = ca.get_cardholder_related_data()?;

    // FIXME: process name field? accept email as argument?!
    let uid: UserID = cardholder.name.expect("expecting name on card").into();

    pp.push(uid.clone().into());

    // 7) make, sign binding -> add
    {
        let signing_builder =
            SignatureBuilder::new(SignatureType::PositiveCertification)
                .set_signature_creation_time(SystemTime::now())?
                .set_key_validity_period(std::time::Duration::new(0, 0))?
                .set_key_flags(
                    // Flags for primary key
                    KeyFlags::empty().set_signing().set_certification(),
                )?;

        // Allow signing on the card
        ca.verify_pw1_for_signing("123456")?;

        // Card-backed signer for bindings
        let mut card_signer = CardSigner::with_pubkey(ca, key_sig);

        let signing_bsig: Packet =
            uid.bind(&mut card_signer, &cert, signing_builder)?.into();

        pp.push(signing_bsig);
    }

    Cert::try_from(pp)
}

/// Implement the `CardUploadableKey` trait that openpgp-card uses to
/// upload (sub)keys to a card.
impl CardUploadableKey for SequoiaKey {
    fn get_key(&self) -> Result<PrivateKeyMaterial> {
        // Decrypt key with password, if set
        let key = match &self.password {
            None => self.key.clone(),
            Some(pw) => self.key.clone().decrypt_secret(
                &openpgp::crypto::Password::from(pw.as_str()),
            )?,
        };

        // Get private cryptographic material
        let unenc = if let Some(
            openpgp::packet::key::SecretKeyMaterial::Unencrypted(ref u),
        ) = key.optional_secret()
        {
            u
        } else {
            panic!("can't get private key material");
        };

        let secret_key_material = unenc.map(|mpis| mpis.clone());

        match (&self.public, secret_key_material) {
            (
                mpi::PublicKey::RSA { e, n },
                mpi::SecretKeyMaterial::RSA { d: _, p, q, u: _ },
            ) => {
                let sq_rsa = SqRSA::new(e.clone(), n.clone(), p, q);

                Ok(PrivateKeyMaterial::R(Box::new(sq_rsa)))
            }
            (
                mpi::PublicKey::ECDH { curve, .. },
                mpi::SecretKeyMaterial::ECDH { scalar },
            ) => {
                let sq_ecc =
                    SqEccKey::new(curve.oid().to_vec(), scalar, EccType::ECDH);

                Ok(PrivateKeyMaterial::E(Box::new(sq_ecc)))
            }
            (
                mpi::PublicKey::ECDSA { curve, .. },
                mpi::SecretKeyMaterial::ECDSA { scalar },
            ) => {
                let sq_ecc = SqEccKey::new(
                    curve.oid().to_vec(),
                    scalar,
                    EccType::ECDSA,
                );

                Ok(PrivateKeyMaterial::E(Box::new(sq_ecc)))
            }
            (
                mpi::PublicKey::EdDSA { curve, .. },
                mpi::SecretKeyMaterial::EdDSA { scalar },
            ) => {
                let sq_ecc = SqEccKey::new(
                    curve.oid().to_vec(),
                    scalar,
                    EccType::EdDSA,
                );

                Ok(PrivateKeyMaterial::E(Box::new(sq_ecc)))
            }
            (p, s) => {
                unimplemented!(
                    "Unexpected algorithms: public {:?}, \
                secret {:?}",
                    p,
                    s
                );
            }
        }
    }

    /// Number of non-leap seconds since January 1, 1970 0:00:00 UTC
    /// (aka "UNIX timestamp")
    fn get_ts(&self) -> u32 {
        let ts: Timestamp = Timestamp::try_from(self.key.creation_time())
            .expect("Creation time cannot be converted into u32 timestamp");
        ts.into()
    }

    fn get_fp(&self) -> [u8; 20] {
        let fp = self.key.fingerprint();
        assert_eq!(fp.as_bytes().len(), 20);

        fp.as_bytes().try_into().unwrap()
    }
}

/// RSA-specific data-structure to hold private (sub)key material for upload
/// with the `openpgp-card` crate.
struct SqRSA {
    e: MPI,
    n: MPI,
    p: ProtectedMPI,
    q: ProtectedMPI,
}

impl SqRSA {
    fn new(e: MPI, n: MPI, p: ProtectedMPI, q: ProtectedMPI) -> Self {
        Self { e, n, p, q }
    }
}

impl RSAKey for SqRSA {
    fn get_e(&self) -> &[u8] {
        self.e.value()
    }

    fn get_n(&self) -> &[u8] {
        self.n.value()
    }

    fn get_p(&self) -> &[u8] {
        self.p.value()
    }

    fn get_q(&self) -> &[u8] {
        self.q.value()
    }
}

/// ECC-specific data-structure to hold private (sub)key material for upload
/// with the `openpgp-card` crate.
struct SqEccKey {
    oid: Vec<u8>,
    scalar: ProtectedMPI,
    ecc_type: EccType,
}

impl SqEccKey {
    fn new(oid: Vec<u8>, scalar: ProtectedMPI, ecc_type: EccType) -> Self {
        SqEccKey {
            oid,
            scalar,
            ecc_type,
        }
    }
}

impl EccKey for SqEccKey {
    fn get_oid(&self) -> &[u8] {
        &self.oid
    }

    fn get_scalar(&self) -> &[u8] {
        self.scalar.value()
    }

    fn get_type(&self) -> EccType {
        self.ecc_type
    }
}

/// Convenience fn to select and upload a (sub)key from a Cert, as a given
/// KeyType. If multiple suitable (sub)keys are found, the first one is
/// used.
///
/// FIXME: picking the (sub)key to upload should probably done with
/// more intent.
pub fn upload_from_cert_yolo(
    oca: &mut CardAdmin,
    cert: &openpgp::Cert,
    key_type: KeyType,
    password: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let policy = StandardPolicy::new();

    // Find all suitable (sub)keys for key_type.
    let mut valid_ka = cert
        .keys()
        .with_policy(&policy, None)
        .secret()
        .alive()
        .revoked(false);
    valid_ka = match key_type {
        KeyType::Decryption => valid_ka.for_storage_encryption(),
        KeyType::Signing => valid_ka.for_signing(),
        KeyType::Authentication => valid_ka.for_authentication(),
        _ => return Err(anyhow!("Unexpected KeyType").into()),
    };

    // FIXME: for now, we just pick the first (sub)key from the list
    if let Some(vka) = valid_ka.next() {
        upload_key(oca, vka, key_type, password).map_err(|e| e.into())
    } else {
        Err(anyhow!("No suitable (sub)key found").into())
    }
}

/// Upload a ValidErasedKeyAmalgamation to the card as a specific KeyType.
///
/// The caller needs to make sure that `vka` is suitable for `key_type`.
pub fn upload_key(
    oca: &mut CardAdmin,
    vka: ValidErasedKeyAmalgamation<SecretParts>,
    key_type: KeyType,
    password: Option<String>,
) -> Result<(), OpenpgpCardError> {
    let sqk = SequoiaKey::new(vka, password);

    oca.upload_key(Box::new(sqk), key_type)
}

pub fn decrypt(
    ca: &mut CardApp,
    cert: &openpgp::Cert,
    msg: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut decrypted = Vec::new();
    {
        let reader = io::BufReader::new(&msg[..]);

        let p = StandardPolicy::new();
        let d = decryptor::CardDecryptor::new(ca, cert, &p)?;

        let db = DecryptorBuilder::from_reader(reader)?;
        let mut decryptor = db.with_policy(&p, None, d)?;

        // Read all data from decryptor and store in decrypted
        io::copy(&mut decryptor, &mut decrypted)?;
    }

    Ok(decrypted)
}

pub fn sign(
    ca: &mut CardApp,
    cert: &openpgp::Cert,
    input: &mut dyn io::Read,
) -> Result<String> {
    let mut armorer = armor::Writer::new(vec![], armor::Kind::Signature)?;
    {
        let p = StandardPolicy::new();
        let s = signer::CardSigner::new(ca, cert, &p)?;

        let message = Message::new(&mut armorer);
        let mut message = Signer::new(message, s).detached().build()?;

        // Process input data, via message
        io::copy(input, &mut message)?;

        message.finalize()?;
    }

    let buffer = armorer.finalize()?;

    String::from_utf8(buffer).context("Failed to convert signature to utf8")
}

/// Mapping function to get a fingerprint from "PublicKeyMaterial +
/// timestamp + KeyType" (intended for use with `CardApp.generate_key()`).
pub fn public_to_fingerprint(
    pkm: &PublicKeyMaterial,
    ts: SystemTime,
    kt: KeyType,
) -> Result<[u8; 20]> {
    // Transform PublicKeyMaterial into a Sequoia Key
    let key = public_key_material_to_key(pkm, kt, ts)?;

    // Get fingerprint from the Sequoia Key
    let fp = key.fingerprint();
    let fp = fp.as_bytes();

    assert_eq!(fp.len(), 20);
    Ok(fp.try_into()?)
}

// --------

/// Representation of an opened OpenPGP card in its basic, freshly opened,
/// state (i.e. no passwords have been verified, default privileges apply).
pub struct CardBase {
    card_app: CardApp,

    // Cache of "application related data".
    //
    // FIXME: Should be invalidated when changing data on the card!
    // (e.g. uploading keys, etc)
    ard: ApplicationRelatedData,
}

impl CardBase {
    pub fn new(card_app: CardApp, ard: ApplicationRelatedData) -> Self {
        Self { card_app, ard }
    }

    /// Get a reference to the internal CardApp object (for use in tests)
    pub fn get_card_app(&mut self) -> &mut CardApp {
        &mut self.card_app
    }

    /// Set up connection (cache "application related data") to a
    /// CardClient, on which the openpgp applet has already been opened.
    pub fn open_card(ccb: CardClientBox) -> Result<Self, OpenpgpCardError> {
        // read and cache "application related data"
        let mut card_app = CardApp::new(ccb);

        let ard = card_app.get_app_data()?;

        card_app.init_caps(&ard)?;

        Ok(Self { card_app, ard })
    }

    // --- application data ---

    /// Load "application related data".
    ///
    /// This is done once, after opening the OpenPGP card applet
    /// (the data is stored in the OpenPGPCard object).
    fn get_app_data(&mut self) -> Result<ApplicationRelatedData> {
        self.card_app.get_app_data()
    }

    pub fn get_aid(&self) -> Result<ApplicationId, OpenpgpCardError> {
        self.ard.get_aid()
    }

    pub fn get_historical(&self) -> Result<Historical, OpenpgpCardError> {
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
    ) -> Result<ExtendedCap, OpenpgpCardError> {
        self.ard.get_extended_capabilities()
    }

    pub fn get_algorithm_attributes(&self, key_type: KeyType) -> Result<Algo> {
        self.ard.get_algorithm_attributes(key_type)
    }

    /// PW status Bytes
    pub fn get_pw_status_bytes(&self) -> Result<PWStatus> {
        self.ard.get_pw_status_bytes()
    }

    pub fn get_fingerprints(
        &self,
    ) -> Result<KeySet<Fingerprint>, OpenpgpCardError> {
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
    pub fn get_cardholder_related_data(&mut self) -> Result<Cardholder> {
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
        if !ec.features.contains(&Features::AlgoAttrsChangeable) {
            // Algorithm attributes can not be changed,
            // list_supported_algo is not supported
            return Ok(None);
        }

        self.card_app.list_supported_algo()
    }

    // ----------

    /// Delete all state on this OpenPGP card
    pub fn factory_reset(&mut self) -> Result<()> {
        self.card_app.factory_reset()
    }

    pub fn verify_pw1_for_signing(
        mut self,
        pin: &str,
    ) -> Result<CardSign, CardBase> {
        assert!(pin.len() >= 6); // FIXME: Err

        if self.card_app.verify_pw1_for_signing(pin).is_ok() {
            Ok(CardSign { oc: self })
        } else {
            Err(self)
        }
    }

    pub fn check_pw1(&mut self) -> Result<Response, OpenpgpCardError> {
        self.card_app.check_pw1()
    }

    pub fn verify_pw1(mut self, pin: &str) -> Result<CardUser, CardBase> {
        assert!(pin.len() >= 6); // FIXME: Err

        if self.card_app.verify_pw1(pin).is_ok() {
            Ok(CardUser { oc: self })
        } else {
            Err(self)
        }
    }

    pub fn check_pw3(&mut self) -> Result<Response, OpenpgpCardError> {
        self.card_app.check_pw3()
    }

    pub fn verify_pw3(mut self, pin: &str) -> Result<CardAdmin, CardBase> {
        assert!(pin.len() >= 8); // FIXME: Err

        if self.card_app.verify_pw3(pin).is_ok() {
            Ok(CardAdmin { oc: self })
        } else {
            Err(self)
        }
    }
}

/// An OpenPGP card after successful verification of PW1 in mode 82
/// (verification for operations other than signing)
pub struct CardUser {
    oc: CardBase,
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardUser.
impl Deref for CardUser {
    type Target = CardBase;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

/// Allow access to fn of CardBase, through CardUser.
impl DerefMut for CardUser {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.oc
    }
}

impl CardUser {
    /// Decrypt the ciphertext in `dm`, on the card.
    pub fn decrypt(
        &mut self,
        dm: Cryptogram,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        self.card_app.decrypt(dm)
    }

    /// Run decryption operation on the smartcard
    /// (7.2.11 PSO: DECIPHER)
    pub(crate) fn pso_decipher(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        self.card_app.pso_decipher(data)
    }
}

/// An OpenPGP card after successful verification of PW1 in mode 81
/// (verification for signing)
pub struct CardSign {
    oc: CardBase,
}

/// Allow access to fn of CardBase, through CardSign.
impl Deref for CardSign {
    type Target = CardBase;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

/// Allow access to fn of CardBase, through CardSign.
impl DerefMut for CardSign {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.oc
    }
}

// FIXME: depending on the setting in "PW1 Status byte", only one
// signature can be made after verification for signing
impl CardSign {
    /// Sign the message in `hash`, on the card.
    pub fn signature_for_hash(
        &mut self,
        hash: Hash,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        self.card_app.signature_for_hash(hash)
    }

    /// Run signing operation on the smartcard
    /// (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)
    pub(crate) fn compute_digital_signature(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, OpenpgpCardError> {
        self.card_app.compute_digital_signature(data)
    }
}

/// An OpenPGP card after successful verification of PW3 ("Admin privileges")
pub struct CardAdmin {
    oc: CardBase,
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardAdmin.
impl Deref for CardAdmin {
    type Target = CardBase;

    fn deref(&self) -> &Self::Target {
        &self.oc
    }
}

/// Allow access to fn of OpenPGPCard, through OpenPGPCardAdmin.
impl DerefMut for CardAdmin {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.oc
    }
}

impl CardAdmin {
    pub fn set_name(
        &mut self,
        name: &str,
    ) -> Result<Response, OpenpgpCardError> {
        if name.len() >= 40 {
            return Err(anyhow!("name too long").into());
        }

        // All chars must be in ASCII7
        if name.chars().any(|c| !c.is_ascii()) {
            return Err(anyhow!("Invalid char in name").into());
        };

        self.card_app.set_name(name)
    }

    pub fn set_lang(
        &mut self,
        lang: &str,
    ) -> Result<Response, OpenpgpCardError> {
        if lang.len() > 8 {
            return Err(anyhow!("lang too long").into());
        }

        self.card_app.set_lang(lang)
    }

    pub fn set_sex(&mut self, sex: Sex) -> Result<Response, OpenpgpCardError> {
        self.card_app.set_sex(sex)
    }

    pub fn set_url(
        &mut self,
        url: &str,
    ) -> Result<Response, OpenpgpCardError> {
        if url.chars().any(|c| !c.is_ascii()) {
            return Err(anyhow!("Invalid char in url").into());
        }

        // Check for max len
        let ec = self.get_extended_capabilities()?;

        if url.len() < ec.max_len_special_do as usize {
            self.card_app.set_url(url)
        } else {
            Err(anyhow!("URL too long").into())
        }
    }

    pub fn upload_key(
        &mut self,
        key: Box<dyn CardUploadableKey>,
        key_type: KeyType,
    ) -> Result<(), OpenpgpCardError> {
        self.card_app.upload_key(key, key_type)
    }
}
