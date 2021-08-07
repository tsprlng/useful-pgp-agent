// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! This library supports using openpgp-card functionality with
//! sequoia_openpgp data structures.

use std::convert::TryFrom;
use std::convert::TryInto;
use std::error::Error;
use std::io;
use std::time::SystemTime;

use anyhow::{anyhow, Context, Result};
use openpgp::armor;
use openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use openpgp::crypto::mpi;
use openpgp::crypto::mpi::{ProtectedMPI, MPI};
use openpgp::packet::key::{SecretParts, UnspecifiedRole};
use openpgp::packet::{key, Key};
use openpgp::parse::{stream::DecryptorBuilder, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Message, Signer};
use sequoia_openpgp as openpgp;

use openpgp_card::card_app::CardApp;
use openpgp_card::{
    errors::OpenpgpCardError, CardAdmin, CardUploadableKey, EccKey, EccType,
    KeyType, PrivateKeyMaterial, PublicKeyMaterial, RSAKey,
};
use sequoia_openpgp::packet::key::{Key4, PublicParts};
use sequoia_openpgp::types::Timestamp;

mod decryptor;
mod signer;

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
    time: SystemTime,
) -> Result<Key<PublicParts, UnspecifiedRole>> {
    match pkm {
        PublicKeyMaterial::R(rsa) => {
            let k4: Key4<key::PublicParts, key::UnspecifiedRole> =
                Key4::import_public_rsa(&rsa.v, &rsa.n, Some(time))?;

            Ok(Key::from(k4))
        }
        _ => unimplemented!("ECC not implemented yet"),
    }
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
    cert: &sequoia_openpgp::Cert,
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
    cert: &sequoia_openpgp::Cert,
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
    cert: &sequoia_openpgp::Cert,
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
