// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod privkey;
mod rpgp;

use std::fmt::{Debug, Formatter};
use std::sync::Mutex;

use openpgp_card::ocard::crypto::Hash;
use openpgp_card::ocard::KeyType;
use openpgp_card::state::Transaction;
use openpgp_card::Card;
use pgp::crypto::checksum;
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::PublicKey;
use pgp::types::{
    EcdsaPublicParams, KeyId, KeyTrait, Mpi, PublicKeyTrait, PublicParams, SecretKeyTrait,
};
pub use privkey::UploadableKey;
use rand::{CryptoRng, Rng};
pub use rpgp::{
    decrypt, fp_from_pub, make_certificate, public_key_material_and_fp_to_key,
    public_key_material_to_key,
};

use crate::rpgp::map_card_err;

/// An individual OpenPGP card key slot, which can be used for private key operations.
pub struct CardSlot<'cs, 't> {
    tx: Mutex<&'cs mut Card<Transaction<'t>>>,

    // Which key slot does this OpenPGP card operate on
    key_type: KeyType,

    // The public key material that corresponds to the key slot of this signer
    //
    // The distinction between primary and subkey is irrelevant here, but we have to use some type.
    // So we model the key data as a public primary key packet.
    public_key: PublicKey,

    touch_prompt: &'cs (dyn Fn() + Send + Sync),
}

impl<'cs, 't> CardSlot<'cs, 't> {
    /// Set up a CardSigner for the card behind `tx`, using the key slot for `key_type`.
    ///
    /// Initializes the CardSigner based on public key information obtained from `public_key`.
    pub fn with_public_key(
        tx: &'cs mut Card<Transaction<'t>>,
        key_type: KeyType,
        public_key: PublicKey,
        touch_prompt: &'cs (dyn Fn() + Send + Sync),
    ) -> Result<Self, pgp::errors::Error> {
        // FIXME: compare the fingerprint between card slot and public_key?

        Ok(Self {
            tx: Mutex::new(tx),
            public_key,
            key_type,
            touch_prompt,
        })
    }

    /// Set up a CardSlot for the card behind `tx`, using the key slot for `key_type`.
    ///
    /// Initializes the CardSigner based on public key information obtained from the card.
    pub fn init_from_card(
        tx: &'cs mut Card<Transaction<'t>>,
        key_type: KeyType,
        touch_prompt: &'cs (dyn Fn() + Send + Sync),
    ) -> Result<Self, pgp::errors::Error> {
        let pk = rpgp::pubkey_from_card(tx, key_type)?;

        Self::with_public_key(tx, key_type, pk, touch_prompt)
    }

    /// The OpenPGP public key material that corresponds to the key in this CardSlot
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The card slot that this CardSlot uses
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    fn touch_required(&self, tx: &mut Card<Transaction<'_>>) -> bool {
        // Touch is required if:
        // - the card supports the feature
        // - and the policy is set to a value other than 'Off'
        if let Ok(Some(uif)) = tx.user_interaction_flag(self.key_type) {
            uif.touch_policy().touch_required()
        } else {
            false
        }
    }
}

impl Debug for CardSlot<'_, '_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // FIXME: also show card identifier
        write!(f, "CardSlot for {:?}", self.public_key)?;

        Ok(())
    }
}

impl KeyTrait for CardSlot<'_, '_> {
    fn fingerprint(&self) -> Vec<u8> {
        self.public_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.public_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public_key.algorithm()
    }
}

impl PublicKeyTrait for CardSlot<'_, '_> {
    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &[Mpi],
    ) -> pgp::errors::Result<()> {
        self.public_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        plain: &[u8],
    ) -> pgp::errors::Result<Vec<Mpi>> {
        self.public_key.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl std::io::Write) -> pgp::errors::Result<()> {
        self.public_key.to_writer_old(writer)
    }
}

pub struct Unlocked;

impl SecretKeyTrait for CardSlot<'_, '_> {
    // We model the key data as a public primary key packet for this type.
    // FIXME: The choice of this type is a bit arbitrary.
    type PublicKey = PublicKey;
    type Unlocked = Self;

    fn unlock<F, G, T>(&self, _pw: F, work: G) -> pgp::errors::Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> pgp::errors::Result<T>,
    {
        work(self)
    }

    fn create_signature<F>(
        &self,
        _key_pw: F,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        #[allow(clippy::unwrap_used)]
        let mut tx = self.tx.lock().unwrap();

        let hash = match self.public_key.algorithm() {
            PublicKeyAlgorithm::RSA => to_hash_rsa(data, hash)?,
            PublicKeyAlgorithm::ECDSA => Hash::ECDSA({
                match self.public_key.public_params() {
                    PublicParams::ECDSA(EcdsaPublicParams::P256 { .. }) => &data[..32],
                    PublicParams::ECDSA(EcdsaPublicParams::P384 { .. }) => &data[..48],
                    PublicParams::ECDSA(EcdsaPublicParams::P521 { .. }) => &data[..64],
                    _ => data,
                }
            }),
            PublicKeyAlgorithm::EdDSA => Hash::EdDSA(data),

            _ => {
                return Err(pgp::errors::Error::Unimplemented(format!(
                    "Unsupported PublicKeyAlgorithm for signature creation: {:?}",
                    self.public_key.algorithm()
                )))
            }
        };

        if self.touch_required(&mut tx) {
            (self.touch_prompt)();
        }

        let sig = match self.key_type {
            KeyType::Signing => tx.card().signature_for_hash(hash).map_err(map_card_err)?,
            KeyType::Authentication => tx
                .card()
                .authenticate_for_hash(hash)
                .map_err(map_card_err)?,
            _ => {
                return Err(pgp::errors::Error::Unimplemented(format!(
                    "Unsupported KeyType for signature creation: {:?}",
                    self.key_type
                )))
            }
        };

        let mpis = match self.public_key.algorithm() {
            PublicKeyAlgorithm::RSA => vec![Mpi::from_raw(sig)],

            PublicKeyAlgorithm::ECDSA => {
                let mid = sig.len() / 2;

                vec![
                    Mpi::from_raw_slice(&sig[..mid]),
                    Mpi::from_raw_slice(&sig[mid..]),
                ]
            }
            PublicKeyAlgorithm::EdDSA => {
                assert_eq!(sig.len(), 64); // FIXME: check curve; add error handling

                vec![
                    Mpi::from_raw_slice(&sig[..32]),
                    Mpi::from_raw_slice(&sig[32..]),
                ]
            }

            alg => {
                return Err(pgp::errors::Error::Unimplemented(format!(
                    "Unsupported algorithm for signature creation: {:?}",
                    alg
                )))
            }
        };

        Ok(mpis)
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn public_params(&self) -> &PublicParams {
        self.public_key.public_params()
    }
}

impl CardSlot<'_, '_> {
    pub fn decrypt(&self, mpis: &[Mpi]) -> pgp::errors::Result<(Vec<u8>, SymmetricKeyAlgorithm)> {
        #[allow(clippy::unwrap_used)]
        let mut tx = self.tx.lock().unwrap();

        let decrypted_key = match self.public_key.public_params() {
            PublicParams::RSA { n, .. } => {
                let mut ciphertext = mpis[0].to_vec();

                // RSA modulus length. We use this length to pad the ciphertext, in case it was
                // zero truncated.
                //
                // FIXME: There might be a problematic corner case when the modulus itself is
                // zero-stripped, and as a consequence we don't pad enough?
                // (We might want to use rounding to "round" to a typical RSA modulus size?)
                let modulus_len = n.len();

                // Left zero-pad `ciphertext` to the length of the RSA modulus
                // (that is: if the ciphertext was zero-stripped, undo that stripping).
                //
                // This padding is not required in most cases. Typically, the ciphertext and
                // modulus should be the same length. However, there is a 1:256 likelihood that
                // the ciphertext happens to start with a 0x0 byte, which OpenPGP will truncate.
                while modulus_len > ciphertext.len() {
                    ciphertext.insert(0, 0u8);
                }

                let cryptogram = openpgp_card::ocard::crypto::Cryptogram::RSA(&ciphertext);

                if self.touch_required(&mut tx) {
                    (self.touch_prompt)();
                }

                tx.card().decipher(cryptogram).map_err(|e| {
                    pgp::errors::Error::Message(format!(
                        "RSA decipher operation on card failed: {}",
                        e
                    ))
                })?
            }

            PublicParams::ECDH {
                curve,
                alg_sym,
                hash,
                ..
            } => {
                let ciphertext = mpis[0].as_bytes();

                // encrypted and wrapped value derived from the session key
                let encrypted_session_key = mpis[2].as_bytes();

                let ciphertext = if *curve == ECCCurve::Curve25519 {
                    assert_eq!(
                        ciphertext[0], 0x40,
                        "Unexpected shape of Cv25519 encrypted data"
                    );

                    // Strip trailing 0x40
                    &ciphertext[1..]
                } else {
                    // For NIST and brainpool: we decrypt the ciphertext as is
                    ciphertext
                };

                let cryptogram = openpgp_card::ocard::crypto::Cryptogram::ECDH(ciphertext);

                if self.touch_required(&mut tx) {
                    (self.touch_prompt)();
                }

                let shared_secret: [u8; 32] = tx
                    .card()
                    .decipher(cryptogram)
                    .map_err(|e| {
                        pgp::errors::Error::Message(format!(
                            "ECDH decipher operation on card failed {}",
                            e
                        ))
                    })?
                    .try_into()
                    .map_err(|res: Vec<u8>| {
                        pgp::errors::Error::Message(format!(
                            "ECDH decipher produced a result of unexpected length {}",
                            res.len()
                        ))
                    })?;

                let encrypted_key_len: usize =
                    mpis[1].first().copied().map(Into::into).unwrap_or(0);

                let decrypted_key: Vec<u8> = pgp::crypto::ecdh::derive_session_key(
                    shared_secret,
                    encrypted_session_key,
                    encrypted_key_len,
                    &(curve.oid(), *alg_sym, *hash),
                    &self.public_key.fingerprint(),
                )?;

                decrypted_key
            }

            pp => {
                return Err(pgp::errors::Error::Message(format!(
                    "decrypt: Unsupported key type  {:?}",
                    pp
                )));
            }
        };

        // strip off the leading session key algorithm octet, and the two trailing checksum octets
        let dec_len = decrypted_key.len();
        let (sessionkey, checksum) = (
            &decrypted_key[1..dec_len - 2],
            &decrypted_key[dec_len - 2..],
        );

        // ... check the checksum, while we have it at hand
        checksum::simple(checksum, sessionkey)?;

        let session_key_algorithm = decrypted_key[0].into();
        Ok((sessionkey.to_vec(), session_key_algorithm))
    }
}

fn to_hash_rsa(data: &[u8], hash: HashAlgorithm) -> pgp::errors::Result<Hash> {
    match hash {
        HashAlgorithm::SHA2_256 => {
            if data.len() == 0x20 {
                #[allow(clippy::unwrap_used)]
                Ok(Hash::SHA256(data.try_into().unwrap()))
            } else {
                Err(pgp::errors::Error::Message(format!(
                    "Illegal digest len for SHA256: {}",
                    data.len()
                )))
            }
        }
        HashAlgorithm::SHA2_384 => {
            if data.len() == 0x30 {
                #[allow(clippy::unwrap_used)]
                Ok(Hash::SHA384(data.try_into().unwrap()))
            } else {
                Err(pgp::errors::Error::Message(format!(
                    "Illegal digest len for SHA384: {}",
                    data.len()
                )))
            }
        }
        HashAlgorithm::SHA2_512 => {
            if data.len() == 0x40 {
                #[allow(clippy::unwrap_used)]
                Ok(Hash::SHA512(data.try_into().unwrap()))
            } else {
                Err(pgp::errors::Error::Message(format!(
                    "Illegal digest len for SHA512: {}",
                    data.len()
                )))
            }
        }
        _ => Err(pgp::errors::Error::Message(format!(
            "Unsupported HashAlgorithm for RSA: {:?}",
            hash
        ))),
    }
}

/// Enum wrapper for the error types of this crate
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("rPGP error: {0}")]
    Rpgp(pgp::errors::Error),

    #[error("OpenPGP card error: {0}")]
    Ocard(openpgp_card::Error),

    #[error("Internal error: {0}")]
    Message(String),
}

impl From<pgp::errors::Error> for Error {
    fn from(value: pgp::errors::Error) -> Self {
        Error::Rpgp(value)
    }
}

impl From<openpgp_card::Error> for Error {
    fn from(value: openpgp_card::Error) -> Self {
        Error::Ocard(value)
    }
}
