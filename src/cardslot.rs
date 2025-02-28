// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fmt::{Debug, Formatter};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
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
    EcdhPublicParams, EcdsaPublicParams, Fingerprint, KeyId, KeyVersion, Mpi, PkeskBytes,
    PublicKeyTrait, PublicParams, SecretKeyTrait, SignatureBytes,
};
use pgp::{Esk, Message, PlainSessionKey};
use rand::{CryptoRng, Rng};

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
        let pk = crate::rpgp::pubkey_from_card(tx, key_type)?;

        Self::with_public_key(tx, key_type, pk, touch_prompt)
    }
}

impl CardSlot<'_, '_> {
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

    pub fn decrypt(
        &self,
        values: &PkeskBytes,
    ) -> pgp::errors::Result<(Vec<u8>, SymmetricKeyAlgorithm)> {
        #[allow(clippy::unwrap_used)]
        let mut tx = self.tx.lock().unwrap();

        let decrypted_key = match (self.public_key.public_params(), values) {
            (PublicParams::RSA { n, .. }, PkeskBytes::Rsa { mpi }) => {
                let mut ciphertext = mpi.to_vec();

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

            (
                PublicParams::ECDH(EcdhPublicParams::Known {
                    curve,
                    alg_sym,
                    hash,
                    ..
                }),
                PkeskBytes::Ecdh {
                    public_point,
                    encrypted_session_key,
                },
            ) => {
                let ciphertext = public_point.as_bytes();

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

                let shared_secret: Vec<u8> = tx.card().decipher(cryptogram).map_err(|e| {
                    pgp::errors::Error::Message(format!(
                        "ECDH decipher operation on card failed {}",
                        e
                    ))
                })?;

                let encrypted_key_len = encrypted_session_key.len();

                let decrypted_key: Vec<u8> = pgp::crypto::ecdh::derive_session_key(
                    &shared_secret,
                    encrypted_session_key,
                    encrypted_key_len,
                    &(curve.clone(), *alg_sym, *hash),
                    self.public_key.fingerprint().as_bytes(),
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

    pub fn decrypt_message(&self, message: &Message) -> Result<Message, pgp::errors::Error> {
        let Message::Encrypted { esk, edata } = message else {
            return Err(pgp::errors::Error::Message(
                "message must be Message::Encrypted".to_string(),
            ));
        };

        let values = match &esk[0] {
            Esk::PublicKeyEncryptedSessionKey(ref k) => k.values()?,
            _ => {
                return Err(pgp::errors::Error::Message(
                    "Expected PublicKeyEncryptedSessionKey".to_string(),
                ))
            }
        };

        let (session_key, session_key_algorithm) =
            self.unlock(String::new, |priv_key| priv_key.decrypt(values))?;

        let plain_session_key = PlainSessionKey::V3_4 {
            key: session_key,
            sym_alg: session_key_algorithm,
        };

        let decrypted = edata.decrypt(plain_session_key)?;

        Ok(decrypted)
    }
}

impl Debug for CardSlot<'_, '_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // FIXME: also show card identifier
        write!(f, "CardSlot for {:?}", self.public_key)?;

        Ok(())
    }
}

impl PublicKeyTrait for CardSlot<'_, '_> {
    fn version(&self) -> KeyVersion {
        KeyVersion::V4 // FIXME?
    }

    fn fingerprint(&self) -> Fingerprint {
        self.public_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.public_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public_key.algorithm()
    }

    fn created_at(&self) -> &DateTime<Utc> {
        self.public_key.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        None
    }

    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> pgp::errors::Result<()> {
        self.public_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: pgp::types::EskType,
    ) -> pgp::errors::Result<PkeskBytes> {
        self.public_key.encrypt(rng, plain, typ)
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> pgp::errors::Result<()> {
        self.public_key.serialize_for_hashing(writer)
    }

    fn public_params(&self) -> &PublicParams {
        self.public_key.public_params()
    }
}

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
    ) -> pgp::errors::Result<SignatureBytes>
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
            PublicKeyAlgorithm::EdDSALegacy => Hash::EdDSA(data),

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
            PublicKeyAlgorithm::RSA => vec![Mpi::from_slice(&sig)],

            PublicKeyAlgorithm::ECDSA => {
                let mid = sig.len() / 2;

                vec![Mpi::from_slice(&sig[..mid]), Mpi::from_slice(&sig[mid..])]
            }
            PublicKeyAlgorithm::EdDSALegacy => {
                assert_eq!(sig.len(), 64); // FIXME: check curve; add error handling

                vec![Mpi::from_slice(&sig[..32]), Mpi::from_slice(&sig[32..])]
            }

            alg => {
                return Err(pgp::errors::Error::Unimplemented(format!(
                    "Unsupported algorithm for signature creation: {:?}",
                    alg
                )))
            }
        };

        Ok(SignatureBytes::Mpis(mpis))
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
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
