// SPDX-FileCopyrightText: Wiktor Kwapisiewicz <wiktor@metacode.biz>
// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod rpgp;

use std::fmt::{Debug, Formatter};
use std::sync::Mutex;

use openpgp_card::{KeyType, Transaction};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::PublicKey;
use pgp::types::{KeyId, KeyTrait, Mpi, PublicKeyTrait, SecretKeyRepr, SecretKeyTrait};
use rand::{CryptoRng, Rng};

/// An individual OpenPGP card key slot, which can be used for private key operations.
pub struct CardSlot<'a> {
    tx: Mutex<Transaction<'a>>,

    // Which key slot does this OpenPGP card operate on
    key_type: KeyType,

    // The public key material that corresponds to the key slot of this signer
    //
    // The distinction between primary and subkey is irrelevant here, but we have to use some type.
    // So we model the key data as a public primary key packet.
    public_key: PublicKey,
}

impl<'a> CardSlot<'a> {
    /// Set up a CardSigner for the card behind `tx`, using the key slot for `key_type`.
    ///
    /// Initializes the CardSigner based on public key information obtained from `public_key`.
    pub fn with_public_key(
        tx: Transaction<'a>,
        key_type: KeyType,
        public_key: PublicKey,
    ) -> Result<Self, pgp::errors::Error> {
        Ok(Self {
            tx: Mutex::new(tx),
            public_key,
            key_type,
        })
    }

    /// Set up a CardSigner for the card behind `tx`, using the key slot for `key_type`.
    ///
    /// Initializes the CardSigner based on public key information obtained from the card.
    pub fn init_from_card(
        mut tx: Transaction<'a>,
        key_type: KeyType,
    ) -> Result<Self, pgp::errors::Error> {
        let pk = rpgp::pubkey_from_card(&mut tx, key_type)?;

        Self::with_public_key(tx, key_type, pk)
    }

    /// The OpenPGP public key material that corresponds to the key in this CardSlot
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The card slot that this CardSlot uses
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
}

impl Debug for CardSlot<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // FIXME: also show card identifier
        write!(f, "CardSigner for {:?}", self.public_key)?;

        Ok(())
    }
}

impl KeyTrait for CardSlot<'_> {
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

impl PublicKeyTrait for CardSlot<'_> {
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

impl SecretKeyTrait for CardSlot<'_> {
    // We model the key data as a public primary key packet for this type.
    // FIXME: The choice of this type is a bit arbitrary.
    type PublicKey = PublicKey;

    fn unlock<F, G>(&self, _pw: F, _work: G) -> pgp::errors::Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> pgp::errors::Result<()>,
    {
        // FIXME: does this get called? if so, what happens to `work`?

        Err(pgp::errors::Error::Unimplemented(
            "CardSlot::unlock is not implemented".to_string(),
        ))
    }

    fn create_signature<F>(
        &self,
        _key_pw: F,
        _hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        let mut tx = self.tx.lock().unwrap();

        let sig = match self.key_type {
            KeyType::Signing => tx.pso_compute_digital_signature(data.into()).expect("sig"),
            _ => unimplemented!(),
        };

        // FIXME

        Ok(vec![
            Mpi::from_raw_slice(&sig[..32]),
            Mpi::from_raw_slice(&sig[32..]),
        ])
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }
}
