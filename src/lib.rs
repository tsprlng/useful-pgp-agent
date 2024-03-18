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
use unimpl::unimpl;

/// An individual OpenPGP card key slot
pub struct CardSlot<'a> {
    tx: Mutex<Transaction<'a>>,

    // Which key slot does this OpenPGP card operate on
    key_type: KeyType,

    // The public key material that corresponds to the key slot of this signer
    //
    // The distinction between primary and subkey is irrelevant here, but we have to use some type.
    // So we model the key data as a public primary key packet.
    pubkey: PublicKey,
}

impl<'a> CardSlot<'a> {
    /// Set up a CardSigner for the card behind `tx`, using the key slot for `key_type`.
    ///
    /// Initializes the CardSigner based on public key information obtained from `pubkey`.
    pub fn with_pubkey(
        tx: Transaction<'a>,
        key_type: KeyType,
        pubkey: PublicKey,
    ) -> Result<Self, pgp::errors::Error> {
        Ok(Self {
            tx: Mutex::new(tx),
            pubkey,
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

        Self::with_pubkey(tx, key_type, pk)
    }
}

impl Debug for CardSlot<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // FIXME: also show card identifier
        write!(f, "CardSigner for {:?}", self.pubkey)?;

        Ok(())
    }
}

impl KeyTrait for CardSlot<'_> {
    fn fingerprint(&self) -> Vec<u8> {
        self.pubkey.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.pubkey.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.pubkey.algorithm()
    }
}

impl PublicKeyTrait for CardSlot<'_> {
    #[unimpl]
    fn verify_signature(
        &self,
        _hash: HashAlgorithm,
        _data: &[u8],
        _sig: &[Mpi],
    ) -> pgp::errors::Result<()>;

    #[unimpl]
    fn encrypt<R: CryptoRng + Rng>(
        &self,
        _rng: &mut R,
        _plain: &[u8],
    ) -> pgp::errors::Result<Vec<Mpi>>;

    #[unimpl]
    fn to_writer_old(&self, _writer: &mut impl std::io::Write) -> pgp::errors::Result<()>;
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

        unimplemented!();
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
        self.pubkey.clone()
    }
}
