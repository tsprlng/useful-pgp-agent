// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::anyhow;
use openpgp_card::crypto_data::Cryptogram;
use openpgp_card::OpenPgpTransaction;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::packet;
use sequoia_openpgp::parse::stream::{DecryptionHelper, MessageStructure, VerificationHelper};
use sequoia_openpgp::types::{Curve, SymmetricAlgorithm};
use sequoia_openpgp::{crypto, KeyHandle};

use crate::PublicKey;

pub struct CardDecryptor<'a, 'app> {
    /// The OpenPGP card (authenticated to allow decryption operations)
    ca: &'a mut OpenPgpTransaction<'app>,

    /// The matching public key for the card's decryption key
    public: PublicKey,

    /// Callback function to signal if touch confirmation is needed
    touch_prompt: &'a (dyn Fn() + Send + Sync),
}

impl<'a, 'app> CardDecryptor<'a, 'app> {
    pub(crate) fn with_pubkey(
        ca: &'a mut OpenPgpTransaction<'app>,
        public: PublicKey,
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> CardDecryptor<'a, 'app> {
        Self {
            ca,
            public,
            touch_prompt,
        }
    }
}

impl<'a, 'app> crypto::Decryptor for CardDecryptor<'a, 'app> {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> sequoia_openpgp::Result<SessionKey> {
        // FIXME: use cached ARD value from caller?
        let ard = self.ca.application_related_data()?;

        // Touch is required if:
        // - the card supports the feature
        // - and the policy is set to a value other than 'Off'
        let touch_required = if let Some(uif) = ard.uif_pso_dec()? {
            uif.touch_policy().touch_required()
        } else {
            false
        };

        // Delegate a decryption operation to the OpenPGP card.
        //
        // This fn prepares the data structures that openpgp-card needs to
        // perform the decryption operation.
        //
        // (7.2.11 PSO: DECIPHER)
        match (ciphertext, self.public.mpis()) {
            (mpi::Ciphertext::RSA { c: ct }, mpi::PublicKey::RSA { .. }) => {
                let dm = Cryptogram::RSA(ct.value());

                if touch_required {
                    (self.touch_prompt)();
                }

                let dec = self.ca.decipher(dm)?;

                let sk = SessionKey::from(&dec[..]);
                Ok(sk)
            }
            (mpi::Ciphertext::ECDH { ref e, .. }, mpi::PublicKey::ECDH { ref curve, .. }) => {
                let dm = if curve == &Curve::Cv25519 {
                    assert_eq!(
                        e.value()[0],
                        0x40,
                        "Unexpected shape of decrypted Cv25519 data"
                    );

                    // Ephemeral key without header byte 0x40
                    Cryptogram::ECDH(&e.value()[1..])
                } else {
                    // NIST curves: ephemeral key with header byte
                    Cryptogram::ECDH(e.value())
                };

                if touch_required {
                    (self.touch_prompt)();
                }

                // Decryption operation on the card
                let mut dec = self.ca.decipher(dm)?;

                // Specifically handle return value format like Gnuk's
                // (Gnuk returns a leading '0x04' byte and
                // an additional 32 trailing bytes)
                if curve == &Curve::NistP256 && dec.len() == 65 {
                    assert_eq!(dec[0], 0x04, "Unexpected shape of decrypted NistP256 data");

                    // see Gnuk src/call-ec.c:82
                    dec = dec[1..33].to_vec();
                }

                #[allow(non_snake_case)]
                let S: crypto::mem::Protected = dec.into();

                Ok(crypto::ecdh::decrypt_unwrap(&self.public, &S, ciphertext)?)
            }

            (ciphertext, public) => Err(anyhow!(
                "Unsupported combination of ciphertext {:?} \
                     and public key {:?} ",
                ciphertext,
                public
            )),
        }
    }
}

impl<'a, 'app> DecryptionHelper for CardDecryptor<'a, 'app> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[packet::PKESK],
        _skesks: &[packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut dec_fn: D,
    ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        // Try to decrypt each PKESK, see:
        // https://docs.sequoia-pgp.org/src/sequoia_openpgp/packet/pkesk.rs.html#125
        for pkesk in pkesks {
            // Only attempt decryption if the KeyIDs match
            // (this check is an optimization)
            if pkesk.recipient() == &self.public.keyid()
                && pkesk
                    .decrypt(self, sym_algo)
                    .map(|(algo, session_key)| dec_fn(algo, &session_key))
                    .unwrap_or(false)
            {
                return Ok(Some(self.public.fingerprint()));
            }
        }

        Ok(None)
    }
}

impl VerificationHelper for CardDecryptor<'_, '_> {
    fn get_certs(
        &mut self,
        _ids: &[KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        Ok(vec![])
    }
    fn check(&mut self, _structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        Ok(())
    }
}
