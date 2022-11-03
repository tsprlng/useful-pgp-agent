// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryInto;

use anyhow::anyhow;
use openpgp_card::crypto_data::Hash;
use openpgp_card::OpenPgpTransaction;
use sequoia_openpgp::crypto;
use sequoia_openpgp::crypto::mpi;
use sequoia_openpgp::types::{Curve, PublicKeyAlgorithm};

use crate::PublicKey;

pub struct CardSigner<'a, 'app> {
    /// The OpenPGP card (authenticated to allow signing operations)
    ca: &'a mut OpenPgpTransaction<'app>,

    /// The matching public key for the card's signing key
    public: PublicKey,

    /// Callback function to signal if touch confirmation is needed
    touch_prompt: &'a (dyn Fn() + Send + Sync),

    /// sign or auth? (true = auth)
    auth: bool,
}

impl<'a, 'app> CardSigner<'a, 'app> {
    pub(crate) fn with_pubkey(
        ca: &'a mut OpenPgpTransaction<'app>,
        public: PublicKey,
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> CardSigner<'a, 'app> {
        CardSigner {
            ca,
            public,
            touch_prompt,
            auth: false,
        }
    }

    pub(crate) fn with_pubkey_for_auth(
        ca: &'a mut OpenPgpTransaction<'app>,
        public: PublicKey,
        touch_prompt: &'a (dyn Fn() + Send + Sync),
    ) -> CardSigner<'a, 'app> {
        CardSigner {
            ca,
            public,
            touch_prompt,
            auth: true,
        }
    }
}

impl<'a, 'app> crypto::Signer for CardSigner<'a, 'app> {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn sign(
        &mut self,
        hash_algo: sequoia_openpgp::types::HashAlgorithm,
        digest: &[u8],
    ) -> sequoia_openpgp::Result<mpi::Signature> {
        // FIXME: use cached ARD value from caller?
        let ard = self.ca.application_related_data()?;

        // Get UIF setting for the sign or auth slot
        let uif = if !self.auth {
            ard.uif_pso_cds()?
        } else {
            ard.uif_pso_aut()?
        };

        // Touch is required if:
        // - the card supports the feature
        // - and the policy is set to a value other than 'Off'
        let touch_required = if let Some(uif) = uif {
            uif.touch_policy().touch_required()
        } else {
            false
        };

        let sig_fn = if !self.auth {
            OpenPgpTransaction::signature_for_hash
        } else {
            OpenPgpTransaction::authenticate_for_hash
        };

        // Delegate a signing (or auth) operation to the OpenPGP card.
        //
        // This fn prepares the data structures that openpgp-card needs to
        // perform the signing operation.
        //
        // (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)
        // or (7.2.13 INTERNAL AUTHENTICATE)

        match (self.public.pk_algo(), self.public.mpis()) {
            #[allow(deprecated)]
            (PublicKeyAlgorithm::RSASign, mpi::PublicKey::RSA { .. })
            | (PublicKeyAlgorithm::RSAEncryptSign, mpi::PublicKey::RSA { .. }) => {
                let hash = match hash_algo {
                    sequoia_openpgp::types::HashAlgorithm::SHA256 => Hash::SHA256(
                        digest
                            .try_into()
                            .map_err(|_| anyhow!("invalid slice length"))?,
                    ),
                    sequoia_openpgp::types::HashAlgorithm::SHA384 => Hash::SHA384(
                        digest
                            .try_into()
                            .map_err(|_| anyhow!("invalid slice length"))?,
                    ),
                    sequoia_openpgp::types::HashAlgorithm::SHA512 => Hash::SHA512(
                        digest
                            .try_into()
                            .map_err(|_| anyhow!("invalid slice length"))?,
                    ),
                    _ => {
                        return Err(anyhow!(
                            "Unsupported hash algorithm for RSA {:?}",
                            hash_algo
                        ));
                    }
                };

                if touch_required {
                    (self.touch_prompt)();
                }

                let sig = sig_fn(self.ca, hash)?;

                let mpi = mpi::MPI::new(&sig[..]);
                Ok(mpi::Signature::RSA { s: mpi })
            }
            (PublicKeyAlgorithm::EdDSA, mpi::PublicKey::EdDSA { .. }) => {
                let hash = Hash::EdDSA(digest);

                if touch_required {
                    (self.touch_prompt)();
                }

                let sig = sig_fn(self.ca, hash)?;

                let r = mpi::MPI::new(&sig[..32]);
                let s = mpi::MPI::new(&sig[32..]);

                Ok(mpi::Signature::EdDSA { r, s })
            }
            (PublicKeyAlgorithm::ECDSA, mpi::PublicKey::ECDSA { curve, .. }) => {
                let hash = match curve {
                    Curve::NistP256 => Hash::ECDSA(&digest[..32]),
                    Curve::NistP384 => Hash::ECDSA(&digest[..48]),
                    Curve::NistP521 => Hash::ECDSA(&digest[..64]),
                    _ => Hash::ECDSA(digest),
                };

                if touch_required {
                    (self.touch_prompt)();
                }

                let sig = sig_fn(self.ca, hash)?;

                let len_2 = sig.len() / 2;
                let r = mpi::MPI::new(&sig[..len_2]);
                let s = mpi::MPI::new(&sig[len_2..]);

                Ok(mpi::Signature::ECDSA { r, s })
            }

            // FIXME: implement NIST etc
            (pk_algo, _) => Err(anyhow!(
                "Unsupported combination of algorithm {:?} and pubkey {:?}",
                pk_algo,
                self.public
            )),
        }
    }
}
