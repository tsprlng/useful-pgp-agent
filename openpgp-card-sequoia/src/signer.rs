// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryInto;

use anyhow::anyhow;

use openpgp::crypto;
use openpgp::crypto::mpi;
use openpgp::types::{Curve, PublicKeyAlgorithm};
use sequoia_openpgp as openpgp;

use openpgp_card::crypto_data::Hash;
use openpgp_card::{CardApp, Error};

use crate::sq_util;
use crate::PublicKey;

pub struct CardSigner<'a> {
    /// The OpenPGP card (authenticated to allow signing operations)
    ca: &'a mut CardApp,

    /// The matching public key for the card's signing key
    public: PublicKey,
}

impl<'a> CardSigner<'a> {
    /// Try to create a CardSigner.
    ///
    /// An Error is returned if no match between the card's signing
    /// key and a (sub)key of `cert` can be made.
    pub fn new(
        ca: &'a mut CardApp,
        cert: &openpgp::Cert,
    ) -> Result<CardSigner<'a>, Error> {
        // Get the fingerprint for the signing key from the card.
        let ard = ca.application_related_data()?;
        let fps = ard.fingerprints()?;
        let fp = fps.signature();

        if let Some(fp) = fp {
            // Transform into Sequoia Fingerprint
            let fp = openpgp::Fingerprint::from_bytes(fp.as_bytes());

            if let Some(eka) = sq_util::get_subkey_by_fingerprint(cert, &fp)? {
                let key = eka.key().clone();
                Ok(Self::with_pubkey(ca, key))
            } else {
                Err(Error::InternalError(anyhow!(
                    "Failed to find (sub)key {} in cert",
                    fp
                )))
            }
        } else {
            Err(Error::InternalError(anyhow!(
                "Failed to get the signing key's Fingerprint from the card"
            )))
        }
    }

    pub(crate) fn with_pubkey(
        ca: &'a mut CardApp,
        public: PublicKey,
    ) -> CardSigner<'a> {
        CardSigner { ca, public }
    }
}

impl<'a> crypto::Signer for CardSigner<'a> {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn sign(
        &mut self,
        hash_algo: openpgp::types::HashAlgorithm,
        digest: &[u8],
    ) -> openpgp::Result<mpi::Signature> {
        // Delegate a signing operation to the OpenPGP card.
        //
        // This fn prepares the data structures that openpgp-card needs to
        // perform the signing operation.
        //
        // (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)

        match (self.public.pk_algo(), self.public.mpis()) {
            #[allow(deprecated)]
            (PublicKeyAlgorithm::RSASign, mpi::PublicKey::RSA { .. })
            | (
                PublicKeyAlgorithm::RSAEncryptSign,
                mpi::PublicKey::RSA { .. },
            ) => {
                let hash = match hash_algo {
                    openpgp::types::HashAlgorithm::SHA256 => Hash::SHA256(
                        digest
                            .try_into()
                            .map_err(|_| anyhow!("invalid slice length"))?,
                    ),
                    openpgp::types::HashAlgorithm::SHA384 => Hash::SHA384(
                        digest
                            .try_into()
                            .map_err(|_| anyhow!("invalid slice length"))?,
                    ),
                    openpgp::types::HashAlgorithm::SHA512 => Hash::SHA512(
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

                let sig = self.ca.signature_for_hash(hash)?;

                let mpi = mpi::MPI::new(&sig[..]);
                Ok(mpi::Signature::RSA { s: mpi })
            }
            (PublicKeyAlgorithm::EdDSA, mpi::PublicKey::EdDSA { .. }) => {
                let hash = Hash::EdDSA(digest);

                let sig = self.ca.signature_for_hash(hash)?;

                let r = mpi::MPI::new(&sig[..32]);
                let s = mpi::MPI::new(&sig[32..]);

                Ok(mpi::Signature::EdDSA { r, s })
            }
            (
                PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA { curve, .. },
            ) => {
                let hash = match curve {
                    Curve::NistP256 => Hash::ECDSA(&digest[..32]),
                    Curve::NistP384 => Hash::ECDSA(&digest[..48]),
                    Curve::NistP521 => Hash::ECDSA(&digest[..64]),
                    _ => Hash::ECDSA(digest),
                };

                let sig = self.ca.signature_for_hash(hash)?;

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
