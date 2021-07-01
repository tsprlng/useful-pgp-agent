// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryInto;

use anyhow::anyhow;
use openpgp::crypto;
use openpgp::crypto::mpi;
use openpgp::policy::Policy;
use openpgp::types::PublicKeyAlgorithm;
use sequoia_openpgp as openpgp;

use openpgp_card::errors::OpenpgpCardError;
use openpgp_card::Hash;
use openpgp_card::OpenPGPCardUser;

use crate::PublicKey;

pub(crate) struct CardSigner<'a> {
    /// The OpenPGP card (authenticated to allow signing operations)
    ocu: &'a OpenPGPCardUser,

    /// The matching public key for the card's signing key
    public: PublicKey,
}

impl<'a> CardSigner<'a> {
    /// Try to create a CardSigner.
    ///
    /// An Error is returned if no match between the card's signing
    /// key and a (sub)key of `cert` can be made.
    pub fn new(
        ocu: &'a OpenPGPCardUser,
        cert: &openpgp::Cert,
        policy: &dyn Policy,
    ) -> Result<CardSigner<'a>, OpenpgpCardError> {
        // Get the fingerprint for the signing key from the card.
        let fps = ocu.get_fingerprints()?;
        let fp = fps.signature();

        if let Some(fp) = fp {
            // Transform into Sequoia Fingerprint
            let fp = openpgp::Fingerprint::from_bytes(fp.as_bytes());

            // Find the matching signing-capable (sub)key in `cert`
            let keys: Vec<_> = cert
                .keys()
                .with_policy(policy, None)
                .alive()
                .revoked(false)
                .for_signing()
                .filter(|ka| ka.fingerprint() == fp)
                .map(|ka| ka.key())
                .collect();

            // Exactly one matching (sub)key should be found. If not, fail!
            if keys.len() == 1 {
                let public = keys[0].clone();

                Ok(CardSigner {
                    ocu,
                    public: public.role_as_unspecified().clone(),
                })
            } else {
                Err(OpenpgpCardError::InternalError(anyhow!(
                    "Failed to find a matching (sub)key in cert"
                )))
            }
        } else {
            Err(OpenpgpCardError::InternalError(anyhow!(
                "Failed to get the signing key's Fingerprint \
                from the card"
            )))
        }
    }
}

impl<'a> crypto::Signer for CardSigner<'a> {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Delegate a signing operation to the OpenPGP card.
    ///
    /// This fn prepares the data structures that openpgp-card needs to
    /// perform the signing operation.
    ///
    /// (7.2.10 PSO: COMPUTE DIGITAL SIGNATURE)
    fn sign(
        &mut self,
        hash_algo: openpgp::types::HashAlgorithm,
        digest: &[u8],
    ) -> openpgp::Result<mpi::Signature> {
        match (self.public.pk_algo(), self.public.mpis()) {
            #[allow(deprecated)]
            (PublicKeyAlgorithm::RSASign, mpi::PublicKey::RSA { .. })
            | (
                PublicKeyAlgorithm::RSAEncryptSign,
                mpi::PublicKey::RSA { .. },
            ) => {
                let sig = match hash_algo {
                    openpgp::types::HashAlgorithm::SHA256 => {
                        let hash =
                            Hash::SHA256(digest.try_into().map_err(|_| {
                                anyhow!("invalid slice length")
                            })?);
                        self.ocu.signature_for_hash(hash)?
                    }
                    openpgp::types::HashAlgorithm::SHA384 => {
                        let hash =
                            Hash::SHA384(digest.try_into().map_err(|_| {
                                anyhow!("invalid slice length")
                            })?);
                        self.ocu.signature_for_hash(hash)?
                    }
                    openpgp::types::HashAlgorithm::SHA512 => {
                        let hash =
                            Hash::SHA512(digest.try_into().map_err(|_| {
                                anyhow!("invalid slice length")
                            })?);
                        self.ocu.signature_for_hash(hash)?
                    }
                    _ => {
                        return Err(anyhow!(
                            "Unsupported hash algorithm for RSA {:?}",
                            hash_algo
                        ));
                    }
                };

                let mpi = mpi::MPI::new(&sig[..]);
                Ok(mpi::Signature::RSA { s: mpi })
            }
            (PublicKeyAlgorithm::EdDSA, mpi::PublicKey::EdDSA { .. }) => {
                let hash = Hash::EdDSA(digest);
                let sig = self.ocu.signature_for_hash(hash)?;

                let r = mpi::MPI::new(&sig[..32]);
                let s = mpi::MPI::new(&sig[32..]);

                Ok(mpi::Signature::EdDSA { r, s })
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
