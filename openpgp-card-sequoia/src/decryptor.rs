// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::anyhow;

use openpgp::crypto;
use openpgp::crypto::mpi;
use openpgp::crypto::SessionKey;
use openpgp::packet;
use openpgp::parse::stream::{
    DecryptionHelper, MessageStructure, VerificationHelper,
};
use openpgp::policy::Policy;
use openpgp::types::{Curve, SymmetricAlgorithm};
use openpgp::Cert;
use sequoia_openpgp as openpgp;

use openpgp_card::crypto_data::Cryptogram;
use openpgp_card::{CardApp, Error};

use crate::sq_util;
use crate::PublicKey;

pub struct CardDecryptor<'a> {
    /// The OpenPGP card (authenticated to allow decryption operations)
    ca: &'a mut CardApp,

    /// The matching public key for the card's decryption key
    public: PublicKey,
}

impl<'a> CardDecryptor<'a> {
    /// Try to create a CardDecryptor.
    ///
    /// An Error is returned if no match between the card's decryption
    /// key and a (sub)key of `cert` can be made.
    pub fn new(
        ca: &'a mut CardApp,
        cert: &Cert,
        policy: &dyn Policy,
    ) -> Result<CardDecryptor<'a>, Error> {
        // Get the fingerprint for the decryption key from the card.
        let ard = ca.get_application_related_data()?;
        let fps = ard.get_fingerprints()?;
        let fp = fps.decryption();

        if let Some(fp) = fp {
            // Transform into Sequoia Fingerprint
            let fp = openpgp::Fingerprint::from_bytes(fp.as_bytes());

            if let Some(vk) =
                sq_util::get_subkey_by_fingerprint(cert, policy, &fp, false)?
            {
                if vk.for_storage_encryption() || vk.for_transport_encryption()
                {
                    let public = vk.key().clone();
                    Ok(Self { ca, public })
                } else {
                    Err(Error::InternalError(anyhow!(
                        "(Sub)key {} in the cert isn't encryption capable",
                        fp
                    )))
                }
            } else {
                Err(Error::InternalError(anyhow!(
                    "Failed to find (sub)key {} in cert",
                    fp
                )))
            }
        } else {
            Err(Error::InternalError(anyhow!(
                "Failed to get the decryption key's Fingerprint from the card"
            )))
        }
    }
}

impl<'a> crypto::Decryptor for CardDecryptor<'a> {
    fn public(&self) -> &PublicKey {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> openpgp::Result<crypto::SessionKey> {
        // Delegate a decryption operation to the OpenPGP card.
        //
        // This fn prepares the data structures that openpgp-card needs to
        // perform the decryption operation.
        //
        // (7.2.11 PSO: DECIPHER)
        match (ciphertext, self.public.mpis()) {
            (mpi::Ciphertext::RSA { c: ct }, mpi::PublicKey::RSA { .. }) => {
                let dm = Cryptogram::RSA(ct.value());
                let dec = self.ca.decipher(dm)?;

                let sk = openpgp::crypto::SessionKey::from(&dec[..]);
                Ok(sk)
            }
            (
                mpi::Ciphertext::ECDH { ref e, .. },
                mpi::PublicKey::ECDH { ref curve, .. },
            ) => {
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

                // Decryption operation on the card
                let mut dec = self.ca.decipher(dm)?;

                // Specifically handle return value format like Gnuk's
                // (Gnuk returns a leading '0x04' byte and
                // an additional 32 trailing bytes)
                if curve == &Curve::NistP256 && dec.len() == 65 {
                    assert_eq!(
                        dec[0], 0x04,
                        "Unexpected shape of decrypted NistP256 data"
                    );

                    // see Gnuk src/call-ec.c:82
                    dec = dec[1..33].to_vec();
                }

                #[allow(non_snake_case)]
                let S: openpgp::crypto::mem::Protected = dec.into();

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

impl<'a> DecryptionHelper for CardDecryptor<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[packet::PKESK],
        _skesks: &[packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut dec_fn: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
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

impl<'a> VerificationHelper for CardDecryptor<'a> {
    fn get_certs(
        &mut self,
        _ids: &[openpgp::KeyHandle],
    ) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(vec![])
    }
    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}
