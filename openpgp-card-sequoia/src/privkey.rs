// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;
use std::convert::TryInto;

use openpgp_card::card_do::{Fingerprint, KeyGenerationTime};
use openpgp_card::crypto_data::{CardUploadableKey, EccKey, EccType, PrivateKeyMaterial, RSAKey};
use openpgp_card::Error;
use sequoia_openpgp::cert::amalgamation::key::ValidErasedKeyAmalgamation;
use sequoia_openpgp::crypto::{mpi, mpi::ProtectedMPI, mpi::MPI};
use sequoia_openpgp::packet::{
    key,
    key::{SecretParts, UnspecifiedRole},
    Key,
};
use sequoia_openpgp::types::{Curve, Timestamp};

/// A SequoiaKey represents the private cryptographic key material of an
/// OpenPGP (sub)key to be uploaded to an OpenPGP card.
pub(crate) struct SequoiaKey {
    key: Key<SecretParts, UnspecifiedRole>,
    public: mpi::PublicKey,
    password: Option<String>,
}

impl SequoiaKey {
    /// A `SequoiaKey` wraps a Sequoia PGP private (sub)key data
    /// (i.e. a ValidErasedKeyAmalgamation) in a form that can be uploaded
    /// by the openpgp-card crate.
    pub(crate) fn new(
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

/// Implement the `CardUploadableKey` trait that openpgp-card uses to
/// upload (sub)keys to a card.
impl CardUploadableKey for SequoiaKey {
    fn private_key(&self) -> Result<PrivateKeyMaterial, Error> {
        // Decrypt key with password, if set
        let key = match &self.password {
            None => self.key.clone(),
            Some(pw) => self
                .key
                .clone()
                .decrypt_secret(&sequoia_openpgp::crypto::Password::from(pw.as_str()))
                .map_err(|e| Error::InternalError(format!("sequoia decrypt failed {:?}", e)))?,
        };

        // Get private cryptographic material
        let unenc = if let Some(key::SecretKeyMaterial::Unencrypted(ref u)) = key.optional_secret()
        {
            u
        } else {
            panic!("can't get private key material");
        };

        let secret_key_material = unenc.map(|mpis| mpis.clone());

        match (self.public.clone(), secret_key_material) {
            (mpi::PublicKey::RSA { e, n }, mpi::SecretKeyMaterial::RSA { d, p, q, u: _ }) => {
                let sq_rsa = SqRSA::new(e, d, n, p, q)?;

                Ok(PrivateKeyMaterial::R(Box::new(sq_rsa)))
            }
            (mpi::PublicKey::ECDH { curve, q, .. }, mpi::SecretKeyMaterial::ECDH { scalar }) => {
                let sq_ecc = SqEccKey::new(curve, scalar, q, EccType::ECDH);

                Ok(PrivateKeyMaterial::E(Box::new(sq_ecc)))
            }
            (mpi::PublicKey::ECDSA { curve, q, .. }, mpi::SecretKeyMaterial::ECDSA { scalar }) => {
                let sq_ecc = SqEccKey::new(curve, scalar, q, EccType::ECDSA);

                Ok(PrivateKeyMaterial::E(Box::new(sq_ecc)))
            }
            (mpi::PublicKey::EdDSA { curve, q, .. }, mpi::SecretKeyMaterial::EdDSA { scalar }) => {
                let sq_ecc = SqEccKey::new(curve, scalar, q, EccType::EdDSA);

                Ok(PrivateKeyMaterial::E(Box::new(sq_ecc)))
            }
            (p, s) => {
                unimplemented!("Unexpected algorithms: public {:?}, secret {:?}", p, s);
            }
        }
    }

    /// Number of non-leap seconds since January 1, 1970 0:00:00 UTC
    /// (aka "UNIX timestamp")
    fn timestamp(&self) -> KeyGenerationTime {
        let ts: Timestamp = Timestamp::try_from(self.key.creation_time())
            .expect("Creation time cannot be converted into u32 timestamp");
        let ts: u32 = ts.into();

        ts.into()
    }

    fn fingerprint(&self) -> Result<Fingerprint, Error> {
        let fp = self.key.fingerprint();
        fp.as_bytes().try_into()
    }
}

/// RSA-specific data-structure to hold private (sub)key material for upload
/// with the `openpgp-card` crate.
struct SqRSA {
    e: MPI,
    n: MPI,
    p: ProtectedMPI,
    q: ProtectedMPI,
    nettle: nettle::rsa::PrivateKey,
}

impl SqRSA {
    #[allow(clippy::many_single_char_names)]
    fn new(
        e: MPI,
        d: ProtectedMPI,
        n: MPI,
        p: ProtectedMPI,
        q: ProtectedMPI,
    ) -> Result<Self, Error> {
        let nettle = nettle::rsa::PrivateKey::new(d.value(), p.value(), q.value(), None)
            .map_err(|e| Error::InternalError(format!("nettle error {:?}", e)))?;

        Ok(Self { e, n, p, q, nettle })
    }
}

impl RSAKey for SqRSA {
    fn e(&self) -> &[u8] {
        self.e.value()
    }

    fn p(&self) -> &[u8] {
        self.p.value()
    }

    fn q(&self) -> &[u8] {
        self.q.value()
    }

    fn pq(&self) -> Box<[u8]> {
        let (_, _, inv) = self.nettle.d_crt();
        inv
    }
    fn dp1(&self) -> Box<[u8]> {
        let (dp, _, _) = self.nettle.d_crt();
        dp
    }
    fn dq1(&self) -> Box<[u8]> {
        let (_, dq, _) = self.nettle.d_crt();
        dq
    }

    fn n(&self) -> &[u8] {
        self.n.value()
    }
}

/// ECC-specific data-structure to hold private (sub)key material for upload
/// with the `openpgp-card` crate.
struct SqEccKey {
    curve: Curve,
    private: ProtectedMPI,
    public: MPI,
    ecc_type: EccType,
}

impl SqEccKey {
    fn new(curve: Curve, private: ProtectedMPI, public: MPI, ecc_type: EccType) -> Self {
        SqEccKey {
            curve,
            private,
            public,
            ecc_type,
        }
    }
}

impl EccKey for SqEccKey {
    fn oid(&self) -> &[u8] {
        self.curve.oid()
    }

    fn private(&self) -> Vec<u8> {
        // FIXME: padding for 25519?
        match self.curve {
            Curve::NistP256 => self.private.value_padded(0x20).to_vec(),
            Curve::NistP384 => self.private.value_padded(0x30).to_vec(),
            Curve::NistP521 => self.private.value_padded(0x42).to_vec(),
            _ => self.private.value().to_vec(),
        }
    }

    fn public(&self) -> Vec<u8> {
        // FIXME: padding?
        self.public.value().to_vec()
    }

    fn ecc_type(&self) -> EccType {
        self.ecc_type
    }
}
