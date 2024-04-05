// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::convert::TryFrom;
use std::convert::TryInto;

use openpgp_card::ocard::crypto::{CardUploadableKey, EccKey, EccType, PrivateKeyMaterial, RSAKey};
use openpgp_card::ocard::data::{Fingerprint, KeyGenerationTime};
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
                .map_err(|e| Error::InternalError(format!("sequoia decrypt failed {e:?}")))?,
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

fn mpi_to_biguint(mpi: &MPI) -> rsa::BigUint {
    slice_to_biguint(mpi.value())
}

fn slice_to_biguint(bytes: &[u8]) -> rsa::BigUint {
    rsa::BigUint::from_bytes_be(bytes)
}

/// RSA-specific data-structure to hold private (sub)key material for upload
/// with the `openpgp-card` crate.
struct SqRSA {
    e: MPI,
    n: MPI,
    p: ProtectedMPI,
    q: ProtectedMPI,
    pq: ProtectedMPI,
    dp1: ProtectedMPI,
    dq1: ProtectedMPI,
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
        let key = rsa::RsaPrivateKey::from_components(
            mpi_to_biguint(&n),
            mpi_to_biguint(&e),
            slice_to_biguint(d.value()),
            vec![slice_to_biguint(p.value()), slice_to_biguint(q.value())],
        )
        .map_err(|e| Error::InternalError(format!("rsa error {e:?}")))?;

        let pq = key
            .qinv()
            .ok_or_else(|| Error::InternalError("pq value missing".into()))?
            .to_biguint()
            .ok_or_else(|| Error::InternalError("conversion to bigunit failed".into()))?
            .to_bytes_be()
            .into();

        let dp1 = key
            .dp()
            .ok_or_else(|| Error::InternalError("dp1 value missing".into()))?
            .to_bytes_be()
            .into();

        let dq1 = key
            .dq()
            .ok_or_else(|| Error::InternalError("dq1 value missing".into()))?
            .to_bytes_be()
            .into();

        Ok(Self {
            e,
            n,
            p,
            q,
            pq,
            dp1,
            dq1,
        })
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
        self.pq.value().into()
    }

    fn dp1(&self) -> Box<[u8]> {
        self.dp1.value().into()
    }

    fn dq1(&self) -> Box<[u8]> {
        self.dq1.value().into()
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
        match self.curve {
            Curve::NistP256 => self.private.value_padded(0x20).to_vec(),
            Curve::NistP384 => self.private.value_padded(0x30).to_vec(),
            Curve::NistP521 => self.private.value_padded(0x42).to_vec(),
            Curve::Cv25519 | Curve::Ed25519 => self.private.value_padded(0x20).to_vec(),
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

#[cfg(test)]
mod tests {
    use openpgp::cert::Cert;
    use openpgp::crypto::mpi::PublicKey;
    use openpgp::packet::key::SecretKeyMaterial;
    use openpgp::parse::Parse;
    use sequoia_openpgp as openpgp;
    use testresult::TestResult;

    use super::*;

    #[test]
    fn parsing_rsa_key() -> TestResult {
        let cert = Cert::from_bytes(
            r#"-----BEGIN PGP PRIVATE KEY BLOCK-----

lQHYBGPmItUBBADp/S0sPqOQF6oBEQf558E5HeVtRP0qyWaVT0/fl7gj2jMSu6kF
de1jbr7AdeQxa7RiOo7m/ob8ZzKIzFNMLVfKsfo4mn5QjYulnadl+dyl87Jj1TlN
iEmeVvKbJUzXf7p4B4zFBFwIoCWtGZMTuUOgvi11Gbt00QwNUZdB10VjNwARAQAB
AAP/dH22pR3kSWL2oMRNX8XZJSn0pENh9RDCsRgE0HDU3IiPv8ZMviq5TjT+44tt
2YrhCbxUk7zpEDUCbCepWrYCS7Q7pMCJul2AdymJBDkNwzrPjNdzPwx1mOIudDFp
uosokjzx/bDNb9c8rdQpB5Oz9f9qZ9WhmfittQvBFPmBjyUCAPHWyhSVt86Wc3Dd
/1nQRLwMHVJK6VszIMO0EYgGvaFN9WXh6VUue9DXnAkHejUDNpsOlJfiAHMDU0fS
PnBX4D0CAPewtqGyIyluZ+S/+MJQBOUqLPzqHHr6smGmbOYFG52RFv17LhQH/02h
sLkd6qXXNUFSOF02XiYV9RywhnSadIMCALP4oM2YGCQL+B5bj3bT1uwoF8O0gwuW
FAc6Sz3ESpaI11ABLOv2wPNS3OcUyyIUe/DPVbekaKswvO57Ddzw5iait7QFQUJD
REWIzgQTAQgAOBYhBBCVR7AQd8pmtyaMetgkYA0A8AOABQJj5iLVAhsBBQsJCAcC
BhUKCQgLAgQWAgMBAh4BAheAAAoJENgkYA0A8AOA5W4EAMGuqrRLFjonYYS97Ypx
zo7HUpOALrLVgfwKoxX2/DdC4FWOQ61cog63KKOiM/DjF/TimLD7R4wls6pbELyD
T038FOlGoWtmtQuf3iUsBKdAYPPiqInaDU9XCy/hm1f7xOz70kpUXVG8K6c6my+b
/fGkli/zcEWR55dOMPeoZ6zF
=QZJ9
-----END PGP PRIVATE KEY BLOCK-----"#,
        )?;
        if let Key::V4(key) = cert.primary_key().key().clone().parts_into_secret()? {
            let (e, n) = if let PublicKey::RSA { e, n } = key.mpis() {
                (e, n)
            } else {
                unreachable!();
            };
            if let Some(SecretKeyMaterial::Unencrypted(secret)) = key.optional_secret() {
                assert!(secret.map(|secret| {
                    if let openpgp::crypto::mpi::SecretKeyMaterial::RSA { d, p, q, .. } = secret {
                        let rsa = SqRSA::new(e.clone(), d.clone(), n.clone(), p.clone(), q.clone())
                            .unwrap();
                        assert_eq!(
                            rsa.pq(),
                            vec![
                                66, 30, 140, 169, 99, 220, 224, 43, 7, 176, 133, 35, 251, 25, 162,
                                178, 14, 200, 188, 60, 82, 126, 134, 117, 184, 10, 186, 28, 162,
                                177, 225, 3, 147, 218, 96, 195, 182, 159, 32, 48, 87, 141, 182, 73,
                                232, 37, 154, 152, 123, 11, 1, 86, 188, 224, 157, 35, 125, 4, 210,
                                229, 233, 121, 207, 14
                            ]
                            .into()
                        );
                        assert_eq!(
                            rsa.dp1(),
                            vec![
                                19, 67, 44, 109, 95, 79, 120, 160, 251, 40, 238, 69, 188, 125, 158,
                                59, 236, 43, 25, 182, 229, 199, 97, 215, 38, 63, 93, 118, 28, 51,
                                86, 121, 195, 38, 14, 76, 107, 128, 124, 84, 50, 24, 55, 143, 228,
                                231, 252, 13, 137, 100, 43, 233, 189, 18, 148, 22, 155, 183, 136,
                                195, 120, 103, 71, 113
                            ]
                            .into()
                        );
                        assert_eq!(
                            rsa.dq1(),
                            vec![
                                29, 192, 92, 47, 143, 246, 41, 67, 217, 182, 224, 88, 64, 254, 219,
                                151, 171, 57, 60, 39, 226, 195, 226, 217, 10, 97, 179, 50, 237,
                                234, 35, 67, 10, 63, 232, 75, 224, 156, 21, 78, 125, 221, 124, 94,
                                219, 144, 144, 9, 21, 143, 138, 181, 167, 146, 39, 128, 251, 176,
                                54, 131, 239, 253, 157, 129
                            ]
                            .into()
                        );
                        true
                    } else {
                        false
                    }
                }))
            } else {
                unreachable!();
            }
        } else {
            unreachable!();
        }

        Ok(())
    }
}
