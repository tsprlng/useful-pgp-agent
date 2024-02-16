// SPDX-FileCopyrightText: 2024 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Handle transformation of user-provided PINs according to the KDF configuration on the card,
//! if any.

use openpgp_card::card_do::KdfDo;
use openpgp_card::Error;
use sha2::Digest;

use crate::PinType;

trait Hasher {
    /// Update the hash with the given value.
    fn update(&mut self, _: &[u8]);

    /// Finalize the hash and return the result.
    fn finish(self: Box<Self>) -> Vec<u8>;
}

#[derive(Default)]
pub struct Sha2_256 {
    inner: sha2::Sha256,
}

impl Hasher for Sha2_256 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finish(self: Box<Self>) -> Vec<u8> {
        self.inner.finalize().as_slice().to_vec()
    }
}

#[derive(Default)]
pub struct Sha2_512 {
    inner: sha2::Sha512,
}

impl Hasher for crate::kdf::Sha2_512 {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finish(self: Box<Self>) -> Vec<u8> {
        self.inner.finalize().as_slice().to_vec()
    }
}

/// Map user-provided pw/pin value to a Vec<u8>.
///
/// This performs a KDF transformation, if the KDF mode is enabled on the card.
pub(crate) fn map_pin(
    pw: &str,
    pin_type: PinType,
    kdf_do: Option<&KdfDo>,
) -> Result<Vec<u8>, Error> {
    match kdf_do {
        None => {
            // KDF DO is not set at all -> use the raw pw bytes as PIN
            Ok(pw.as_bytes().to_vec())
        }
        Some(kdf) if kdf.kdf_algo() == 0 => {
            //  KDF algo is "0" -> use the raw pw bytes as PIN
            Ok(pw.as_bytes().to_vec())
        }
        Some(kdf) => {
            // KDF transformation needs to be applied to PIN

            match kdf.kdf_algo() {
                3 => itersalt(
                    pw,
                    kdf.hash_algo(),
                    kdf.iter_count(),
                    match pin_type {
                        PinType::Pw1 => kdf.salt_pw1(),
                        PinType::Rc => kdf.salt_rc(),
                        PinType::Pw3 => kdf.salt_pw3(),
                    },
                ),
                _ => Err(Error::UnsupportedFeature(
                    "The KDF mode on the card is currently unsupported".to_string(),
                )),
            }
        }
    }
}

/// see https://www.rfc-editor.org/rfc/rfc4880.html#section-3.7.1.3
fn itersalt(
    pw: &str,
    hash_algo: Option<u8>,
    count: Option<u32>,
    salt: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let hash_algo = match hash_algo {
        Some(hash_algo) => hash_algo,
        None => {
            return Err(Error::InternalError(
                "No KDF hash algorithm setting found".to_string(),
            ))
        }
    };

    // number of bytes that should be hashed
    let mut count = match count {
        Some(count) => count,
        None => {
            return Err(Error::InternalError(
                "No KDF iteration count setting found".to_string(),
            ))
        }
    } as usize;

    let salt = match salt {
        Some(salt) => salt,
        None => {
            return Err(Error::InternalError(
                "No KDF salt setting found".to_string(),
            ))
        }
    };

    // set up hasher
    let mut hasher: Box<dyn Hasher> = match hash_algo {
        0x08 => Box::<Sha2_256>::default(),
        0x0A => Box::<Sha2_512>::default(),
        _ => {
            return Err(Error::InternalError(
                "KDF: unsupported hash algorithm setting".to_string(),
            ))
        }
    };

    if count < salt.len() + pw.len() {
        return Err(Error::InternalError(
            "KDF: dubiously small count".to_string(),
        ));
    }

    // salt and pw must be hashed complete, at least once
    hasher.update(salt);
    count -= salt.len();

    hasher.update(pw.as_bytes());
    count -= pw.len();

    loop {
        if count >= salt.len() {
            hasher.update(salt);
            count -= salt.len();
        } else {
            hasher.update(&salt[0..count]);
            break;
        }

        if count >= pw.len() {
            hasher.update(pw.as_bytes());
            count -= pw.len();
        } else {
            hasher.update(&pw.as_bytes()[0..count]);
            break;
        }
    }

    Ok(hasher.finish())
}
