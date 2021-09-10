// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Simple wrappers for performing very specific tasks with Sequoia PGP

use anyhow::{Context, Result};
use std::io;

use openpgp::armor;
use openpgp::crypto;
use openpgp::parse::{
    stream::{DecryptionHelper, DecryptorBuilder, VerificationHelper},
    Parse,
};
use openpgp::policy::Policy;
use openpgp::serialize::stream::{Message, Signer};
use sequoia_openpgp as openpgp;

pub fn sign_helper<S>(s: S, input: &mut dyn io::Read) -> Result<String>
where
    S: crypto::Signer + Send + Sync,
{
    let mut armorer = armor::Writer::new(vec![], armor::Kind::Signature)?;
    {
        let message = Message::new(&mut armorer);
        let mut message = Signer::new(message, s).detached().build()?;

        // Process input data, via message
        io::copy(input, &mut message)?;

        message.finalize()?;
    }

    let buffer = armorer.finalize()?;

    String::from_utf8(buffer).context("Failed to convert signature to utf8")
}

pub fn decryption_helper<D>(
    d: D,
    msg: Vec<u8>,
    p: &dyn Policy,
) -> Result<Vec<u8>>
where
    D: crypto::Decryptor + VerificationHelper + DecryptionHelper,
{
    let mut decrypted = Vec::new();
    {
        let reader = io::BufReader::new(&msg[..]);

        let db = DecryptorBuilder::from_reader(reader)?;
        let mut decryptor = db.with_policy(p, None, d)?;

        // Read all data from decryptor and store in decrypted
        io::copy(&mut decryptor, &mut decrypted)?;
    }

    Ok(decrypted)
}
