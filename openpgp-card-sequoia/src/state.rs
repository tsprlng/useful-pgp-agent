// SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! States of a card are modeled by the types `Open`, `Transaction`, `User`, `Sign`, `Admin`.

use openpgp_card::card_do::ApplicationRelatedData;
use openpgp_card::{OpenPgp, OpenPgpTransaction};

use crate::Card;

/// States that a `Card` can be in.
///
/// See the implementations for more detail.
pub trait State {}

impl State for Open {}
impl State for Transaction<'_> {}
impl State for User<'_, '_> {}
impl State for Sign<'_, '_> {}
impl State for Admin<'_, '_> {}

/// State of an OpenPGP card in its base state, no transaction has been started.
///
/// A transaction can be started on the card, in this state.
pub struct Open {
    pub(crate) pgp: OpenPgp,
}

/// State of an OpenPGP card once a transaction has been started.
///
/// The cards is in its base state, base authorization applies.
/// Card-Operations that don't require PIN validation can be performed in this state.
/// This includes many read-operations from the card.
///
/// (Note that a factory-reset can be performed in this base state.)
pub struct Transaction<'a> {
    pub(crate) opt: OpenPgpTransaction<'a>,

    // Cache of "application related data".
    //
    // FIXME: Should be invalidated when changing data on the card!
    // (e.g. uploading keys, etc)
    //
    // This field should probably be an Option<> that gets invalidated when appropriate and
    // re-fetched lazily.
    pub(crate) ard: ApplicationRelatedData,

    // verify status of pw1
    pub(crate) pw1: bool,

    // verify status of pw1 for signing
    pub(crate) pw1_sign: bool,

    // verify status of pw3
    pub(crate) pw3: bool,
}

/// State of an OpenPGP card after successfully verifying the User PIN
/// (this verification allow user operations other than signing).
///
/// In this state, e.g. decryption operations and authentication operations can be performed.
pub struct User<'app, 'open> {
    pub(crate) tx: &'open mut Card<Transaction<'app>>,
}

/// State of an OpenPGP card after successfully verifying PW1 for signing.
///
/// In this state, signatures can be issued.
pub struct Sign<'app, 'open> {
    pub(crate) tx: &'open mut Card<Transaction<'app>>,
}

/// State of an OpenPGP card after successful verification the Admin PIN.
///
/// In this state, the card can be configured, e.g.: importing key material onto the card,
/// or setting the cardholder name.
pub struct Admin<'app, 'open> {
    pub(crate) tx: &'open mut Card<Transaction<'app>>,
}
