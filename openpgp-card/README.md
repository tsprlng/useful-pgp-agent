<!--
SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

**OpenPGP card client library**

This crate implements a client library for the
[OpenPGP card](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf)
specification, in Rust.

This library provides low level, OpenPGP implementation-agnostic access to 
OpenPGP cards. Its communication with cards is based on simple data 
structures that closely match the formats defined in the OpenPGP card 
specification.

**Card access backends**

This crate doesn't contain code to talk to cards. Implementations of the traits
`CardBackend`/`CardTransaction` need to be provided for access to cards.

The crates [openpgp-card-pcsc](https://crates.io/crates/openpgp-card-pcsc)
and the experimental crate [openpgp-card-scdc](https://crates.io/crates/openpgp-card-scdc)
provide implementations of these traits for use with this crate.

**Sequoia PGP wrapper**

See the companion crate [openpgp-card-sequoia](https://crates.io/crates/openpgp-card-sequoia)
for a high level wrapper to use this library with [Sequoia PGP](https://sequoia-pgp.org/).