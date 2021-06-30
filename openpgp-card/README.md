<!--
SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

**OpenPGP card client library**

This crate implements a client library for the
[OpenPGP card](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.1.pdf)
specification, in Rust.

This library is OpenPGP implementation-agnostic. Its communication with 
the card is based on simple data structures, derived from the formats 
defined in the OpenPGP card specification.

**Sequoia PGP wrapper**

See the companion crate
[openpgp-card-sequoia](https://crates.io/crates/openpgp-card-sequoia)
for a convenient wrapper to use this library with
[Sequoia PGP](https://sequoia-pgp.org/).