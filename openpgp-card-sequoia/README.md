<!--
SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

**OpenPGP card for Sequoia PGP**

This crate is a thin wrapper for the
[openpgp-card](https://crates.io/crates/openpgp-card) crate.
It offers convenient access to
[OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card)
functionality with [Sequoia PGP](https://sequoia-pgp.org/).

**Example code**

The program `main.rs` performs a number of functions on an OpenPGP card.
To use it, you need to set an environment variable to the serial number of 
the OpenPGP card you want to use.

NOTE: data on this card will be deleted in the process of running this 
program!

```
$ export TEST_CARD_SERIAL="01234567"
$ cargo run
```

You can see a lot more debugging output by increasing the log-level, 
like this:

```
$ RUST_LOG=trace cargo run
```