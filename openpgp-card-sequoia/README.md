<!--
SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

**OpenPGP card usage with Sequoia PGP**

This crate is a higher level wrapper for the
[openpgp-card](https://crates.io/crates/openpgp-card) crate.

It offers convenient access to
[OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card)
functionality using [Sequoia PGP](https://sequoia-pgp.org/).

Note: the current API of this crate is an early draft, reflected by version numbers in the 0.0.x range.

**Example code**

The program `examples/test.rs` performs a number of functions on an OpenPGP card.
To run it, you need to set an environment variable to the identifier of 
the OpenPGP card you want to use.

NOTE: data on this card will be deleted in the process of running this 
program!

```
$ export TEST_CARD_IDENT="0123:4567ABCD"
$ cargo run --example test
```

You can see more debugging output by increasing the log-level, like this:

```
$ RUST_LOG=trace cargo run --example test
```