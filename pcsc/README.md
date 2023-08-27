<!--
SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# PC/SC based smart card backend

This crate provides `PcscBackend` and `PcscTransaction`, which are implementations of the 
`CardBackend` and `CardTransactions` traits from the [`card-backend`](https://crates.io/crates/card-backend) crate.

This implementation uses the [pcsc](https://crates.io/crates/pcsc) Rust wrapper crate
to access OpenPGP cards.

Mainly intended for use with the [openpgp-card](https://gitlab.com/openpgp-card/openpgp-card) library.

## Documentation on PC/SC

[PC/SC](https://en.wikipedia.org/wiki/PC/SC) is a standard for interaction with smartcards and readers.

The workgroup publishes an [overview]( https://pcscworkgroup.com/specifications/)
and a [set of documents](https://pcscworkgroup.com/specifications/download/) detailing the standard.

The [pcsc-lite](https://pcsclite.apdu.fr/ ) implementation is used on many free software systems
([API documentation for pcsc-lite](https://pcsclite.apdu.fr/api/group__API.html)).

Microsoft [documentation](https://docs.microsoft.com/en-us/windows/win32/api/winscard/)
about their implementation of PC/SC.
