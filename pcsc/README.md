<!--
SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# PC/SC client for the openpgp-card library

This crate provides `PcscBackend` and `PcscTransaction`, which are implementations of the 
`CardBackend` and `CardTransactions` traits from the [`openpgp-card`](https://crates.io/crates/openpgp-card) crate.

This implementation uses the [pcsc](https://crates.io/crates/pcsc) Rust wrapper crate
to access OpenPGP cards.

## Documentation

[PC/SC](https://en.wikipedia.org/wiki/PC/SC) is a standard for interaction with smartcards and readers.

The workgroup publishes an [overview]( https://pcscworkgroup.com/specifications/)
and a [set of documents](https://pcscworkgroup.com/specifications/download/) detailing the standard.

The [pcsc-lite](https://pcsclite.apdu.fr/ ) implementation is used on many free software systems
([API documentation for pcsc-lite](https://pcsclite.apdu.fr/api/group__API.html)).

Microsoft [documentation](https://docs.microsoft.com/en-us/windows/win32/api/winscard/)
about their implementation of PC/SC.
