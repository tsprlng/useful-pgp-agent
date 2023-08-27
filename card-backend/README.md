<!--
SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Backend trait for Smart Card crates

This crate defines the `CardBackend` and `CardTransactions` traits.

The initial target for this abstraction layer was the
[openpgp-card](https://gitlab.com/openpgp-card/openpgp-card) set of client libraries
for OpenPGP card. This trait offers an implementation-agnostic means to access cards.
