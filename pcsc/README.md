<!--
SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

**pcsc client for the openpgp-card library**

This crate provides `PcscClient`, which is an implementation of the 
`CardClient` trait that uses [pcsc](https://crates.io/crates/pcsc)
to access OpenPGP cards.