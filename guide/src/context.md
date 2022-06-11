<!--
SPDX-FileCopyrightText: 2022 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# OpenPGP card "hardware tokens"

This series of guides describes how to use [OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card) "hardware tokens"
(e.g. [YubiKey](https://www.yubico.com/products/), [Nitrokey](https://www.nitrokey.com/)
or [Gnuk](https://www.fsij.org/doc-gnuk/)) with new - and still experimental - Sequoia PGP-based tools.

## What are OpenPGP cards?

OpenPGP cards are hardware tokens that can store private key material and perform cryptographic operations.
The point of using such a device is that private cryptographic key material is never directly accessible to the
user's computer.

This way, even if the user's computer is compromised, their private OpenPGP key material is protected from being
exfiltrated by an attacker.

## Tool support, so far

Until now, most users have interacted with OpenPGP cards using one or both of:

1. [GnuPG](https://www.gnupg.org) (which internally uses a subsystem called [scdaemon](https://www.gnupg.org/documentation/manuals/gnupg/Invoking-SCDAEMON.html)), or

2. [OpenKeychain](https://www.openkeychain.org/) (OpenKeychain can be used via the K9 email software), or the related [TermBot](https://github.com/cotechde/termbot) SSH client, on Android devices.

## New OpenPGP card tools

This series of guides introduces a new set of tools that leverage OpenPGP cards, written in Rust.
These tools are built on a set of [OpenPGP card libraries](https://gitlab.com/openpgp-card/openpgp-card)
and [Sequoia PGP](https://sequoia-pgp.org/).

The ultimate goal of this series is to document a complete suite of easy-to-use tools for all use cases around
OpenPGP cards.
