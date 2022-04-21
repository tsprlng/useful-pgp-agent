<!--
SPDX-FileCopyrightText: 2022 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# OpenPGP card "hardware tokens"

This series of articles describes how to use [OpenPGP card](https://en.wikipedia.org/wiki/OpenPGP_card) devices
(e.g. [YubiKey](https://www.yubico.com/products/), [Nitrokey](https://www.nitrokey.com/)
or [Gnuk](https://www.fsij.org/doc-gnuk/)) with new - and still experimental - Sequoia PGP-based tools.

OpenPGP cards are hardware tokens that can store private key material and perform cryptographic operations.
The point of using such a device is that private cryptographic key material is never directly accessible to the
user's computer.

This way, even if the user's computer is compromised, their private OpenPGP key material is protected from being
exfiltrated by an attacker.


## New tools

Until now, most users have interacted with OpenPGP cards using one or both of:

1. [GnuPG](https://www.gnupg.org) (which internally uses a subsystem called [scdaemon](https://www.gnupg.org/documentation/manuals/gnupg/Invoking-SCDAEMON.html)), or

2. [OpenKeychain](https://www.openkeychain.org/) (OpenKeychain can be used via the K9 email software), or the related [TermBot](https://github.com/cotechde/termbot) SSH client, on Android devices.

This project works towards a new set of tools, using a library-first approach, written in Rust.
These tools are based on a set of [OpenPGP card libraries](https://gitlab.com/hkos/openpgp-card) and [Sequoia PGP](https://sequoia-pgp.org/).
