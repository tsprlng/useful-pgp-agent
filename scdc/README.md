<!--
SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

**scdaemon client for the openpgp-card library**

This crate provides `ScdClient`, which is an implementation of the 
CardClient trait that uses an instance of GnuPG's
[scdaemon](https://www.gnupg.org/documentation/manuals/gnupg/Invoking-SCDAEMON.html)
to access OpenPGP cards.