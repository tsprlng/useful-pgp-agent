<!--
SPDX-FileCopyrightText: 2021-2023 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# scdaemon based backend (e.g., for the openpgp-card library)

This crate provides `ScdBackend`/`ScdTransaction`, which is an implementation
of the `CardBackend`/`CardTransaction` traits that uses an instance of GnuPG's
[scdaemon](https://www.gnupg.org/documentation/manuals/gnupg/Invoking-SCDAEMON.html)
to access OpenPGP cards.

Note that (unlike `card-backend-pcsc`), this backend doesn't implement
transaction guarantees.

## Known limitations

- Uploading RSA 4096 keys via `scdaemon` doesn't work with cards that don't 
  support Command Chaining (e.g. the "Floss Shop OpenPGP Smart Card").
  This is caused by a size limitation for client requests via the
  [Assuan](https://www.gnupg.org/documentation/manuals/assuan/) protocol.
  Assuan "Client requests" are limited to 1000 chars. Commands are sent as 
  ASCII encoded hex, so APDU commands are limited to around 480 bytes. This 
  is insufficient for importing RSA 4096 keys to the card (all other 
  OpenPGP card operations fit into this constraint).

- When using `scdaemon` via pcsc (by configuring `scdaemon` with 
  `disable-ccid`), choosing a specific card of multiple plugged-in OpenPGP 
  cards seems to be broken.
  So you probably want to plug in only one OpenPGP card at a time when using 
  `openpgp-card-scdc` combined with `disable-ccid`.

- When using `scdaemon` via its default `ccid` driver, choosing a 
  specific one of multiple plugged-in OpenPGP cards seems to only work up 
  to 4 plugged-in cards.
  So you probably want to plug in at most four OpenPGP cards at a time when 
  using `card-backend-scdc` with its ccid driver.
  (This limit has been raised in GnuPG 2.3.x)
