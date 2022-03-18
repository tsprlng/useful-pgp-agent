<!--
SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# OpenPGP card tools

This crate contains two tools for inspecting, configuring and using OpenPGP
cards: `opgpcard` and `opgpcard-pin`.

# Install

One easy way to install this crate is via the "cargo" tool.

The following build dependencies are needed for current Debian:

```
# apt install rustc cargo clang pkg-config nettle-dev libpcsclite-dev
```

And for current Fedora:

```
# dnf install rustc cargo clang nettle-devel pcsc-lite-devel
```

Afterwards, you can install this crate by running:

```
$ cargo install openpgp-card-tools
```

Finally, add `$HOME/.cargo/bin` to your PATH to be able to run the installed
binaries.

## opgpcard

A tool to inspect, configure and use OpenPGP cards. All calls of this tool are
non-interactive (this tool is designed to be easily usable from
shell-scripts).

### List and inspect cards

List idents of all currently connected cards:

```
$ opgpcard list
```

Print status information about a card. The card is implicitly selected.
However, this only works if exactly one card is connected:

```
$ opgpcard status
```

Explicitly print the status information for a specific card:

```
$ opgpcard status -c ABCD:01234567
```

Add `-v` for more verbose card status (including the list of supported
algorithms of the card, if the card returns that list):

```
$ opgpcard status -c ABCD:01234567 -v
```

### Using a card for ssh auth

To use an OpenPGP card for ssh login, an authentication key needs to exist on the card.

To allow login, the ssh public key representation of the authentications key needs to be added to
`.ssh/authorized_keys` on the remote machine. `opgpcard ssh` shows the ssh public key string for the authentication
key on the card.

### Import keys

Import private key onto a card. This works if at most one (sub)key per role (
sign, decrypt, auth) exists in `key.priv`:

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> import key.priv
```

Import private key onto a card while explicitly selecting subkeys. Explicitly
specified fingerprints are necessary if more than one subkey exists
in `key.priv` for any role (note: spaces in fingerprints are ignored).

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> import key.priv \
 --sig-fp "F290 DBBF 21DB 8634 3C96  157B 87BE 15B7 F548 D97C" \
 --dec-fp "3C6E 08F6 7613 8935 8B8D  7666 73C7 F1A9 EEDA C360" \
 --auth-fp "D6AA 48EF 39A2 6F26 C42D  5BCB AAD2 14D5 5332 C838"
```

When fingerprints are only specified for a subset of the roles, no keys will
be imported for the other roles.

### Generate Keys on the card

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> generate -p <user-pin-file> -o <output-cert-file> 25519
```

### Set card metadata

Set cardholder name:

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> name "Bar<<Foo"
```

Set cardholder URL:

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> url "https://keyurl.example"
```

### Signing

For now, this tool only supports creating detached signatures, like this
(if no input file is set, stdin is read):

```
$ opgpcard sign --detached -c ABCD:01234567 -p <user-pin-file> -s <cert-file> <input-file>
```

### Decrypting

Decryption using a card (if no input file is set, stdin is read):

```
$ opgpcard decrypt -c ABCD:01234567 -p <user-pin-file> -r <cert-file> <input-file>
```

### Factory reset

Factory reset:

```
$ opgpcard factory-reset -c ABCD:01234567
```

NOTE: you do not need a PIN to reset a card!

### Using file-descriptors for PINs

When using a shell like
[bash](https://www.gnu.org/software/bash/manual/html_node/Redirections.html#Here-Strings)
, you can pass user and/or admin PINs via file-descriptors:

```
$ opgpcard sign --detached -c ABCD:01234567 -p /dev/fd/3 -s <cert-file> 3<<<123456
```

```
$ opgpcard admin -c ABCD:01234567 -P /dev/fd/3 generate -p /dev/fd/4 -o <output-cert-file> 25519 3<<<12345678 4<<<123456
```

### Directly entering PINs on card readers with pinpad

If your OpenPGP card is inserted in a card reader with a pinpad, this tool 
offers you the option to use the pinpad to enter the user- or admin-PINs.
To do this, you can omit the `-p` and/or '`-P`' parameters - then you will 
be prompted to enter the user or admin PINs where needed. 

## opgpcard-pin

An interactive tool to set the admin and user PINs, and to reset the user PIN
on OpenPGP cards.

Set the user PIN (requires admin PIN):

```
opgpcard-pin -c ABCD:01234567 set-user-pin
```

Set new admin PIN (requires admin PIN):

```
opgpcard-pin -c ABCD:01234567 set-admin-pin
```

Reset user PIN after it has been blocked (requires admin PIN):

```
opgpcard-pin -c ABCD:01234567 reset-user-pin -a
```

Set resetting code (requires admin PIN):

```
opgpcard-pin -c ABCD:01234567 set-reset-code
```

Reset user PIN (requires resetting code):

```
opgpcard-pin -c ABCD:01234567 reset-user-pin
```

### Directly entering PINs on card readers with pinpad

If your OpenPGP card is inserted in a card reader with a pinpad, this tool
assumes you will want to enter all PINs via that pinpad. It will prompt 
you to enter PINs accordingly.