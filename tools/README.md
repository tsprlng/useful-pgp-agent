<!--
SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# OpenPGP card tools

This crate contains two tools for inspecting, configuring and using OpenPGP 
cards:

`opgpcard` and `opgpcard-pin`

## opgpcard

A tool to inspect, configure and use OpenPGP cards. All calls of this tool 
are non-interactive (this tool is designed to be easily usable from 
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
$ opgpcard status -c ABCD:12345678
```

Add `-v` for more verbose card status, including the list of supported
algorithms of the card:
```
$ opgpcard status -c ABCD:12345678 -v
```

### Import keys

Import private key onto a card. This works if at most one (sub)key
per role (sign, decrypt, auth) exists in `key.priv`:
```
$ opgpcard admin -c ABCD:12345678 -p <pin-file> import key.priv
```

Import private key onto a card while explicitly selecting subkeys.
Explicitly specified fingerprints are necessary if more than one subkey
exists in `key.priv` for any role (note: spaces in fingerprints are 
ignored).
```
$ opgpcard admin -c ABCD:12345678 -p <pin-file> import key.priv \
 --sig-fp "F290 DBBF 21DB 8634 3C96  157B 87BE 15B7 F548 D97C" \
 --dec-fp "3C6E 08F6 7613 8935 8B8D  7666 73C7 F1A9 EEDA C360" \
 --auth-fp "D6AA 48EF 39A2 6F26 C42D  5BCB AAD2 14D5 5332 C838"
```

When fingerprints are only specified for a subset of the roles, no 
keys will be imported for the other roles.

### Generate Keys on the card

```
$ opgpcard admin -c ABCD:12345678 -p <admin-pin-file> generate --user-pin-file <user-pin-file> -o <output-file> 25519
```

### Set card metadata

Set cardholder name:
```
$ opgpcard admin -c ABCD:12345678 -p <pin-file> name "Bar<<Foo"
```

Set cardholder URL:
```
$ opgpcard admin -c ABCD:12345678 -p <pin-file> url "https://keyurl.example"
```

### Signing

For now, this tool only supports creating detached signatures, like this
(if no input file is set, stdin is read):

```
$ opgpcard sign --detached -c ABCD:12345678 -p <pin-file> -s <cert-file> <input-file>
```

### Decrypting

Decryption using a card (if no input file is set, stdin is read):

```
$ opgpcard decrypt -c ABCD:12345678 -p <pin-file> -r <cert-file> <input-file>
```

### Factory reset

Factory reset:
```
$ opgpcard factory-reset -c ABCD:12345678
```

## opgpcard-pin

An interactive tool to set the admin and user PINs, and to reset the user 
PIN on OpenPGP cards.

Set the user PIN (requires admin PIN):
```
opgpcard-pin -c ABCD:12345678 set-user-pin
```

Set new admin PIN (requires admin PIN):
```
opgpcard-pin -c ABCD:12345678 set-admin-pin
```

Reset user PIN after it has been blocked (requires admin PIN):
```
opgpcard-pin -c ABCD:12345678 reset-user-pin -a
```

Set resetting code (requires admin PIN):
```
opgpcard-pin -c ABCD:12345678 set-reset-code
```

Reset user PIN (requires resetting code):
```
opgpcard-pin -c ABCD:12345678 reset-user-pin
```
