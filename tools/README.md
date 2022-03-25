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
Available OpenPGP cards:
 ABCD:01234567
 ABCD:87654321
```

Print status information about a card. The card is implicitly selected.
However, this only works if exactly one card is connected:

```
$ opgpcard status
OpenPGP card ABCD:01234567 (card version 2.0)

Cardholder: Foo Bar

Signature key
  fingerprint: 1FE2 E8F1 9FE8 7D0D 8AAF  5579 8CB7 58BA 502F 2458
  created: 2022-03-25 20:15:49
  algorithm: Ed25519 (EdDSA)

Decryption key
  fingerprint: 68CB 4EDD 4D49 90B8 2CEC  2D22 EF7E 5B6A 2012 694C
  created: 2022-03-25 20:15:49
  algorithm: Cv25519 (ECDH)

Authentication key
  fingerprint: 59A5 CD3E A88F 8707 D887  EAAE 1354 5F40 4E11 BE1C
  created: 2022-03-25 20:15:49
  algorithm: Ed25519 (EdDSA)

Signature counter: 3
Signature pin only valid once: true
Password validation retry count:
  user pw: 3, reset: 3, admin pw: 3

```

Explicitly print the status information for a specific card (this command syntax is needed, when more than one card
is plugged in):

```
$ opgpcard status --card ABCD:01234567
```

Add `-v` for more verbose card status (including the list of supported
algorithms, if the card returns an algorithm list):

```
$ opgpcard status -c ABCD:01234567 -v
OpenPGP card ABCD:01234567 (card version 2.0)

Cardholder: Foo Bar

Signature key
  fingerprint: 1FE2 E8F1 9FE8 7D0D 8AAF  5579 8CB7 58BA 502F 2458
  created: 2022-03-25 20:15:49
  algorithm: Ed25519 (EdDSA)
  public key material: ECC, data: 4C6364692AA4212AA95CF25FF31FD5F94CCAC173BFD77C918E443F09FAAFE3F5

Decryption key
  fingerprint: 68CB 4EDD 4D49 90B8 2CEC  2D22 EF7E 5B6A 2012 694C
  created: 2022-03-25 20:15:49
  algorithm: Cv25519 (ECDH)
  public key material: ECC, data: B99202743227D87D5F24639937DF75C936AC7933CE3328F5BF6AFA174A4A8745

Authentication key
  fingerprint: 59A5 CD3E A88F 8707 D887  EAAE 1354 5F40 4E11 BE1C
  created: 2022-03-25 20:15:49
  algorithm: Ed25519 (EdDSA)
  public key material: ECC, data: BFE1E5EB31032E0F4320E163082BEDBAD2A6318EC368375F7A65D22AC7AB7444

Signature counter: 3
Signature pin only valid once: true
Password validation retry count:
  user pw: 3, reset: 3, admin pw: 3

Supported algorithms:
SIG: RSA 2048 [e 32]
SIG: RSA 4096 [e 32]
SIG: Secp256k1 (ECDSA)
SIG: Ed25519 (EdDSA)
SIG: Ed448 (EdDSA)
DEC: RSA 2048 [e 32]
DEC: RSA 4096 [e 32]
DEC: Secp256k1 (ECDSA)
DEC: Cv25519 (ECDH)
DEC: X448 (ECDH)
AUT: RSA 2048 [e 32]
AUT: RSA 4096 [e 32]
AUT: Secp256k1 (ECDSA)
AUT: Ed25519 (EdDSA)
AUT: Ed448 (EdDSA)
```

### Using a card for ssh auth

To use an OpenPGP card for ssh login authentication, a PGP authentication key needs to exist on the card.

`opgpcard ssh` then shows the ssh public key string representation of the PGP authentication
key on the card, like this:

```
$ opgpcard ssh
OpenPGP card ABCD:01234567

Authentication key fingerprint:
BEC2E8D8AD9C54A6AEDE71CCA1CE6FAC5ABF0BE4

Authentication key as ssh public key:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII2dcYBqMCamidT5MpE3Cl3MIKcYMBekGXbK2aaN6JaH opgpcard:ABCD:01234567
```

To allow login to a remote machine, that ssh public key can be added to
`.ssh/authorized_keys` on that remote machine.

In the example output above, this string is the ssh public key:

`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII2dcYBqMCamidT5MpE3Cl3MIKcYMBekGXbK2aaN6JaH opgpcard:ABCD:01234567`

### Set card metadata

Set cardholder name:

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> name "Foo Bar"
```

Set cardholder URL:

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> url "https://key.url.example"
```

### Import keys

Import private key onto a card. This works if at most one (sub)key per role
(sign, decrypt, auth) exists in `key.priv`:

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
 Generate subkey for Signing
 Generate subkey for Decryption
 Generate subkey for Authentication
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: 1FE2 E8F1 9FE8 7D0D 8AAF  5579 8CB7 58BA 502F 2458
Comment: Foo Bar

xjMEYj4i9RYJKwYBBAHaRw8BAQdATGNkaSqkISqpXPJf8x/V+UzKwXO/13yRjkQ/
Cfqv4/XNB0ZvbyBCYXLCwAYEExYKAHgFgmI+IvUFiQAAAAAJEIy3WLpQLyRYRxQA
AAAAAB4AIHNhbHRAbm90YXRpb25zLnNlcXVvaWEtcGdwLm9yZ3soPdGvhvnI629W
zuGvgJCQEuuFoH/+3FheWD4xNy16ApsDFiEEH+Lo8Z/ofQ2Kr1V5jLdYulAvJFgA
AJlVAQDHvutZW5ExN5Tcx92mNhU9w1Gkzn2yQf0xrZENLQqhjQD/cKa27RlOVHt1
psAhx/v0UcaYO5NABZorTsKrJWYzOAfOMwRiPiL1FgkrBgEEAdpHDwEBB0C/4eXr
MQMuD0Mg4WMIK+260qYxjsNoN196ZdIqx6t0RMLABgQYFgoAeAWCYj4i9QWJAAAA
AAkQjLdYulAvJFhHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Au
b3JnVNZH1uV5zflAPMPspQLrTaWf8uwaePLWl6nbuclDck8CmyAWIQQf4ujxn+h9
DYqvVXmMt1i6UC8kWAAAIfEBAO0yXwlbrNymuwCsU22Yy95JA2QpUnMBsY7dizvP
8Or+AP92UH8dwDElhynFgw9KkyR2ZU69k1Eeb1snnO5K8eA1Bc44BGI+IvUSCisG
AQQBl1UBBQEBB0C5kgJ0MifYfV8kY5k333XJNqx5M84zKPW/avoXSkqHRQMBCgnC
wAYEGBYKAHgFgmI+IvUFiQAAAAAJEIy3WLpQLyRYRxQAAAAAAB4AIHNhbHRAbm90
YXRpb25zLnNlcXVvaWEtcGdwLm9yZ2fdVPQT78DqbSOmY8Rv6Bn/nDRsNW55yyt/
RNxxCInzApsMFiEEH+Lo8Z/ofQ2Kr1V5jLdYulAvJFgAAOz6AQDijdln/VMFqG1t
T+/zIUpoJ3YbpT0PTrC5wv/PRaTBGwD+KRiYeJS05fX5BPjMn3sVL8/EYF628BMZ
x3z8hDoRKAU=
=v95a
-----END PGP PUBLIC KEY BLOCK-----
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

### Set a new user PIN

Setting a new user PIN requires the admin PIN:

```
opgpcard-pin -c ABCD:01234567 set-user-pin
```
(The default admin PIN on unconfigured cards is typically `12345678`)

### Set new admin PIN

This requires the (previous) admin PIN.

```
opgpcard-pin -c ABCD:01234567 set-admin-pin
```

(The default admin PIN on unconfigured cards is typically `12345678`)

### Recover from blocked user PIN (using the admin PIN)

When a user has entered a wrong user PIN too often, the card goes into a blocked state, in which presenting the
user PIN is not possible anymore. The purpose of this is to prevent attackers from trying all possible PINs
(e.g. after stealing a card).

To be able to use the card again, the user PIN must be "reset".

Reset user PIN after it has been blocked (requires admin PIN):

```
opgpcard-pin -c ABCD:01234567 reset-user-pin -a
```

### Recover from blocked user PIN (using the resetting code)

The resetting code is an optional/alternative method to recover from a blocked user PIN.

Context: in some (e.g. corporate) settings, users might not be given the admin PIN for their cards.
Instead, an admin may define a resetting code and give that code to the user.

Set resetting code (requires admin PIN):

```
opgpcard-pin -c ABCD:01234567 set-reset-code
```

Once a reset code has been defined, the user can
reset the blocked user PIN, using the resetting code:

```
opgpcard-pin -c ABCD:01234567 reset-user-pin
```

### Directly entering PINs on card readers with pinpad

If your OpenPGP card is inserted in a card reader with a pinpad, this tool
assumes you will want to enter all PINs via that pinpad. It will prompt 
you to enter PINs accordingly.