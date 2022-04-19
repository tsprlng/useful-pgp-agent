<!--
SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
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
usable in a non-interactive way (this tool is designed to be easily usable from
shell-scripts).

Alternatively, PINs can be entered interactively on the host computer, or via a pinpad on the smartcard reader,
if available.

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

Add `-v` for more verbose card status (this prints public key data for each key slot):

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
```

### Get an OpenPGP public key representation from a card

This command returns an OpenPGP public key representation of the keys on a card.

To bind the decryption and authentication subkeys (if any) to the signing key, the user pin needs to be provided.

```
$ opgpcard pubkey
OpenPGP card ABCD:01234567
Enter user PIN:
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: F9C7 97CB 1AF2 1C68 AEEC  8D4D 1002 89F5 5EF6 B2D4
Comment: baz

xjMEYkOmahYJKwYBBAHaRw8BAQdADwHIuuSgboyzgcLci8Hc0Q15YHKfDP8/CZG4
uumYosXNA2JhesLABgQTFgoAeAWCYkjTagWJAAAAAAkQEAKJ9V72stRHFAAAAAAA
HgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3JnifpLw5yhNlKffk7V+P9g
idnIM3j6l3k34+p7tMQmCPoCmwMWIQT5x5fLGvIcaK7sjU0QAon1Xvay1AAAhJkB
AIEhZTDuc9xARVK8ta51SOpX3mZs/UYA5a+UrB6vpmZ3AP4k14gFQ6q/cl/SOhPR
FpCAvYlqL8rb3gc2sFIZDfYUDM4zBGJDpmoWCSsGAQQB2kcPAQEHQDRodITykZoi
hIIPZcFZ2bMXvo20YEv+I1eg2kFQ2qSqwsAGBBgWCgB4BYJiSNNqBYkAAAAACRAQ
Aon1Xvay1EcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5vcmcI
5rVHhWA5cGdYlyQJYRXv4osAyFlyznFiUOATnoT6LgKbIBYhBPnHl8sa8hxoruyN
TRACifVe9rLUAADpTwD/a+AlBGryfLsqFzIhdJRpGkoOl0H+xcgk3vcaPUQq0pcA
/3TtUmaJ5w60qb/Px7/Q+MTymHH54elRY4lvwIfbvkUIzjgEYkOmahIKKwYBBAGX
VQEFAQEHQO5KBZ7cMwwjsXGOWWMqgAkCyNdw7smcx/+jBEk0m38dAwEKCcLABgQY
FgoAeAWCYkjTagWJAAAAAAkQEAKJ9V72stRHFAAAAAAAHgAgc2FsdEBub3RhdGlv
bnMuc2VxdW9pYS1wZ3Aub3Jn9IwQkbcw9W0jfrduv1q4qNhsOgJWkGTMbVyvQCug
YpcCmwwWIQT5x5fLGvIcaK7sjU0QAon1Xvay1AAAfTwBAPSQq/hGcGjAWNePHoLH
5zA/ePu1vaY1nh2dPhqtUg8+AP0TDG96MJxlM8SJUQXtQsJCAEo4qT9GnGi7MyTU
nvraDw==
=es4l
-----END PGP PUBLIC KEY BLOCK-----
```

You can query a specific card

```
$ opgpcard pubkey -c ABCD:01234567
```

And/or pass the user PIN as a file, for non-interactive use":

```
$ opgpcard pubkey -p <user-pin-file>
```

#### Caution: the exported public key material isn't always what you want

The result of exporting public key material from a card is only an approximation of the original public key, since
some metadata is not available on OpenPGP cards. This missing metadata includes expiration dates.

Also, if your card only contains subkeys, but not the original primary key, then the exported certificate will use the
signing subkey from the card as the primary key for the exported certificate.

One way to safely process this exported public key material from a card is via `sq key adopt`.

You can use this approach when you have access to your private primary key material (in the following example, we
assume this key is available in `key.pgp`). Then you can bind the public key material from a card to your key:

```
opgpcard pubkey > public.key
sq key adopt key.pgp public.pgp
```

In that process, you will be able to manually set any relevant flags.


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

### Show OpenPGP card metadata

Print information about the capabilities of a card, including the list of supported algorithms (if the card returns
that list).

Most of the output is probably not of interest to regular users.

```
$ opgpcard info
OpenPGP card FFFE:12345678 (card version 2.0)

Application Identifier: D276000124 01 01 0200 FFFE 12345678 0000
Manufacturer [FFFE]: Range reserved for randomly assigned serial numbers.

Card Capabilities:
- command chaining

Card service data:
- Application Selection by full DF name
- EF.DIR and EF.ATR/INFO access services by the GET DATA command (BER-TLV): 010

Extended Capabilities:
- get challenge
- key import
- PW Status changeable
- algorithm attributes changeable
- KDF-DO
- maximum length of challenge: 32
- maximum length cardholder certificates: 2048
- maximum command length: 255
- maximum response length: 256

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

Or to query a specific card:

```
$ opgpcard info --card ABCD:01234567
```

### Admin commands

All `admin` commands need the admin PIN. It can be provided as a file, with `-P <admin-pin-file>`,
for non-interactive use.

Alternatively, the PIN can be entered interactively on the host computer, or via a pinpad if the OpenPGP card is
used in a smartcard reader that has a pinpad.

#### Set cardholder name

Set cardholder name, with pin file:

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> name "Foo Bar"
```

Set cardholder name, with interactive PIN input
(either on the host computer, or via a smartcard reader pinpad):

```
$ opgpcard admin -c ABCD:01234567 name "Foo Bar"
```

#### Set cardholder URL

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> url "https://key.url.example"
```

or interactively

```
$ opgpcard admin -c ABCD:01234567 url "https://key.url.example"
```

#### Import keys

Import private key onto a card. This works if at most one (sub)key per role
(sign, decrypt, auth) exists in `key.priv`:

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> import key.priv
```

or interactively

```
$ opgpcard admin -c ABCD:01234567 import key.priv
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

#### Generate Keys on the card

Key generation needs both the admin PIN and the user PIN (the user PIN is needed to export the new key as a public key).

The user PIN can be provided with the `-p <user-pin-file>`, or interactively on the host computer or via the smartcard
reader pinpad.

```
$ opgpcard admin -c ABCD:01234567 -P <admin-pin-file> generate -p <user-pin-file> -o <output-cert-file> 25519
```

or interactively

```
$ opgpcard admin -c ABCD:01234567 generate -o <output-cert-file> 25519
```

Output will look like:

```
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

or interactively

```
$ opgpcard sign --detached -c ABCD:01234567 -s <cert-file> <input-file>
```

### Decrypting

Decryption using a card (if no input file is set, stdin is read):

```
$ opgpcard decrypt -c ABCD:01234567 -p <user-pin-file> -r <cert-file> <input-file>
```

or interactively

```
$ opgpcard decrypt -c ABCD:01234567 -r <cert-file> <input-file>
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