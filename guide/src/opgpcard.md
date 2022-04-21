<!--
SPDX-FileCopyrightText: 2022 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# The opgpcard tool

To set up (or inspect) an OpenPGP card, we'll use the `opgpcard` tool.
So first, we install that tool.

In short:

1. install the build dependencies, then
2. `cargo install openpgp-card-tools`

Longer form [installation instructions](https://gitlab.com/hkos/openpgp-card/-/tree/main/tools#install).


# Exploring the state of an OpenPGP card

Using the `opgpcard` tool (installed above), you can easily check the status of a card that is plugged in:

`$ opgpcard status`

The output will start like this:

```
OpenPGP card FFFE:12345678 (card version 2.0)
[...]
```

In this case, the card identifier is `FFFE:12345678` (you'll need to use the identifier for your card, in some of the following steps).


# Specifying which card to operate on

For read operations, when exactly one card is plugged in, `opgpcard` will automatically use that card.

In all other cases (when multiple cards are plugged in, or for any write operations), you need to specify which card
you want to interact with, via the `-c` parameter.

For example:

`$ opgpcard status -c FFFE:12345678`

## Enumerating all available cards

You can use `opgpcard list` to enumerate all cards that are connected to the system.


# PINs

For some operations, OpenPGP cards require the user to provide a 'PIN', to show that the user is authorized to perform the operation.

Most OpenPGP cards distinguish two different PINs:

1. a *User PIN* and
2. an *Admin PIN*.

The User PIN is needed for cryptographic operations (such as decryption or signing with the card).
The Admin PIN is needed to configure the card itself (for example to import a key onto a card).

On new (or factory reset) cards, the default User PIN is typically `123456`, the default Admin PIN is `12345678`.

## Modes of PIN entry

`opgpcard` supports three different modes of PIN entry:

1. When the OpenPGP card is inserted in a Smartcard reader with a pinpad (that is, when the OpenPGP card is inserted into a hardware reader device that has a numerical keypad), PINs can be entered directly via that pinpad.

2. If no pinpad reader is available, PINs can be entered directly on the host computer.

3. Alternatively it's possible to supply PINs via a file (or a file descriptor), which can be convenient in non-interactive settings.

## Changing your User and Admin PIN from the default values

To change the User PIN from its default of `123456` to a value that third parties can't easily guess, run:

`$ opgpcard pin -c FFFE:12345678 set-user`

This command will ask you to enter the current User PIN (so `123456`, if your card is new), and then a new PIN,
twice (to avoid inadvertently setting the PIN to an unintended value).

And analogously for the Admin PIN, to change it from its default of `12345678`:

`$ opgpcard pin -c FFFE:12345678 set-admin`

Typically, the minimum length is 6 digits for the User PIN and 8 digits for the Admin PIN.

(Note that if you lose your Admin PIN, there is no way to recover it! In that case you can start over by blanking the
card with the `factory-reset` command. This resets the PINs to their defaults and removes all keys from the card.)


# Setting metadata on a card

## Set name

You can set a "Cardholder Name" on an OpenPGP card. That name field is informational. 

`opgpcard admin -c FFFE:12345678 name "Alice Adams"`

## Set URL

You can set a URL on an OpenPGP card.

The URL "should contain a Link to a set of public keys in OpenPGP format, related to the card".
Some software may use this URL to obtain a copy of the corresponding public key for a card.

`$ opgpcard admin -c FFFE:12345678 url <url>`

If you do use the URL field, the URL should serve a copy of your public key.
For most use cases, you don't need to set this URL.

# Importing a key to a card

*(This operation will delete keys that currently exist on your card.
Make sure your card doesn't contain irreplaceable keys before you import keys!)*

If you have a key that you want to use, you can use that key.

If you don't (or if you want to first experiment with a test-key) you can generate a new key with the `sq` utility
(available as `sequoia-sq` in a number of distributions, or installable with the `cargo` Rust package manager).

```
$ sq key generate --export key.pgp
```

We can inspect this newly generated key (or your pre-existing key) by running:

```
$ sq inspect key.pgp
key.pgp: Transferable Secret Key.

    Fingerprint: 17F2509AB619C8D78B598E54567817AC43A7F7AE
Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
Public-key size: 256 bits
     Secret key: Unencrypted
  Creation time: 2022-04-20 09:46:27 UTC
Expiration time: 2025-04-20 03:12:48 UTC (creation time + P1095DT62781S)
      Key flags: certification

         Subkey: E7A3D0E45991BE6445668CFD348634FD4CC638CA
Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm
Public-key size: 256 bits
     Secret key: Unencrypted
  Creation time: 2022-04-20 09:46:27 UTC
Expiration time: 2025-04-20 03:12:48 UTC (creation time + P1095DT62781S)
      Key flags: signing

         Subkey: 593970CE20BFE3D58AA4EF12EA988C77EEC05B0A
Public-key algo: ECDH public key algorithm
Public-key size: 256 bits
     Secret key: Unencrypted
  Creation time: 2022-04-20 09:46:27 UTC
Expiration time: 2025-04-20 03:12:48 UTC (creation time + P1095DT62781S)
      Key flags: transport encryption, data-at-rest encryption
```

In this case, we see (in the `Key flags` field) that the primary key `17F2509AB619C8D78B598E54567817AC43A7F7AE`
can be used for certification only.
In addition, there is a signing subkey `E7A3D0E45991BE6445668CFD348634FD4CC638CA`
and an encryption subkey `593970CE20BFE3D58AA4EF12EA988C77EEC05B0A`:

To explicitly import the two subkeys onto our card, we run:

```
$ opgpcard admin -c FFFE:12345678 import --sig-fp E7A3D0E45991BE6445668CFD348634FD4CC638CA --dec-fp 593970CE20BFE3D58AA4EF12EA988C77EEC05B0A key.pgp
Enter Admin PIN:
Uploading E7A3D0E45991BE6445668CFD348634FD4CC638CA as signing key
Uploading 593970CE20BFE3D58AA4EF12EA988C77EEC05B0A as decryption key
```

Checking the card's status now shows:

```
$ opgpcard status
OpenPGP card FFFE:12345678 (card version 2.0)

Signature key
  fingerprint: E7A3 D0E4 5991 BE64 4566  8CFD 3486 34FD 4CC6 38CA
  created: 2022-04-20 09:46:27
  algorithm: Ed25519 (EdDSA)

Decryption key
  fingerprint: 5939 70CE 20BF E3D5 8AA4  EF12 EA98 8C77 EEC0 5B0A
  created: 2022-04-20 09:46:27
  algorithm: Cv25519 (ECDH)

Authentication key
  algorithm: RSA 2048 [e 32]

Signature counter: 0
Signature pin only valid once: true
Password validation retry count:
  user pw: 3, reset: 3, admin pw: 3
```

The two subkeys have been loaded into the suitable slots on the card.

In fact, for this key, we don't need to explicitly specify the fingerprints. `opgpcard admin import` automatically
imports keys that contain exactly one signing (sub)key, and zero or one decryption and authentication subkeys, respectively:

```
opgpcard admin -c FFFE:12345678 import key.pgp
Enter Admin PIN:
Uploading E7A3D0E45991BE6445668CFD348634FD4CC638CA as signing key
Uploading 593970CE20BFE3D58AA4EF12EA988C77EEC05B0A as decryption key
```


# Key generation on a card

*(This operation will delete keys that currently exist on your card.
Make sure your card doesn't contain irreplaceable keys before you generate keys on your card!)*

This step will generate a new set of ECC Curve25519 keys on your OpenPGP card: 

`opgpcard admin -c FFFE:12345678 generate -o output-cert.pub 25519`

The file `output-cert.pub` will contain the OpenPGP public key that corresponds to the newly generated keys on the card.
We won't need this public key for ssh use (but you might need it if you want to use the key on this card for other purposes).

## Pros and cons of generating keys on a card

When you generate keys on your card, your computer never has access to the private key material.
This is nice if you want to be sure that the private key material can not possibly get exfiltrated from your computer,
even if it is fully compromised.

On the other hand, this means that you can - by design - not make a backup (or second copy) of these private keys.
If the card is lost (or breaks) these keys are gone forever. 

Depending on your use case, these tradeoffs may or may not be a good fit for your goals.
