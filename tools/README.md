<!--
SPDX-FileCopyrightText: 2021-2022 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# OpenPGP card tools

This crate contains the `opgpcard` tool for inspecting, configuring and using OpenPGP
cards.

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

`opgpcard` uses the PC/SC framework. So on Linux-based systems, you need to make sure the `pcscd`
service is running, to be able to access your OpenPGP cards.

## opgpcard

A tool to inspect, configure and use OpenPGP cards.

This tool is designed to be equally convenient for regular interactive use, as well as from scripts.
To this end, all functionality of this tool is alternatively usable in a non-interactive manner (see below).

When using the tool in interactive contexts, two methods of PIN entry are supported:
in most cases, PINs can (and must) be entered via the host computer.
When a pin pad is available on the smartcard reader, PIN entry will be requested via this pin pad.

### List cards

List idents of all currently connected cards:

```
$ opgpcard list
Available OpenPGP cards:
 ABCD:01234567
 0007:87654321
```

### Inspect card status

Print status information about the data on a card.
The card is implicitly selected (if exactly one card is connected):

```
$ opgpcard status
OpenPGP card ABCD:01234567 (card version 3.4)

Cardholder: Alice Adams
Language preferences: 'en'

Signature key
  Fingerprint: 034B 348C EDA2 064C AA22  74E4 7563 E86F 5CAB C2A4
  Creation Time: 2022-05-21 13:15:19 UTC
  Algorithm: Ed25519 (EdDSA)
  Signatures made: 11

Decryption key
  Fingerprint: 338B EE09 3950 D831 A76F  0EB9 13D6 2DF6 8C9E 5176
  Creation Time: 2022-05-21 13:15:19 UTC
  Algorithm: Cv25519 (ECDH)

Authentication key
  Fingerprint: 4881 A22E 7EC6 26D1 1202  50B0 A7D7 F0D5 0C8D F719
  Creation Time: 2022-05-21 13:15:19 UTC
  Algorithm: Ed25519 (EdDSA)

Remaining PIN attempts: User: 3, Admin: 3, Reset Code: 0
```

Explicitly print the status information for a specific card (this command syntax is needed, when more than one card
is plugged in):

```
$ opgpcard status --card ABCD:01234567
```

Add `-v` for more verbose card status:

```
OpenPGP card ABCD:01234567 (card version 3.4)

Cardholder: Alice Adams
Language preferences: 'en'

Signature key
  Fingerprint: 034B 348C EDA2 064C AA22  74E4 7563 E86F 5CAB C2A4
  Creation Time: 2022-05-21 13:15:19 UTC
  Algorithm: Ed25519 (EdDSA)
  Touch policy: Cached (features: Button)
  Key Status: generated
  User PIN presentation is valid for unlimited signatures
  Signatures made: 11

Decryption key
  Fingerprint: 338B EE09 3950 D831 A76F  0EB9 13D6 2DF6 8C9E 5176
  Creation Time: 2022-05-21 13:15:19 UTC
  Algorithm: Cv25519 (ECDH)
  Touch policy: Off (features: Button)
  Key Status: generated

Authentication key
  Fingerprint: 4881 A22E 7EC6 26D1 1202  50B0 A7D7 F0D5 0C8D F719
  Creation Time: 2022-05-21 13:15:19 UTC
  Algorithm: Ed25519 (EdDSA)
  Touch policy: Off (features: Button)
  Key Status: generated

Attestation key:
  Algorithm: RSA 2048 [e 17]
  Touch policy: Cached (features: Button)

Remaining PIN attempts: User: 3, Admin: 3, Reset Code: 0
Key Status (#129): imported
```

The `--public-key-material` flag additionally outputs the raw public key data for each key slot.

### Get an OpenPGP public key representation from a card

This command returns an OpenPGP public key representation of the keys on a card.

To bind the decryption and authentication subkeys (if any) to the signing key, the user pin needs to be provided.

```
$ opgpcard pubkey
OpenPGP card ABCD:01234567
Enter User PIN:
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: F9C7 97CB 1AF2 1C68 AEEC  8D4D 1002 89F5 5EF6 B2D4
Comment: Alice Adams

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
$ opgpcard pubkey --card ABCD:01234567
```

In the process of exporting the key material on a card as a certificate (public key), one or more User IDs can be
bound to the certificate:

```
$ opgpcard pubkey --userid "Alice Adams <alice@example.org>"
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
59A5CD3EA88F8707D887EAAE13545F404E11BE1C

SSH public key:
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

Application Identifier: D276000124 01 0200 FFFE 12345678 0000
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
- SIG: RSA 2048 [e 32]
- SIG: RSA 4096 [e 32]
- SIG: Secp256k1 (ECDSA)
- SIG: Ed25519 (EdDSA)
- SIG: Ed448 (EdDSA)
- DEC: RSA 2048 [e 32]
- DEC: RSA 4096 [e 32]
- DEC: Secp256k1 (ECDSA)
- DEC: Cv25519 (ECDH)
- DEC: X448 (ECDH)
- AUT: RSA 2048 [e 32]
- AUT: RSA 4096 [e 32]
- AUT: Secp256k1 (ECDSA)
- AUT: Ed25519 (EdDSA)
- AUT: Ed448 (EdDSA)
```

Or to query a specific card:

```
$ opgpcard info --card ABCD:01234567
```

### Admin commands

All `admin` commands need the Admin PIN. It can be provided as a file, with `-P <admin-pin-file>`,
for non-interactive use (see below).

By default, the PIN must be entered interactively on the host computer, or via a pin pad if the OpenPGP card is
used in a smart card reader that has a pin pad.

#### Set touch policy

Cards can require confirmation by the user before cryptographic operations are performed
(this confirmation feature is often implemented as a mechanical button on the card).

However, not all cards implement this feature.

Rationale: when a card requires touch confirmation, an attacker who gains control of the user's host computer
cannot perform cryptographic operations on the card at will - even after they learn the user's PINs.

This feature is configured per key slot. The user can choose to require (or not require) touch confirmation separately
for signing, decryption, authentication and attestation operations.

E.g., when the touch policy is set to `On` for the `SIG` key slot, then every signing operation requires a touch button
confirmation:

```
$ opgpcard admin --card ABCD:01234567 touch --key SIG --policy On
```

Valid values for the key slot are: `SIG`, `DEC`, `AUT`, `ATT` (some cards only support the first three).

Available policies can include: `Off`, `On`, `Fixed`, `Cached`, `CachedFixed`.
Some cards only support a subset of these.

- `Off` means that no touch confirmation is required.
- `On` means that each operation requires on touch confirmation.
- The `Fixed` policies are like `On`, but the policies cannot be changed without performing a factory reset on the card.
- With the `Cached` policies, a touch confirmation is valid for multiple operations within 15 seconds.


#### Set cardholder name

Set the (informational) cardholder name:

```
$ opgpcard admin --card ABCD:01234567 name "Alice Adams"
```

#### Set certificate URL

The URL field on OpenPGP cards is intended to point to the certificate (or "public key") the corresponds to the keys
that are present on the card.

It can be set like this:

```
$ opgpcard admin --card ABCD:01234567 url "https://key.url.example"
```

##### Using `keys.openpgp.org` for the URL

If you have uploaded (or plan to upload) your certificate (your public key) to the `keys.openpgp.org` keyserver,
you can point the URL field on your card there:

If the fingerprint of your certificate is `0123456789ABCDEF0123456789ABCDEF01234567`, then you can set the URL
as follows:

```
$ opgpcard admin --card FFFE:12345678 url "https://keys.openpgp.org/vks/v1/by-fingerprint/0123456789ABCDEF0123456789ABCDEF01234567"
```

##### Other common options for certificate URLs

You can use any URL that serves your certificate ("public key"), including links to:

- gitlab (`https://gitlab.com/<username>.gpg`) or github (`https://github.com/<username>.gpg`)
- any other keyserver, such as https://keyserver.ubuntu.com/,
- a WKD server,
- a copy of your certificate on your personal website, ...


#### Import keys

Import private key onto a card. This works if at most one (sub)key per role
(sign, decrypt, auth) exists in `key.priv`:

```
$ opgpcard admin --card ABCD:01234567 import key.priv
```

Import private key onto a card while explicitly selecting subkeys. Explicitly
specified fingerprints are necessary if more than one subkey exists
in `key.priv` for any role (spaces in fingerprints are ignored).

```
$ opgpcard admin --card ABCD:01234567 -P <admin-pin-file> import key.priv \
 --sig-fp "F290 DBBF 21DB 8634 3C96  157B 87BE 15B7 F548 D97C" \
 --dec-fp "3C6E 08F6 7613 8935 8B8D  7666 73C7 F1A9 EEDA C360" \
 --auth-fp "D6AA 48EF 39A2 6F26 C42D  5BCB AAD2 14D5 5332 C838"
```

When fingerprints are only specified for a subset of the roles, no keys will
be imported for the other roles.

If the private (sub)keys in the import file are password protected, the user will be prompted to enter
the password. If (sub)keys are encrypted with different passwords, the user will be prompted multiple times.
(Background: OpenPGP keys can be password protected when they are stored in files, but on an OpenPGP card
the keys always exist in unencrypted form. Therefore, they need to be decrypted for import.)

(NOTE: There is currently no mechanism to non-interactively provide passwords to import password protected
OpenPGP keys)

#### Generate Keys on the card

This command generates new keys on an OpenPGP card. It creates the corresponding certificate ("public key")
representation in an output file.

```
$ opgpcard admin --card ABCD:01234567 generate --output <output-cert-file> cv25519
```

Note that key generation needs both the Admin PIN and the User PIN (the User PIN is needed to export the new key as
a public key).

Output will look like:

```
Enter Admin PIN:
Enter User PIN:
 Generate subkey for Signing
 Generate subkey for Decryption
 Generate subkey for Authentication
```

The `<output-cert-file>` will contain the corresponding certificate ("public key").

As part of the process of generating key material on a card, one or more User IDs can be included with the exported
certificate:

```
$ opgpcard admin --card ABCD:01234567 generate --userid "Alice Adams <alice@example.org>" --output <output-cert-file> cv25519
```


### Signing

For now, this tool only supports creating detached signatures, like this
(if no input file is set, stdin is read):

```
$ opgpcard sign --detached --card ABCD:01234567 <input-file>
```

### Decrypting

Decryption using a card (if no input file is set, stdin is read):

```
$ opgpcard decrypt --card ABCD:01234567 <input-file>
```

### PIN management

OpenPGP cards use PINs (numerical passwords) to verify that a user is allowed to perform an operation.

To use cryptographic operations on a card (such as decryption or signing), the *User PIN* is required.

To configure a card (for example to import OpenPGP key material into the card's key slots), the *Admin PIN* is needed.

By default, on unconfigured (or factory reset) cards, the User PIN is typically set to `123456`,
and the Admin PIN is set to `12345678`.

#### Blocked cards and resetting

When a user has entered a wrong User PIN too often, the card goes into a blocked state, in which presenting the
User PIN successfully is not possible anymore. The purpose of this is to prevent attackers from trying all possible
PINs (e.g. after stealing a card).

To be able to use the card again, the User PIN must be "reset".

A User PIN reset can be performed by presenting the Admin PIN.

#### The resetting code

OpenPGP cards offer an additional, optional, *Resetting Code* mechanism.

The resetting code may be configured on a card and used to reset the User PIN if it has been forgotten or blocked.
When unblocking a card with the Resetting Code, the Admin PIN is not needed.

The Resetting Code mechanism is only useful in scenarios where a user doesn't have access to (or prefers not to use)
the Admin PIN (e.g. in some corporate settings, users might not be given the Admin PIN for
their cards. Instead, an admin may define a resetting code and give that code to the user).

On un-configured (or factory reset) cards, the Resetting Code is typically unset.


#### Set a new User PIN

Setting a new User PIN requires the Admin PIN:

```
$ opgpcard pin --card ABCD:01234567 set-user
```

#### Set new Admin PIN

This requires the (previous) Admin PIN.

```
$ opgpcard pin --card ABCD:01234567 set-admin
```

#### Reset User PIN with Admin PIN

The User PIN can be reset to a different (or the same) PIN by providing the Admin PIN.
This is possible at any time, including when a wrong User PIN has been entered too often,
and the card refuses to accept the User PIN anymore.

```
$ opgpcard pin --card ABCD:01234567 reset-user
```

#### Configuring the resetting code

The resetting code is an alternative mechanism to recover from a lost or locked User PIN.

You can set the resetting code after verifying the Admin PIN. Once a resetting code is configured on your card,
you can use that code to reset the User PIN without needing the Admin PIN.

```
$ opgpcard pin --card ABCD:01234567 set-reset
```

#### Reset User PIN with the resetting code

If a resetting code is configured on a card, you can use that code to reset the User PIN:

```
$ opgpcard pin --card ABCD:01234567 reset-user-rc
Enter resetting code:
Enter new User PIN:
Repeat the new User PIN:

User PIN has been set.
```

### Factory reset

A factory reset erases all data on your card, including the private key material that the card stores.

```
$ opgpcard factory-reset --card ABCD:01234567
```

NOTE: you do not need a PIN to reset a card!

### Directly entering PINs on card readers with pin pad

If your OpenPGP card is inserted in a card reader with a pin pad, this tool 
offers you the option to use the pin pad to enter the User- or Admin PINs.
To do this, you can omit the `-p` and/or `-P` parameters. Then you will 
be prompted to enter the user or Admin PINs where needed. 


### Machine-readable Output (JSON, YAML)

This tool is can optionally provide its output in JSON (or YAML) format.
The functionality is intended for scripting use.

For all commands that return relevant output, the parameter `--output-format json` chooses JSON as the output format.

For example, with the `status` command:

```
$ opgpcard --output-format json status
{
  "schema_version": "0.9.0",
  "ident": "ABCD:01234567",
  "card_version": "3.4",
  "cardholder_name": "Alice Adams",
  "language_preferences": [],
  "certificate_url": "http://alice.example/alice.pgp",
  "signature_key": {
    "fingerprint": "A393 4505 BC51 1177 2E0B  845A 142C C9AB 7126 5C00",
    "creation_time": "2022-10-31 13:45:35 UTC",
    "algorithm": "Ed25519 (EdDSA)",
    "touch_policy": "Off",
    "touch_features": "Button",
    "status": "generated",
    "public_key_material": "ECC [Ed25519 (EdDSA)], data: 3A2B88EF788FA59575E3C4DB89EE367DBD0D9E93B6CE26B7686D32E94958F32A"
  },
  "signature_count": 3,
  "user_pin_valid_for_only_one_signature": false,
  "decryption_key": {
    "fingerprint": "0643 F2A9 6605 4158 CCFA  B11F C7D2 0DBA DA64 84E0",
    "creation_time": "2022-10-31 13:45:35 UTC",
    "algorithm": "Cv25519 (ECDH)",
    "touch_policy": "Off",
    "touch_features": "Button",
    "status": "generated",
    "public_key_material": "ECC [Cv25519 (ECDH)], data: AF97CA49B2D89998605985AEDAA19097A0CE7E5CC681B1ABD1C8610933FDB320"
  },
  "authentication_key": {
    "fingerprint": "2BA3 3B42 90DE 337D 1DF8  54B3 2E20 E550 3ABC 57A9",
    "creation_time": "2022-10-31 13:45:35 UTC",
    "algorithm": "Ed25519 (EdDSA)",
    "touch_policy": "Off",
    "touch_features": "Button",
    "status": "generated",
    "public_key_material": "ECC [Ed25519 (EdDSA)], data: 80178ECE7F16ACDFDB0A645C81E72287761F03488CE3AE01F74279AA88A9018C"
  },
  "attestation_key": {
    "fingerprint": null,
    "creation_time": null,
    "algorithm": "RSA 2048 [e 17]",
    "touch_policy": "Off",
    "touch_features": "Button",
    "status": null,
    "public_key_material": null
  },
  "user_pin_remaining_attempts": 3,
  "admin_pin_remaining_attempts": 3,
  "reset_code_remaining_attempts": 0
}
```


### Non-interactive use

All commands that require PIN entry can be used non-interactively by providing PINs via files
(see the section "Using file-descriptors to provide PINs" for a variation on this).

In almost all contexts, `-p` is used to provide the User PIN and `-P` to provide the Admin PIN
(the exception is when changing a PIN on the card, then a different parameter is used to provide the new PIN).

**Examples of non-interactive use**

- Setting the cardholder name:

`$ opgpcard admin --card ABCD:01234567 -P <admin-pin-file> name "Alice Adams"`

- Importing a key to the card:

`$ opgpcard admin --card ABCD:01234567 -P <admin-pin-file> import key.priv`

- Generating key material on the card:

`$ opgpcard admin --card ABCD:01234567 -P <admin-pin-file> generate -p <user-pin-file> --output <output-cert-file> cv25519`

- Creating a detached signature:

`$ opgpcard sign --detached --card ABCD:01234567 -p <user-pin-file> <input-file>`

**Examples of non-interactive PIN management**

- Setting a new User PIN:

`$ opgpcard pin --card ABCD:01234567 set-user -p <old-user-pin-file> -q <new-user-pin-file>`

- Setting a new Admin PIN:

`$ opgpcard pin --card ABCD:01234567 set-admin -P <old-admin-pin-file> -Q <new-admin-pin-file>`

- Setting a new User PIN based on the Admin PIN (and unblocking the card, if needed):

`$ opgpcard pin --card ABCD:01234567 reset-user -P <admin-pin-file> -p <new-user-pin-file>`

- Setting the resetting code:

`$ opgpcard pin --card ABCD:01234567 set-reset -P <admin-pin-file> -r <resetting-code-file>`

- Setting a new User ID based on the resetting code (and unblocking the card, if needed):

`$ opgpcard pin --card ABCD:01234567 reset-user-rc -r <resetting-code-file> -p <new-user-pin-file>`

#### Using file-descriptors to provide PINs

When using a shell like
[bash](https://www.gnu.org/software/bash/manual/html_node/Redirections.html#Here-Strings)
, you can pass User- and/or Admin PINs via file-descriptors (instead of from a file on disk):

```
$ opgpcard sign --detached --card ABCD:01234567 -p /dev/fd/3 3<<<123456
```

```
$ opgpcard admin --card ABCD:01234567 -P /dev/fd/3 generate -p /dev/fd/4 --output <output-cert-file> cv25519 3<<<12345678 4<<<123456
```

### Attestation

Yubico implements a [proprietary extension](https://developers.yubico.com/PGP/Attestation.html) to the OpenPGP card
standard to *"cryptographically certify that a certain asymmetric key has been generated on device, and not imported"*.

This feature is available on YubiKey 5 devices with firmware version 5.2 or newer.

#### Attestation key/certificate

*"The YubiKey is preloaded with an attestation certificate and matching attestation key issued by the Yubico CA.
The template and key are replaceable, which permits an individual or organization to issue attestations verifiable 
with their own CA if they prefer. If replaced, the Yubico template can never be restored."*

This tool does not currently support replacing the attestation key on a YubiKey.
It only supports use of the Yubico-provided attestation key to generate "attestation statements".

The attestation certificate on a card can be inspected as follows:

```
$ opgpcard attestation cert
-----BEGIN CERTIFICATE-----
[...]
-----END CERTIFICATE-----
```

#### Generating an attestation statement

For any key slot on the card you can generate an attestation statement,
if the key material in that key slot has been generated on the card.

It's not possible to generate attestation statements for key material that was imported to the card
(the attestation statement certifies that the key has been generated on the card).

To generate an attestation statement, run:

```
$ opgpcard attestation generate --key SIG --card 0006:01234567
```

Supported values for `--key` are `SIG`, `DEC` and `AUT`.

Generation of an attestation requires the User PIN. By default, it also requires touch confirmation
(the touch policy configuration for the attestation key slot is set to `On` by default).

#### Viewing an attestation statement

When the YubiKey generates an attestation statement, it gets stored in a `cardholder certificate` data object on the card.

After an attestation statement has been generated, it can be read from the card and viewed in pem-encoded format:

```
$ opgpcard attestation statement --key SIG
-----BEGIN CERTIFICATE-----
[...]
-----END CERTIFICATE-----
```

Supported values for `--key` are `SIG`, `DEC` and `AUT`.
