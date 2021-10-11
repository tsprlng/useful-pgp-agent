<!--
SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

The main purpose of this test suite is to be able to test the behavior
of different OpenPGP card implementation.

These tests rely partly on the card-app abstraction layer in
openpgp-card. For crypto-operations, the higher level API 
openpgp-card-sequoia (which relies on Sequoia PGP) is also used.


# Building / Dependencies

To build this crate on Debian 11, you need to install 

`apt install rustc libpcsclite-dev pkg-config nettle-dev clang libclang-dev`

Fedora 34:
`dnf install rustc cargo pcsc-lite-devel pkg-config nettle-devel clang clang-devel`

# Purpose

These tests assert (and fail) in cases where a certain behavior is
expected from all cards, and a card doesn't conform.
However, in some aspects, card behavior is expected to diverge, and
it's not ok for us to just fail and reject the card's output,
even when it contradicts the OpenPGP card spec.

For such cases, these tests return a TestOutput (which is a
Vec<TestResult>), to document the return values of the card in question.

## Example for card-specific behavior

Yubikey 5 fails to handle the VERIFY command with empty data
(see OpenPGP card spec, 7.2.2: "If the command is called
without data, the actual access status of the addressed password is
returned or the access status is set to 'not verified'").

The Yubikey 5 erroneously returns Status 0x6a80 ("Incorrect parameters in
the command data field").


# Running

To access a card via pcsc, we need to install and start `pcscd`.

```
apt install pcscd
systemctl enable pcscd
systemctl start pcscd
```

(Alternatively, you could use the experimental scdaemon backend)


# Running tests against an emulated Gnuk via PC/SC

Install additional dependencies (Debian 11: `# apt install make usbip`,
Fedora 34: `# dnf install make usbip`)

We'll use the stable 1.2 branch of Gnuk, with the latest patches for 
chopstx (which are necessary for emulated Gnuk to work with PC/SC).

Get the Gnuk source code:

```
git clone https://git.gniibe.org/cgit/gnuk/gnuk.git/
cd gnuk
git checkout STABLE-BRANCH-1-2
git submodule update --init
cd chopstx
git checkout master
cd ../src
```

## Build the emulated Gnuk

We aren't using KDF in our tests, so we disable Gnuk's default behavior 
(by default, emulated Gnuk considers KDF "required") with the 
"kdf_do=optional" variable.

```
kdf_do=optional ./configure --target=GNU_LINUX --enable-factory-reset
make
```

## Run the emulated Gnuk

Emulated Gnuk connects to the system via http://usbip.sourceforge.net/.
This means that we need to load the kernel module `vhci_hcd` to connect 
to a running emulated Gnuk instance.

First, we start the emulated Gnuk from a non-root account:

```
./build/gnuk --vidpid=234b:0000
```

Then, as root, we attach to the emulated Gnuk device:

```
# modprobe vhci_hcd
# usbip attach -r 127.0.0.1 -b 1-1
```

Afterwards, emulated Gnuk is connected to the system.
We can now talk to it, e.g. we can look it up with `pcsc_scan`:

```
$ pcsc_scan
Using reader plug'n play mechanism
Scanning present readers...
[..]
2: Free Software Initiative of Japan Gnuk (FSIJ-1.2.18-EMULATED) 00 00
[..]
```

## Run the card-functionality tests against the emulated Gnuk

Determine the ident of connected OpenPGP cards (and specifically of our 
emulated Gnuk instance):

```
$ cargo run --bin list-cards
[...]

The following OpenPGP cards are connected to your system:
 FFFE:F1420A7A
```

Edit the test config file in `config/test-cards.toml` to use this emulated 
Gnuk, e.g. like this:

```
[card.gnuk_emu]
backend.pcsc = "FFFE:F1420A7A"
config.keygen = ["RSA2k/32", "Curve25519"]
config.import = ["data/rsa2k.sec", "data/rsa4k.sec", "data/25519.sec"]
```

Running the import and key generation tests:

```
$ cargo run --bin import
[...]

$ cargo run --bin keygen
[...]
```