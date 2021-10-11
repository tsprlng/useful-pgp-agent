<!--
SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

This test suite has two goals:

1) To test openpgp-card and its backends, as well as openpgp-card-sequoia.
2) To be able to compare the behavior of different OpenPGP card
   implementations.

The tests are built mostly on top of the `card-app` abstraction layer in
`openpgp-card`. For crypto-operations, the higher level API 
`openpgp-card-sequoia` (which relies on Sequoia PGP) is used.


# Building / Dependencies

To build this crate on Debian 11, you need to install 

`apt install rustc libpcsclite-dev pkg-config nettle-dev clang libclang-dev`

Fedora 34:
`dnf install rustc cargo pcsc-lite-devel pkg-config nettle-devel clang clang-devel`

# Purpose

These tests assert (and fail) in cases where a certain behavior is
expected from all cards, and a card doesn't conform.

However, card behavior diverges from the spec in some cases.
It's not ok for us to just fail and reject the card's output, in some of 
these cases, even when a card contradicts the OpenPGP card spec.

For such cases, these tests return a TestOutput (which is a
Vec<TestResult>), to document the return values of the card in question.

## Example for card-specific behavior that contradicts the spec

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


# Running tests against emulated Gnuk via PC/SC

## About Gnuk

Gnuk is a free implementation of the OpenPGP card spec by 
[Gniibe](https://www.gniibe.org/), see:
http://www.fsij.org/doc-gnuk/. (Gniibe also designs and produces open 
hardware to run the Gnuk software on, see https://www.gniibe.org/tag/fst-01.html)

For our purposes, we will run the Gnuk code in "emulated" mode, meaning it 
will run on our host, instead of on a USB-connected device (as one would 
usually use Gnuk).

## Building Gnuk

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

Now we can build the emulated Gnuk.

We don't want to use KDF in our tests, so we disable Gnuk's default behavior 
(by default, emulated Gnuk considers KDF "required") with the 
"kdf_do=optional" variable (I am not aware of any OpenPGP card that 
requires KDF by default, so the tests currently don't use KDF).

```
kdf_do=optional ./configure --target=GNU_LINUX --enable-factory-reset
make
```

## Running the emulated Gnuk

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

First, we determine the ident of connected OpenPGP cards (and specifically of 
our emulated Gnuk instance):

```
$ cargo run --bin list-cards
[...]

The following OpenPGP cards are connected to your system:
 FFFE:F1420A7A
```

The we edit the test config file in `config/test-cards.toml` to use this 
emulated Gnuk. The configuration should look like this:

```
[card.gnuk_emu]
backend.pcsc = "FFFE:F1420A7A"
config.keygen = ["RSA2k/32", "Curve25519"]
config.import = ["data/rsa2k.sec", "data/rsa4k.sec", "data/25519.sec"]
```

Now we can run the `card-functionality` tests, e.g. import and key generation:

```
$ cargo run --bin import
[...]

$ cargo run --bin keygen
[...]
```