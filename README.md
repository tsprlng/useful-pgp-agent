# Multi-card PGP smartcard agent (WORK IN PROGRESS)

My main use case for PGP smart cards (Yubikeys) is to either sign commits or decrypt passwords.

I always wanted to have the tools for these tasks SEAMLESSLY and EFFORTLESSLY switch between using two different cards when the laptop is docked / undocked. (Impossible with `gpg`/`gpg-agent`.)

I also wanted a convenient way to re-use the same cached PIN entry across these multiple cards.

Also, this needs to be possible to do reliably, without holding transactions open unnecessarily and also without randomly blocking when an unrelated card has a session open in a different application.

This all seems to cut across too many layers to be achievable without touching... every layer.

Here I'm re-using a lot of someone else's excellent work on these layers, as you'll see.

## Current status

This is not a polished end product, but more like a personal experiment / learning platform. However it is actually reliable enough that I have now started using it with my password manager on Linux. Hopefully when signatures are done, that'll finally be the end of the years of misery and suffering with `gpg`, at least in terms of daily use. Then gradual improvements can be made to concurrency and the edge cases that cause crashes.

On MacOS, monitoring for plug/unplug events doesn't work reliably at all because Apple's special pcscd seems to produce spurious state changes that cause some of these crashes. Might fix that eventually, but I don't really use MacOS for work anyway, so meh.

Realistically, it probably isn't usable by anyone else yet. It relies on the server running in a tmux so that the card PIN can be entered. The "front end" is a nasty little Ruby script.

## Layout

This is a fork of https://codeberg.org/openpgp-card/openpgp-card, modified slightly to make a couple of things inside the library public so that this thing can use them.

This project comprises the following library crates:

- [openpgp-card](https://crates.io/crates/openpgp-card), a low-level OpenPGP card client API.
  It is PGP implementation agnostic.
- [card-backend](https://crates.io/crates/card-backend), a shared trait for backends that perform raw communication with smart cards
- [card-backend-pcsc](https://crates.io/crates/card-backend-pcsc), a backend implementation to communicate with smart cards via [pcsc](https://pcsclite.apdu.fr/).
- [card-backend-scdc](https://crates.io/crates/card-backend-scdc), a backend implementation to communicate with smart cards via [scdaemon](https://www.gnupg.org/documentation/manuals/gnupg/Invoking-SCDAEMON.html#Invoking-SCDAEMON).
- [openpgp-card-rpgp](https://crates.io/crates/openpgp-card-rpgp), a companion crate for conveniently using openpgp-card with  [rPGP](https://github.com/rpgp/rpgp/).
- [openpgp-card-sequoia](https://crates.io/crates/openpgp-card-sequoia), a wrapping API for conveniently using openpgp-card with [Sequoia PGP](https://sequoia-pgp.org/).
- [openpgp-card-state](https://crates.io/crates/openpgp-card-state), shared infrastructure for handling card metadata and User PINs in applications.

There is also supposed to be a clone of https://codeberg.org/openpgp-card/rpgp (in `./rpgp`), duplicated here as a branch `rpgp` to make it easier to get as a submodule -- with one patch to edit Cargo.toml to make it work in a subdirectory as part of the same build. This is necessary so that all of this related code can share correctly versioned types.

Finally, the actual code I'm working on is in `src/`, and a big chunk of this is lifted from another related project, https://codeberg.org/openpgp-card/openpgp-card-tools.
