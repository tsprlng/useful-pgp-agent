<!--
SPDX-FileCopyrightText: 2022 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# SSH login using an OpenPGP card

In this guide, we'll set up OpenPGP card-based SSH logins to a remote machine.

We assume that you have an OpenPGP card plugged into your client machine, and that an authentication key is available
on that card.

We also assume that the `opgpcard` tool [is installed](https://hkos.gitlab.io/openpgp-card/opgpcard.html#install).

## Optional: generate throwaway keys on your card, for this guide

If you have a blank OpenPGP card, and want to generate throwaway keys to try this guide, you can generate keys on the
card by running:

```
$ opgpcard admin -c FFFE:12345678 generate -o /tmp/cert.pub 25519
```

Replace `FFFE:12345678` with the identifier of your own card (as shown by `opgpcard list`).

This command instructs your card to generate a set of ECC Curve 25519 keys. Not all cards support this algorithm.
If yours doesn't, you can generate RSA 2048 keys instead:

```
$ opgpcard admin -c FFFE:12345678 generate -o /tmp/cert.pub rsa2048
```

Key generation will ask for both the Admin PIN (`12345678` by default) and the User PIN (`123456` by default).
You can ignore the public key output in `/tmp/cert.pub`, if you don't want to use these keys outside this guide.

If you only generate keys to try this guide, you'll probably want to run `opgpcard factory-reset -c <identifier>` at
the end. This will revert your card back into a blank state (and remove our throwaway keys).

# Allowing access to the remote server

Now we'll add our "SSH public key" to the remote machine's list of authorized keys.

More specifically, we'll add the SSH public key that corresponds to the authentication key on our OpenPGP card.
This tells the remote machine that we want our OpenPGP card to be considered a valid means of authorization to log in.

## Adding the public key to `authorized_keys` on a remote machine

To see the SSH public key representation of the authentication key on our OpenPGP card, we run `opgpcard ssh`:

```
$ opgpcard ssh
OpenPGP card FFFE:12345678

Authentication key fingerprint:
7A21F955A14C1C134D9EAE90E8B3EFD2581F3113

SSH public key:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP3GtBCzGAUjg8iN9JOo5f+cFCYLaWE8titbIbimtKwe opgpcard:FFFE:12345678
```

In this output, the last line shows our SSH public key, which is:

`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP3GtBCzGAUjg8iN9JOo5f+cFCYLaWE8titbIbimtKwe opgpcard:FFFE:12345678`

We add this line to the `~/.ssh/authorized_keys` file in an account on a remote server.

Now the SSH daemon on that machine will consider the authentication key on our OpenPGP card as proof that we're allowed
to log in.

(Note that the public key line doesn't need to be kept secret. Only its counterpart, the secret key on our card, is
sensitive.)

# Setting up the client side

Next we install two pieces of software on our client machine, to communicate with the remote machine using
the [SSH authentication protocol](https://datatracker.ietf.org/doc/html/rfc4252) protocol:

1) an OpenPGP card-based private key store daemon, and
2) an ssh-agent implementation.
 
Each of these will listen to a Unix domain socket (we'll define an environment variable for each).

In this guide, for demonstration purposes, we'll run these services in a terminal, as Rust debug builds, with rather 
chatty debug output (in production systems, you'll probably want to run release builds as system services).

NOTE: These services are in an early experimental stage. Read the documentation for caveats, and don't use them
in sensitive contexts, just yet.

## Card-based Private Key Store

This is an experimental Private Key Store that enables use of cryptographic keys stored on OpenPGP cards.

We'll build and run it in place, for this guide:

```
$ export PKS_OPENPGP_CARD=$XDG_RUNTIME_DIR/pks-openpgp-card.sock

$ git clone https://gitlab.com/sequoia-pgp/pks-openpgp-card
$ cd pks-openpgp-card
$ cargo run -- -H unix://$PKS_OPENPGP_CARD
```

## Private Key Store-based SSH Agent

An SSH Agent implementation that can use keys on OpenPGP cards, via the Private Key Store from the previous step.

```
$ export PKS_OPENPGP_CARD=$XDG_RUNTIME_DIR/pks-openpgp-card.sock
$ export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ssh-agent-pks.sock

$ git clone https://gitlab.com/sequoia-pgp/ssh-agent-pks
$ cd ssh-agent-pks
$ cargo run -- -H unix://$SSH_AUTH_SOCK --endpoint $PKS_OPENPGP_CARD
```

## Using the SSH Agent

To use `ssh-agent-pks` from your system's SSH client, the variable `SSH_AUTH_SOCK` must point to it:

`export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ssh-agent-pks.sock`

### Register a card with the agent

Once the two services are running, you can register an OpenPGP card with the `ssh-agent-pks` OpenSSH agent, by telling
it to add the authentication key from the card:

`ssh-add -s /7A21F955A14C1C134D9EAE90E8B3EFD2581F3113`

`7A21F955A14C1C134D9EAE90E8B3EFD2581F3113` is the fingerprint of our authentication key, as shown from
`opgpcard ssh`, above. You need to add the fingerprint of your OpenPGP card's authentication key.
Don't forget to add a slash before the fingerprint!

You will be prompted to "Enter passphrase for PKCS#11" (don't let this message confuse you: you actually need to enter the User PIN for your OpenPGP card, but the SSH software doesn't know this).

Remember that the User PIN is `123456` by default, on most cards (and remember to change the PIN for cards that
you'll use productively).

This operation is not persisting anything on disk, for now. You always need to add keys to `ssh-agent-pks` after
starting it.

## Log into remote machines

When `SSH_AUTH_SOCK` is set, you should now be able to `ssh <remote-machine>`.
This will use the authentication key on your OpenPGP card to authorize your login.

Yay!
