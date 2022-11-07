#!/usr/bin/python3
#
# WARNING: This will wipe any information on a card. Do not use it unless
# you're very sure you don't mind.
#
# Prepare an OpenPGP card for use within a hypothetical organization:
#
# - factory reset the card
# - set card holder name, if desired
# - generate elliptic curve 25519 keys
# - write to stdout a JSON object with the card id, card holder, and
#   key fingerprints
#
# Usage: run with --help.
#
# SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
# SPDX-License-Identifier: MIT OR Apache-2.0


import argparse
import json
import sys
from subprocess import run


tracing = False


def trace(msg):
    if tracing:
        sys.stderr.write(f"DEBUG: {msg}\n")
        sys.stderr.flush()


def opgpcard_raw(args):
    argv = ["opgpcard"] + args
    trace(f"running {argv}")
    p = run(argv, capture_output=True)
    if p.returncode != 0:
        raise Exception(f"opgpcard failed:\n{p.stderr}")
    o = p.stdout
    trace(f"opgpcard raw output: {o!r}")
    return o


def opgpcard_json(args):
    o = json.loads(opgpcard_raw(["--output-format=json"] + args))
    trace(f"opgpcard JSON output: {o}")
    return o


def list_cards():
    return opgpcard_json(["list"])["idents"]


def pick_card(card):
    cards = list_cards()
    if card is None:
        if not cards:
            raise Exception("No cards found")
        if len(cards) > 1:
            raise Exception(f"Can't pick card automatically: found {len(cards)} cards")
        return cards[0]
    elif card in cards:
        return card
    else:
        raise Exception(f"Can't find specified card {card}")


def factory_reset(card):
    opgpcard_raw(["factory-reset", "--card", card])


def set_card_holder(card, admin_pin, name):
    trace(f"set card holder to {name!r}")
    opgpcard_raw(["admin", "--card", card, "--admin-pin", admin_pin, "name", name])


def generate_key(card, admin_pin, user_pin):
    opgpcard_raw(
        [
            "admin",
            f"--card={card}",
            f"--admin-pin={admin_pin}",
            "generate",
            f"--user-pin={user_pin}",
            "--output=/dev/null",
            "cv25519",
        ]
    )


def status(card):
    o = opgpcard_json(["status", f"--card={card}"])
    return {
        "card_ident": o["ident"],
        "cardholder_name": o["cardholder_name"],
        "signature_key": o["signature_key"]["fingerprint"],
        "decryption_key": o["signature_key"]["fingerprint"],
        "authentication_key": o["signature_key"]["fingerprint"],
    }


def card_is_empty(card):
    o = status(card)
    del o["card_ident"]
    for key in o:
        if o[key]:
            return False
    return True


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--force", action="store_true", help="prepare a card that has data")
    p.add_argument(
        "--verbose", action="store_true", help="produce debugging output to stderr"
    )
    p.add_argument("--card", help="card identifier, default is to pick the only one")
    p.add_argument("--card-holder", help="name of card holder", required=True)
    p.add_argument(
        "--admin-pin", action="store", help="set file with admin PIN", required=True
    )
    p.add_argument(
        "--user-pin", action="store", help="set file with user PIN", required=True
    )
    args = p.parse_args()

    if args.verbose:
        global tracing
        tracing = True

    trace(f"args: {args}")
    card = pick_card(args.card)
    if not args.force and not card_is_empty(card):
        raise Exception(f"card {card} has existing keys, not touching it")
    factory_reset(card)
    set_card_holder(card, args.admin_pin, args.card_holder)
    key = generate_key(card, args.admin_pin, args.user_pin)
    o = status(card)
    print(json.dumps(o, indent=4))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        sys.stderr.write(f"ERROR: {e}\n")
        sys.exit(1)
