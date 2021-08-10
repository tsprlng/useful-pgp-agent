<!--
SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

These tests rely mainly on the card-app abstraction layer in
openpgp-card. However, for crypto-operations, higher level APIs and
Sequoia PGP are used.

The main purpose of this test suite is to be able to test the behavior
of different OpenPGP card implementation.

These tests assert (and fail) in cases where a certain behavior is
expected from all cards, and a card doesn't conform.
However, in some aspects, card behavior is expected to diverge, and
it's not ok for us to just fail and reject the card's output.
Even when it contradicts the OpenPGP card spec.

For such cases, these tests return a TestOutput, which is a
Vec<TestResult>, to document the return values of the card in question.

e.g.: the Yubikey 5 fails to handle the VERIFY command with empty data
(see OpenPGP card spec, 7.2.2: "If the command is called
without data, the actual access status of the addressed password is
returned or the access status is set to 'not verified'").

The Yubikey 5 erroneously returns Status 0x6a80 ("Incorrect parameters in
the command data field").
