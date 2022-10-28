<!--
SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Introduction

This document describes the requirements and acceptance criteria for
the `opgpcard` tool, and also how to verify that they are met. This
document is meant to be read and understood by all stakeholders, and
processed by the [Subplot](https://subplot.tech/) tool, which also
generates code to automatically perform the verification.

## Note about running the tests described here

The verification scenarios in this document assume the availability of
a virtual smart card. Specifically one described in
<https://gitlab.com/openpgp-card/virtual-cards>. The
`openpgp-card/tools` crate is set up to generate tests only if the
environment variable `CARD_BASED_TESTS` is set (to any value),
and the `openpgp-card` repository `.gitlab-ci.yml` file is set up to
set that environment variable when the repository is tested in GitLab CI.

This means that if you run `cargo test`, no test code is normally
generated from this document. To run the tests locally, outside of
GitLab CI, use the script `tools/cargo-test-in-docker`.

# Acceptance criteria

These scenarios mainly test the JSON output format of the tool. That
format is meant for consumption by other tools, and it is thus more
important that it stays stable. The text output that is meant for
human consumption may change at will, so it's not worth testing.

## Smoke test

_Requirement: The tool can report its version._

Justification: This is useful mainly to make sure the tool can be run
at all. As such, it acts as a simple [smoke
test](https://en.wikipedia.org/wiki/Smoke_testing_(software)).
However, if this fails, then nothing else has a chance to work.

Note that this is not in JSON format, as it is output by the `clap`
library, and `opgpcard` doesn't affect what it looks like.

~~~scenario
given an installed opgpcard
when I run opgpcard --version
then stdout matches regex ^opgpcard \d+\.\d+\.\d+$
~~~

## List cards: `opgpcard list`

_Requirement: The tool lists available cards._

This is not at all a thorough test, but it exercises the simple happy
paths of the subcommand.

~~~scenario
given an installed opgpcard
when I run opgpcard --output-format=json list
then stdout, as JSON, matches embedded file list.json
~~~

~~~{#list.json .file .json}
{
   "idents": ["AFAF:00001234"]
}
~~~

## Card status: `opgpcard status`

_Requirement: The tool shows status of available cards._

This is not at all a thorough test, but it exercises the simple happy
paths of the subcommand.

~~~scenario
given an installed opgpcard
when I run opgpcard --output-format=json status
then stdout, as JSON, matches embedded file status.json
~~~

~~~{#status.json .file .json}
{
  "card_version": "2.0",
  "ident": "AFAF:00001234"
}
~~~

## Card information: `opgpcard info`

_Requirement: The tool shows information about available cards._

This is not at all a thorough test, but it exercises the simple happy
paths of the subcommand.

~~~scenario
given an installed opgpcard
when I run opgpcard --output-format=json info
then stdout, as JSON, matches embedded file info.json
~~~

~~~{#info.json .file .json}
{
  "card_version": "2.0",
  "application_id": "D276000124 01 01 0200 AFAF 00001234 0000",
  "manufacturer_id": "AFAF",
  "manufacturer_name": "Unknown",
  "card_service_data": [],
  "ident": "AFAF:00001234"
}
~~~

## Key generation: `opgpcard generate` and `opgpcard decrypt`

_Requirement: The tool is able to generate keys and use them for decryption._

This is not at all a thorough test, but it exercises the simple happy
paths of the subcommand.

~~~scenario
given an installed opgpcard
given file admin.pin
given file user.pin
when I run opgpcard admin --card AFAF:00001234  --admin-pin admin.pin generate --user-pin user.pin --output certfile
then file certfile contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then file certfile contains "-----END PGP PUBLIC KEY BLOCK-----"

given file message
when I run sq encrypt message --recipient-cert certfile --output message.enc
and I run opgpcard decrypt  --card AFAF:00001234 --user-pin user.pin message.enc --output message.dec
then files message and message.dec match
~~~

~~~{#admin.pin .file}
12345678
~~~

~~~{#user.pin .file}
123456
~~~

~~~{#message .file}
Hello World!
~~~

## Key generation: `opgpcard generate` and `opgpcard sign`

_Requirement: The tool is able to generate keys and use them for signing._

This is not at all a thorough test, but it exercises the simple happy
paths of the subcommand.

~~~scenario
given an installed opgpcard
given file admin.pin
given file user.pin
when I run opgpcard admin --card AFAF:00001234 --admin-pin admin.pin generate --user-pin user.pin --output certfile
then file certfile contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then file certfile contains "-----END PGP PUBLIC KEY BLOCK-----"

given file message
when I run opgpcard sign message --card AFAF:00001234 --user-pin user.pin --detached --output message.sig
when I run sq verify message --detached message.sig --signer-cert certfile
then stderr contains "1 good signature."
~~~

## Key import: `opgpcard import` and `opgpcard decrypt`

_Requirement: The tool is able to import keys and use them for decryption._

This is not at all a thorough test, but it exercises the simple happy
paths of the subcommand.

~~~scenario
given an installed opgpcard
given file admin.pin
given file user.pin
given file nist256key
when I run opgpcard admin --card AFAF:00001234 --admin-pin admin.pin import nist256key
then stdout contains "CCCFFFAAC77C9F9D3BB2D2CA3C93515DA813C03F"
then stdout contains "360EC3C59A7D8E51DCE9FA1171858B15EE7F4BCA"
then stdout contains "6D186AC7C6761FC22BE07557D2BE4918C44C74D9"

given file message
when I run sq encrypt message --recipient-cert nist256key --output message.enc
and I run opgpcard decrypt  --card AFAF:00001234 --user-pin user.pin message.enc --output message.dec
then files message and message.dec match
~~~

## Key import: `opgpcard import` and `opgpcard sign`

_Requirement: The tool is able to import keys and use them for signing._

This is not at all a thorough test, but it exercises the simple happy
paths of the subcommand.

~~~scenario
given an installed opgpcard
given file admin.pin
given file nist256key
when I run opgpcard admin --card AFAF:00001234 --admin-pin admin.pin import nist256key
then stdout contains "CCCFFFAAC77C9F9D3BB2D2CA3C93515DA813C03F"
then stdout contains "360EC3C59A7D8E51DCE9FA1171858B15EE7F4BCA"
then stdout contains "6D186AC7C6761FC22BE07557D2BE4918C44C74D9"

given file user.pin
given file message
when I run opgpcard sign message --card AFAF:00001234 --user-pin user.pin --detached --output message.sig
when I run sq verify message --detached message.sig --signer-cert nist256key
then stderr contains "1 good signature."
~~~

~~~{#nist256key .file}
-----BEGIN PGP PRIVATE KEY BLOCK-----

lHcEYPP/JxMIKoZIzj0DAQcCAwT5a9JIM6BX1zxvFkNr2LMGLyTw72+iXsUZlA8X
w3Bn91jVRpSSIITjibHKliS2e2kZlaoHOZvlXmZ3nqOANjV+AAEAzCPG24MzHigZ
qyoaNr+7o6u/D8DndXHhsrERqm9cCgcOybQfTklTVCBQMjU2IDxuaXN0MjU2QGV4
YW1wbGUub3JnPoiQBBMTCAA4FiEEzM//qsd8n507stLKPJNRXagTwD8FAmDz/ycC
GwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQPJNRXagTwD+bZAD/fu4NjabH
GKHB1dIpqX+opDt8E3RFes58P+p4wh8W+xEBAMcPs6HLYvcLLkqtpV06wKYngPY+
Ln/wcpQOagwO+EgfnHsEYPP/JxIIKoZIzj0DAQcCAwTtyP4rOGNlU+Tzpa7UYv5h
jR/T9DzMVUntaFhb3Cm0ung7IEGNAOcbgpCx/fdm7BPL+9MJB+qwpsz8bQa4DfnE
AwEIBwABALvh9XLpqe1MqwPodYlWKgw4me/tR2FNKmLXPC1gl3g7EAeIeAQYEwgA
IBYhBMzP/6rHfJ+dO7LSyjyTUV2oE8A/BQJg8/8nAhsMAAoJEDyTUV2oE8A/SMMA
/3DuQU8hb+U9U2nX93bHwpTBQfAONsEn/vUeZ6u4NdX4AP9ABH//08SFfFttiWHm
TTAR9e57Rw0DhI/wb6qqWABIyZx3BGDz/zkTCCqGSM49AwEHAgMEJz+bbG6RHQag
BoULLuklPRUtQauVTxM9WZZG3PEAnIZuu4LKkHn/JPAN04iSV+K3lBWN+HALVZSV
kFweNSOX6gAA/RD5JKvdwS3CofhQY+czewkb8feXGLQIaPS9rIWP7QX4En2IeAQY
EwgAIBYhBMzP/6rHfJ+dO7LSyjyTUV2oE8A/BQJg8/85AhsgAAoJEDyTUV2oE8A/
CSkA/2WnUoIwtv4ZBhuCpJY/GIFqRJEPgQ7DW1bXTrYsoTehAQD1wDkG0vD6Jnfu
QIPHexNllmYakW7WNqu1gobPuNEQyw==
=E2Hb
-----END PGP PRIVATE KEY BLOCK-----
~~~
