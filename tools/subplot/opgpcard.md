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
