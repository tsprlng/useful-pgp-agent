<!--
SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Scripting around opgpcard

The `opgpcard` tool can manipulate an OpenPGP smart card (also known
as hardware token). There are various commercial as well as Free Software-implementations of the standard.
Well known commercial products with OpenPGP card support include YubiKey and Nitrokey. This tool is meant to work with
any card that implements the OpenPGP smart card interface.

`opgpcard` supports structured output as JSON and YAML. The default is
human-readable text. The structured output it meant to be consumed by
other programs, and is versioned.

For example, to list all the OpenPGP cards connected to a system:

~~~sh
$ opgpcard --output-format=json list
{
  "schema_version": "1.0.0",
  "idents": [
    "ABCD:01234567"
  ]
}
$
~~~

The structured output is versioned (text output is not), using the
field name `schema_version`. The version numbering follows [semantic
versioning](https://semver.org/):

* if a field is added, the minor level is incremented, and patch level
  is set to zero
* if a field is removed, the major level is incremented, and minor and
  patch level are set to zero
* if there are changed with no semantic impatc, the patch level is
  incremented

Each version of `opgpcard` supports only the latest minor version for
each major version. Consumers of the output have to be OK with added
fields.

Thus, for example, if the `opgpcard list` command would add a new
field for when the command was run, the output might look like this:

~~~sh
$ opgpcard --output-format=json list
{
  "schema_version": "1.1.0",
  "date": "Tue, 18 Oct 2022 18:07:41 +0300",
  "idents": [
    "ABCD:01234567"
  ]
}
$
~~~

A new field means the minor level in the schema version is
incremented.
