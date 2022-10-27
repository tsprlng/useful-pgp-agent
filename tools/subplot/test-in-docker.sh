#!/usr/bin/env bash
#
# Run "cargo test" inside a Docker container with virtual cards
# installed and running. This will allow at least rudimentary testing
# of actual card functionality of opgpcard.
#
# SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

image="registry.gitlab.com/openpgp-card/virtual-cards/smartpgp-builddeps"

src="$(cd .. && pwd)"

if ! [ -e Cargo.toml ] || ! grep '^name.*openpgp-card-tools' Cargo.toml; then
	echo "MUST run this in the root of the openpgp-card-tool crate" 1>&2
	exit 1
fi

cargo build
docker run --rm -t \
	--volume "cargo:/cargo" \
	--volume "dotcargo:/root/.cargo" \
	--volume "$src:/opt" "$image" \
	bash -c '
/etc/init.d/pcscd start && \
su - -c "sh /home/jcardsim/run-card.sh >/dev/null" jcardsim && \
cd /opt/tools && env CARGO_TARGET_DIR=/cargo cargo test'
