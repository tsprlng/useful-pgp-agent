# SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
# SPDX-License-Identifier: CC0-1.0

# Run pcscd (as root)
/etc/init.d/pcscd start

# Run the javacard applet (as jcardsim)
su - -c "sh /home/jcardsim/run-card.sh" jcardsim

# Run the openpgp-card test code (as ocard).
# This uses $1 as the name of the binary to run.
su - -c "cd openpgp-card/card-functionality/ && cargo run --bin $1" ocard

