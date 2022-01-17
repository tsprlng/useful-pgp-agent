// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CardApp exposes functionality of the "OpenPGP card" application.

/// Low-level access to OpenPGP card functionality.
///
/// Not many checks are performed here (e.g. for valid data lengths).
/// Such checks should be performed on a higher layer, if needed.
///
/// Also, no caching of data is done here. If necessary, caching should
/// be done on a higher layer.
pub struct CardApp {}

impl CardApp {}
