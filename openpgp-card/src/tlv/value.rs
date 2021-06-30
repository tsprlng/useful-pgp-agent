// SPDX-FileCopyrightText: 2021 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Debug, Eq, PartialEq)]
pub enum Value {
    // "Primitive (Simple) DO"
    S(Vec<u8>),

    // "Constructed DO"
    C(Tlv),
}

impl Value {
    pub fn data(&self) -> &[u8] {
        match self {
            Value::S(v) => &v,
            Value::C(c) => &c.0,
        }
    }
}
