// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fir>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs::File;
use std::path::Path;

fn main() {
    // Only generate test code from the subplot, if a virtual smart
    // card is available. This is a kludge until Subplot can do
    // conditional scenarios
    // (https://gitlab.com/subplot/subplot/-/issues/20).
    let flagfile = Path::new("virtual-card-available");
    if flagfile.exists() {
        subplot_build::codegen("subplot/opgpcard.subplot")
            .expect("failed to generate code with Subplot");
        println!("cargo:warning=generating subplot tests");
    } else {
        // If we're not generating code from the subplot, we should at
        // least create an empty file so that the tests/opgpcard.rs
        // file can include it. Otherwise the build will fail.
        println!("cargo:warning=flagfile not found");
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let include = Path::new(&out_dir).join("opgpcard.rs");
        eprintln!("build.rs: include={}", include.display());
        if !include.exists() {
            File::create(include).unwrap();
        }
    }
}
