// SPDX-FileCopyrightText: 2022 Lars Wirzenius <liw@liw.fi>
// SPDX-License-Identifier: MIT OR Apache-2.0

use subplotlib::file::SubplotDataFile;
use subplotlib::steplibrary::runcmd::Runcmd;

use serde_json::Value;
use std::path::Path;

#[derive(Debug, Default)]
struct SubplotContext {}

impl ContextElement for SubplotContext {}

#[step]
#[context(SubplotContext)]
#[context(Runcmd)]
fn install_opgpcard(context: &ScenarioContext) {
    let target_exe = env!("CARGO_BIN_EXE_opgpcard");
    let target_path = Path::new(target_exe);
    let target_path = target_path.parent().ok_or("No parent?")?;
    context.with_mut(
        |context: &mut Runcmd| {
            context.prepend_to_path(target_path);
            Ok(())
        },
        false,
    )?;
}

#[step]
#[context(Runcmd)]
fn stdout_matches_json_file(context: &ScenarioContext, file: SubplotDataFile) {
    let expected: Value = serde_json::from_slice(file.data())?;
    println!("expecting JSON: {:#?}", expected);

    let stdout = context.with(|runcmd: &Runcmd| Ok(runcmd.stdout_as_string()), false)?;
    let actual: Value = serde_json::from_str(&stdout)?;
    println!("stdout JSON: {:#?}", actual);

    println!("fuzzy checking JSON values");
    assert!(json_eq(&actual, &expected));
}

// Fuzzy match JSON values. For objects, anything in expected must be
// in actual, but it's OK for there to be extra things.
fn json_eq(actual: &Value, expected: &Value) -> bool {
    match actual {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            println!("simple value");
            println!("actual  ={:?}", actual);
            println!("expected={:?}", expected);
            let eq = actual == expected;
            println!("simple value eq={}", eq);
            return eq;
        }
        Value::Array(a_values) => {
            if let Value::Array(e_values) = expected {
                println!("both actual and equal are arrays");
                for (a_value, e_value) in a_values.iter().zip(e_values.iter()) {
                    println!("comparing corresponding array elements");
                    if !json_eq(a_value, e_value) {
                        println!("array elements differ");
                        return false;
                    }
                }
                println!("arrays match");
                return true;
            } else {
                println!("actual is array, expected is not");
                return false;
            }
        }
        Value::Object(a_obj) => {
            if let Value::Object(e_obj) = expected {
                println!("both actual and equal are objects");
                for key in e_obj.keys() {
                    println!("checking key {}", key);
                    if !a_obj.contains_key(key) {
                        println!("key {} is missing from actual", key);
                        return false;
                    }
                    let a_value = a_obj.get(key).unwrap();
                    let e_value = e_obj.get(key).unwrap();
                    let eq = json_eq(a_value, e_value);
                    println!("values for {} eq={}", key, eq);
                    if !eq {
                        return false;
                    }
                }
                println!("objects match");
                return true;
            } else {
                println!("actual is object, expected is not");
                return false;
            }
        }
    }
}
