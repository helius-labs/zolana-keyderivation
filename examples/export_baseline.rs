#[path = "../tests/common/mod.rs"]
mod common;

use std::{env, fs, path::Path, process::Command};

use common::fixtures::*;
use serde::{de::DeserializeOwned, Serialize};
use zolana_keypair::{Curve, KeypairError};

const BASELINE: &str = "51f70d529f9b51a1da6e4f5f43221895d6009adc";

fn export<I: DeserializeOwned, O: Serialize>(
    groups: &mut serde_json::Value,
    name: &str,
    derive: impl Fn(&I, &str) -> Result<O, KeypairError>,
) {
    for case in groups[name].as_array_mut().expect("case array") {
        let input: I = serde_json::from_value(case["input"].clone()).expect("typed input");
        let id = case["id"].as_str().expect("case ID");
        let expected = match derive(&input, id) {
            Ok(outputs) => Expected::Ok { outputs },
            Err(KeypairError::InvalidSecretKey) => Expected::Error {
                error: ExpectedError::InvalidSecretKey,
            },
            Err(KeypairError::InvalidDerivationSeed { got, expected }) => Expected::Error {
                error: ExpectedError::InvalidDerivationSeed { got, expected },
            },
            Err(error) => panic!("{id}: unexpected error: {error}"),
        };
        case["expected"] = serde_json::to_value(expected).unwrap();
    }
}

fn main() {
    let output = env::args()
        .nth(1)
        .expect("usage: cargo run --example export_baseline -- <new-output-directory>");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = root.join("../zolana");
    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&candidate)
        .output()
        .unwrap();
    assert!(revision.status.success());
    assert_eq!(
        String::from_utf8(revision.stdout).unwrap().trim(),
        BASELINE,
        "export requires the pinned baseline"
    );
    let status = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .current_dir(candidate)
        .output()
        .unwrap();
    assert!(
        status.status.success() && status.stdout.is_empty(),
        "export requires a clean baseline"
    );
    // Refuse existing destinations so export cannot overwrite committed fixtures.
    fs::create_dir(&output).expect("output directory must not already exist");
    for filename in [
        "ed25519.json",
        "p256.json",
        "seed_based_keypair.json",
        "slip10.json",
    ] {
        let source = fs::read_to_string(root.join("test-vectors").join(filename)).unwrap();
        let mut fixture: serde_json::Value = serde_json::from_str(&source).unwrap();
        match filename {
            "ed25519.json" => {
                export(&mut fixture, "derivation_cases", common::ed25519);
                export(&mut fixture, "role_expansion_cases", |input, _| {
                    common::expansion(input, Curve::Ed25519)
                });
            }
            "p256.json" => {
                export(&mut fixture, "derivation_cases", common::p256);
                export(&mut fixture, "role_expansion_cases", |input, _| {
                    common::expansion(input, Curve::P256)
                });
            }
            "seed_based_keypair.json" => export(&mut fixture, "cases", |input, _| {
                common::seed_account(input)
            }),
            "slip10.json" => {
                export(&mut fixture, "master_cases", |input, _| {
                    common::master(input)
                });
                export(&mut fixture, "child_cases", |input, _| common::child(input));
            }
            _ => unreachable!(),
        }
        fs::write(
            Path::new(&output).join(filename),
            serde_json::to_string_pretty(&fixture).unwrap() + "\n",
        )
        .unwrap();
    }
}
