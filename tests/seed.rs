mod common;

use common::fixtures::*;

#[test]
fn candidate_matches_frozen_seed_based_keypairs() {
    let fixture: SeedFixture = load_fixture(
        include_str!("../test-vectors/seed_based_keypair.json"),
        "seed",
    );
    for case in fixture.cases {
        assert_result(
            &format!("seed/{}", case.id),
            common::seed_account(&case.input),
            &case.expected,
        );
    }
}

#[test]
fn local_slip10_matches_published_master_vectors() {
    let fixture: Slip10Fixture =
        load_fixture(include_str!("../test-vectors/slip10.json"), "slip10");
    for case in fixture.master_cases {
        assert_result(
            &format!("slip10/{}", case.id),
            common::master(&case.input),
            &case.expected,
        );
    }
}

#[test]
fn local_slip10_matches_published_child_vectors() {
    let fixture: Slip10Fixture =
        load_fixture(include_str!("../test-vectors/slip10.json"), "slip10");
    for case in fixture.child_cases {
        assert_result(
            &format!("slip10/{}", case.id),
            common::child(&case.input),
            &case.expected,
        );
    }
}

#[test]
fn fixture_inventory_is_complete_and_unique() {
    let ed: RailFixture<Ed25519Output> =
        load_fixture(include_str!("../test-vectors/ed25519.json"), "ed25519");
    let p256: RailFixture<P256Output> =
        load_fixture(include_str!("../test-vectors/p256.json"), "p256");
    let seed: SeedFixture = load_fixture(
        include_str!("../test-vectors/seed_based_keypair.json"),
        "seed",
    );
    let slip: Slip10Fixture = load_fixture(include_str!("../test-vectors/slip10.json"), "slip10");
    assert_eq!(
        (ed.derivation_cases.len(), ed.role_expansion_cases.len()),
        (4, 6)
    );
    assert_eq!(
        (p256.derivation_cases.len(), p256.role_expansion_cases.len()),
        (7, 6)
    );
    assert_eq!(seed.cases.len(), 3);
    assert_eq!((slip.master_cases.len(), slip.child_cases.len()), (3, 2));
    let mut ids = std::collections::HashSet::new();
    for fixture in [&ed as &dyn Fixture, &p256, &seed, &slip] {
        for group in fixture.case_metadata() {
            for (id, _) in group {
                assert!(ids.insert(id), "duplicate case ID: {id}");
            }
        }
    }
    assert_eq!(ids.len(), 31);
}

#[test]
fn malformed_fixtures_are_rejected() {
    let original: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/ed25519.json")).unwrap();
    let signing = "/derivation_cases/0/input/signing_secret";
    for (name, pointer, value, message) in [
        (
            "malformed hex",
            signing,
            serde_json::json!("gg"),
            "hexadecimal",
        ),
        ("odd hex", signing, serde_json::json!("0"), "Odd number"),
        (
            "short key",
            signing,
            serde_json::json!("00".repeat(31)),
            "expected 32 bytes",
        ),
        (
            "long key",
            signing,
            serde_json::json!("00".repeat(33)),
            "expected 32 bytes",
        ),
        (
            "empty list",
            "/derivation_cases",
            serde_json::json!([]),
            "must not be empty",
        ),
        (
            "duplicate ID",
            "/derivation_cases/1/id",
            original["derivation_cases"][0]["id"].clone(),
            "duplicate case ID",
        ),
        (
            "missing output",
            "/derivation_cases/0/expected/outputs",
            serde_json::json!({}),
            "missing field",
        ),
    ] {
        let mut fixture = original.clone();
        *fixture.pointer_mut(pointer).unwrap() = value;
        let error = parse_fixture::<RailFixture<Ed25519Output>>(&fixture.to_string()).unwrap_err();
        assert!(error.contains(message), "{name}: {error}");
    }
    for pointer in [
        "",
        "/derivation_cases/0",
        "/derivation_cases/0/input",
        "/derivation_cases/0/expected",
        "/derivation_cases/0/expected/outputs",
    ] {
        let mut fixture = original.clone();
        fixture
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::json!(true));
        assert!(
            parse_fixture::<RailFixture<Ed25519Output>>(&fixture.to_string())
                .unwrap_err()
                .contains("unknown field")
        );
    }
    let mut seed: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/seed_based_keypair.json")).unwrap();
    seed["cases"][0]["input"]["account"] = serde_json::json!(2147483648u32);
    assert!(parse_fixture::<SeedFixture>(&seed.to_string())
        .unwrap_err()
        .contains("below 2^31"));
    let mut slip: serde_json::Value =
        serde_json::from_str(include_str!("../test-vectors/slip10.json")).unwrap();
    slip["child_cases"][0]["input"]["index"] = serde_json::json!(2147483648u32);
    assert!(parse_fixture::<Slip10Fixture>(&slip.to_string())
        .unwrap_err()
        .contains("below 2^31"));
}
