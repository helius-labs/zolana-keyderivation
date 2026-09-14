mod common;

use common::fixtures::{assert_result, load_fixture, Ed25519Output, RailFixture};
use zolana_keypair::Curve;

#[test]
fn candidate_matches_frozen_eddsa_signature_derivation() {
    let fixture: RailFixture<Ed25519Output> =
        load_fixture(include_str!("../test-vectors/ed25519.json"), "ed25519");
    for case in fixture.derivation_cases {
        let context = format!("ed25519/{}", case.id);
        assert_result(
            &context,
            common::ed25519(&case.input, &context),
            &case.expected,
        );
    }
}

#[test]
fn candidate_matches_ed25519_expansion_boundaries() {
    let fixture: RailFixture<Ed25519Output> =
        load_fixture(include_str!("../test-vectors/ed25519.json"), "ed25519");
    for case in fixture.role_expansion_cases {
        assert_result(
            &format!("ed25519/{}", case.id),
            common::expansion(&case.input, Curve::Ed25519),
            &case.expected,
        );
    }
}
