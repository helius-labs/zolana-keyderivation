mod common;

use common::fixtures::{assert_result, load_fixture, P256Output, RailFixture};
use zolana_keypair::Curve;

#[test]
fn candidate_matches_frozen_p256_key_exchange_derivation() {
    let fixture: RailFixture<P256Output> =
        load_fixture(include_str!("../test-vectors/p256.json"), "p256");
    for case in fixture.derivation_cases {
        let context = format!("p256/{}", case.id);
        assert_result(
            &context,
            common::p256(&case.input, &context),
            &case.expected,
        );
    }
}

#[test]
fn candidate_matches_p256_expansion_boundaries() {
    let fixture: RailFixture<P256Output> =
        load_fixture(include_str!("../test-vectors/p256.json"), "p256");
    for case in fixture.role_expansion_cases {
        assert_result(
            &format!("p256/{}", case.id),
            common::expansion(&case.input, Curve::P256),
            &case.expected,
        );
    }
}
