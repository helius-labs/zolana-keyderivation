use serde_json::Value;
use zolana_keypair::{
    derivation::{ed25519_derivation_message, expand_roles},
    Curve, SigningKey,
};

fn text(value: &Value) -> &str {
    value.as_str().expect("vector field is a string")
}

fn decode<const N: usize>(value: &Value) -> [u8; N] {
    hex::decode(text(value))
        .expect("vector field is hexadecimal")
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| {
            panic!("vector field has {} bytes; expected {N}", bytes.len())
        })
}

#[test]
fn candidate_matches_frozen_eddsa_signature_derivation() {
    let vectors: Value = serde_json::from_str(include_str!("../test-vectors/key_derivation.json"))
        .expect("key derivation vectors are valid JSON");
    let expected = &vectors["ed25519_rail"];

    let signing = SigningKey::from_ed25519_bytes(&decode(&expected["signing_secret"]));
    let signer_pubkey = signing
        .pubkey()
        .as_ed25519()
        .expect("ed25519 signing public key");
    assert_eq!(hex::encode(signer_pubkey), text(&expected["signer_pubkey"]));
    assert_eq!(
        hex::encode(ed25519_derivation_message(&signer_pubkey)),
        text(&expected["derivation_message"])
    );

    let seed = signing.derivation_seed().expect("ed25519 derivation seed");
    assert_eq!(
        hex::encode(seed.as_slice()),
        text(&expected["derivation_seed"])
    );

    let (nullifier, viewing) =
        expand_roles(&seed, Curve::Ed25519).expect("role expansion succeeds");
    assert_eq!(
        hex::encode(nullifier.secret()),
        text(&expected["nullifier_secret"])
    );
    assert_eq!(
        hex::encode(nullifier.pubkey().expect("nullifier public key")),
        text(&expected["nullifier_pubkey"])
    );
    assert_eq!(
        hex::encode(viewing.secret_bytes().as_slice()),
        text(&expected["viewing_secret"])
    );
    assert_eq!(
        hex::encode(viewing.pubkey().as_bytes()),
        text(&expected["viewing_pubkey"])
    );
}
