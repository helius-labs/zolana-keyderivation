use ed25519_dalek_bip32::ExtendedSigningKey;
use hkdf::hmac::{Hmac, Mac};
use p256::{
    elliptic_curve::{Field, PrimeField},
    Scalar,
};
use serde_json::Value;
use sha2::Sha512;
use solana_derivation_path::DerivationPath;
use solana_seed_phrase::generate_seed_from_seed_phrase_and_passphrase;
use zolana_keypair::{
    derivation::{ed25519_derivation_message, expand_roles},
    Curve, NullifierKey, ShieldedKeypair, SigningKey, ViewingKey,
};

const TSPP_COIN_TYPE: u32 = 1_392_955_331;
const NIST256P1_MASTER_HMAC_KEY: &[u8] = b"Nist256p1 seed";

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

fn assert_expanded_roles(section: &Value, seed: &[u8], curve: Curve) {
    let (nullifier, viewing) = expand_roles(seed, curve).expect("role expansion succeeds");
    assert_eq!(
        hex::encode(nullifier.secret()),
        text(&section["nullifier_secret"])
    );
    assert_eq!(
        hex::encode(nullifier.pubkey().expect("nullifier public key")),
        text(&section["nullifier_pubkey"])
    );
    assert_eq!(
        hex::encode(viewing.secret_bytes().as_slice()),
        text(&section["viewing_secret"])
    );
    assert_eq!(
        hex::encode(viewing.pubkey().as_bytes()),
        text(&section["viewing_pubkey"])
    );
}

#[test]
fn candidate_matches_frozen_key_derivation() {
    let vectors: Value = serde_json::from_str(include_str!("../test-vectors/key_derivation.json"))
        .expect("key derivation vectors are valid JSON");

    let ed25519 = &vectors["ed25519_rail"];
    let signing = SigningKey::from_ed25519_bytes(&decode(&ed25519["signing_secret"]));
    let signer_pubkey = signing
        .pubkey()
        .as_ed25519()
        .expect("ed25519 signing public key");
    assert_eq!(hex::encode(signer_pubkey), text(&ed25519["signer_pubkey"]));
    assert_eq!(
        hex::encode(ed25519_derivation_message(&signer_pubkey)),
        text(&ed25519["derivation_message"])
    );
    let seed = signing.derivation_seed().expect("ed25519 derivation seed");
    assert_eq!(
        hex::encode(seed.as_slice()),
        text(&ed25519["derivation_seed"])
    );
    assert_expanded_roles(ed25519, &seed, Curve::Ed25519);

    let p256 = &vectors["p256_rail"];
    let signing =
        SigningKey::from_p256_bytes(&decode(&p256["signing_secret"])).expect("P-256 signing key");
    let seed = signing.derivation_seed().expect("P-256 derivation seed");
    assert_eq!(hex::encode(seed.as_slice()), text(&p256["derivation_seed"]));
    assert_expanded_roles(p256, &seed, Curve::P256);

    let keypair = ShieldedKeypair::from_keypair(signing).expect("P-256 shielded keypair");
    assert_eq!(
        hex::encode(
            keypair
                .nullifier_key
                .pubkey()
                .expect("nullifier public key")
        ),
        text(&p256["nullifier_pubkey"])
    );
}

fn solana_path(account: u32) -> String {
    format!("m/44'/501'/{account}'/0'")
}

fn tspp_path(account: u32, role: u32) -> String {
    format!("m/44'/{TSPP_COIN_TYPE}'/{account}'/{role}'/0'")
}

fn derive_ed25519_node(seed: &[u8], path: &str) -> [u8; 32] {
    let path = DerivationPath::from_absolute_path_str(path).expect("valid derivation path");
    ExtendedSigningKey::from_seed(seed)
        .expect("root node from seed")
        .derive(&path)
        .expect("hardened derivation")
        .signing_key
        .to_bytes()
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts this key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn split_digest(digest: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let (left, right) = digest.split_at(32);
    (
        left.try_into().expect("32-byte digest half"),
        right.try_into().expect("32-byte digest half"),
    )
}

fn nist256p1_master(seed: &[u8]) -> (Scalar, [u8; 32]) {
    let mut digest = hmac_sha512(NIST256P1_MASTER_HMAC_KEY, seed);
    loop {
        let (key_bytes, chain) = split_digest(&digest);
        let key: Option<Scalar> = Scalar::from_repr(key_bytes.into()).into();
        if let Some(key) = key.filter(|scalar| !bool::from(scalar.is_zero())) {
            return (key, chain);
        }
        digest = hmac_sha512(NIST256P1_MASTER_HMAC_KEY, &digest);
    }
}

fn nist256p1_hardened_child(key: &Scalar, chain: &[u8; 32], index: u32) -> (Scalar, [u8; 32]) {
    let hardened = (0x8000_0000u32 + index).to_be_bytes();
    let mut data = Vec::with_capacity(37);
    data.push(0);
    data.extend_from_slice(&key.to_bytes());
    data.extend_from_slice(&hardened);
    loop {
        let digest = hmac_sha512(chain, &data);
        let (tweak_bytes, child_chain) = split_digest(&digest);
        let tweak: Option<Scalar> = Scalar::from_repr(tweak_bytes.into()).into();
        if let Some(tweak) = tweak {
            let child_key = tweak + key;
            if !bool::from(child_key.is_zero()) {
                return (child_key, child_chain);
            }
        }
        data.clear();
        data.push(1);
        data.extend_from_slice(&child_chain);
        data.extend_from_slice(&hardened);
    }
}

fn derive_p256_node(seed: &[u8], path: &[u32]) -> [u8; 32] {
    let (mut key, mut chain) = nist256p1_master(seed);
    for &index in path {
        (key, chain) = nist256p1_hardened_child(&key, &chain, index);
    }
    key.to_bytes().into()
}

fn nullifier_secret(node: &[u8; 32]) -> [u8; 31] {
    node[1..].try_into().expect("31-byte nullifier secret")
}

#[test]
fn candidate_matches_frozen_seed_based_keypairs() {
    let vectors: Value =
        serde_json::from_str(include_str!("../test-vectors/seed_based_keypair.json"))
            .expect("seed-based vectors are valid JSON");
    let seed = generate_seed_from_seed_phrase_and_passphrase(text(&vectors["mnemonic"]), "");

    for expected in vectors["accounts"]
        .as_array()
        .expect("accounts is an array")
    {
        let account = u32::try_from(
            expected["account"]
                .as_u64()
                .expect("account is an unsigned integer"),
        )
        .expect("account fits u32");
        let signing_secret = derive_ed25519_node(&seed, &solana_path(account));
        let nullifier_secret =
            nullifier_secret(&derive_ed25519_node(&seed, &tspp_path(account, 1)));
        let viewing_secret = derive_p256_node(&seed, &[44, TSPP_COIN_TYPE, account, 2, 0]);

        assert_eq!(
            hex::encode(signing_secret),
            text(&expected["signing_secret"])
        );
        assert_eq!(
            hex::encode(nullifier_secret),
            text(&expected["nullifier_secret"])
        );
        assert_eq!(
            hex::encode(viewing_secret),
            text(&expected["viewing_secret"])
        );

        let signing = SigningKey::from_ed25519_bytes(&signing_secret);
        let nullifier = NullifierKey::from_secret(nullifier_secret);
        let viewing = ViewingKey::from_bytes(&viewing_secret).expect("P-256 viewing key");
        assert_eq!(
            hex::encode(
                signing
                    .pubkey()
                    .as_ed25519()
                    .expect("ed25519 signing public key")
            ),
            text(&expected["signing_pubkey"])
        );
        assert_eq!(
            hex::encode(nullifier.pubkey().expect("nullifier public key")),
            text(&expected["nullifier_pubkey"])
        );
        assert_eq!(
            hex::encode(viewing.pubkey().as_bytes()),
            text(&expected["viewing_pubkey"])
        );
    }
}
