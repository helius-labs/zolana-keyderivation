use ed25519_dalek_bip32::ExtendedSigningKey;
use hkdf::hmac::{Hmac, Mac};
use p256::{
    elliptic_curve::{Field, PrimeField},
    Scalar,
};
use sha2::Sha512;
use solana_derivation_path::DerivationPath;

pub const TSPP_COIN_TYPE: u32 = 1_392_955_331;
const NIST256P1_MASTER_HMAC_KEY: &[u8] = b"Nist256p1 seed";

pub fn solana_path(account: u32) -> String {
    format!("m/44'/501'/{account}'/0'")
}

pub fn tspp_path(account: u32, role: u32) -> String {
    format!("m/44'/{TSPP_COIN_TYPE}'/{account}'/{role}'/0'")
}

pub fn derive_ed25519_node(seed: &[u8], path: &str) -> [u8; 32] {
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

pub fn nist256p1_master(seed: &[u8]) -> (Scalar, [u8; 32]) {
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

pub fn nist256p1_hardened_child(key: &Scalar, chain: &[u8; 32], index: u32) -> (Scalar, [u8; 32]) {
    assert!(index < 0x8000_0000, "child index must be below 2^31");
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

pub fn derive_p256_node(seed: &[u8], path: &[u32]) -> [u8; 32] {
    let (mut key, mut chain) = nist256p1_master(seed);
    for &index in path {
        (key, chain) = nist256p1_hardened_child(&key, &chain, index);
    }
    key.to_bytes().into()
}

pub fn nullifier_secret(node: &[u8; 32]) -> [u8; 31] {
    node[1..].try_into().expect("31-byte nullifier secret")
}
