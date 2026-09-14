// Each integration-test binary uses a different subset of this shared support code.
#![allow(dead_code)]

pub mod fixtures;
pub mod seed;

use fixtures::*;
use p256::{elliptic_curve::PrimeField, Scalar};
use solana_seed_phrase::generate_seed_from_seed_phrase_and_passphrase;
use zolana_keypair::{
    derivation::{ed25519_derivation_message, expand_roles},
    Curve, KeypairError, NullifierKey, ShieldedKeypair, SigningKey, ViewingKey,
};

pub fn roles(nullifier: &NullifierKey, viewing: &ViewingKey) -> Result<RoleOutput, KeypairError> {
    Ok(RoleOutput {
        nullifier_secret: Hex(*nullifier.secret()),
        nullifier_pubkey: Hex(nullifier.pubkey()?),
        viewing_secret: Hex(*viewing.secret_bytes()),
        viewing_pubkey: Hex(*viewing.pubkey().as_bytes()),
    })
}

pub fn expansion(input: &ExpansionInput, curve: Curve) -> Result<RoleOutput, KeypairError> {
    let (nullifier, viewing) = expand_roles(&input.seed.0, curve)?;
    roles(&nullifier, &viewing)
}

fn derived_roles(
    signing: SigningKey,
    context: &str,
) -> Result<(Vec<u8>, RoleOutput), KeypairError> {
    let seed = signing.derivation_seed()?.to_vec();
    let (nullifier, viewing) = expand_roles(&seed, signing.curve())?;
    let outputs = roles(&nullifier, &viewing)?;
    let keypair = ShieldedKeypair::from_keypair(signing)?;
    let assembled = roles(&keypair.nullifier_key, &keypair.viewing_key)?;
    assert_outputs(
        &format!("{context}: assembled keypair"),
        &assembled,
        &outputs,
    );
    Ok((seed, outputs))
}

pub fn ed25519(input: &SigningInput, context: &str) -> Result<Ed25519Output, KeypairError> {
    let signing = SigningKey::from_ed25519_bytes(&input.signing_secret.0);
    let signer_pubkey = signing.pubkey().as_ed25519()?;
    let derivation_message = Bytes(ed25519_derivation_message(&signer_pubkey));
    let (seed, roles) = derived_roles(signing, context)?;
    Ok(Ed25519Output {
        signer_pubkey: Hex(signer_pubkey),
        derivation_message,
        derivation_seed: Hex(seed
            .try_into()
            .unwrap_or_else(|_| panic!("{context}: derivation_seed: expected 64 bytes"))),
        nullifier_secret: roles.nullifier_secret,
        nullifier_pubkey: roles.nullifier_pubkey,
        viewing_secret: roles.viewing_secret,
        viewing_pubkey: roles.viewing_pubkey,
    })
}

pub fn p256(input: &SigningInput, context: &str) -> Result<P256Output, KeypairError> {
    let signing = SigningKey::from_p256_bytes(&input.signing_secret.0)?;
    let (seed, roles) = derived_roles(signing, context)?;
    Ok(P256Output {
        derivation_seed: Hex(seed
            .try_into()
            .unwrap_or_else(|_| panic!("{context}: derivation_seed: expected 32 bytes"))),
        nullifier_secret: roles.nullifier_secret,
        nullifier_pubkey: roles.nullifier_pubkey,
        viewing_secret: roles.viewing_secret,
        viewing_pubkey: roles.viewing_pubkey,
    })
}

pub fn seed_account(input: &SeedInput) -> Result<SeedOutput, KeypairError> {
    assert!(input.account < 0x8000_0000, "account must be below 2^31");
    let root = generate_seed_from_seed_phrase_and_passphrase(&input.mnemonic, &input.passphrase);
    let signing_secret = seed::derive_ed25519_node(&root, &seed::solana_path(input.account));
    let nullifier_secret = seed::nullifier_secret(&seed::derive_ed25519_node(
        &root,
        &seed::tspp_path(input.account, 1),
    ));
    let viewing_secret =
        seed::derive_p256_node(&root, &[44, seed::TSPP_COIN_TYPE, input.account, 2, 0]);
    let signing = SigningKey::from_ed25519_bytes(&signing_secret);
    let nullifier = NullifierKey::from_secret(nullifier_secret);
    let viewing = ViewingKey::from_bytes(&viewing_secret)?;
    Ok(SeedOutput {
        signing_secret: Hex(signing_secret),
        signing_pubkey: Hex(signing.pubkey().as_ed25519()?),
        nullifier_secret: Hex(nullifier_secret),
        nullifier_pubkey: Hex(nullifier.pubkey()?),
        viewing_secret: Hex(viewing_secret),
        viewing_pubkey: Hex(*viewing.pubkey().as_bytes()),
    })
}

pub fn master(input: &ExpansionInput) -> Result<NodeOutput, KeypairError> {
    let (key, chain) = seed::nist256p1_master(&input.seed.0);
    Ok(NodeOutput {
        private_key: Hex(key.to_bytes().into()),
        chain_code: Hex(chain),
    })
}

pub fn child(input: &ChildInput) -> Result<NodeOutput, KeypairError> {
    let key = Option::<Scalar>::from(Scalar::from_repr(input.parent_key.0.into()))
        .ok_or(KeypairError::InvalidSecretKey)?;
    let (key, chain) = seed::nist256p1_hardened_child(&key, &input.parent_chain.0, input.index);
    Ok(NodeOutput {
        private_key: Hex(key.to_bytes().into()),
        chain_code: Hex(chain),
    })
}
