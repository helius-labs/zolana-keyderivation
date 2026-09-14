# zolana-keyderivation

This repository checks whether a Zolana revision derives the same wallet keys as the pinned `release/dev-v2` baseline.

The tests own their expected bytes. Separate suites load `zolana-keypair` from a sibling Zolana checkout and check the Ed25519 and P-256 rails byte for byte. The seed suite derives child secrets locally, then checks the candidate Zolana key constructors and public keys. It does not exercise a candidate mnemonic-to-child-key implementation.

## Run

Clone both repositories into the same directory:

```bash
git clone https://github.com/helius-labs/zolana
git clone https://github.com/helius-labs/zolana-keyderivation
git -C zolana checkout <release-tag-or-sha>
cd zolana
cargo test --manifest-path ../zolana-keyderivation/Cargo.toml
```

Running from the Zolana directory selects the candidate's Rust toolchain. Run individual suites with:

```bash
cargo test --manifest-path ../zolana-keyderivation/Cargo.toml --test eddsa_signature
cargo test --manifest-path ../zolana-keyderivation/Cargo.toml --test p256_key_exchange
cargo test --manifest-path ../zolana-keyderivation/Cargo.toml --test seed
```

CI accepts a Zolana tag or full SHA through `workflow_dispatch`.

## Tests

The three suites run 31 named cryptographic cases: 10 Ed25519, 13 P-256, and 8 seed/SLIP-10 cases. Additional tests check fixture format and case inventory. Failures identify the suite, case ID, and mismatched output field or error.

Role keys are the nullifier and viewing keys. Valid signing cases check the derivation seed and both role secrets/public keys, including the keys assembled by `ShieldedKeypair::from_keypair`. Ed25519 cases also check the signer public key and wrapped derivation message.

### Ed25519

Fixtures: [ed25519.json](test-vectors/ed25519.json).

| Case | What it checks |
| --- | --- |
| `ed25519_baseline` | Existing deployed Ed25519 derivation bytes remain unchanged. |
| `ed25519_zero_seed` | A 32-byte all-zero signing seed derives the expected keys. |
| `ed25519_ff_seed` | A 32-byte all-`ff` signing seed derives the expected keys. |
| `ed25519_ascending_seed` | Signing-seed bytes `00`–`1f` derive the expected keys. |
| `ed25519_expand_zero` | A 64-byte all-zero derivation seed expands to the expected role keys. |
| `ed25519_expand_ff` | A 64-byte all-`ff` derivation seed expands to the expected role keys. |
| `ed25519_expand_empty` | An empty derivation seed is rejected. |
| `ed25519_expand_short` | A 63-byte derivation seed is rejected. |
| `ed25519_expand_long` | A 65-byte derivation seed is rejected. |
| `ed25519_expand_p256_length` | A 32-byte derivation seed is rejected on the Ed25519 rail. |

### P-256

Fixtures: [p256.json](test-vectors/p256.json). `n` is the P-256 group order. Private scalars are 32-byte big-endian values.

| Case | What it checks |
| --- | --- |
| `p256_baseline` | Existing deployed P-256 derivation bytes remain unchanged. |
| `p256_scalar_one` | Scalar `1` derives the expected keys. |
| `p256_scalar_n_minus_one` | Scalar `n−1` derives the expected keys. |
| `p256_scalar_zero` | Scalar `0` is rejected with `InvalidSecretKey`. |
| `p256_scalar_n` | Scalar `n` is rejected with `InvalidSecretKey`. |
| `p256_scalar_n_plus_one` | Scalar `n+1` is rejected with `InvalidSecretKey`. |
| `p256_scalar_max` | The maximum 256-bit scalar is rejected with `InvalidSecretKey`. |
| `p256_expand_zero` | A 32-byte all-zero derivation seed expands to the expected role keys. |
| `p256_expand_ff` | A 32-byte all-`ff` derivation seed expands to the expected role keys. |
| `p256_expand_empty` | An empty derivation seed is rejected. |
| `p256_expand_short` | A 31-byte derivation seed is rejected. |
| `p256_expand_long` | A 33-byte derivation seed is rejected. |
| `p256_expand_ed25519_length` | A 64-byte derivation seed is rejected on the P-256 rail. |

All invalid expansion lengths check `InvalidDerivationSeed`, including the actual and required lengths. Correctly sized zero/`ff` expansion inputs test the KDF contract; they do not establish that those bytes came from a signer. P-256 scalars `1` and `n−1` yield the same ECDH x-coordinate and therefore the same derivation seed and role keys.

### Seed derivation

Fixtures: [seed_based_keypair.json](test-vectors/seed_based_keypair.json) and [slip10.json](test-vectors/slip10.json). Account cases use the same test mnemonic and an empty passphrase. SLIP-10 cases check the local P-256 derivation algorithm against published private keys and chain codes.

| Case | What it checks |
| --- | --- |
| `seed_account_0` | The existing mnemonic derives the expected account `0` keys. |
| `seed_account_1` | The existing mnemonic derives the expected account `1` keys. |
| `seed_account_max` | The existing mnemonic derives the expected account `2147483647` keys. |
| `slip10_master_short` | A published 16-byte seed produces the expected master key and chain code. |
| `slip10_master_long` | A published 64-byte seed produces the expected master key and chain code. |
| `slip10_master_retry` | Master-key retry produces the published final key and chain code. |
| `slip10_child_zero` | Hardened child `0` matches the published key and chain code. |
| `slip10_child_retry` | Hardened child `28578` exercises retry and matches the published result. |

### Fixture checks

The seed suite also checks the 31-case inventory and unique IDs across all fixtures. Fixture validation rejects malformed or odd-length hex, incorrect fixed widths, missing output fields, unknown fields, duplicate IDs, empty case lists, and account/child indices above `2147483647`.

Owner and compressed-address hashes, encryption, and signing/ECDH guards are outside this compatibility boundary.

## Expected bytes

Fixtures contain lowercase hex with leading zeros preserved. Each named case specifies its input and either fixed outputs or a specific error. Tests never generate or rewrite expected bytes.

New outputs must agree between the pinned Rust baseline and the independent Noble/circomlibjs reference. Published SLIP-10 cases must also match their source. See [vector provenance and reproduction commands](test-vectors/README.md).
