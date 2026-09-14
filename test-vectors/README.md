# Vector provenance

The expected bytes belong to this repository. Candidate tests read them without regenerating them.

## Sources

- **Compatibility baseline:** Zolana [`51f70d529f9b51a1da6e4f5f43221895d6009adc`](https://github.com/helius-labs/zolana/tree/51f70d529f9b51a1da6e4f5f43221895d6009adc).
- **Existing cases:** `ed25519_baseline`, `p256_baseline`, `seed_account_0`, and `seed_account_1` preserve every original input/output value from this repository's commit `2e861e654cd21efefd678a07eecfde0e54ef3e5f`.
- **SLIP-10 source:** [`slip-0010.md` at `570ed55b7fde158f1116be34fc2faa35dada5912`](https://github.com/satoshilabs/slips/blob/570ed55b7fde158f1116be34fc2faa35dada5912/slip-0010.md). The master cases come from P-256 test vectors 1 and 2 and the seed-retry example. The child cases use vector 1's `m/0H` and the derivation-retry example's `m/28578H`. Private keys and chain codes match the published text.
- **Independent reference:** `@noble/curves` 2.4.0, `@noble/hashes` 2.4.0, and `circomlibjs` 0.1.7. Direct versions and transitive dependencies are pinned in [the reference package lock](../tools/reference/package-lock.json). The script imports no Zolana code.

All 31 cases were checked against the independent reference. The four original cases were compared with their original values, and all five SLIP-10 cases were checked against the pinned publication. The reference verifies 19 successful cases and 12 expected-error cases.

## Format

Every case has `id`, `description`, `input`, and `expected`. Successful expectations use `{"status":"ok","outputs":{...}}`; errors use `{"status":"error","error":{"kind":...}}`. `invalid_derivation_seed` errors also specify `got` and `expected` byte lengths. IDs are unique across all four JSON files. Rust types reject unknown fields, malformed hex, incorrect fixed widths, and missing required fields.

| Value | Encoding |
| --- | --- |
| Hex strings | Lowercase, even length, no prefix or separators; preserve leading zeros |
| Ed25519 signing secret/public key | 32 raw bytes |
| Ed25519 derivation seed | 64-byte RFC 8032 signature over the wrapped message |
| P-256 private scalar / derivation seed | 32 bytes, big-endian / ECDH x-coordinate |
| Nullifier secret | 31 bytes; left-pad with one zero byte for the Poseidon input |
| Nullifier public key | One-input Circom-compatible BN254 Poseidon result, 32-byte big-endian |
| Viewing secret/public key | 32-byte P-256 scalar / 33-byte compressed SEC1 point |
| SLIP-10 chain code | 32 bytes |
| Account/child index | Unsigned integer below `2^31`; the hardened bit is added by the derivation helper |

The reference constructs the Ed25519 message from the off-chain envelope and `TSPP/derive/v1`, signs it with Noble, and expands the role secrets with HKDF-SHA256. The P-256 rail uses the fixed `P_DERIVE_SEC1` point from the baseline and its ECDH x-coordinate. The 48-byte viewing-key HKDF output is reduced as a big-endian integer modulo the P-256 group order. Nullifier public keys use circomlibjs Poseidon rather than Zolana's Rust hasher.

Seed-account derivation uses PBKDF2-HMAC-SHA512 with 2048 iterations and the following hardened paths:

- Signing: `m/44'/501'/account'/0'` on Ed25519.
- Nullifier: `m/44'/1392955331'/account'/1'/0'` on Ed25519, dropping the first secret byte.
- Viewing: `m/44'/1392955331'/account'/2'/0'` on P-256.

These seed cases use an ASCII mnemonic and an empty passphrase. They do not test mnemonic validation or a production mnemonic-recovery API.

## Reproduce baseline outputs

Use a clean sibling Zolana checkout at the exact baseline revision. From this repository:

```bash
git -C ../zolana checkout 51f70d529f9b51a1da6e4f5f43221895d6009adc
vector_export_dir=$(mktemp -d)
cargo +1.97.0 run --example export_baseline -- "$vector_export_dir/vectors"
```

The exporter requires the baseline revision and an unchanged tracked working tree. It reads the fixture inputs and writes proposed outputs into a new directory. Existing output directories are rejected, so it cannot overwrite the committed fixture directory. The exporter shares the local seed helpers with the Rust tests; it is not the independent reference.

Verify that exported outputs agree with the separate implementation:

```bash
npm --prefix tools/reference ci --ignore-scripts --no-audit --no-fund
node tools/reference/verify-vectors.mjs "$vector_export_dir/vectors"
```

Verify the committed fixtures directly:

```bash
npm --prefix tools/reference run verify
```

Baseline export and verification used Rust 1.97.0 and Node 25.9.0. The reference dependencies require Node 20.19 or newer. Node is needed only for independent verification; the compatibility workflow runs Rust tests.

## Adding or changing cases

Add inputs with an ID that names the boundary and a description that states its purpose. Generate proposed outputs from the pinned baseline, compare every field with the independent reference, then review the fixture diff before accepting it. A mismatch requires investigation; do not change expected bytes to make a candidate pass. Keep existing compatibility outputs unchanged unless an intentional baseline migration is explicitly reviewed.

For standard-algorithm cases, copy the published expected bytes and record the exact source revision. The normal test run must never invoke a generator or update the fixture files.

## Validation

All 31 cases and the fixture-format/inventory checks pass against both revisions:

| Zolana revision | Rust toolchain |
| --- | --- |
| `51f70d529f9b51a1da6e4f5f43221895d6009adc` | 1.97.0 |
| `68570938d3a0ef6e5d986244981418e1758e5b58` | 1.98.1 |

Acceptance checks temporarily changed one expected output byte in each fixture family, one expected error variant, and one expected error length. All six changes caused the corresponding test to fail with its case ID; output mismatches also identified the field. The original fixtures were restored afterward.
