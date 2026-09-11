# zolana-keyderivation

Byte copies of Zolana wallet key-derivation fixtures. CI `cmp`s them to [helius-labs/zolana](https://github.com/helius-labs/zolana) and re-runs zolana's keypair and TypeScript tests at those SHAs.

A Solana signer expands to a derivation seed, then nullifier and viewing keys, then the owner hashes the proof uses. Drift at any step is a different registry identity.

The JSON records one toy secret and the bytes derived from it. Sign `ed25519_derivation_message(pubkey)` and check the signature and keys against the file. That is wallet math. Program, prover, and Photon have their own tests.

## Pins

Each pin is `git show <sha>:<path>` of six files. Job `copy-honest` runs `cmp pins/<sha>/file zolana/<file>` at that SHA.

| Short SHA | Full SHA | Branch |
| --- | --- | --- |
| `51f70d52` | `51f70d529f9b51a1da6e4f5f43221895d6009adc` | `release/dev-v2` (deployed) |
| `529c6ce0` | `529c6ce0e31abd1c2821421c67e187f77e3256a6` | `main` |

`derivation_message` and `derivation_seed` match across pins. `owner_*` hashes differ. Compare a pin to zolana at that SHA.

- `test-vectors/key_derivation.json`
- `sdk-libs/keypair/tests/vectors.rs`
- `sdk-libs/keypair/tests/cases/derivation.rs`
- `sdk-libs/keypair/tests/seed_based_keypair.rs`
- `sdk-libs/ts/test/key-derivation-vectors.test.ts`
- `sdk-libs/ts/test/seed-based-keypair.test.ts`

## Second test

Checkout zolana at the pin SHA and run:

```bash
git clone https://github.com/helius-labs/zolana
cd zolana
git checkout 51f70d529f9b51a1da6e4f5f43221895d6009adc   # or 529c6ce0e31abd1c2821421c67e187f77e3256a6
cargo nextest run -p zolana-keypair
npm ci
npm run test --workspace @heliuslabs/zolana
```

`mirror-zolana` is that checkout and those commands. `copy-honest` `cmp`s this repo's copies to the same SHA.

Workflow `gate` with `workflow_dispatch` (optional `sha`) `cmp`s the main-pin JSON to a candidate zolana revision.

## Spec

[`docs/derivation-v1.md`](docs/derivation-v1.md) copies zolana `docs/spec.md` lines 303-548 (`## Owner Hash` through `## PDA`) at `529c6ce0e31abd1c2821421c67e187f77e3256a6`.

Source: [docs/spec.md at 529c6ce0e](https://github.com/helius-labs/zolana/blob/529c6ce0e31abd1c2821421c67e187f77e3256a6/docs/spec.md).

## Partner submissions

Add `submissions/<org-or-name>/key_derivation.json` in a PR. CI compares `ed25519_rail` message, seed, and nullifier/viewing keys to the `release/dev-v2` pin. See [`submissions/README.md`](submissions/README.md).
