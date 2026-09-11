# zolana-keyderivation

Frozen copies of Zolana wallet key-derivation fixtures, plus a second CI gate.

A wallet here is not one key. From a signer you get a derivation seed, then nullifier and viewing keys, then hashes the circuit sees. If any step drifts, the account still works locally but it is a different person on-chain.

These vectors freeze one toy secret and record the bytes after it. Rust, TypeScript, and an HSM that signs the same message can check they derive the same wallet, not a lookalike that still signs. They do not prove you match the deployed program, prover, or Photon.

## Pins

Each pin is a byte-for-byte `git show` of the six files from [helius-labs/zolana](https://github.com/helius-labs/zolana). `cmp` is per-pin: `pins/<sha>/file` versus zolana at that SHA. Do not treat the two pins' `key_derivation.json` as equal; `derivation_message` / `derivation_seed` match, `owner_*` hashes do not.

| Short SHA | Full SHA | Branch |
| --- | --- | --- |
| `51f70d52` | `51f70d529f9b51a1da6e4f5f43221895d6009adc` | `release/dev-v2` (current deployment) |
| `529c6ce0` | `529c6ce0e31abd1c2821421c67e187f77e3256a6` | `main` |

Files in each pin:

- `test-vectors/key_derivation.json`
- `sdk-libs/keypair/tests/vectors.rs`
- `sdk-libs/keypair/tests/cases/derivation.rs`
- `sdk-libs/keypair/tests/seed_based_keypair.rs`
- `sdk-libs/ts/test/key-derivation-vectors.test.ts`
- `sdk-libs/ts/test/seed-based-keypair.test.ts`

## Second test

The copied `.rs` / `.ts` files do not compile in this repo. Clone zolana at the pin SHA and run the same commands zolana already uses:

```bash
git clone https://github.com/helius-labs/zolana
cd zolana
git checkout 51f70d529f9b51a1da6e4f5f43221895d6009adc   # or 529c6ce0e31abd1c2821421c67e187f77e3256a6
cargo nextest run -p zolana-keypair
npm ci
npm run test --workspace @heliuslabs/zolana
```

CI job `mirror-zolana` does that checkout and those two test commands. Job `copy-honest` `cmp`s this repo's copies against the same SHA.

To check whether latest zolana `main` still matches the main pin JSON, run workflow `gate` with `workflow_dispatch` (optional input `sha`).

## Spec

[`docs/derivation-v1.md`](docs/derivation-v1.md) is a verbatim extract of zolana `docs/spec.md` lines 303-548 (`## Owner Hash` through end of `## PDA`) at `529c6ce0e31abd1c2821421c67e187f77e3256a6`.

Source: [docs/spec.md at 529c6ce0e](https://github.com/helius-labs/zolana/blob/529c6ce0e31abd1c2821421c67e187f77e3256a6/docs/spec.md).

## Partner submissions

Open a PR adding `submissions/<org-or-name>/key_derivation.json` with the same shape as zolana's file. CI compares `ed25519_rail` message, seed, and nullifier/viewing keys to the `release/dev-v2` pin. See [`submissions/README.md`](submissions/README.md). Issues are also fine if you send a gist instead.
