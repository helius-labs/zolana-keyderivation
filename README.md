# zolana-keyderivation

This repository checks whether a Zolana revision derives the same wallet keys as the deployed `release/dev-v2` version.

The tests own their expected bytes. Separate tests load `zolana-keypair` from a sibling Zolana checkout and check the Ed25519 and P-256 rails byte for byte. The seed-phrase test derives child secrets locally, then checks the candidate Zolana key constructors and public keys. It does not exercise a candidate mnemonic-to-child-key implementation.

## Run

Clone both repositories into the same directory:

```bash
git clone https://github.com/helius-labs/zolana
git clone https://github.com/helius-labs/zolana-keyderivation
git -C zolana checkout <release-tag-or-sha>
cd zolana-keyderivation
cargo test
```

CI accepts a Zolana tag or full SHA through `workflow_dispatch`.

The three compatibility tests cover the derivation message, derivation seed, nullifier keys, viewing keys, and seed-phrase child keys. Owner and compressed-address hashes are tested by Zolana because those values depend on circuit hashing rather than wallet key derivation.
