# Partner submissions

Open a pull request that adds `submissions/<org-or-name>/key_derivation.json` with the same shape as zolana's `test-vectors/key_derivation.json`.

CI compares these `ed25519_rail` fields to the `release/dev-v2` pin (`51f70d529f9b51a1da6e4f5f43221895d6009adc`):

- `derivation_message`
- `derivation_seed`
- `nullifier_secret`
- `nullifier_pubkey`
- `viewing_secret`
- `viewing_pubkey`

Equal strings pass. CI reads JSON; it does not execute the submitted file.

You can also open an issue and attach the JSON.
