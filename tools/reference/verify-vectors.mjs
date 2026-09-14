import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { buildPoseidon } from 'circomlibjs';

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const COIN_TYPE = 1392955331;
const P_DERIVE = bytes('039ef16592429da1403eaa29058eb7d9d5ad15a2ea557174f7b01ff7fe484eeeaf');
const poseidon = await buildPoseidon();

function bytes(value) {
  assert.match(value, /^(?:[0-9a-f]{2})*$/, 'expected lowercase byte hex');
  return Uint8Array.from(Buffer.from(value, 'hex'));
}
function hex(value) { return Buffer.from(value).toString('hex'); }
function utf8(value) { return new TextEncoder().encode(value); }
function concat(...parts) { return Uint8Array.from(Buffer.concat(parts)); }
function integer(value) { return BigInt(`0x${hex(value)}`); }
function scalarBytes(value) { return bytes(value.toString(16).padStart(64, '0')); }
function hmac512(key, data) { return hmac(sha512, key, data); }
function success(outputs) { return { status: 'ok', outputs }; }
function failure(error) { return { status: 'error', error }; }

function roleOutputs(nullifier, viewing) {
  const publicNullifier = poseidon.F.toObject(poseidon([integer(nullifier)]));
  return {
    nullifier_secret: hex(nullifier),
    nullifier_pubkey: hex(scalarBytes(publicNullifier)),
    viewing_secret: hex(viewing),
    viewing_pubkey: hex(p256.getPublicKey(viewing, true)),
  };
}

function expand(seed, rail) {
  const expected = rail === 'ed25519' ? 64 : 32;
  if (seed.length !== expected) {
    return failure({ kind: 'invalid_derivation_seed', got: seed.length, expected });
  }
  const tag = rail === 'ed25519' ? 'ed25519' : 'ecdh';
  const nullifier = hkdf(sha256, seed, undefined, utf8(`TSPP/nf_key/${tag}/v1`), 31);
  const wide = hkdf(sha256, seed, undefined, utf8(`TSPP/view_key/${tag}/v1`), 48);
  // Rust's scalar_from_okm reduces the 48-byte big-endian integer modulo n.
  const viewing = scalarBytes(integer(wide) % N);
  assert.notEqual(integer(viewing), 0n, 'fixture must not derive a zero viewing scalar');
  return success(roleOutputs(nullifier, viewing));
}

function deriveSigning(input, rail) {
  const secret = bytes(input.signing_secret);
  assert.equal(secret.length, 32);
  if (rail === 'p256') {
    if (integer(secret) === 0n || integer(secret) >= N) {
      return failure({ kind: 'invalid_secret_key' });
    }
    const seed = p256.getSharedSecret(secret, P_DERIVE, true).slice(1);
    return success({ derivation_seed: hex(seed), ...expand(seed, rail).outputs });
  }
  const pubkey = ed25519.getPublicKey(secret);
  const payload = utf8('TSPP/derive/v1');
  const message = concat(
    Uint8Array.of(255), utf8('solana offchain'), Uint8Array.of(0), sha256(payload),
    Uint8Array.of(0, 1), pubkey, Uint8Array.of(payload.length, 0), payload,
  );
  const seed = ed25519.sign(message, secret);
  return success({
    signer_pubkey: hex(pubkey), derivation_message: hex(message), derivation_seed: hex(seed),
    ...expand(seed, rail).outputs,
  });
}

function hardenedIndex(index) {
  assert(Number.isInteger(index) && index >= 0 && index < 2 ** 31);
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, index + 2 ** 31, false);
  return result;
}

function master(seed, curve) {
  const label = utf8(curve === 'ed25519' ? 'ed25519 seed' : 'Nist256p1 seed');
  let digest = hmac512(label, seed);
  while (curve !== 'ed25519' && (integer(digest.slice(0, 32)) === 0n || integer(digest.slice(0, 32)) >= N)) {
    digest = hmac512(label, digest);
  }
  return { key: digest.slice(0, 32), chain: digest.slice(32) };
}

function child(parent, index, curve) {
  const suffix = hardenedIndex(index);
  let digest = hmac512(parent.chain, concat(Uint8Array.of(0), parent.key, suffix));
  for (;;) {
    const tweak = digest.slice(0, 32);
    const chain = digest.slice(32);
    if (curve === 'ed25519') return { key: tweak, chain };
    const result = (integer(tweak) + integer(parent.key)) % N;
    if (integer(tweak) < N && result !== 0n) return { key: scalarBytes(result), chain };
    digest = hmac512(parent.chain, concat(Uint8Array.of(1), chain, suffix));
  }
}

function derivePath(root, path, curve) {
  let node = master(root, curve);
  for (const index of path) node = child(node, index, curve);
  return node.key;
}

function seedAccount(input) {
  const root = pbkdf2(sha512, utf8(input.mnemonic.normalize('NFKD')), utf8(`mnemonic${input.passphrase.normalize('NFKD')}`), { c: 2048, dkLen: 64 });
  const signing = derivePath(root, [44, 501, input.account, 0], 'ed25519');
  const nullifier = derivePath(root, [44, COIN_TYPE, input.account, 1, 0], 'ed25519').slice(1);
  const viewing = derivePath(root, [44, COIN_TYPE, input.account, 2, 0], 'p256');
  return success({ signing_secret: hex(signing), signing_pubkey: hex(ed25519.getPublicKey(signing)), ...roleOutputs(nullifier, viewing) });
}

function nodeOutputs(node) {
  return success({ private_key: hex(node.key), chain_code: hex(node.chain) });
}

function check(cases, derive, context) {
  for (const test of cases) {
    const actual = derive(test.input);
    assert.deepEqual(actual, test.expected, `${context}/${test.id}`);
  }
  return cases.length;
}

const directory = process.argv[2] ? resolve(process.argv[2]) : fileURLToPath(new URL('../../test-vectors/', import.meta.url));
function read(name) { return JSON.parse(readFileSync(resolve(directory, name), 'utf8')); }
let count = 0;
for (const rail of ['ed25519', 'p256']) {
  const fixture = read(`${rail}.json`);
  count += check(fixture.derivation_cases, function (input) { return deriveSigning(input, rail); }, rail);
  count += check(fixture.role_expansion_cases, function (input) { return expand(bytes(input.seed), rail); }, rail);
}
count += check(read('seed_based_keypair.json').cases, seedAccount, 'seed');
const slip = read('slip10.json');
count += check(slip.master_cases, function (input) { return nodeOutputs(master(bytes(input.seed), 'p256')); }, 'slip10');
count += check(slip.child_cases, function (input) {
  return nodeOutputs(child({ key: bytes(input.parent_key), chain: bytes(input.parent_chain) }, input.index, 'p256'));
}, 'slip10');
assert.equal(count, 31, 'expected the complete 31-case fixture set');
console.log(`Verified ${count} cases with independent Noble/circomlibjs reference.`);
