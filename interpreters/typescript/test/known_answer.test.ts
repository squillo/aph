/**
 * WHY THIS FILE EXISTS: every constant in `testkit/vectors.ts` is asserted to
 * come from an RFC, and an assertion in a comment is not evidence. These are
 * known-answer tests: they sign the RFC's own message with the RFC's own seed
 * and compare against the RFC's own signature. If a hex digit were mistyped,
 * every downstream test would fail in a confusing place; here it fails in the
 * one place that names the document to check.
 *
 * WHAT THEY PIN: that the RFC 8032 §7.1 seed/public-key/message/signature
 * quadruples are transcribed correctly AND that SubtleCrypto's Ed25519
 * implements RFC 8032 — the platform rung law 12 rests on. Plus the two
 * SubtleCrypto behaviours this implementation depends on and does not control:
 * Ed25519 determinism, and ECDSA's LACK of it.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { bytesEqual, bytesToHex } from '../src/baseenc.js';
import { sha256, signEd25519, signEs256, verifyEd25519, verifyEs256 } from '../src/webcrypto.js';
import {
  ED25519_VECTORS,
  RFC8032_TEST_2,
  ed25519SigningKey,
  ed25519VerifyingKey,
  p256SigningKey,
  p256VerifyingKey,
} from '../testkit/vectors.js';

for (const vector of ED25519_VECTORS) {
  test(`${vector.name}: signing the RFC's message reproduces the RFC's signature`, async () => {
    const signing = await ed25519SigningKey(vector);
    const produced = await signEd25519(signing, vector.message);
    assert.equal(bytesToHex(produced), bytesToHex(vector.signature));
  });

  test(`${vector.name}: the RFC's signature verifies under the RFC's public key`, async () => {
    const verifying = await ed25519VerifyingKey(vector);
    assert.equal(await verifyEd25519(verifying, vector.signature, vector.message), true);
  });

  test(`${vector.name}: a one-bit change to the signature is rejected`, async () => {
    const verifying = await ed25519VerifyingKey(vector);
    const tampered = Uint8Array.from(vector.signature);
    tampered[0] = (tampered[0] as number) ^ 0x01;
    assert.equal(await verifyEd25519(verifying, tampered, vector.message), false);
  });
}

test('Ed25519 is DETERMINISTIC, which is what makes a committed cross-implementation artifact possible', async () => {
  // RFC 8032 derives the nonce from the key and the message, so two signings
  // agree byte for byte. The whole (<-) direction of the cross-verification
  // bar depends on this and on nothing else.
  const key = await ed25519SigningKey(RFC8032_TEST_2);
  const message = new TextEncoder().encode('the same message, signed twice');
  const first = await signEd25519(key, message);
  const second = await signEd25519(key, message);
  assert.ok(bytesEqual(first, second));
});

test('WebCrypto ECDSA is RANDOMIZED, which is why no ES256 artifact is committed', async () => {
  // SubtleCrypto exposes no RFC 6979 deterministic mode. Two signings of one
  // message with one key differ, so an ES256 envelope minted here cannot be
  // byte-pinned. This test exists so that scope limit is a measured fact in
  // the suite rather than a claim in a README — and so that a future platform
  // that DID become deterministic would be noticed rather than assumed.
  const key = await p256SigningKey();
  const message = new TextEncoder().encode('the same message, signed twice');
  const first = await signEs256(key, message);
  const second = await signEs256(key, message);
  assert.equal(first.length, 64, 'SubtleCrypto returns IEEE P1363 r||s, not DER');
  assert.equal(bytesEqual(first, second), false);
  // Both still verify: randomized does not mean unreliable.
  const verifying = await p256VerifyingKey();
  assert.equal(await verifyEs256(verifying, first, message), true);
  assert.equal(await verifyEs256(verifying, second, message), true);
});

test('the RFC 6979 A.2.5 public point imports from its COMPRESSED SEC1 form', async () => {
  // A did:key carries the compressed point (§8.4.3) and WebCrypto's `raw` EC
  // import wants the uncompressed one. This pins that the SPKI wrapper in
  // `src/webcrypto.ts` gets the platform to decompress it — the reason this
  // implementation never computes a modular square root.
  const signing = await p256SigningKey();
  const verifying = await p256VerifyingKey();
  const message = new TextEncoder().encode('compressed-point import');
  assert.equal(await verifyEs256(verifying, await signEs256(signing, message), message), true);
});

test('SHA-256 of the empty string is the digest the corpus uses as its anchor', async () => {
  // Named because the eight SHAPE-ONLY fixtures (the NotaryAttested
  // placeholders) carry exactly this value; a reader meeting it there should
  // be able to find out here what it is. The class is named rather than a
  // bare count asserted, because the signed golden also carried this digest
  // until the body-hash vector landed — a frozen number here would have been
  // true or false depending on which lane landed first.
  assert.equal(
    bytesToHex(await sha256(new Uint8Array(0))),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
});
