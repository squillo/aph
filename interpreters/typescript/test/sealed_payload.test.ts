/**
 * WHY THIS FILE EXISTS: the v0.2 delta (`spec/aph-0.2.md`)
 * declares `sealedPayload`, and this implementation is the delta's
 * NON-READER role made concrete — it parses the member strictly, enforces
 * the wire-version rule, and verifies AROUND the seal as opaque bytes. It
 * deliberately never OPENS a seal: WebCrypto has no ChaCha20-Poly1305, and
 * this package's central claim is the platform's own crypto and nothing
 * else. A capability faked in userland cipher code would cost the claim
 * that makes the rest trustworthy.
 *
 * WHAT IT PINS: the committed v0.2 vector parses and its version is
 * admitted; the same member on an aphVersion "0.1" wire refuses at strict
 * parse with the declaration message; the member's own shape is strict; and
 * a full verify of the vector proceeds PAST parsing to the signature check
 * — proving the seal is opaque carriage under the existing pipeline, not a
 * bypass of it.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { AphError, AphParseError } from '../src/errors.js';
import { parseEnvelope } from '../src/parse.js';
import { verifyEnvelope } from '../src/verify.js';
import { readExample } from '../testkit/corpus.js';

const VECTOR = 'v0.2/sealed_envelope.json';

test('the committed v0.2 sealed vector strict-parses', () => {
  const envelope = parseEnvelope(readExample(VECTOR));
  assert.equal(envelope.aphVersion, '0.2');
  const sealed = envelope.credentialSubject.sealedPayload;
  assert.ok(sealed, 'the vector carries the member');
  assert.equal(sealed.suite, 'APH-SEAL-1');
  assert.equal(sealed.reader.id, 'did:web:receiver.example.com');
});

test('sealedPayload on an aphVersion 0.1 wire refuses at strict parse', () => {
  // The wire-version rule, from this side: the same bytes under the final
  // version are malformed for the version they claim — the cross-member
  // rule a v0.1-only build enforces implicitly via its unknown-member
  // refusal, enforced here explicitly because this build KNOWS the member.
  const downgraded = readExample(VECTOR).replace('"aphVersion": "0.2"', '"aphVersion": "0.1"');
  assert.throws(
    () => parseEnvelope(downgraded),
    (error: unknown) =>
      error instanceof AphParseError && error.message.includes('declared from aphVersion "0.2"'),
  );
});

test('the sealed member itself is strict about its own shape', () => {
  const smuggled = readExample(VECTOR).replace('"suite":', '"extra": 1, "suite":');
  assert.throws(
    () => parseEnvelope(smuggled),
    (error: unknown) => error instanceof AphParseError,
  );
});

test('verification treats the seal as opaque carriage, not a bypass', async () => {
  // The vector's proof is illustrative, so a FULL verify refuses at the
  // signature — which is the point: the pipeline reached the signature,
  // meaning the sealed member rode through parsing and into ordinary
  // verification exactly as the delta's verification step specifies for
  // every verifier that is not the reader.
  await assert.rejects(
    () => verifyEnvelope(readExample(VECTOR), { now: '2026-05-21T00:05:00Z' }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E001',
  );
});

test('the SIGNED sealed vector verifies end-to-end in this implementation, keyless', async () => {
  // The strongest completion artifact this suite holds: a v0.2 envelope
  // carrying an audience binding AND a sealed payload, signed by a did:key
  // notary, admitted by the INDEPENDENT implementation with no supplied
  // keys — the audience step satisfied as the named verifier, the seal
  // ridden as opaque bytes, the signature verified over the ciphertext it
  // covers. Two implementations, one verdict, no plaintext.
  const verified = await verifyEnvelope(readExample('v0.2/sealed_signed_envelope.json'), {
    now: '2026-05-21T00:05:00Z',
    verifierId: 'did:web:ssot.example.com',
    actCoordinates: { kind: 'slack', teamId: 'T01234567', channelId: 'C01234567' },
  });
  assert.equal(verified.attestationMode, 'NotaryAttested');
  assert.ok(verified.envelope.credentialSubject.sealedPayload);
});

