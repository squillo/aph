/**
 * WHY THIS FILE EXISTS: `examples/ts_minted_envelope.json` is a COMMITTED file
 * that a Rust conformance test verifies. Committed bytes rot: the signing path
 * moves, nobody re-mints, and the artifact quietly becomes a record of an
 * implementation that no longer exists. This is the tripwire — regenerate from
 * the same constants and compare byte for byte, so the file cannot drift from
 * the code that claims to produce it.
 *
 * WHAT IT PINS: byte identity of the committed artifact against a fresh mint;
 * that this implementation admits its own output through the full §8.3
 * procedure INCLUDING step 8; and the two properties that make the artifact
 * worth committing at all — it needs no supplied key, and Ed25519 makes it
 * reproducible.
 *
 * WHEN THE FILE IS ABSENT the test SKIPS with the command that creates it,
 * rather than failing: minting is a build step — `npm run mint` — and a red
 * suite before the first mint would say nothing true. The Rust side is where
 * absence is a hard failure; by then the artifact is supposed to exist.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { didKeyVerificationMethod } from '../src/didkey.js';
import { serializeEnvelopeDocument } from '../src/serialize.js';
import { verifyEnvelope } from '../src/verify.js';
import { exampleExists, readExample } from '../testkit/corpus.js';
import {
  TS_MINTED_BODY,
  TS_MINTED_EVALUATION_INSTANT,
  TS_MINTED_FILE,
  buildTsMintedEnvelope,
  tsMintedNotaryDid,
  tsMintedPrincipalDid,
} from '../testkit/ts_minted.js';

const MINT_HINT = `run \`npm run build && npm run mint\` to create examples/${TS_MINTED_FILE}`;

test('a fresh mint is BYTE-IDENTICAL to the committed artifact', async (t) => {
  if (!exampleExists(TS_MINTED_FILE)) {
    t.skip(`examples/${TS_MINTED_FILE} is not on disk — ${MINT_HINT}`);
    return;
  }
  assert.equal(serializeEnvelopeDocument(await buildTsMintedEnvelope()), readExample(TS_MINTED_FILE));
});

test('minting twice produces the same bytes, which is what makes committing it honest', async () => {
  // Ed25519 derives its nonce from the key and the message (RFC 8032), so two
  // runs agree. This does not depend on the artifact existing, and it is the
  // property the whole (<-) direction rests on — checked separately so a
  // determinism regression is not hidden behind a skipped file check.
  const first = serializeEnvelopeDocument(await buildTsMintedEnvelope());
  const second = serializeEnvelopeDocument(await buildTsMintedEnvelope());
  assert.equal(first, second);
});

test('the artifact is admitted by the full §8.3 procedure with NO supplied key', async (t) => {
  if (!exampleExists(TS_MINTED_FILE)) {
    t.skip(`examples/${TS_MINTED_FILE} is not on disk — ${MINT_HINT}`);
    return;
  }
  // Both parties are `did:key`, so every key travels inside the document. That
  // is the difference from the Rust golden, whose `did:web` notary key has to
  // be handed in — and it is what makes this artifact checkable by someone who
  // has read nothing but the spec.
  const verified = await verifyEnvelope(readExample(TS_MINTED_FILE), {
    now: TS_MINTED_EVALUATION_INSTANT,
    requireMode: 'PrincipalSigned',
    bodyBytes: new TextEncoder().encode(TS_MINTED_BODY),
  });
  assert.equal(verified.attestationMode, 'PrincipalSigned');
  assert.equal(verified.embeddedMandateChecked, true);
  assert.equal(verified.bodyHashChecked, true);
});

test('the artifact publishes its complete body in preview, so §8.3 step 8 needs no second file', async (t) => {
  if (!exampleExists(TS_MINTED_FILE)) {
    t.skip(`examples/${TS_MINTED_FILE} is not on disk — ${MINT_HINT}`);
    return;
  }
  const communication = (await buildTsMintedEnvelope()).credentialSubject.communication;
  const bodyBytes = new TextEncoder().encode(TS_MINTED_BODY);
  // The shape-only fixtures pair the SHA-256 of the empty string with a
  // NON-ZERO bodySize — a combination no body can satisfy — and publish no
  // body. Here the two agree with each other and with the text a reader sees.
  assert.equal(communication.preview, TS_MINTED_BODY);
  assert.equal(communication.bodySize, bodyBytes.length);
  assert.notEqual(
    communication.bodySha256,
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
});

test('the artifact names both parties by DERIVED did:key identifiers, not by pasted literals', async () => {
  // A fixture that carried a hard-coded DID could claim an identity its own key
  // does not produce, and the signature would still verify under whatever key
  // the DID happened to decode to.
  const envelope = await buildTsMintedEnvelope();
  const proofs = Array.isArray(envelope.proof) ? envelope.proof : [envelope.proof];
  assert.equal(envelope.credentialSubject.humanPrincipal.id, tsMintedPrincipalDid());
  assert.equal(envelope.issuer, tsMintedPrincipalDid());
  assert.equal(
    (proofs[0] as { verificationMethod: string }).verificationMethod,
    didKeyVerificationMethod(tsMintedPrincipalDid()),
  );
  assert.equal(
    (proofs[1] as { verificationMethod: string }).verificationMethod,
    didKeyVerificationMethod(tsMintedNotaryDid()),
  );
  assert.equal(envelope.credentialSubject.notarization.notaryService.id, tsMintedNotaryDid());
});
