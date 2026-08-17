/**
 * WHY THIS FILE EXISTS: this is the (->) half of the cross-verification bar —
 * the point at which a second implementation stops being a plausible reading
 * of a document and becomes a thing that admits what the reference produced.
 * `examples/principal_signed_envelope.json` was minted by the Rust reference;
 * nothing in this package contributed a byte of it.
 *
 * WHAT THEY PIN: all FOUR real Ed25519 signatures on the golden, each checked
 * individually so a failure names which base diverged — the two envelope
 * proofs over their §7.2.1 bases and the two §6.1 mandate signatures — plus
 * the whole §8.3 / §8.3.1 procedure end to end, the §7.1.11 chain linkage, the
 * §7.2.1 issuance order, and the §7.1.7.1 mandate-to-envelope bindings.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalizeToBytes } from '../src/jcs.js';
import { mandateSigningBase, proofBase } from '../src/bases.js';
import { multibaseDecode } from '../src/baseenc.js';
import { parseEnvelope } from '../src/parse.js';
import { verifyEnvelope, verifyProofAt } from '../src/verify.js';
import { verifyProofStructure } from '../src/structure.js';
import { importEd25519PublicKey, verifyEd25519 } from '../src/webcrypto.js';
import { readExample } from '../testkit/corpus.js';
import {
  GOLDEN_EVALUATION_INSTANT,
  GOLDEN_FILE,
  goldenSuppliedKeys,
} from '../testkit/golden.js';
import { RFC8032_TEST_2, RFC8032_TEST_3 } from '../testkit/vectors.js';

function golden(): string {
  return readExample(GOLDEN_FILE);
}

test('the golden strict-parses and its structure PROVES PrincipalSigned', () => {
  const envelope = parseEnvelope(golden());
  // Proved by the two-element chain whose head resolves to humanPrincipal.id —
  // not read off the `attestationMode` label, which a notary key could write.
  assert.equal(verifyProofStructure(envelope), 'PrincipalSigned');
});

test('the golden signature 1 of 4: the PRINCIPAL proof over the ONE-ELEMENT ARRAY base', async () => {
  // The likeliest place for two implementations to diverge (§7.2.1): the base
  // keeps `proof` an array of one, and empties proofValue rather than removing it.
  const envelope = parseEnvelope(golden());
  assert.equal(await verifyProofAt(envelope, 0, { keys: goldenSuppliedKeys() }), true);
});

test('the golden signature 2 of 4: the NOTARY countersignature over the two-proof base', async () => {
  const envelope = parseEnvelope(golden());
  assert.equal(await verifyProofAt(envelope, 1, { keys: goldenSuppliedKeys() }), true);
});

test('the golden signature 3 of 4: the mandate principalSignature under the human key', async () => {
  const envelope = parseEnvelope(golden());
  const mandate = envelope.credentialSubject.policy.delegationMandate;
  assert.ok(mandate);
  const key = await importEd25519PublicKey(RFC8032_TEST_2.publicKey);
  const verified = await verifyEd25519(
    key,
    multibaseDecode(mandate.principalSignature),
    canonicalizeToBytes(mandateSigningBase(mandate, 'principalSignature')),
  );
  assert.equal(verified, true);
});

test('the golden signature 4 of 4: the mandate notarySignature under the notary key', async () => {
  const envelope = parseEnvelope(golden());
  const mandate = envelope.credentialSubject.policy.delegationMandate;
  assert.ok(mandate);
  const key = await importEd25519PublicKey(RFC8032_TEST_3.publicKey);
  const verified = await verifyEd25519(
    key,
    multibaseDecode(mandate.notarySignature),
    canonicalizeToBytes(mandateSigningBase(mandate, 'notarySignature')),
  );
  assert.equal(verified, true);
});

test('the golden is ADMITTED by the whole §8.3 / §8.3.1 procedure', async () => {
  const verified = await verifyEnvelope(golden(), {
    now: GOLDEN_EVALUATION_INSTANT,
    keys: goldenSuppliedKeys(),
    requireMode: 'PrincipalSigned',
  });
  assert.equal(verified.attestationMode, 'PrincipalSigned');
  assert.equal(verified.embeddedMandateChecked, true);
  // §8.3 step 8 did NOT run: the golden publishes no body, so there is nothing
  // to hash. Asserted rather than left implicit — the gap is real and the
  // README says so, and a test that quietly skipped it would hide the claim.
  assert.equal(verified.bodyHashChecked, false);
});

test('stripping the countersignature does NOT yield a valid single-proof envelope (§7.2.1 domain separation)', async () => {
  // The attack §7.2.1's array form exists to stop: an intermediary removes the
  // notary proof and re-presents the human's own proof as a notary
  // attestation. The remaining proof was signed over the ARRAY base, so as a
  // bare object it verifies under no key — and the structure rules refuse the
  // shape before the signature is even reached.
  const envelope = parseEnvelope(golden());
  const principal = Array.isArray(envelope.proof) ? envelope.proof[0] : envelope.proof;
  assert.ok(principal);
  const stripped = parseEnvelope(
    JSON.stringify({ ...(JSON.parse(golden()) as object), proof: principal }),
  );
  assert.throws(() => verifyProofStructure(stripped), { code: 'APH_E013' });

  // And independently of the structure rule: the bytes do not verify either.
  const key = await importEd25519PublicKey(RFC8032_TEST_2.publicKey);
  const asObjectBase = canonicalizeToBytes(proofBase(stripped, 0));
  const verified = await verifyEd25519(key, multibaseDecode(principal.proofValue), asObjectBase);
  assert.equal(verified, false);
});
