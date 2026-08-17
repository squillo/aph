/**
 * WHY THIS FILE EXISTS: writing this implementation from the specification
 * surfaced a place where v0.1 contradicts itself, and a second implementation
 * that resolved it silently would have wasted the finding. §6.1's field table
 * says a mandate signature covers the canonical form "MINUS" the signature
 * fields; §7.2.1 closes with "In every case the signer sets the field to the
 * empty string rather than removing the member". Removing a member and
 * emptying it produce different JCS bytes, so exactly one reading can be the
 * one anyone has actually signed.
 *
 * WHAT IT PINS: that the PUBLISHED bytes select the REMOVAL reading, for both
 * mandate signatures — and, just as importantly, that the emptying reading
 * does NOT verify, so the choice in `src/bases.ts` rests on evidence rather
 * than on a preference. If a future revision of the spec settles the other
 * way, this test is where the contradiction is re-measured, and it will say
 * which reading the corpus moved to.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { mandateSigningBase, mandateSigningBaseWithMembersEmptied } from '../src/bases.js';
import { multibaseDecode } from '../src/baseenc.js';
import { canonicalize, canonicalizeToBytes, type JsonValue } from '../src/jcs.js';
import { parseEnvelope } from '../src/parse.js';
import { importEd25519PublicKey, verifyEd25519 } from '../src/webcrypto.js';
import type { DelegationMandate } from '../src/types.js';
import { readExample } from '../testkit/corpus.js';
import { GOLDEN_FILE } from '../testkit/golden.js';
import { RFC8032_TEST_2, RFC8032_TEST_3, type Ed25519TestVector } from '../testkit/vectors.js';

function goldenMandate(): DelegationMandate {
  const mandate = parseEnvelope(readExample(GOLDEN_FILE)).credentialSubject.policy
    .delegationMandate;
  assert.ok(mandate, 'the golden must embed its parent §6.1 mandate');
  return mandate;
}

async function verifiesUnder(
  vector: Ed25519TestVector,
  signature: string,
  base: JsonValue,
): Promise<boolean> {
  const key = await importEd25519PublicKey(vector.publicKey);
  return verifyEd25519(key, multibaseDecode(signature), canonicalizeToBytes(base));
}

test('the published mandate principalSignature covers the form with both members REMOVED', async () => {
  const mandate = goldenMandate();
  assert.equal(
    await verifiesUnder(
      RFC8032_TEST_2,
      mandate.principalSignature,
      mandateSigningBase(mandate, 'principalSignature'),
    ),
    true,
    'the §6.1 removal reading must verify — src/bases.ts implements it',
  );
});

test('the emptying reading of §7.2.1 does NOT verify the published principalSignature', async () => {
  // The refutation. Without it, "removal works" would be compatible with both
  // readings producing the same bytes, and the finding would be unproven.
  const mandate = goldenMandate();
  assert.equal(
    await verifiesUnder(
      RFC8032_TEST_2,
      mandate.principalSignature,
      mandateSigningBaseWithMembersEmptied(mandate, 'principalSignature'),
    ),
    false,
  );
});

test('the published mandate notarySignature covers the form with notarySignature REMOVED and principalSignature PRESENT', async () => {
  const mandate = goldenMandate();
  assert.equal(
    await verifiesUnder(
      RFC8032_TEST_3,
      mandate.notarySignature,
      mandateSigningBase(mandate, 'notarySignature'),
    ),
    true,
  );
});

test('the emptying reading does NOT verify the published notarySignature either', async () => {
  const mandate = goldenMandate();
  assert.equal(
    await verifiesUnder(
      RFC8032_TEST_3,
      mandate.notarySignature,
      mandateSigningBaseWithMembersEmptied(mandate, 'notarySignature'),
    ),
    false,
  );
});

test('the two candidate bases really are different bytes, so the test above can discriminate', () => {
  // If they canonicalized identically the four assertions would be vacuous.
  const mandate = goldenMandate();
  for (const slot of ['principalSignature', 'notarySignature'] as const) {
    assert.notEqual(
      canonicalize(mandateSigningBase(mandate, slot)),
      canonicalize(mandateSigningBaseWithMembersEmptied(mandate, slot)),
    );
  }
});

test('the ENVELOPE bases empty rather than remove, which is the rule §7.2.1 states correctly', async () => {
  // Stated here beside the mandate finding so a reader does not over-generalize
  // it: `proofValue` IS emptied, and the golden's two envelope proofs are the
  // proof of that — they verify in `verify_golden.test.ts` over bases built by
  // `proofBase`, which sets the member to "" and never deletes it.
  const envelope = parseEnvelope(readExample(GOLDEN_FILE));
  const proofs = Array.isArray(envelope.proof) ? envelope.proof : [envelope.proof];
  assert.equal(proofs.length, 2);
  for (const proof of proofs) {
    assert.equal(typeof proof.proofValue, 'string');
    assert.ok((proof.proofValue as string).length > 0);
  }
});
