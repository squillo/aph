/**
 * §7.2.1 — the canonicalization base per proof, and per mandate signature.
 *
 * This module answers exactly one question: WHICH BYTES does a given signature
 * cover? Getting it wrong is the likeliest way for two implementations to fail
 * to verify each other, which is why the specification states each base
 * exactly and why each one gets its own named function here.
 *
 * Two rules run together in the ENVELOPE bases and are easy to conflate:
 *  - a proof's OWN `proofValue` is set to the EMPTY STRING, never removed. JCS
 *    over an object with a member absent and JCS over the same object with the
 *    member empty produce different bytes (§7.2 implementation note).
 *  - a proof that comes AFTER the one being covered is REMOVED FROM THE ARRAY.
 *    That is array membership, not member emptying, and both rules apply
 *    (§7.2.1 closing paragraph).
 *
 * The MANDATE bases follow a third rule that contradicts the first, and the
 * contradiction is in the specification rather than in this code — see
 * {@link mandateSigningBase}.
 */

import type { JsonObject, JsonValue } from './jcs.js';
import type { DelegationMandate, EnvelopeProof, NotarizationEnvelope } from './types.js';

/**
 * A deep copy, so building a base never mutates the document a caller is still
 * holding. `structuredClone` is a platform builtin and handles the JSON value
 * graph exactly.
 */
function clone<T>(value: T): T {
  return structuredClone(value);
}

/**
 * The base for the proof at `index`.
 *
 *  - single-object `proof` (a lone notary proof): the object form is kept and
 *    only its own `proofValue` is emptied.
 *  - a chain: `proof` stays an ARRAY truncated to include this proof and every
 *    proof before it, with this proof's `proofValue` emptied and the earlier
 *    ones complete.
 *
 * The array form is load-bearing and not cosmetic. `"proof": [{...}]` and
 * `"proof": {...}` canonicalize to different bytes, which DOMAIN-SEPARATES a
 * principal proof from a lone notary proof: were the object form used for the
 * head of a chain, an intermediary could strip the notary proof and re-present
 * the remainder as a valid single-proof envelope, and a recipient would read
 * the human's own proof as a notary attestation.
 */
export function proofBase(envelope: NotarizationEnvelope, index: number): JsonValue {
  const copy = clone(envelope) as unknown as JsonObject;

  if (!Array.isArray(copy.proof)) {
    if (index !== 0) {
      throw new RangeError(`proof base: a single-object proof has no index ${index}`);
    }
    (copy.proof as unknown as EnvelopeProof).proofValue = '';
    return copy as unknown as JsonValue;
  }

  const chain = copy.proof as unknown as EnvelopeProof[];
  if (index < 0 || index >= chain.length) {
    throw new RangeError(`proof base: index ${index} is outside a ${chain.length}-proof chain`);
  }
  const covered = chain.slice(0, index + 1);
  (covered[index] as EnvelopeProof).proofValue = '';
  copy.proof = covered as unknown as JsonValue;
  return copy as unknown as JsonValue;
}

/**
 * ⚠ A SPECIFICATION COLLISION THIS IMPLEMENTATION HAD TO RESOLVE.
 *
 * The mandate bases are the one place where two normative sentences of v0.1
 * disagree, and writing this module from the spec alone is what surfaced it:
 *
 *  - §6.1's field table says `principalSignature` covers the canonical form
 *    "MINUS both signature fields" and `notarySignature` covers it "MINUS the
 *    `notarySignature` field (with `principalSignature` PRESENT)". MINUS a
 *    field is REMOVAL of the member.
 *  - §7.2.1 repeats that wording in its `Mandates` bullet and then closes with
 *    "In every case the signer sets the field to the **empty string** rather
 *    than removing the member" — a sentence written about `proofValue` whose
 *    "in every case" reaches the mandate bullet three lines above it.
 *
 * JCS over an object with a member absent and JCS over the same object with
 * the member empty are DIFFERENT BYTES, so the two readings never verify each
 * other and one of them has to be wrong. The published bytes decide it:
 * `test/mandate_base_ambiguity.test.ts` builds both candidates over
 * `examples/principal_signed_envelope.json`'s embedded mandate and asserts
 * that exactly one verifies — the REMOVAL reading, which is what this function
 * implements and what §6.1's field table says. The empty-string sentence is
 * correct for `proofValue` and overreaches for mandates.
 *
 * Filed as a spec defect via CONTRIBUTING.md's reporting path: §7.2.1's closing
 * sentence should be scoped to proof values, or §6.1's "MINUS" should become
 * "emptied".
 * It is NOT fixed here — an implementation that quietly followed the reading
 * the published corpus contradicts would be unable to verify anything anyone
 * has actually signed.
 */
export function mandateSigningBase(
  mandate: DelegationMandate,
  slot: 'principalSignature' | 'notarySignature',
): JsonValue {
  const copy = clone(mandate) as unknown as JsonObject;
  // `notarySignature` leaves in both cases: it does not exist yet when the
  // principal grants, and a countersignature cannot cover itself.
  delete copy.notarySignature;
  if (slot === 'principalSignature') delete copy.principalSignature;
  return copy as unknown as JsonValue;
}

/**
 * The refuted reading — signature members EMPTIED rather than removed. Kept as
 * a named function for exactly one purpose: so the ambiguity test can state
 * both candidates and show which the published bytes select. Nothing on a
 * production path may call it.
 */
export function mandateSigningBaseWithMembersEmptied(
  mandate: DelegationMandate,
  slot: 'principalSignature' | 'notarySignature',
): JsonValue {
  const copy = clone(mandate) as unknown as JsonObject;
  if (slot === 'principalSignature') copy.notarySignature = '';
  copy[slot] = '';
  return copy as unknown as JsonValue;
}
