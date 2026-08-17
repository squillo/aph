/**
 * §7.1.11 + §7.1.7 — the proof structure, and its agreement with the
 * `attestationMode` LABEL.
 *
 * Everything in this module runs BEFORE any signature is checked, and none of
 * it needs a key. That ordering is the point: `attestationMode` is a
 * self-asserted string, and a holder of a notary key could write
 * `PrincipalSigned` above a single notary proof whose `proofPurpose` is
 * `assertionMethod` — indistinguishable from a principal proof by purpose
 * alone. A verifier that trusted the label would report a forged authorization
 * as the human's own signature. The binding to `credentialSubject.humanPrincipal.id`
 * is what closes it, because the notary does not hold that key.
 */

import { aphError } from './errors.js';
import { didOf } from './didkey.js';
import {
  isProofChain,
  proofsOf,
  type AttestationMode,
  type EnvelopeProof,
  type NotarizationEnvelope,
} from './types.js';

/** The LABEL. §7.1.7: absent means `NotaryAttested`, unambiguously. */
export function declaredAttestationMode(envelope: NotarizationEnvelope): AttestationMode {
  return envelope.credentialSubject.policy.attestationMode ?? 'NotaryAttested';
}

/**
 * The mode the STRUCTURE proves, refusing any envelope whose label and shape
 * disagree in either direction (`APH_E013`).
 *
 * Returns the proven mode so a caller cannot obtain a mode without the check
 * having run — the same reason the revocation check takes a key by value
 * rather than resolving one internally.
 */
export function verifyProofStructure(envelope: NotarizationEnvelope): AttestationMode {
  const declared = declaredAttestationMode(envelope);
  const proofs = proofsOf(envelope);

  if (!isProofChain(envelope)) {
    // §7.1.11: a single-object `proof` is a notary proof, and the envelope is
    // NotaryAttested. A `PrincipalSigned` label above it is the forgery this
    // rule exists to refuse.
    if (declared !== 'NotaryAttested') {
      throw aphError(
        'APH_E013',
        'attestationMode is "PrincipalSigned" above a single-object proof; §7.1.11 admits that ' +
          'label only on a two-element chain whose head is the principal\'s key',
      );
    }
    const only = proofs[0] as EnvelopeProof;
    if (only.id !== undefined) {
      throw aphError(
        'APH_E013',
        '§7.1.11 omits `id` on a single-object proof, which has nothing to link to',
      );
    }
    if (only.previousProof !== undefined) {
      throw aphError('APH_E013', 'a single-object proof countersigns nothing and carries no previousProof');
    }
    return 'NotaryAttested';
  }

  // §7.1.11: an array is a W3C proof chain constrained to exactly two roles.
  if (proofs.length !== 2) {
    throw aphError(
      'APH_E013',
      `a proof chain has exactly two elements (principal, then notary); this one has ${proofs.length}`,
    );
  }
  if (declared !== 'PrincipalSigned') {
    throw aphError(
      'APH_E013',
      '§7.1.11 requires a two-element chain to carry attestationMode "PrincipalSigned"; this one ' +
        `is ${envelope.credentialSubject.policy.attestationMode === undefined ? 'unlabelled' : `labelled "${declared}"`}`,
    );
  }

  const principal = proofs[0] as EnvelopeProof;
  const notary = proofs[1] as EnvelopeProof;

  if (principal.proofPurpose !== 'assertionMethod') {
    throw aphError(
      'APH_E013',
      `the principal proof's proofPurpose is "${principal.proofPurpose}"; §7.1.11 fixes it at "assertionMethod"`,
    );
  }
  if (notary.proofPurpose !== 'authentication') {
    throw aphError(
      'APH_E013',
      `the notary proof's proofPurpose is "${notary.proofPurpose}"; §7.1.11 fixes it at "authentication"`,
    );
  }

  // The binding that makes the label mean something: the head of the chain must
  // be the HUMAN's key. A proof made by any other key is not the principal's
  // proof, whatever its proofPurpose says.
  const humanPrincipalDid = envelope.credentialSubject.humanPrincipal.id;
  if (didOf(principal.verificationMethod) !== humanPrincipalDid) {
    throw aphError(
      'APH_E013',
      `the chain head's verificationMethod resolves to ${didOf(principal.verificationMethod)}, ` +
        `not to credentialSubject.humanPrincipal.id (${humanPrincipalDid})`,
    );
  }

  // §7.1.11: each proof in a chain MUST carry an id, and the notary proof MUST
  // carry previousProof naming the principal's. Array position is a hint;
  // previousProof is the binding — a verifier that trusted order alone would
  // accept a chain an intermediary reordered.
  if (typeof principal.id !== 'string' || principal.id.length === 0) {
    throw aphError('APH_E013', 'the principal proof in a chain carries no id');
  }
  if (typeof notary.id !== 'string' || notary.id.length === 0) {
    throw aphError('APH_E013', 'the notary proof in a chain carries no id');
  }
  if (principal.id === notary.id) {
    throw aphError('APH_E013', `both proofs in the chain carry the id ${principal.id}`);
  }
  if (principal.previousProof !== undefined) {
    throw aphError(
      'APH_E013',
      'the principal proof is the head of the chain and countersigns nothing, so it carries no previousProof',
    );
  }
  if (notary.previousProof === undefined) {
    throw aphError('APH_E013', 'the notary proof carries no previousProof naming what it countersigns');
  }
  if (notary.previousProof !== principal.id) {
    throw aphError(
      'APH_E013',
      `the notary proof's previousProof (${notary.previousProof}) names no proof in this chain`,
    );
  }

  return 'PrincipalSigned';
}

/**
 * The no-downgrade gate (§8.3.1 step 1a, `APH_E012`).
 *
 * A verifier whose policy requires `PrincipalSigned` refuses anything else NOW,
 * before doing work — there is no silent downgrade from a stronger attestation
 * to a weaker one, for the same reason §8.4.6 forbids downgrading key
 * discovery: an attacker who can defeat the weak path will always present the
 * weak path.
 */
export function requireAttestationMode(
  envelope: NotarizationEnvelope,
  required: AttestationMode,
): void {
  const declared = declaredAttestationMode(envelope);
  if (declared !== required) {
    throw aphError(
      'APH_E012',
      `verifier policy requires ${required}; this envelope is ${declared}`,
    );
  }
}
