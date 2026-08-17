/**
 * §7.2.1 — minting, in the normative issuance order.
 *
 *   1. the Notary Service evaluates policy and PREPARES the complete envelope,
 *      including `credentialSubject.notarization`;
 *   2. the PRINCIPAL signs that envelope, producing the first proof;
 *   3. the NOTARY countersigns, producing the second proof over everything
 *      including the principal's.
 *
 * The order is not stylistic. Reverse steps 1 and 2 and the principal would
 * have to sign notary-produced fields that do not exist yet — the circularity
 * the §7.2.1 bases are written to avoid. The shape of this module enforces it:
 * a caller hands in an envelope WITHOUT proofs, and there is no way to obtain
 * the notary proof except by having produced the principal proof first.
 */

import { proofBase, mandateSigningBase } from './bases.js';
import { canonicalizeToBytes } from './jcs.js';
import type { JsonObject } from './jcs.js';
import type {
  Cryptosuite,
  DelegationMandate,
  EnvelopeProof,
  NotarizationEnvelope,
  ProofType,
} from './types.js';

/**
 * A key that can produce a `proofValue`, named by the verification method that
 * will resolve to its public half.
 *
 * The signer owns the ENCODING as well as the signature because the two proof
 * formats of §8.2 encode differently — multibase base58btc for a
 * `DataIntegrityProof`, a compact detached JWS for `JsonWebSignature2020` — and
 * a mint path that knew about both would have to branch on a format it does not
 * otherwise care about. No private key appears in this interface: a `Signer` is
 * a capability, so a hardware key, a keychain and a published test vector are
 * all the same shape here.
 */
export interface Signer {
  readonly verificationMethod: string;
  readonly proofType: ProofType;
  /** §7.1.11: present for `DataIntegrityProof`, omitted for `JsonWebSignature2020`. */
  readonly cryptosuite?: Cryptosuite;
  encodeProofValue(canonical: Uint8Array): Promise<string>;
}

/** An envelope as the notary prepares it in step 1: everything but `proof`. */
export type PreparedEnvelope = Omit<NotarizationEnvelope, 'proof'>;

export interface ProofMetadata {
  readonly id: string;
  /** RFC 3339. A CONSTANT in every deterministic fixture — this module reads no clock. */
  readonly created: string;
}

function proofSkeleton(
  signer: Signer,
  created: string,
  purpose: 'assertionMethod' | 'authentication',
  id?: string,
  previousProof?: string,
): EnvelopeProof {
  // Member order here is the PUBLISHED CORPUS's order, not §7.1.11's field
  // table — the two differ, and the corpus is the defensible source because it
  // is what a reader diffing this artifact against
  // `examples/principal_signed_envelope.json` actually sees. Both of that
  // file's proof blocks carry exactly this sequence. (§7.1.11's table runs
  // id, type, cryptosuite, verificationMethod, created, proofPurpose,
  // previousProof, proofValue; a table is a description of fields, not a
  // serialization order, and the spec makes no ordering requirement.)
  // Canonicalization sorts keys, so none of this can change which bytes a
  // signature covers — it only keeps the two published artifacts diffable.
  const proof = { type: signer.proofType } as EnvelopeProof;
  if (signer.cryptosuite !== undefined) proof.cryptosuite = signer.cryptosuite;
  proof.verificationMethod = signer.verificationMethod;
  proof.created = created;
  proof.proofPurpose = purpose;
  proof.proofValue = '';
  if (id !== undefined) proof.id = id;
  if (previousProof !== undefined) proof.previousProof = previousProof;
  return proof;
}

/**
 * Mints a `PrincipalSigned` envelope: the two-element chain of §7.1.11.
 *
 * `policy.attestationMode` is FILLED IN when the prepared envelope omits it and
 * REFUSED when it says something else: the label and the structure must agree,
 * and this function is the one place that knows the structure it just built. A
 * caller that wants the member at a particular position in the emitted JSON
 * places it itself and this only checks it.
 */
export async function mintPrincipalSignedEnvelope(params: {
  readonly prepared: PreparedEnvelope;
  readonly principal: Signer;
  readonly principalProof: ProofMetadata;
  readonly notary: Signer;
  readonly notaryProof: ProofMetadata;
}): Promise<NotarizationEnvelope> {
  const { prepared, principal, principalProof, notary, notaryProof } = params;

  const draft = structuredClone(prepared) as unknown as JsonObject;
  const policy = (draft.credentialSubject as JsonObject).policy as JsonObject;
  if (policy.attestationMode === undefined) {
    policy.attestationMode = 'PrincipalSigned';
  } else if (policy.attestationMode !== 'PrincipalSigned') {
    throw new TypeError(
      `mint: the prepared envelope is labelled "${String(policy.attestationMode)}" but this ` +
        'function builds the two-element chain §7.1.11 admits only under "PrincipalSigned"',
    );
  }

  const principalBlock = proofSkeleton(
    principal,
    principalProof.created,
    'assertionMethod',
    principalProof.id,
  );
  const withPrincipal = { ...draft, proof: [principalBlock] } as unknown as NotarizationEnvelope;

  // Step 2. The base is the envelope with `proof` a ONE-ELEMENT ARRAY and this
  // proof's own proofValue empty — proofBase(_, 0) builds exactly that.
  principalBlock.proofValue = await principal.encodeProofValue(
    canonicalizeToBytes(proofBase(withPrincipal, 0)),
  );

  const notaryBlock = proofSkeleton(
    notary,
    notaryProof.created,
    'authentication',
    notaryProof.id,
    principalProof.id,
  );
  const withBoth = {
    ...draft,
    proof: [principalBlock, notaryBlock],
  } as unknown as NotarizationEnvelope;

  // Step 3. The notary's base carries BOTH proofs with the principal's
  // proofValue complete — which is what makes this a countersignature rather
  // than a second independent signature, and why a notary cannot detach the
  // principal's proof and re-attach it to a different envelope.
  notaryBlock.proofValue = await notary.encodeProofValue(
    canonicalizeToBytes(proofBase(withBoth, 1)),
  );

  return withBoth;
}

/** Mints a `NotaryAttested` envelope: the single-object `proof` of §7.1.11. */
export async function mintNotaryAttestedEnvelope(params: {
  readonly prepared: PreparedEnvelope;
  readonly notary: Signer;
  readonly created: string;
}): Promise<NotarizationEnvelope> {
  const { prepared, notary, created } = params;
  // §7.1.11: a single-object proof omits `id` — it has nothing to link to — and
  // uses `assertionMethod` for wire compatibility.
  const block = proofSkeleton(notary, created, 'assertionMethod');
  const envelope = { ...structuredClone(prepared), proof: block } as unknown as NotarizationEnvelope;
  block.proofValue = await notary.encodeProofValue(canonicalizeToBytes(proofBase(envelope, 0)));
  return envelope;
}

/**
 * Signs a §6.1 Delegation Mandate: the principal grants, then the notary
 * countersigns what the principal signed. Same ordering argument as the
 * envelope chain — the notary's base contains the principal's completed
 * signature, so the countersignature cannot be moved to a different grant.
 *
 * Both signers must be `DataIntegrityProof` signers: §6.1's signature members
 * are multibase strings with no place to carry a JWS header.
 */
export async function signDelegationMandate(params: {
  readonly mandate: Omit<DelegationMandate, 'principalSignature' | 'notarySignature'>;
  readonly principal: Signer;
  readonly notary: Signer;
}): Promise<DelegationMandate> {
  for (const [role, signer] of [
    ['principal', params.principal],
    ['notary', params.notary],
  ] as const) {
    if (signer.proofType !== 'DataIntegrityProof') {
      throw new TypeError(
        `mint: the ${role} signer emits ${signer.proofType}, but a §6.1 mandate signature is a ` +
          'bare multibase string',
      );
    }
  }
  const signed: DelegationMandate = {
    ...structuredClone(params.mandate),
    principalSignature: '',
    notarySignature: '',
  };
  signed.principalSignature = await params.principal.encodeProofValue(
    canonicalizeToBytes(mandateSigningBase(signed, 'principalSignature')),
  );
  signed.notarySignature = await params.notary.encodeProofValue(
    canonicalizeToBytes(mandateSigningBase(signed, 'notarySignature')),
  );
  return signed;
}
