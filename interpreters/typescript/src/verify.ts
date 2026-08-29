/**
 * §8.3 + §8.3.1 — the recipient verification procedure.
 *
 * The BOUNDARY, stated once: this verifier parses bytes it is handed and NEVER
 * fetches. §8.4 key discovery and §6.3.3's status fetch are both network acts,
 * so keys arrive as parameters and `now` arrives as a parameter. A library that
 * read its own clock could not be tested deterministically, and one that
 * resolved its own keys would hide which anchor a verdict rested on.
 *
 * The step numbering below is §8.3's. One departure from its LIST order is
 * deliberate and marked at the site: the algorithm gate (step 7) runs before
 * the signature check (step 5), because reaching a signature check with an
 * algorithm the verifier does not support is unconstructible — there is
 * nothing to verify WITH. §8.3's ordering is an enumeration of obligations,
 * not a schedule.
 */

import { AphParseError, AphKeyUnavailableError, aphError } from './errors.js';
import { proofBase, mandateSigningBase } from './bases.js';
import { base64urlDecode, base64urlEncode, bytesToHex, multibaseDecode } from './baseenc.js';
import { decodeDidKey, didOf, isDidKey } from './didkey.js';
import { canonicalizeToBytes } from './jcs.js';
import { parseEnvelope } from './parse.js';
import { requireAttestationMode, verifyProofStructure } from './structure.js';
import {
  DEFAULT_CLOCK_SKEW_SECONDS,
  RECOMMENDED_MAX_ENVELOPE_BYTES,
  isProofChain,
  proofsOf,
  type AttestationMode,
  type DelegationMandate,
  type EnvelopeProof,
  type NotarizationEnvelope,
} from './types.js';
import {
  importPublicKey,
  normalizeEcdsaSignature,
  sha256,
  verifyEd25519,
  verifyEs256,
  type PublicKeyMaterial,
} from './webcrypto.js';

/**
 * Keys the caller supplies for verification methods this verifier cannot decode
 * offline — every `did:web` and every DNS-published notary key. Lookup is by
 * full DID URL first, then by bare DID, so a caller may pin a specific
 * `#fragment` or hand over one key for the whole subject.
 *
 * A `did:key` is never looked up here: it carries its own bytes (§8.4.3) and
 * letting a supplied entry shadow them would be a downgrade of the strongest
 * anchor the protocol has.
 */
export type SuppliedKeys = Readonly<Record<string, PublicKeyMaterial>>;

export interface VerifyOptions {
  /** RFC 3339 instant to evaluate against. Required — this module reads no clock. */
  readonly now: string;
  readonly clockSkewSeconds?: number;
  /** §8.3.1 step 1a policy gate. Omit to accept whichever mode the envelope proves. */
  readonly requireMode?: AttestationMode;
  readonly keys?: SuppliedKeys;
  /** §8.3 step 8: the actual outbound body bytes, when the transport delivered them. */
  readonly bodyBytes?: Uint8Array;
  readonly maxEnvelopeBytes?: number;
  /**
   * §8.3 step 5a (RFC 0003): this verifier's own identity, compared against
   * `credentialSubject.audience.id` when the envelope names one. Omitting it
   * does NOT skip the check — an envelope WITH an audience meets a verifier
   * that cannot determine its own identity, and §8.3 says reject, not skip.
   * An envelope with no audience never consults this.
   */
  readonly verifierId?: string;
  /**
   * §8.3 step 5a: the delivery coordinates of the act this verifier is being
   * asked to perform, compared member-by-member against
   * `audience.channelBinding` when present. Same reject-not-skip rule: a
   * binding nobody can check is refused.
   */
  readonly actCoordinates?: Readonly<Record<string, unknown>>;
  /**
   * §8.3 step 8b (RFC 0003): the verifier's single-use ledger. When supplied,
   * an `id` already in the set refuses with APH_E018, and a successful verify
   * ADDS the id — returning from this function is this library's acceptance
   * moment. When omitted the obligation still exists; it is simply being kept
   * by the caller somewhere this function cannot see, and the caller should
   * be able to say where.
   */
  readonly consumedIds?: Set<string>;
  /**
   * §8.2 detached-JWS signing input. RFC 7797 with `b64:false` makes the input
   * `BASE64URL(header) || "." || <raw payload bytes>`; some deployed signers
   * base64url-encode the payload anyway. `auto` accepts either and is the
   * default so a published vector verifies whichever way it was made; the
   * minting path always produces the RFC 7797 form.
   */
  readonly jwsPayloadEncoding?: 'auto' | 'raw' | 'base64url';
}

export interface VerifiedEnvelope {
  readonly envelope: NotarizationEnvelope;
  /** The mode the STRUCTURE proved, not the label it carried. */
  readonly attestationMode: AttestationMode;
  /** True when §8.3 step 8 actually ran, i.e. the caller supplied body bytes. */
  readonly bodyHashChecked: boolean;
  /** True when an embedded §6.1 mandate was present and both its signatures verified. */
  readonly embeddedMandateChecked: boolean;
}

function instant(value: string, what: string): number {
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    throw new AphParseError(what, `"${value}" is not an RFC 3339 timestamp`);
  }
  return parsed;
}

/** §8.4.3 offline decode, else the caller's supply. Never a fetch. */
export function resolveVerifyingKey(
  verificationMethod: string,
  keys: SuppliedKeys | undefined,
): PublicKeyMaterial {
  if (isDidKey(verificationMethod)) {
    const decoded = decodeDidKey(verificationMethod);
    return { algorithm: decoded.algorithm, keyBytes: decoded.keyBytes };
  }
  const supplied = keys?.[verificationMethod] ?? keys?.[didOf(verificationMethod)];
  if (!supplied) throw new AphKeyUnavailableError(verificationMethod);
  return supplied;
}

/** §8.1: the algorithm a `DataIntegrityProof` cryptosuite pins. */
function algorithmOfCryptosuite(proof: EnvelopeProof): 'Ed25519' | 'P256' {
  if (proof.cryptosuite === undefined) {
    // §8.1: reject any envelope omitting an algorithm declaration.
    throw aphError(
      'APH_E010',
      'a DataIntegrityProof carries no cryptosuite, so it declares no algorithm',
    );
  }
  return proof.cryptosuite === 'eddsa-jcs-2022' ? 'Ed25519' : 'P256';
}

interface JwsParts {
  readonly protectedHeaderB64: string;
  readonly signature: Uint8Array;
  readonly algorithm: 'Ed25519' | 'P256';
}

/**
 * Splits and checks a §8.2 compact detached JWS.
 *
 * RFC 7515 §A.5 writes the detached form with an EMPTY payload segment
 * (`header..signature`); §8.2 describes it as "header.signature". Both spellings
 * denote the same thing, so both are accepted and the empty middle segment is
 * required to actually be empty — a payload riding in a "detached" JWS would be
 * a second, unsigned copy of the document.
 */
function parseDetachedJws(proof: EnvelopeProof, path: string): JwsParts {
  const segments = proof.proofValue.split('.');
  if (segments.length === 3) {
    if (segments[1] !== '') {
      throw new AphParseError(`${path}.proofValue`, 'a detached JWS carries no payload segment');
    }
  } else if (segments.length !== 2) {
    throw new AphParseError(
      `${path}.proofValue`,
      `expected a compact detached JWS, got ${segments.length} segments`,
    );
  }
  const protectedHeaderB64 = segments[0] as string;
  const signatureB64 = segments[segments.length - 1] as string;

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64urlDecode(protectedHeaderB64))) as Record<
      string,
      unknown
    >;
  } catch (cause) {
    throw new AphParseError(
      `${path}.proofValue`,
      `the JWS protected header is not base64url JSON: ${(cause as Error).message}`,
    );
  }

  const alg = header.alg;
  if (alg === 'none' || typeof alg !== 'string') {
    throw aphError('APH_E010', 'the JWS protected header declares no usable alg (§8.1 rejects "none")');
  }
  if (alg !== 'EdDSA' && alg !== 'ES256') {
    throw aphError('APH_E010', `the JWS protected header declares alg "${alg}", which is not ES256 or EdDSA`);
  }

  // §8.2 fixes the remaining header members. §11 has no code for a malformed
  // proof block, so a violation is reported as the strict-shape failure it is
  // rather than borrowing APH_E013, which names chain linkage and nothing else.
  const expectations: ReadonlyArray<readonly [string, unknown]> = [
    ['kid', proof.verificationMethod],
    ['typ', 'aph+jws'],
    ['cty', 'vc+ld+json'],
    ['b64', false],
  ];
  for (const [member, expected] of expectations) {
    if (header[member] !== expected) {
      throw new AphParseError(
        `${path}.proofValue/protected.${member}`,
        `§8.2 requires ${member} = ${JSON.stringify(expected)}, got ${JSON.stringify(header[member])}`,
      );
    }
  }
  const crit = header.crit;
  if (!Array.isArray(crit) || crit.length !== 1 || crit[0] !== 'b64') {
    throw new AphParseError(
      `${path}.proofValue/protected.crit`,
      '§8.2 requires crit = ["b64"] — without it a verifier may ignore b64:false and hash the wrong bytes',
    );
  }

  return {
    protectedHeaderB64,
    signature: base64urlDecode(signatureB64),
    algorithm: alg === 'EdDSA' ? 'Ed25519' : 'P256',
  };
}

/**
 * Both signature forms this implementation verifies are fixed width: RFC 8032
 * Ed25519 is 64 bytes, and RFC 7518 ES256 is `r||s` over a 32-byte field.
 */
const FIXED_SIGNATURE_BYTES = 64;

async function verifySignatureBytes(
  material: PublicKeyMaterial,
  algorithm: 'Ed25519' | 'P256',
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  if (material.algorithm !== algorithm) {
    throw aphError(
      'APH_E010',
      `the proof pins ${algorithm} but the resolved verification method holds a ` +
        `${material.algorithm} key`,
    );
  }

  let key: CryptoKey;
  try {
    key = await importPublicKey(material);
  } catch {
    // A verification method whose bytes are not a USABLE public key verifies
    // nothing, and that is a signature failure rather than a crash. §8.4.3's
    // decode already checked the multicodec and the length; whether the bytes
    // name a point on the curve is a question only the platform can answer,
    // and it answers it by rejecting the import. Returning false lets the
    // caller report APH_E001 or APH_E011 by role, which is what §11 asks for —
    // both are defined as "the signature did not verify", split by WHOSE key
    // it was, and an unusable key produces exactly that outcome. Throwing
    // instead would surface a platform exception through a protocol API and
    // lose the role distinction §11 insists on keeping.
    return false;
  }

  // A wrong-width signature cannot be the signature of anything, and some
  // runtimes reject it by THROWING rather than by returning false. Checking
  // the width first makes the verdict the same everywhere, which matters
  // because eight published fixtures carry illustrative proof values whose
  // decoded length is not promised to be 64.
  const normalized =
    algorithm === 'Ed25519' ? signature : normalizeEcdsaSignatureOrEmpty(signature);
  if (normalized.length !== FIXED_SIGNATURE_BYTES) return false;

  return algorithm === 'Ed25519'
    ? verifyEd25519(key, normalized, message)
    : verifyEs256(key, normalized, message);
}

/**
 * {@link normalizeEcdsaSignature}, but a malformed DER body yields empty bytes
 * instead of throwing — an unparseable signature is one that does not verify.
 */
function normalizeEcdsaSignatureOrEmpty(signature: Uint8Array): Uint8Array {
  try {
    return normalizeEcdsaSignature(signature);
  } catch {
    return new Uint8Array(0);
  }
}

/**
 * Decodes a multibase signature, yielding empty bytes when the value is not
 * multibase at all.
 *
 * Every signature slot in this protocol carries attacker-supplied text, and a
 * malformed one is a signature that does not verify — not an exception through
 * a protocol API. Empty bytes then fail the fixed-width gate, so the caller
 * reports the §11 code its role assigns (APH_E001, APH_E011 or APH_E006)
 * rather than a `TypeError` a recipient's pipeline has to know about.
 */
function decodedSignatureOrEmpty(value: string): Uint8Array {
  try {
    return multibaseDecode(value);
  } catch {
    return new Uint8Array(0);
  }
}

/**
 * Verifies one proof of an envelope over its own §7.2.1 base.
 *
 * Exported because a caller reproducing README target 2 wants to check the four
 * signatures one at a time and see WHICH one failed — a single boolean over the
 * whole document tells an implementer nothing about where they diverged.
 */
export async function verifyProofAt(
  envelope: NotarizationEnvelope,
  index: number,
  options: Pick<VerifyOptions, 'keys' | 'jwsPayloadEncoding'>,
): Promise<boolean> {
  const proof = proofsOf(envelope)[index] as EnvelopeProof;
  const path = isProofChain(envelope) ? `$.proof[${index}]` : '$.proof';
  const material = resolveVerifyingKey(proof.verificationMethod, options.keys);
  const canonical = canonicalizeToBytes(proofBase(envelope, index));

  if (proof.type === 'DataIntegrityProof') {
    const algorithm = algorithmOfCryptosuite(proof);
    // §8.2: the signature bytes are multibase base58btc. For ecdsa-jcs-2019 the
    // W3C suite fixes the fixed-width r||s form; a DER-wrapped value is
    // tolerated on the read side (see normalizeEcdsaSignature) and never
    // produced by this implementation.
    return verifySignatureBytes(
      material,
      algorithm,
      decodedSignatureOrEmpty(proof.proofValue),
      canonical,
    );
  }

  const jws = parseDetachedJws(proof, path);
  const prefix = new TextEncoder().encode(`${jws.protectedHeaderB64}.`);
  const encoding = options.jwsPayloadEncoding ?? 'auto';
  const payloads: Uint8Array[] = [];
  if (encoding === 'raw' || encoding === 'auto') payloads.push(canonical);
  if (encoding === 'base64url' || encoding === 'auto') {
    payloads.push(new TextEncoder().encode(base64urlEncode(canonical)));
  }
  for (const payload of payloads) {
    const signingInput = new Uint8Array(prefix.length + payload.length);
    signingInput.set(prefix, 0);
    signingInput.set(payload, prefix.length);
    if (await verifySignatureBytes(material, jws.algorithm, jws.signature, signingInput)) {
      return true;
    }
  }
  return false;
}

/**
 * §8.3.1 step 1d / §7.1.7.1 — the embedded mandate.
 *
 * The mandate is checked whenever one is embedded, not only in the
 * `NotaryAttested` case §8.3.1 scopes the REQUIREMENT to. In that mode it is
 * the only evidence the human authorized anything; in `PrincipalSigned` mode a
 * mandate that does not bind to this envelope is still a defect, and admitting
 * it would leave "some human granted some agent something" reading as this
 * human's grant for this send.
 */
export async function verifyEmbeddedMandate(
  envelope: NotarizationEnvelope,
  mandate: DelegationMandate,
  notaryKey: PublicKeyMaterial,
  options: Pick<VerifyOptions, 'keys'>,
): Promise<void> {
  const subject = envelope.credentialSubject;

  // Bindings first: a signature check on a mandate that is not THIS envelope's
  // parent proves only that the signature is real, and an attacker could staple
  // any validly-signed mandate to any envelope.
  if (mandate.humanPrincipalDid !== subject.humanPrincipal.id) {
    throw aphError(
      'APH_E011',
      `the embedded mandate grants authority for ${mandate.humanPrincipalDid}, but this envelope's ` +
        `principal is ${subject.humanPrincipal.id}`,
    );
  }
  if (mandate.agentDid !== subject.agent.id) {
    throw aphError(
      'APH_E011',
      `the embedded mandate grants authority to ${mandate.agentDid}, but this envelope's agent is ` +
        subject.agent.id,
    );
  }
  const namedId = subject.policy.delegationMandateId;
  if (namedId !== undefined && namedId !== null && namedId !== mandate.id) {
    throw aphError(
      'APH_E011',
      `policy.delegationMandateId names ${namedId} but the embedded mandate is ${mandate.id}`,
    );
  }

  // §6.1: the principal's signature is checked FIRST — a countersignature over
  // an unverifiable grant proves nothing.
  // A §6.1 mandate signature carries no cryptosuite member: the algorithm is
  // whatever the resolved key can perform, so the algorithm argument is the
  // key's own and the mismatch arm inside verifySignatureBytes cannot fire here.
  // §6.1 describes `notarySignature` as "Multibase- or base64url-encoded". This
  // decoder accepts multibase ONLY, deliberately: two spellings of the same
  // signature make a mandate's bytes non-unique, which is the failure mode §7.2
  // spends a whole section arguing against, and every published artifact uses
  // multibase. Filed with the mandate-base collision rather than accommodated.
  const principalKey = resolveVerifyingKey(mandate.humanPrincipalDid, options.keys);
  const principalOk = await verifySignatureBytes(
    principalKey,
    principalKey.algorithm,
    decodedSignatureOrEmpty(mandate.principalSignature),
    canonicalizeToBytes(mandateSigningBase(mandate, 'principalSignature')),
  );
  if (!principalOk) {
    throw aphError('APH_E011', `the embedded mandate's principalSignature did not verify under ${mandate.humanPrincipalDid}`);
  }

  const notaryOk = await verifySignatureBytes(
    notaryKey,
    notaryKey.algorithm,
    decodedSignatureOrEmpty(mandate.notarySignature),
    canonicalizeToBytes(mandateSigningBase(mandate, 'notarySignature')),
  );
  if (!notaryOk) {
    throw aphError('APH_E006', "the embedded mandate's notarySignature did not verify under the notary's key");
  }

  if (mandate.allowedRecipientClasses !== undefined) {
    // RFC 0005: a constrained grant refuses a class outside it AND a missing
    // declaration — a constraint escapable by omission would teach every
    // over-broad agent the same trick.
    const declared = subject.channel.recipientClass;
    if (declared === undefined || !mandate.allowedRecipientClasses.includes(declared)) {
      throw aphError(
        'APH_E020',
        `the envelope declares recipient class ${declared ?? 'nothing'}; the mandate allows ` +
          `[${mandate.allowedRecipientClasses.join(', ')}]`,
      );
    }
  }
  if (!mandate.allowedChannels.includes(subject.channel.kind)) {
    throw aphError(
      'APH_E005',
      `channel "${subject.channel.kind}" is not among the mandate's allowedChannels ` +
        `[${mandate.allowedChannels.join(', ')}]`,
    );
  }

  // §7.1.7.1 step 4 is a CHANNEL-AND-WINDOW check and MUST NOT be described as
  // more: a Delegation Mandate constrains channel, rate and time, and cannot
  // express a recipient allow-list or a content class.
  const envelopeFrom = instant(envelope.validFrom, '$.validFrom');
  if (
    envelopeFrom < instant(mandate.validFrom, '$..delegationMandate.validFrom') ||
    envelopeFrom > instant(mandate.validUntil, '$..delegationMandate.validUntil')
  ) {
    throw aphError(
      'APH_E003',
      `the envelope's validFrom (${envelope.validFrom}) falls outside the mandate's window ` +
        `(${mandate.validFrom} .. ${mandate.validUntil})`,
    );
  }
}

/** §8.3 step 8. Separate because a recipient without the body bytes skips it entirely. */
export async function verifyBodyHash(
  envelope: NotarizationEnvelope,
  bodyBytes: Uint8Array,
): Promise<void> {
  const digest = bytesToHex(await sha256(bodyBytes));
  const claimed = envelope.credentialSubject.communication.bodySha256;
  if (digest !== claimed) {
    throw aphError(
      'APH_E009',
      `the body hashes to ${digest} but the envelope binds ${claimed}`,
    );
  }
  const size = envelope.credentialSubject.communication.bodySize;
  if (size !== bodyBytes.length) {
    throw aphError(
      'APH_E009',
      `the body is ${bodyBytes.length} bytes but the envelope binds bodySize ${size}`,
    );
  }
}

/**
 * §8.3 step 8a — the revocation status check, as far as an offline verifier can
 * take it.
 *
 * §6.3.3.4's trichotomy has exactly three outcomes and "skip because I could
 * not look" is not one of them. Absent means SKIP; present-and-unresolvable
 * means REJECT with APH_E008. A verifier with no status transport can only ever
 * land in the second of those when an entry is present, so that is what this
 * does — refusing rather than quietly advancing, because an attacker who can
 * make the status check FAIL must not thereby get to choose that it is SKIPPED.
 */
export function checkCredentialStatus(envelope: NotarizationEnvelope): void {
  if (envelope.credentialStatus === undefined) return;
  throw aphError(
    'APH_E008',
    'this envelope carries a credentialStatus reference and this verifier has no §6.3.3 status ' +
      'transport, so the status could not be established. §6.3.3.4 case 2 makes that a refusal, ' +
      'never a skip.',
  );
}

/**
 * The whole §8.3 / §8.3.1 procedure.
 *
 * Accepts JSON TEXT or an already-parsed value. Text is preferred: the byte
 * bound of §7.1.7.1 is a bound on unauthenticated input, and it can only be
 * applied to bytes.
 */
export async function verifyEnvelope(
  input: string | unknown,
  options: VerifyOptions,
): Promise<VerifiedEnvelope> {
  // §7.1.7.1 Bounds: canonicalization happens BEFORE signature verification, so
  // the work done on unauthenticated input is bounded before any of it starts.
  if (typeof input === 'string') {
    const limit = options.maxEnvelopeBytes ?? RECOMMENDED_MAX_ENVELOPE_BYTES;
    const size = new TextEncoder().encode(input).length;
    if (size > limit) {
      throw new AphParseError('$', `envelope is ${size} bytes, over the ${limit}-byte bound`);
    }
  }

  // Step 1 — strict parse.
  const envelope = parseEnvelope(input);

  // Step 1a — the mode gate, then the label-versus-structure agreement. The
  // policy refusal comes first so a verifier that will not accept the weaker
  // claim spends nothing discovering it.
  if (options.requireMode !== undefined) requireAttestationMode(envelope, options.requireMode);
  const attestationMode = verifyProofStructure(envelope);

  const proofs = proofsOf(envelope);
  const notaryIndex = proofs.length - 1;
  const notaryProof = proofs[notaryIndex] as EnvelopeProof;

  if (attestationMode === 'PrincipalSigned') {
    // Steps 1b + 1c — the principal's key and proof. A verifier MUST NOT
    // proceed to the notary proof on failure: a countersignature cannot rescue
    // an unauthorized envelope.
    if (!(await verifyProofAt(envelope, 0, options))) {
      throw aphError(
        'APH_E011',
        "the principal proof did not verify over its §7.2.1 base (the envelope with the notary " +
          "proof discarded, `proof` kept as a ONE-ELEMENT ARRAY, and the principal's own proofValue emptied)",
      );
    }
    // Step 1e — issuance order (§7.2.1). A notary proof dated before the
    // principal proof it claims to have observed is not merely odd: each
    // signature must cover only bytes that existed when it was made.
    const principalProof = proofs[0] as EnvelopeProof;
    const decision = instant(
      envelope.credentialSubject.notarization.decisionTimestamp,
      '$.credentialSubject.notarization.decisionTimestamp',
    );
    if (instant(principalProof.created, '$.proof[0].created') < decision) {
      throw aphError(
        'APH_E013',
        `the principal proof is dated ${principalProof.created}, before the notary's own ` +
          `decisionTimestamp ${envelope.credentialSubject.notarization.decisionTimestamp} — the ` +
          'principal signs the envelope the notary has already prepared (§7.2.1)',
      );
    }
    if (
      instant(notaryProof.created, '$.proof[1].created') <
      instant(principalProof.created, '$.proof[0].created')
    ) {
      throw aphError(
        'APH_E013',
        `the notary proof is dated ${notaryProof.created}, before the principal proof ` +
          `(${principalProof.created}) it claims to have observed`,
      );
    }
  }

  // Steps 2-5 for the notary proof, unchanged by the chain rules.
  const notaryKey = resolveVerifyingKey(notaryProof.verificationMethod, options.keys);
  if (!(await verifyProofAt(envelope, notaryIndex, options))) {
    throw aphError('APH_E001', 'the notary proof did not verify over its §7.2.1 base');
  }

  // Step 5a — the audience check (RFC 0003). Placed with the other
  // signature-adjacent checks: after the proofs, before the window and the
  // body hash. Absence of the field is the producer's bearer-credential
  // decision and admits; absence of the verifier's OWN identity while the
  // field is present refuses, because a check a verifier may skip when
  // inconvenient is not a check.
  const audience = envelope.credentialSubject.audience;
  if (audience !== undefined) {
    if (options.verifierId === undefined) {
      throw aphError(
        'APH_E017',
        `the envelope names audience ${audience.id} and this verifier was given no identity ` +
          'to compare against — §8.3 step 5a rejects rather than skips',
      );
    }
    if (audience.id !== options.verifierId) {
      throw aphError(
        'APH_E017',
        `the envelope names audience ${audience.id}; this verifier is ${options.verifierId}`,
      );
    }
    const binding = audience.channelBinding;
    if (binding !== undefined) {
      const act = options.actCoordinates;
      if (act === undefined) {
        throw aphError(
          'APH_E017',
          'the audience carries a channelBinding and this verifier was given no act ' +
            'coordinates to compare against — §8.3 step 5a rejects rather than skips',
        );
      }
      for (const [member, bound] of Object.entries(binding)) {
        const actual = act[member];
        if (actual === undefined) {
          throw aphError(
            'APH_E017',
            `audience.channelBinding.${member} is bound and the act has no such coordinate`,
          );
        }
        if (JSON.stringify(actual) !== JSON.stringify(bound)) {
          throw aphError(
            'APH_E017',
            `audience.channelBinding.${member} is ${JSON.stringify(bound)}; the act's is ` +
              JSON.stringify(actual),
          );
        }
      }
    }
  }

  // Step 1d — the embedded mandate, once the notary key it countersigns under
  // is the one already resolved for the proof. Resolving it twice would be two
  // chances to disagree about who the notary is.
  const mandate = envelope.credentialSubject.policy.delegationMandate;
  let embeddedMandateChecked = false;
  if (mandate !== undefined && mandate !== null) {
    await verifyEmbeddedMandate(envelope, mandate, notaryKey, options);
    embeddedMandateChecked = true;
  }

  // Step 6 — the validity window, with §8.3's RECOMMENDED skew tolerance.
  const skewMs = (options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS) * 1000;
  const now = instant(options.now, 'options.now');
  const from = instant(envelope.validFrom, '$.validFrom');
  const until = instant(envelope.validUntil, '$.validUntil');
  if (now + skewMs < from || now - skewMs > until) {
    throw aphError(
      'APH_E019',
      `evaluated at ${options.now}, outside the envelope window ${envelope.validFrom} .. ` +
        `${envelope.validUntil} — the envelope's OWN window (APH_E003 is a mandate consulted ` +
        'past its expiry, and this implementation shipped that miscite until RFC 0003 gave ' +
        'the envelope window its own code)',
    );
  }

  // Step 8 — the body hash, when the transport delivered the body too.
  let bodyHashChecked = false;
  if (options.bodyBytes !== undefined) {
    await verifyBodyHash(envelope, options.bodyBytes);
    bodyHashChecked = true;
  }

  // Step 8a — revocation status.
  checkCredentialStatus(envelope);

  // Step 8b — single-use (RFC 0003). LAST, at the acceptance moment: a
  // verifier that refuses for any other reason has not consumed the id, and
  // recording here means a crash between check and act cannot spend the
  // envelope twice.
  if (options.consumedIds !== undefined) {
    if (options.consumedIds.has(envelope.id)) {
      throw aphError('APH_E018', `envelope ${envelope.id} was already accepted once`);
    }
    options.consumedIds.add(envelope.id);
  }

  return { envelope, attestationMode, bodyHashChecked, embeddedMandateChecked };
}
