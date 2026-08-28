/**
 * §8.3 step 1 — strict parse.
 *
 * "Strict" means an unknown member is a HARD ERROR, never a dropped field:
 * §7.1's forward-compatibility behaviour is to fail fast on spec drift, so a
 * producer cannot smuggle a claim past a verifier that does not understand it.
 * The one exception is `channel.recipientAddressing` (§7.4), whose sub-fields
 * are channel-shaped and opaque.
 *
 * The rules here are derived from the specification's field tables, not from
 * any other implementation's serializer configuration. Where the spec closes a
 * value set, this parser closes it too — an unrecognized member of a closed set
 * is a failure and never something to ignore (§6.3.3.5 states the reasoning in
 * general terms: a producer could otherwise disable a check on any verifier
 * simply by writing a word that verifier has never seen).
 */

import { AphParseError } from './errors.js';
import {
  APH_VERSION,
  ATTESTATION_MODES,
  CHANNEL_KINDS,
  CONTENT_CLASSES,
  CONTEXT_APH_V1,
  CONTEXT_VC_V2,
  CRYPTOSUITES,
  MAX_BODY_PREVIEW_BYTES,
  POLICY_DECISIONS,
  PROOF_PURPOSES,
  PROOF_TYPES,
  TYPE_AGENT_SEND_AUTHORIZATION,
  TYPE_VERIFIABLE_CREDENTIAL,
  type NotarizationEnvelope,
} from './types.js';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function object(value: unknown, path: string): Record<string, unknown> {
  if (!isPlainObject(value)) throw new AphParseError(path, 'expected a JSON object');
  return value;
}

/**
 * The strict-parse primitive. Every object in the wire shape names its complete
 * member set here, so adding a field to the protocol means adding it in exactly
 * one place — and forgetting to means the parser refuses it, loudly, which is
 * the failure mode worth having.
 */
function members(
  value: unknown,
  path: string,
  required: readonly string[],
  optional: readonly string[],
): Record<string, unknown> {
  const record = object(value, path);
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new AphParseError(
        `${path}.${key}`,
        `unknown member — §7.1 requires strict deserialization; allowed here: ${[...allowed]
          .sort()
          .join(', ')}`,
      );
    }
  }
  for (const key of required) {
    if (!(key in record)) throw new AphParseError(`${path}.${key}`, 'required member is missing');
  }
  return record;
}

function str(record: Record<string, unknown>, path: string, key: string): string {
  const value = record[key];
  if (typeof value !== 'string') throw new AphParseError(`${path}.${key}`, 'expected a string');
  return value;
}

function optStr(record: Record<string, unknown>, path: string, key: string): string | undefined {
  return key in record ? str(record, path, key) : undefined;
}

function nullableStr(
  record: Record<string, unknown>,
  path: string,
  key: string,
): string | null | undefined {
  if (!(key in record)) return undefined;
  if (record[key] === null) return null;
  return str(record, path, key);
}

function uint(record: Record<string, unknown>, path: string, key: string): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new AphParseError(`${path}.${key}`, 'expected a non-negative integer');
  }
  return value;
}

function stringArray(record: Record<string, unknown>, path: string, key: string): string[] {
  const value = record[key];
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new AphParseError(`${path}.${key}`, 'expected an array of strings');
  }
  return value as string[];
}

function closedEnum<T extends string>(
  record: Record<string, unknown>,
  path: string,
  key: string,
  allowed: readonly T[],
): T {
  const value = str(record, path, key);
  if (!(allowed as readonly string[]).includes(value)) {
    throw new AphParseError(
      `${path}.${key}`,
      `"${value}" is not in the closed set {${allowed.join(', ')}}`,
    );
  }
  return value as T;
}

/**
 * The array form of `closedEnum`, for a member whose ENTRIES are each drawn
 * from a closed set.
 *
 * Kept separate from `stringArray` because the two assert different things:
 * one is a shape, this is a VOCABULARY. A closed-set array checked only for
 * shape survives the parse and fails later, at the membership test that
 * consumes it — and there a value no implementation defines and a value that is
 * simply out of scope produce the identical answer, so a corrupt grant is
 * reported as an ordinary scope denial and whoever reads the refusal is sent to
 * fix the wrong thing. Refusing at the READ keeps those two events apart, and
 * the index in the path names which entry did it.
 */
function closedEnumArray<T extends string>(
  record: Record<string, unknown>,
  path: string,
  key: string,
  allowed: readonly T[],
): T[] {
  const values = stringArray(record, path, key);
  values.forEach((value, index) => {
    if (!(allowed as readonly string[]).includes(value)) {
      throw new AphParseError(
        `${path}.${key}[${index}]`,
        `"${value}" is not in the closed set {${allowed.join(', ')}}`,
      );
    }
  });
  return values as T[];
}

const LOWERCASE_SHA256_HEX = /^[0-9a-f]{64}$/;

function parseHumanPrincipal(value: unknown, path: string): void {
  const record = members(value, path, ['id', 'displayName'], []);
  str(record, path, 'id');
  str(record, path, 'displayName');
}

function parseAgent(value: unknown, path: string): void {
  const record = members(value, path, ['id', 'displayName', 'version'], ['agentCardUri']);
  str(record, path, 'id');
  str(record, path, 'displayName');
  str(record, path, 'version');
  optStr(record, path, 'agentCardUri');
}

function parseChannel(value: unknown, path: string): void {
  const record = members(value, path, ['kind', 'recipientAddressing'], []);
  closedEnum(record, path, 'kind', CHANNEL_KINDS);
  // §7.4: opaque by design. Strict-parsing a channel vendor's addressing blob
  // would make every new field that vendor adds a protocol break.
  object(record.recipientAddressing, `${path}.recipientAddressing`);
}

function parseCommunication(value: unknown, path: string): void {
  const record = members(
    value,
    path,
    ['contentClass', 'bodySha256', 'bodySize', 'previewLines', 'preview'],
    [],
  );
  closedEnum(record, path, 'contentClass', CONTENT_CLASSES);
  const digest = str(record, path, 'bodySha256');
  if (!LOWERCASE_SHA256_HEX.test(digest)) {
    throw new AphParseError(`${path}.bodySha256`, 'expected 64 lowercase hex characters');
  }
  uint(record, path, 'bodySize');
  uint(record, path, 'previewLines');
  const preview = str(record, path, 'preview');
  // §7.1.6 bounds the preview in BYTES, not characters: a multi-byte emoji in a
  // preview would pass a character-count check and fail a conformant one.
  if (new TextEncoder().encode(preview).length > MAX_BODY_PREVIEW_BYTES) {
    throw new AphParseError(
      `${path}.preview`,
      `exceeds MAX_BODY_PREVIEW_BYTES (${MAX_BODY_PREVIEW_BYTES} bytes)`,
    );
  }
}

export function parseDelegationMandate(value: unknown, path: string): void {
  const record = members(
    value,
    path,
    [
      'id',
      'humanPrincipalDid',
      'agentDid',
      'allowedChannels',
      'validFrom',
      'validUntil',
      'principalSignature',
      'notarySignature',
    ],
    ['rateLimitPerHour'],
  );
  str(record, path, 'id');
  str(record, path, 'humanPrincipalDid');
  str(record, path, 'agentDid');
  // §6.1's field table spells this "array of strings" and its column describes
  // the strings as CHANNEL KINDS, which §7.1.5 closes. The set is what governs:
  // §7.1.7.1 step 4 asks whether `channel.kind` — itself closed — appears here,
  // so an entry outside the set can never match anything, and admitting one
  // would leave a grant that reads as authority while conveying none. §6.3.3.5
  // states the general rule this is an instance of: an unrecognized member of a
  // closed set is a failure, or a producer disables a check on any verifier by
  // writing a word that verifier has never seen.
  const channels = closedEnumArray(record, path, 'allowedChannels', CHANNEL_KINDS);
  if (channels.length === 0) {
    throw new AphParseError(`${path}.allowedChannels`, '§6.1 requires at least one entry');
  }
  if ('rateLimitPerHour' in record && record.rateLimitPerHour !== null) {
    uint(record, path, 'rateLimitPerHour');
  }
  const from = str(record, path, 'validFrom');
  const until = str(record, path, 'validUntil');
  if (!(from < until)) {
    throw new AphParseError(
      `${path}.validFrom`,
      '§6.1 requires validFrom to sort before validUntil',
    );
  }
  str(record, path, 'principalSignature');
  str(record, path, 'notarySignature');
}

function parsePolicy(value: unknown, path: string): void {
  const record = members(
    value,
    path,
    ['decision', 'matchedScope'],
    ['delegationMandateId', 'attestationMode', 'delegationMandate', 'actChain'],
  );
  closedEnum(record, path, 'decision', POLICY_DECISIONS);
  str(record, path, 'matchedScope');
  nullableStr(record, path, 'delegationMandateId');
  if ('attestationMode' in record) closedEnum(record, path, 'attestationMode', ATTESTATION_MODES);
  if ('delegationMandate' in record && record.delegationMandate !== null) {
    parseDelegationMandate(record.delegationMandate, `${path}.delegationMandate`);
  }
  if ('actChain' in record) stringArray(record, path, 'actChain');
}

function parseNotarization(value: unknown, path: string): void {
  const record = members(
    value,
    path,
    ['notaryService', 'decisionTimestamp', 'decisionLatencyMs'],
    [],
  );
  const servicePath = `${path}.notaryService`;
  const service = members(
    record.notaryService,
    servicePath,
    ['id', 'name', 'version'],
    // §7.1.9: declared here and not only in §15, because a field a notary MAY
    // send has to appear in the shape a verifier parses or conformant verifiers
    // would reject conformant notaries.
    ['attestedDigest', 'attestationUri'],
  );
  str(service, servicePath, 'id');
  str(service, servicePath, 'name');
  str(service, servicePath, 'version');
  optStr(service, servicePath, 'attestedDigest');
  optStr(service, servicePath, 'attestationUri');
  str(record, path, 'decisionTimestamp');
  uint(record, path, 'decisionLatencyMs');
}

function parseAppleAurAcceptance(value: unknown, path: string): void {
  const record = members(
    value,
    path,
    ['userId', 'deviceId', 'aurVersionHash', 'acceptedAt', 'documentKind'],
    [],
  );
  for (const key of ['userId', 'deviceId', 'aurVersionHash', 'acceptedAt', 'documentKind']) {
    str(record, path, key);
  }
}

function parseCredentialSubject(value: unknown, path: string): void {
  const record = members(
    value,
    path,
    ['humanPrincipal', 'agent', 'channel', 'communication', 'policy', 'notarization'],
    ['appleAurAcceptance'],
  );
  parseHumanPrincipal(record.humanPrincipal, `${path}.humanPrincipal`);
  parseAgent(record.agent, `${path}.agent`);
  parseChannel(record.channel, `${path}.channel`);
  parseCommunication(record.communication, `${path}.communication`);
  parsePolicy(record.policy, `${path}.policy`);
  parseNotarization(record.notarization, `${path}.notarization`);
  if ('appleAurAcceptance' in record) {
    parseAppleAurAcceptance(record.appleAurAcceptance, `${path}.appleAurAcceptance`);
  }
}

function parseLinkedMandate(value: unknown, path: string): void {
  const record = members(
    value,
    path,
    [],
    ['ap2IntentMandateUri', 'ap2SignedPayloadB64', 'vaultMutation'],
  );
  nullableStr(record, path, 'ap2IntentMandateUri');
  nullableStr(record, path, 'ap2SignedPayloadB64');
  if ('vaultMutation' in record) {
    const mutationPath = `${path}.vaultMutation`;
    const mutation = members(
      record.vaultMutation,
      mutationPath,
      ['kind', 'grant_scope_id'],
      ['ap2_signed_payload_b64'],
    );
    // §7.5.3's `kind` is an internally-tagged discriminator whose variant fields
    // differ per variant, so its interior is validated only as far as the tag.
    // Its keys are snake_case ON PURPOSE (§7.5.3 interior key-casing note):
    // re-canonicalizing an already-signed envelope must not change its bytes.
    const kind = object(mutation.kind, `${mutationPath}.kind`);
    if (typeof kind.kind !== 'string') {
      throw new AphParseError(`${mutationPath}.kind.kind`, 'expected a string variant tag');
    }
    str(mutation, mutationPath, 'grant_scope_id');
    optStr(mutation, mutationPath, 'ap2_signed_payload_b64');
  }
}

function parseCredentialStatus(value: unknown, path: string): void {
  const record = members(
    value,
    path,
    ['type', 'statusPurpose', 'statusListIndex', 'statusListCredential'],
    ['id'],
  );
  optStr(record, path, 'id');
  closedEnum(record, path, 'type', ['BitstringStatusListEntry'] as const);
  // §6.3.3.5: the purpose set is CLOSED at exactly one member. "suspension" is
  // deliberately excluded because §6.3.2 forbids re-activation.
  closedEnum(record, path, 'statusPurpose', ['revocation'] as const);
  const index = str(record, path, 'statusListIndex');
  // §6.3.3.6: a string, because in a runtime where every JSON number is an
  // IEEE-754 double an index past 2^53 rounds silently and reads a DIFFERENT
  // bit — answering with full confidence a question about another mandate.
  if (!/^\d+$/.test(index)) {
    throw new AphParseError(`${path}.statusListIndex`, 'expected a base-10 integer in a string');
  }
  const url = str(record, path, 'statusListCredential');
  if (!url.startsWith('https://')) {
    throw new AphParseError(`${path}.statusListCredential`, '§6.3.3.2 requires an https: URL');
  }
}

function parseProof(value: unknown, path: string): void {
  const record = members(
    value,
    path,
    ['type', 'verificationMethod', 'created', 'proofPurpose', 'proofValue'],
    ['id', 'cryptosuite', 'previousProof'],
  );
  optStr(record, path, 'id');
  const type = closedEnum(record, path, 'type', PROOF_TYPES);
  if ('cryptosuite' in record) {
    closedEnum(record, path, 'cryptosuite', CRYPTOSUITES);
    if (type === 'JsonWebSignature2020') {
      throw new AphParseError(
        `${path}.cryptosuite`,
        '§7.1.11 omits cryptosuite for JsonWebSignature2020 — the algorithm is in the JWS header',
      );
    }
  }
  // A DataIntegrityProof with no cryptosuite is NOT refused here: §8.1 makes an
  // omitted algorithm declaration a verification failure (APH_E010), and
  // reporting it as a shape error would lose that code.
  str(record, path, 'verificationMethod');
  str(record, path, 'created');
  closedEnum(record, path, 'proofPurpose', PROOF_PURPOSES);
  optStr(record, path, 'previousProof');
  str(record, path, 'proofValue');
}

/**
 * Strict-parses an envelope from JSON text or an already-decoded value.
 *
 * Returns the SAME object it validated, typed — not a copy, and not a model
 * built from it. Canonicalization then runs over the bytes' own structure.
 */
export function parseEnvelope(input: string | unknown): NotarizationEnvelope {
  let value: unknown = input;
  if (typeof input === 'string') {
    try {
      value = JSON.parse(input) as unknown;
    } catch (cause) {
      throw new AphParseError('$', `not valid JSON: ${(cause as Error).message}`);
    }
  }

  const path = '$';
  const record = members(
    value,
    path,
    [
      'aphVersion',
      '@context',
      'type',
      'id',
      'issuer',
      'validFrom',
      'validUntil',
      'credentialSubject',
      'proof',
    ],
    ['linkedMandate', 'credentialStatus'],
  );

  const version = str(record, path, 'aphVersion');
  if (version !== APH_VERSION) {
    throw new AphParseError(
      '$.aphVersion',
      `MUST be "${APH_VERSION}" for this draft, got "${version}"`,
    );
  }

  const context = stringArray(record, path, '@context');
  if (context[0] !== CONTEXT_VC_V2 || context[1] !== CONTEXT_APH_V1) {
    throw new AphParseError(
      '$.@context',
      `§7.1.1 requires "${CONTEXT_VC_V2}" first, then "${CONTEXT_APH_V1}"`,
    );
  }

  const types = stringArray(record, path, 'type');
  for (const required of [TYPE_VERIFIABLE_CREDENTIAL, TYPE_AGENT_SEND_AUTHORIZATION]) {
    if (!types.includes(required)) {
      throw new AphParseError('$.type', `§7.1.1 requires "${required}" among the type entries`);
    }
  }

  str(record, path, 'id');
  str(record, path, 'issuer');
  str(record, path, 'validFrom');
  str(record, path, 'validUntil');
  parseCredentialSubject(record.credentialSubject, '$.credentialSubject');

  if ('linkedMandate' in record && record.linkedMandate !== null) {
    parseLinkedMandate(record.linkedMandate, '$.linkedMandate');
  }

  if ('credentialStatus' in record) {
    // §7.1.1: OMITTED when absent, never `null` — an envelope carrying no status
    // reference stays byte-identical to a pre-revision envelope, which is what
    // keeps extension-unaware fixtures and their signatures valid.
    if (record.credentialStatus === null) {
      throw new AphParseError(
        '$.credentialStatus',
        '§7.1.1 omits this member when absent and MUST NOT emit it as null',
      );
    }
    parseCredentialStatus(record.credentialStatus, '$.credentialStatus');
    // §6.3.3.1: a status reference with nothing to be the status OF is
    // malformed, not merely unhelpful.
    const policy = object(
      object(record.credentialSubject, '$.credentialSubject').policy,
      '$.credentialSubject.policy',
    );
    if (policy.delegationMandateId === null || policy.delegationMandateId === undefined) {
      throw new AphParseError(
        '$.credentialStatus',
        '§6.3.3.1 requires a non-null credentialSubject.policy.delegationMandateId beside it',
      );
    }
  }

  const proof = record.proof;
  if (Array.isArray(proof)) {
    // Length is NOT policed here: §7.1.11 refuses a chain of the wrong length
    // with APH_E013, and turning that into a parse error would lose the code
    // that tells a recipient the chain was the problem.
    proof.forEach((entry, index) => parseProof(entry, `$.proof[${index}]`));
  } else {
    parseProof(proof, '$.proof');
  }

  return record as unknown as NotarizationEnvelope;
}
