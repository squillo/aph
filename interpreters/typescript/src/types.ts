/**
 * The v0.1 wire shape (spec §7.1, §6.1, §6.3.3.1) as TypeScript types.
 *
 * These interfaces describe the JSON EXACTLY as it appears on the wire — same
 * member names, same nesting, no case transform. That is deliberate: the same
 * object the parser validates is the object the canonicalizer serializes, so
 * there is no model-to-wire mapping that could drift and change which bytes a
 * signature covers.
 */

import type { JsonObject } from './jcs.js';

export const CHANNEL_KINDS = [
  'slack',
  'email',
  'discord',
  'teams',
  'whatsapp',
  'google_chat',
  'imessage',
  'service',
  'squillo',
] as const;
export type ChannelKind = (typeof CHANNEL_KINDS)[number];

/**
 * §7.1.5 (RFC 0005): who CONSUMES what lands on the channel. The second
 * dimension the a2a_email request was really asking for — a refinement that
 * must apply to every kind is not a kind. Closed at two deliberately; grown
 * by amendment like every closed set here.
 */
export const RECIPIENT_CLASSES = ['human', 'agent'] as const;
export type RecipientClass = (typeof RECIPIENT_CLASSES)[number];

export const CONTENT_CLASSES = [
  'Reply',
  'New',
  'Mention',
  'DM',
  'Channel',
  'BulkSend',
  'Broadcast',
  'Mutation',
] as const;
export type ContentClass = (typeof CONTENT_CLASSES)[number];

export const POLICY_DECISIONS = ['AlwaysAllow', 'AskEveryTime', 'NeverAllow'] as const;
export type PolicyDecision = (typeof POLICY_DECISIONS)[number];

export const ATTESTATION_MODES = ['PrincipalSigned', 'NotaryAttested'] as const;
export type AttestationMode = (typeof ATTESTATION_MODES)[number];

export const PROOF_TYPES = ['DataIntegrityProof', 'JsonWebSignature2020'] as const;
export type ProofType = (typeof PROOF_TYPES)[number];

/** §8.1: `eddsa-jcs-2022` implies EdDSA, `ecdsa-jcs-2019` implies ES256. */
export const CRYPTOSUITES = ['eddsa-jcs-2022', 'ecdsa-jcs-2019'] as const;
export type Cryptosuite = (typeof CRYPTOSUITES)[number];

export const PROOF_PURPOSES = ['assertionMethod', 'authentication'] as const;
export type ProofPurpose = (typeof PROOF_PURPOSES)[number];

export const APH_VERSION = '0.1';
export const CONTEXT_VC_V2 = 'https://www.w3.org/ns/credentials/v2';
export const CONTEXT_APH_V1 = 'https://w3id.org/aph/v1';
export const TYPE_VERIFIABLE_CREDENTIAL = 'VerifiableCredential';
export const TYPE_AGENT_SEND_AUTHORIZATION = 'AgentSendAuthorizationCredential';

/** §7.1.7.1: a verifier bounds work on unauthenticated input before canonicalizing. */
export const RECOMMENDED_MAX_ENVELOPE_BYTES = 65536;

/** §7.1.6: `preview` MUST NOT exceed MAX_BODY_PREVIEW_BYTES. */
export const MAX_BODY_PREVIEW_BYTES = 8192;

/** §8.3 step 6 RECOMMENDED clock-skew tolerance. */
export const DEFAULT_CLOCK_SKEW_SECONDS = 60;

export interface HumanPrincipalRef {
  id: string;
  displayName: string;
}

export interface AgentRef {
  id: string;
  agentCardUri?: string;
  displayName: string;
  version: string;
}

export interface ChannelDescriptor {
  kind: ChannelKind;
  /**
   * §7.1.5 (RFC 0005): optional, omitted when absent — absence is "no
   * claim", and a sender's value is a CLAIM either way: it constrains an
   * honest-but-over-broad agent, not a hostile one.
   */
  recipientClass?: RecipientClass;
  /** §7.4: channel-shaped and OPAQUE — its sub-fields are never strict-parsed. */
  recipientAddressing: JsonObject;
}

export interface CommunicationDescriptor {
  contentClass: ContentClass;
  bodySha256: string;
  bodySize: number;
  previewLines: number;
  preview: string;
}

export interface DelegationMandate {
  id: string;
  humanPrincipalDid: string;
  agentDid: string;
  /**
   * §6.1 channel scope. TYPED to the §7.1.5 closed set, not `string[]`: the
   * only question ever asked of this list is whether a `channel.kind` — itself
   * closed — is in it, so an entry outside the set is unmatchable, and a
   * `string[]` would let this implementation MINT a grant the reference
   * refuses to read. The parser closes the same set on the way in.
   */
  allowedChannels: ChannelKind[];
  /**
   * §6.1 (RFC 0005): recipient classes the human granted. ABSENT means
   * unconstrained — which every pre-RFC-0005 signed grant is, and an absent
   * member keeps those grants' signed bytes intact. An EMPTY array is a
   * coherent grant allowing no consumer at all: not the same statement.
   */
  allowedRecipientClasses?: RecipientClass[];
  rateLimitPerHour?: number | null;
  validFrom: string;
  validUntil: string;
  principalSignature: string;
  notarySignature: string;
}

export interface PolicyDescriptor {
  decision: PolicyDecision;
  matchedScope: string;
  delegationMandateId?: string | null;
  /** §7.1.7: ABSENT means `NotaryAttested`. Never read as "unknown". */
  attestationMode?: AttestationMode;
  delegationMandate?: DelegationMandate | null;
  actChain?: string[];
}

export interface NotaryServiceRef {
  id: string;
  name: string;
  version: string;
  attestedDigest?: string;
  attestationUri?: string;
}

export interface NotarizationMetadata {
  notaryService: NotaryServiceRef;
  decisionTimestamp: string;
  decisionLatencyMs: number;
}

export interface AppleAurAcceptance {
  userId: string;
  deviceId: string;
  aurVersionHash: string;
  acceptedAt: string;
  documentKind: string;
}

export interface CredentialSubject {
  humanPrincipal: HumanPrincipalRef;
  agent: AgentRef;
  channel: ChannelDescriptor;
  communication: CommunicationDescriptor;
  policy: PolicyDescriptor;
  notarization: NotarizationMetadata;
  appleAurAcceptance?: AppleAurAcceptance;
  audience?: Audience;
  actClassification?: ActClassification;
}

/**
 * §7.1.13 (RFC 0003): who may accept this envelope. Absence is the
 * producer's DECISION to issue a bearer credential — an envelope without
 * this member is byte-identical to one minted before the field existed.
 */
export interface Audience {
  /** DID of the endpoint entitled to accept (§8.3 step 5a, APH_E017). */
  id: string;
  /**
   * Restates the delivery coordinates the envelope authorizes so an
   * envelope for one channel cannot be spent on another. Open members by
   * design: everything beside `kind` IS coordinate data, compared
   * member-by-member against the act's coordinates.
   */
  channelBinding?: AudienceChannelBinding;
}

/** §7.1.13: `kind` from the closed set; every other member is a coordinate. */
export interface AudienceChannelBinding {
  kind: ChannelKind;
  [coordinate: string]: unknown;
}

/**
 * §7.1.12: what the sender says this act MEANS, against vocabularies both
 * parties can resolve independently.
 *
 * Both members are arrays for different reasons. `labels` because one act
 * carries verdicts from several families at once. `vocabularies` because an
 * overlay is a separate published artifact with its own digest — a verdict
 * folded from a base and a tightening overlay came from two artifacts, and
 * naming one would put a false statement inside a signature.
 */
export interface ActClassification {
  vocabularies: VocabularyRef[];
  /** Each `FAMILY/LABEL`. A bare label names nothing: the family scopes it. */
  labels: string[];
}

/** §7.1.12: a published vocabulary, named and pinned by its own digest. */
export interface VocabularyRef {
  name: string;
  version: string;
  /** The bundle's `integrity` value, verbatim — never a re-encoding. */
  digest: string;
}

export interface VaultMutation {
  /** §7.5.3: an internally-tagged discriminator object with snake_case interior keys. */
  kind: JsonObject;
  grant_scope_id: string;
  ap2_signed_payload_b64?: string;
}

export interface LinkedMandate {
  ap2IntentMandateUri?: string | null;
  ap2SignedPayloadB64?: string | null;
  vaultMutation?: VaultMutation;
}

/** §6.3.3.1 `BitstringStatusListEntry`. */
export interface CredentialStatusEntry {
  id?: string;
  type: 'BitstringStatusListEntry';
  statusPurpose: 'revocation';
  /** §6.3.3.6: a base-10 integer IN A STRING, never a JSON number. */
  statusListIndex: string;
  statusListCredential: string;
}

export interface EnvelopeProof {
  id?: string;
  type: ProofType;
  cryptosuite?: Cryptosuite;
  verificationMethod: string;
  created: string;
  proofPurpose: ProofPurpose;
  previousProof?: string;
  proofValue: string;
}

export interface NotarizationEnvelope {
  aphVersion: string;
  '@context': string[];
  type: string[];
  id: string;
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: CredentialSubject;
  linkedMandate?: LinkedMandate | null;
  /** §7.1.1: OMITTED when absent — never emitted as `null`. */
  credentialStatus?: CredentialStatusEntry;
  proof: EnvelopeProof | EnvelopeProof[];
}

/** The two proof carriages of §7.1.11, discriminated by JSON shape alone. */
export function proofsOf(envelope: NotarizationEnvelope): EnvelopeProof[] {
  return Array.isArray(envelope.proof) ? envelope.proof : [envelope.proof];
}

export function isProofChain(envelope: NotarizationEnvelope): boolean {
  return Array.isArray(envelope.proof);
}
