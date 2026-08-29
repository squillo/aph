/**
 * The (←) cross-verification artifact: an envelope THIS implementation mints
 * for the Rust reference to verify.
 *
 * Everything here is a CONSTANT. No clock is read, no identifier is generated,
 * no key is created — the same inputs produce the same bytes on every machine
 * and every run, which is what lets `examples/ts_minted_envelope.json` be
 * committed and byte-compared. Ed25519 is deterministic in both stacks
 * (RFC 8032 derives the nonce from the key and the message), so this direction
 * of the cross-verification is pinnable; ES256 is not, and is covered by a
 * runtime self-test instead — see `test/es256_selftest.test.ts`.
 *
 * THREE DELIBERATE DIFFERENCES from `examples/principal_signed_envelope.json`,
 * each of which makes this artifact prove something that one does not:
 *
 *  1. The NOTARY is a `did:key`, not a `did:web`. The golden's notary key has
 *     to be handed to a verifier out of band; this one travels inside the
 *     identifier, so the artifact verifies with NO configuration at all — the
 *     property that makes it a fair test of a stranger's implementation.
 *  2. The body binding is REAL and INTERNALLY CONSISTENT. The shape-only
 *     fixtures pair the SHA-256 of the EMPTY STRING with a NON-ZERO `bodySize`
 *     — a combination no body can satisfy — and publish no body at all, so a
 *     verifier has nothing to hash. Here the complete body is short enough to
 *     travel in `preview` verbatim, `bodySize` is its UTF-8 length and
 *     `bodySha256` is its digest — both computed at mint time from the one body
 *     constant, so they cannot drift from each other or from the text a reader
 *     can see. §8.3 step 8 is checkable against the published file alone.
 *  3. The ids and the window are its own. Nothing here collides with the
 *     `{1..8}` channel sequence or the `d1`/`f1`/`f2`/`f3` golden tail.
 */

import { encodeDidKeyEd25519, didKeyVerificationMethod } from '../src/didkey.js';
import { bytesToHex } from '../src/baseenc.js';
import { mintPrincipalSignedEnvelope, signDelegationMandate } from '../src/mint.js';
import { ed25519DataIntegritySigner } from '../src/signers.js';
import { sha256 } from '../src/webcrypto.js';
import type { NotarizationEnvelope, PreparedEnvelope } from '../src/index.js';

import { RFC8032_TEST_2, RFC8032_TEST_3, ed25519SigningKey } from './vectors.js';

export const TS_MINTED_FILE = 'ts_minted_envelope.json';

/**
 * The complete outbound body, as bytes and as the text a reader sees.
 *
 * One line, ASCII, and short — deliberately, so it fits in `preview` whole. A
 * verifier can therefore reproduce `bodySha256` from the published envelope
 * without a second file, and the §8.3 step 8 check has something real to check.
 */
export const TS_MINTED_BODY = 'prod rollout finished at 14:02 UTC\n';

/** RFC 3339 constants. The ordering §7.2.1 requires is visible in the values. */
const VALID_FROM = '2026-06-01T11:55:00Z';
const VALID_UNTIL = '2026-06-01T12:05:00Z';
const DECISION_AT = '2026-06-01T00:00:00Z';
const PRINCIPAL_SIGNED_AT = '2026-06-01T00:00:01Z';
const NOTARY_COUNTERSIGNED_AT = '2026-06-01T00:00:02Z';
const MANDATE_VALID_FROM = '2026-05-31T00:00:00Z';
const MANDATE_VALID_UNTIL = '2026-06-02T00:00:00Z';

/** `c` for cross-verification: a tail no other example in the corpus uses. */
const ENVELOPE_ID = 'urn:uuid:00000000-0000-4000-8000-0000000000c3';
const PRINCIPAL_PROOF_ID = 'urn:uuid:00000000-0000-4000-8000-0000000000c1';
const NOTARY_PROOF_ID = 'urn:uuid:00000000-0000-4000-8000-0000000000c2';
const MANDATE_ID = 'urn:uuid:00000000-0000-4000-8000-0000000000d2';

const AGENT_DID = 'did:web:agent.squillo.com';
const CHANNEL_KIND = 'slack';

/** The `did:key` identifiers, DERIVED from the published seeds rather than pasted. */
export function tsMintedPrincipalDid(): string {
  return encodeDidKeyEd25519(RFC8032_TEST_2.publicKey);
}

export function tsMintedNotaryDid(): string {
  return encodeDidKeyEd25519(RFC8032_TEST_3.publicKey);
}

/**
 * Builds and signs the artifact, in the §7.2.1 issuance order.
 *
 * Async because the body digest is taken through SubtleCrypto like every other
 * hash in this implementation — there is no second SHA-256 anywhere here, which
 * is the only way `bodySha256` and the verifier's step-8 recomputation cannot
 * disagree.
 */
export async function buildTsMintedEnvelope(): Promise<NotarizationEnvelope> {
  const principalDid = tsMintedPrincipalDid();
  const notaryDid = tsMintedNotaryDid();
  const principalMethod = didKeyVerificationMethod(principalDid);
  const notaryMethod = didKeyVerificationMethod(notaryDid);

  const principalKey = await ed25519SigningKey(RFC8032_TEST_2);
  const notaryKey = await ed25519SigningKey(RFC8032_TEST_3);
  const principalSigner = ed25519DataIntegritySigner(principalKey, principalMethod);
  const notarySigner = ed25519DataIntegritySigner(notaryKey, notaryMethod);

  const bodyBytes = new TextEncoder().encode(TS_MINTED_BODY);

  // Step 1 of §7.2.1 in two parts: the standing grant the notary already holds,
  // then the envelope it prepares under that grant.
  const mandate = await signDelegationMandate({
    mandate: {
      id: MANDATE_ID,
      humanPrincipalDid: principalDid,
      agentDid: AGENT_DID,
      allowedChannels: [CHANNEL_KIND],
      rateLimitPerHour: 20,
      validFrom: MANDATE_VALID_FROM,
      validUntil: MANDATE_VALID_UNTIL,
    },
    principal: principalSigner,
    notary: notarySigner,
  });

  const prepared: PreparedEnvelope = {
    aphVersion: '0.1',
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/aph/v1'],
    type: ['VerifiableCredential', 'AgentSendAuthorizationCredential'],
    id: ENVELOPE_ID,
    // §7.3.1: in PrincipalSigned mode the HUMAN is the issuing authority and
    // the notary is a witness, so `issuer` is the principal's DID.
    issuer: principalDid,
    validFrom: VALID_FROM,
    validUntil: VALID_UNTIL,
    credentialSubject: {
      humanPrincipal: { id: principalDid, displayName: 'Scott Wyatt' },
      agent: {
        id: AGENT_DID,
        agentCardUri: 'https://agent.squillo.com/.well-known/agent-card.json',
        displayName: 'Squillo Concierge',
        version: '1.0',
      },
      channel: {
        kind: CHANNEL_KIND,
        recipientAddressing: {
          teamId: 'T01234567',
          channelId: 'C01234567',
          parentTs: '1716249600.000100',
        },
      },
      communication: {
        contentClass: 'Reply',
        bodySha256: bytesToHex(await sha256(bodyBytes)),
        bodySize: bodyBytes.length,
        previewLines: 1,
        // The whole body: see the module docs for why that is the point.
        preview: TS_MINTED_BODY,
      },
      policy: {
        decision: 'AlwaysAllow',
        matchedScope: 'per-channel',
        delegationMandateId: MANDATE_ID,
        actChain: [],
        attestationMode: 'PrincipalSigned',
        delegationMandate: mandate,
      },
      notarization: {
        notaryService: {
          id: notaryDid,
          name: 'Squillo Notary Service',
          version: '0.1.0',
        },
        decisionTimestamp: DECISION_AT,
        decisionLatencyMs: 12,
      },
    },
    // Emitted explicitly as null to match the corpus's existing shape: every
    // published example carries it, and an artifact that silently dropped it
    // would be testing a shape the reference has never emitted.
    linkedMandate: null,
  };

  // Steps 2 and 3: the principal signs what the notary prepared, then the
  // notary countersigns what the principal signed.
  return mintPrincipalSignedEnvelope({
    prepared,
    principal: principalSigner,
    principalProof: { id: PRINCIPAL_PROOF_ID, created: PRINCIPAL_SIGNED_AT },
    notary: notarySigner,
    notaryProof: { id: NOTARY_PROOF_ID, created: NOTARY_COUNTERSIGNED_AT },
  });
}

/** An instant inside the artifact's validity window, for verification tests. */
export const TS_MINTED_EVALUATION_INSTANT = '2026-06-01T12:00:00Z';
