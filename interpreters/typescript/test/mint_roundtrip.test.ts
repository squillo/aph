/**
 * WHY THIS FILE EXISTS: a verifier and a minter can agree with each other and
 * both be wrong — that is precisely the failure a single implementation cannot
 * detect. These tests do not prove interoperability (the golden and the Rust
 * cross-verify test do that); they prove the two halves of THIS implementation
 * meet, and they exercise the §7.1.7.1 rules that need a FRESHLY SIGNED mandate
 * to reach at all. Editing the golden's embedded mandate breaks the envelope
 * proofs that cover it, so `APH_E005` and the mandate-window `APH_E003` are
 * unreachable from the published corpus and would otherwise go untested.
 *
 * WHAT THEY PIN: the §7.2.1 issuance order enforced by the shape of the mint
 * API, both proof carriages of §7.1.11, §6.1 mandate signing, the channel-scope
 * refusal, the mandate-window refusal, and byte-stable serialization.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { AphError } from '../src/errors.js';
import { encodeDidKeyEd25519, didKeyVerificationMethod } from '../src/didkey.js';
import { bytesToHex } from '../src/baseenc.js';
import {
  mintNotaryAttestedEnvelope,
  mintPrincipalSignedEnvelope,
  signDelegationMandate,
  type PreparedEnvelope,
} from '../src/mint.js';
import { parseEnvelope } from '../src/parse.js';
import { serializeEnvelopeDocument } from '../src/serialize.js';
import { ed25519DataIntegritySigner } from '../src/signers.js';
import { verifyEnvelope } from '../src/verify.js';
import { sha256 } from '../src/webcrypto.js';
import type { ChannelKind, DelegationMandate } from '../src/types.js';
import { RFC8032_TEST_2, RFC8032_TEST_3, ed25519SigningKey } from '../testkit/vectors.js';

const NOW = '2026-06-01T12:00:00Z';
const BODY = 'a short body, published whole in preview so step 8 has something to check\n';

/**
 * A PARAMETERIZED builder, deliberately separate from
 * `testkit/ts_minted.ts`'s fixed one: the committed artifact must never gain a
 * knob, or a future test could change the bytes the Rust side verifies.
 */
async function prepare(options: {
  readonly principalDid: string;
  readonly notaryDid: string;
  readonly mandate?: DelegationMandate;
  readonly validFrom?: string;
  readonly channelKind?: 'slack' | 'email';
  /** §7.1.7: the human in PrincipalSigned mode, the notary in NotaryAttested. */
  readonly issuer?: string;
}): Promise<PreparedEnvelope> {
  const bodyBytes = new TextEncoder().encode(BODY);
  return {
    aphVersion: '0.1',
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/aph/v1'],
    type: ['VerifiableCredential', 'AgentSendAuthorizationCredential'],
    id: 'urn:uuid:00000000-0000-4000-8000-0000000000a1',
    issuer: options.issuer ?? options.principalDid,
    validFrom: options.validFrom ?? '2026-06-01T00:00:00Z',
    validUntil: '2026-06-02T00:00:00Z',
    credentialSubject: {
      humanPrincipal: { id: options.principalDid, displayName: 'Scott Wyatt' },
      agent: { id: 'did:web:agent.squillo.com', displayName: 'Squillo Concierge', version: '1.0' },
      channel: {
        kind: options.channelKind ?? 'slack',
        recipientAddressing: { teamId: 'T01234567', channelId: 'C01234567' },
      },
      communication: {
        contentClass: 'Reply',
        bodySha256: bytesToHex(await sha256(bodyBytes)),
        bodySize: bodyBytes.length,
        previewLines: 1,
        preview: BODY,
      },
      policy: {
        decision: 'AlwaysAllow',
        matchedScope: 'per-channel',
        delegationMandateId: options.mandate?.id ?? null,
        attestationMode: 'PrincipalSigned',
        delegationMandate: options.mandate ?? null,
      },
      notarization: {
        notaryService: { id: options.notaryDid, name: 'Test Notary', version: '0.1.0' },
        decisionTimestamp: '2026-06-01T00:00:00Z',
        decisionLatencyMs: 7,
      },
    },
    linkedMandate: null,
  };
}

async function signers(): Promise<{
  principalDid: string;
  notaryDid: string;
  principal: ReturnType<typeof ed25519DataIntegritySigner>;
  notary: ReturnType<typeof ed25519DataIntegritySigner>;
}> {
  const principalDid = encodeDidKeyEd25519(RFC8032_TEST_2.publicKey);
  const notaryDid = encodeDidKeyEd25519(RFC8032_TEST_3.publicKey);
  return {
    principalDid,
    notaryDid,
    principal: ed25519DataIntegritySigner(
      await ed25519SigningKey(RFC8032_TEST_2),
      didKeyVerificationMethod(principalDid),
    ),
    notary: ed25519DataIntegritySigner(
      await ed25519SigningKey(RFC8032_TEST_3),
      didKeyVerificationMethod(notaryDid),
    ),
  };
}

async function mandateFor(options: {
  readonly principalDid: string;
  readonly allowedChannels: ChannelKind[];
  readonly validFrom?: string;
  readonly validUntil?: string;
}): Promise<DelegationMandate> {
  const { principal, notary } = await signers();
  return signDelegationMandate({
    mandate: {
      id: 'urn:uuid:00000000-0000-4000-8000-0000000000a2',
      humanPrincipalDid: options.principalDid,
      agentDid: 'did:web:agent.squillo.com',
      allowedChannels: options.allowedChannels,
      validFrom: options.validFrom ?? '2026-05-31T00:00:00Z',
      validUntil: options.validUntil ?? '2026-06-02T00:00:00Z',
    },
    principal,
    notary,
  });
}

test('a PrincipalSigned envelope this implementation mints is admitted by its own verifier', async () => {
  const { principalDid, notaryDid, principal, notary } = await signers();
  const mandate = await mandateFor({ principalDid, allowedChannels: ['slack'] });
  const envelope = await mintPrincipalSignedEnvelope({
    prepared: await prepare({ principalDid, notaryDid, mandate }),
    principal,
    principalProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a3', created: '2026-06-01T00:00:01Z' },
    notary,
    notaryProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a4', created: '2026-06-01T00:00:02Z' },
  });

  const verified = await verifyEnvelope(serializeEnvelopeDocument(envelope), {
    now: NOW,
    requireMode: 'PrincipalSigned',
    bodyBytes: new TextEncoder().encode(BODY),
  });
  assert.equal(verified.attestationMode, 'PrincipalSigned');
  assert.equal(verified.embeddedMandateChecked, true);
  // Step 8 runs here where it cannot on the golden: the body is published in
  // full inside `preview`, so a verifier holding only this file can re-hash it.
  assert.equal(verified.bodyHashChecked, true);
});

test('a NotaryAttested envelope minted with the single-object carriage verifies too', async () => {
  const { principalDid, notaryDid, notary } = await signers();
  // §7.1.7: in NotaryAttested mode the NOTARY is the issuing authority, so
  // `issuer` is its DID rather than the human's.
  const prepared = await prepare({ principalDid, notaryDid, issuer: notaryDid });
  // §7.1.11: absent label means NotaryAttested, and the mint must not write
  // the stronger one over a lone proof.
  delete (prepared.credentialSubject.policy as { attestationMode?: unknown }).attestationMode;
  const envelope = await mintNotaryAttestedEnvelope({
    prepared,
    notary,
    created: '2026-06-01T00:00:02Z',
  });
  assert.equal(Array.isArray(envelope.proof), false);

  const verified = await verifyEnvelope(serializeEnvelopeDocument(envelope), { now: NOW });
  assert.equal(verified.attestationMode, 'NotaryAttested');
});

test('the mint API makes the §7.2.1 order unconstructible in reverse', async () => {
  // Not a runtime check but a shape check: there is no way to obtain the notary
  // proof without having produced the principal proof, because the notary's
  // base is built from the envelope that already carries it. What CAN be got
  // wrong is the label, so that is what is refused.
  const { principalDid, notaryDid, principal, notary } = await signers();
  const prepared = await prepare({ principalDid, notaryDid });
  (prepared.credentialSubject.policy as { attestationMode?: unknown }).attestationMode =
    'NotaryAttested';
  await assert.rejects(
    () =>
      mintPrincipalSignedEnvelope({
        prepared,
        principal,
        principalProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a3', created: '2026-06-01T00:00:01Z' },
        notary,
        notaryProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a4', created: '2026-06-01T00:00:02Z' },
      }),
    TypeError,
  );
});

test('APH_E005 — a channel outside the mandate scope is refused, with a REAL mandate signature', async () => {
  const { principalDid, notaryDid, principal, notary } = await signers();
  // The mandate grants email; the envelope sends on Slack. Both mandate
  // signatures are genuine, so the refusal cannot be a signature failure in
  // disguise — which is the only way to prove the scope rule is what fired.
  const mandate = await mandateFor({ principalDid, allowedChannels: ['email'] });
  const envelope = await mintPrincipalSignedEnvelope({
    prepared: await prepare({ principalDid, notaryDid, mandate, channelKind: 'slack' }),
    principal,
    principalProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a3', created: '2026-06-01T00:00:01Z' },
    notary,
    notaryProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a4', created: '2026-06-01T00:00:02Z' },
  });
  await assert.rejects(
    () => verifyEnvelope(serializeEnvelopeDocument(envelope), { now: NOW }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E005',
  );
});

test('APH_E003 — an envelope outside the MANDATE window is refused even while inside its own', async () => {
  const { principalDid, notaryDid, principal, notary } = await signers();
  const mandate = await mandateFor({
    principalDid,
    allowedChannels: ['slack'],
    validFrom: '2026-01-01T00:00:00Z',
    validUntil: '2026-01-02T00:00:00Z',
  });
  const envelope = await mintPrincipalSignedEnvelope({
    prepared: await prepare({ principalDid, notaryDid, mandate }),
    principal,
    principalProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a3', created: '2026-06-01T00:00:01Z' },
    notary,
    notaryProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a4', created: '2026-06-01T00:00:02Z' },
  });
  // The envelope's own window is fine at NOW; the standing authority it was
  // issued under expired in January. §7.1.7.1 step 4 is the check that notices.
  await assert.rejects(
    () => verifyEnvelope(serializeEnvelopeDocument(envelope), { now: NOW }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E003',
  );
});

test('serialization is byte-stable: parse of the emitted document re-emits the same bytes', async () => {
  const { principalDid, notaryDid, principal, notary } = await signers();
  const envelope = await mintPrincipalSignedEnvelope({
    prepared: await prepare({ principalDid, notaryDid }),
    principal,
    principalProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a3', created: '2026-06-01T00:00:01Z' },
    notary,
    notaryProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a4', created: '2026-06-01T00:00:02Z' },
  });
  const document = serializeEnvelopeDocument(envelope);
  // JSON.parse preserves member order, and the strict parser returns the
  // object it validated rather than a rebuilt model — so a round trip that
  // changed the bytes would mean the parser is quietly normalizing something.
  assert.equal(serializeEnvelopeDocument(parseEnvelope(document)), document);
  assert.ok(document.endsWith('\n'));
});
