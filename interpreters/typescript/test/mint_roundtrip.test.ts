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
import type { ChannelKind, DelegationMandate, RecipientClass } from '../src/types.js';
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
  readonly allowedRecipientClasses?: RecipientClass[];
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
      ...(options.allowedRecipientClasses !== undefined
        ? { allowedRecipientClasses: options.allowedRecipientClasses }
        : {}),
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

// ── RFC 0003: audience, single-use, and the envelope window's own code ──
//
// These run on MINTED envelopes, not the shape-only corpus, because §8.3
// puts the audience gate AFTER signature verification: on an illustrative
// fixture the E001 refusal fires first and step 5a is unreachable. A gate
// only testable behind a real signature must be tested behind one.

async function auditedEnvelope(): Promise<string> {
  const { principalDid, notaryDid, notary } = await signers();
  const prepared = await prepare({ principalDid, notaryDid, issuer: notaryDid });
  delete (prepared.credentialSubject.policy as { attestationMode?: unknown }).attestationMode;
  (prepared.credentialSubject as { audience?: unknown }).audience = {
    id: 'did:web:ssot.example.com',
    channelBinding: { kind: 'slack', teamId: 'T01234567' },
  };
  const envelope = await mintNotaryAttestedEnvelope({
    prepared,
    notary,
    created: '2026-06-01T00:00:02Z',
  });
  return serializeEnvelopeDocument(envelope);
}

test('step 5a: the named verifier with matching coordinates is admitted', async () => {
  // The positive path, pinned so the gate cannot rot into refusing everyone
  // while its refusal tests stay green.
  const verified = await verifyEnvelope(await auditedEnvelope(), {
    now: NOW,
    verifierId: 'did:web:ssot.example.com',
    actCoordinates: { kind: 'slack', teamId: 'T01234567', threadTs: 'incidental' },
  });
  assert.equal(verified.attestationMode, 'NotaryAttested');
});

test('step 5a: a verifier with no identity REJECTS an audience-bearing envelope, not skips', async () => {
  // RFC 0003's sharpest sentence. Skipping here would make the binding
  // decoration precisely where an attacker relays the envelope.
  await assert.rejects(
    async () => verifyEnvelope(await auditedEnvelope(), { now: NOW }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E017',
  );
});

test('step 5a: the wrong verifier is refused with APH_E017', async () => {
  await assert.rejects(
    async () =>
      verifyEnvelope(await auditedEnvelope(), {
        now: NOW,
        verifierId: 'did:web:other.example.com',
        actCoordinates: { kind: 'slack', teamId: 'T01234567' },
      }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E017',
  );
});

test('step 5a: a bound coordinate the act lacks, or contradicts, refuses', async () => {
  // The member-by-member rule: a constraint that cannot be checked is
  // refused, and one that checks false is refused — both E017.
  await assert.rejects(
    async () =>
      verifyEnvelope(await auditedEnvelope(), {
        now: NOW,
        verifierId: 'did:web:ssot.example.com',
      }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E017',
  );
  await assert.rejects(
    async () =>
      verifyEnvelope(await auditedEnvelope(), {
        now: NOW,
        verifierId: 'did:web:ssot.example.com',
        actCoordinates: { kind: 'slack', teamId: 'T_ELSEWHERE' },
      }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E017',
  );
});

test('step 8b: acceptance spends the id, and a refusal consumes nothing', async () => {
  // RFC 0003 measured the defect as 100 presentations, 100 admissions. With
  // a ledger supplied, presentation two is APH_E018 — and a presentation
  // refused for ANOTHER reason must not spend the envelope, which is why
  // recording happens at the acceptance moment and not before.
  const { principalDid, notaryDid, notary } = await signers();
  const prepared = await prepare({ principalDid, notaryDid, issuer: notaryDid });
  delete (prepared.credentialSubject.policy as { attestationMode?: unknown }).attestationMode;
  const envelope = serializeEnvelopeDocument(
    await mintNotaryAttestedEnvelope({ prepared, notary, created: '2026-06-01T00:00:02Z' }),
  );
  const consumedIds = new Set<string>();

  // A refusal first: outside the window. The ledger must stay empty.
  await assert.rejects(
    () => verifyEnvelope(envelope, { now: '2027-01-01T00:00:00Z', consumedIds }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E019',
  );
  assert.equal(consumedIds.size, 0);

  await verifyEnvelope(envelope, { now: NOW, consumedIds });
  assert.equal(consumedIds.size, 1);
  await assert.rejects(
    () => verifyEnvelope(envelope, { now: NOW, consumedIds }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E018',
  );
});

test("APH_E019 — the envelope's OWN window has its own code now", async () => {
  // This implementation SHIPPED the E003 miscite for the envelope window;
  // RFC 0003 added the code that makes the two refusals distinguishable.
  // The mandate-window test above still pins E003 for the mandate side, so
  // the pair of tests is the weld holding the distinction.
  const { principalDid, notaryDid, notary } = await signers();
  const prepared = await prepare({ principalDid, notaryDid, issuer: notaryDid });
  delete (prepared.credentialSubject.policy as { attestationMode?: unknown }).attestationMode;
  const envelope = await mintNotaryAttestedEnvelope({
    prepared,
    notary,
    created: '2026-06-01T00:00:02Z',
  });
  await assert.rejects(
    () => verifyEnvelope(serializeEnvelopeDocument(envelope), { now: '2027-01-01T00:00:00Z' }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E019',
  );
});

// ── RFC 0005: the recipient-class constraint on minted envelopes ──

test('APH_E020 — a constrained grant refuses a declared class outside it', async () => {
  // The motivating case verbatim: the human granted "slack to PEOPLE"; the
  // act is unattended agent-to-agent traffic on the same medium. Before
  // RFC 0005 nothing on the wire could refuse this.
  const { principalDid, notaryDid, principal, notary } = await signers();
  const mandate = await mandateFor({
    principalDid,
    allowedChannels: ['slack'],
    allowedRecipientClasses: ['human'],
  });
  const prepared = await prepare({ principalDid, notaryDid, mandate });
  (prepared.credentialSubject.channel as { recipientClass?: unknown }).recipientClass = 'agent';
  const envelope = await mintPrincipalSignedEnvelope({
    prepared,
    principal,
    principalProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a3', created: '2026-06-01T00:00:01Z' },
    notary,
    notaryProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a4', created: '2026-06-01T00:00:02Z' },
  });
  await assert.rejects(
    () => verifyEnvelope(serializeEnvelopeDocument(envelope), { now: NOW }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E020',
  );
});

test('APH_E020 — declaring NOTHING under a constrained grant refuses too', async () => {
  // A constraint escapable by omission is not a constraint. The refusal
  // names `nothing` so the operator sees which failure this was.
  const { principalDid, notaryDid, principal, notary } = await signers();
  const mandate = await mandateFor({
    principalDid,
    allowedChannels: ['slack'],
    allowedRecipientClasses: ['human'],
  });
  const envelope = await mintPrincipalSignedEnvelope({
    prepared: await prepare({ principalDid, notaryDid, mandate }),
    principal,
    principalProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a3', created: '2026-06-01T00:00:01Z' },
    notary,
    notaryProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a4', created: '2026-06-01T00:00:02Z' },
  });
  await assert.rejects(
    () => verifyEnvelope(serializeEnvelopeDocument(envelope), { now: NOW }),
    (error: unknown) =>
      error instanceof AphError && error.code === 'APH_E020' && error.message.includes('nothing'),
  );
});

test('a declared class inside the grant is admitted, and an unconstrained grant checks nothing', async () => {
  // Positive controls for both arms, so the refusal tests above cannot rot
  // into a check that refuses everyone.
  const { principalDid, notaryDid, principal, notary } = await signers();
  const constrained = await mandateFor({
    principalDid,
    allowedChannels: ['slack'],
    allowedRecipientClasses: ['human'],
  });
  const prepared = await prepare({ principalDid, notaryDid, mandate: constrained });
  (prepared.credentialSubject.channel as { recipientClass?: unknown }).recipientClass = 'human';
  const envelope = await mintPrincipalSignedEnvelope({
    prepared,
    principal,
    principalProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a3', created: '2026-06-01T00:00:01Z' },
    notary,
    notaryProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a4', created: '2026-06-01T00:00:02Z' },
  });
  const verified = await verifyEnvelope(serializeEnvelopeDocument(envelope), { now: NOW });
  assert.equal(verified.embeddedMandateChecked, true);

  const unconstrained = await mandateFor({ principalDid, allowedChannels: ['slack'] });
  const bare = await mintPrincipalSignedEnvelope({
    prepared: await prepare({ principalDid, notaryDid, mandate: unconstrained }),
    principal,
    principalProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a3', created: '2026-06-01T00:00:01Z' },
    notary,
    notaryProof: { id: 'urn:uuid:00000000-0000-4000-8000-0000000000a4', created: '2026-06-01T00:00:02Z' },
  });
  await verifyEnvelope(serializeEnvelopeDocument(bare), { now: NOW });
});

