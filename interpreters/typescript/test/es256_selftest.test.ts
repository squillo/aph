/**
 * WHY THIS FILE EXISTS: §8.1 makes BOTH `ES256` and `EdDSA` MUST-support, and
 * §8.2 makes both proof carriages MUST-support, but only the Ed25519
 * Data Integrity path can be pinned to a committed artifact. SubtleCrypto's
 * ECDSA is randomized — it exposes no RFC 6979 deterministic mode — so an
 * ES256 envelope minted here has different bytes on every run and there is
 * nothing to commit. A mint-then-verify inside ONE run is what remains, and it
 * is a real test: it exercises the same bases, the same canonicalization, the
 * same encodings, and the same structure rules.
 *
 * WHAT THEY PIN: `ecdsa-jcs-2019` end to end over a P-256 `did:key` principal,
 * the `JsonWebSignature2020` carriage of §8.2 with its fixed protected header,
 * MIXED algorithms across one chain, and the header rules a verifier must
 * enforce (`b64:false` with `crit:["b64"]`, an empty payload segment, and a
 * `kid` that matches the proof's own verification method).
 *
 * The other half of ES256 coverage is the (->) direction: this implementation
 * verifies the reference's published `ecdsa-jcs-2019` vector when one is on
 * disk — see the corpus harness. That half checks bytes THIS package did not
 * produce; this half checks the paths it does.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { AphParseError } from '../src/errors.js';
import { base64urlDecode, base64urlEncode, bytesToHex } from '../src/baseenc.js';
import { didKeyVerificationMethod, encodeDidKeyEd25519, encodeDidKeyP256 } from '../src/didkey.js';
import { mintPrincipalSignedEnvelope, type PreparedEnvelope } from '../src/mint.js';
import { serializeEnvelopeDocument } from '../src/serialize.js';
import {
  detachedJwsSigner,
  ed25519DataIntegritySigner,
  es256DataIntegritySigner,
} from '../src/signers.js';
import { verifyEnvelope, verifyProofAt } from '../src/verify.js';
import { parseEnvelope } from '../src/parse.js';
import { derToP1363, p1363ToDer, sha256, signEs256, verifyEs256 } from '../src/webcrypto.js';
import type { Signer } from '../src/mint.js';
import {
  RFC6979_A25_P256_COMPRESSED,
  RFC8032_TEST_3,
  ed25519SigningKey,
  p256SigningKey,
  p256VerifyingKey,
} from '../testkit/vectors.js';

const NOW = '2026-06-01T12:00:00Z';
const BODY = 'an ES256 self-test body\n';

const PRINCIPAL_PROOF_ID = 'urn:uuid:00000000-0000-4000-8000-0000000000b1';
const NOTARY_PROOF_ID = 'urn:uuid:00000000-0000-4000-8000-0000000000b2';

async function prepared(principalDid: string, notaryDid: string): Promise<PreparedEnvelope> {
  const bodyBytes = new TextEncoder().encode(BODY);
  return {
    aphVersion: '0.1',
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/aph/v1'],
    type: ['VerifiableCredential', 'AgentSendAuthorizationCredential'],
    id: 'urn:uuid:00000000-0000-4000-8000-0000000000b3',
    issuer: principalDid,
    validFrom: '2026-06-01T00:00:00Z',
    validUntil: '2026-06-02T00:00:00Z',
    credentialSubject: {
      humanPrincipal: { id: principalDid, displayName: 'Scott Wyatt' },
      agent: { id: 'did:web:agent.squillo.com', displayName: 'Squillo Concierge', version: '1.0' },
      channel: { kind: 'slack', recipientAddressing: { teamId: 'T0', channelId: 'C0' } },
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
        attestationMode: 'PrincipalSigned',
      },
      notarization: {
        notaryService: { id: notaryDid, name: 'Test Notary', version: '0.1.0' },
        decisionTimestamp: '2026-06-01T00:00:00Z',
        decisionLatencyMs: 7,
      },
    },
  };
}

async function mintChain(principal: Signer, notary: Signer, principalDid: string, notaryDid: string) {
  return mintPrincipalSignedEnvelope({
    prepared: await prepared(principalDid, notaryDid),
    principal,
    principalProof: { id: PRINCIPAL_PROOF_ID, created: '2026-06-01T00:00:01Z' },
    notary,
    notaryProof: { id: NOTARY_PROOF_ID, created: '2026-06-01T00:00:02Z' },
  });
}

test('ecdsa-jcs-2019: a P-256 did:key principal signs and this verifier admits it', async () => {
  const principalDid = encodeDidKeyP256(RFC6979_A25_P256_COMPRESSED);
  const notaryDid = encodeDidKeyEd25519(RFC8032_TEST_3.publicKey);
  const envelope = await mintChain(
    es256DataIntegritySigner(await p256SigningKey(), didKeyVerificationMethod(principalDid)),
    ed25519DataIntegritySigner(
      await ed25519SigningKey(RFC8032_TEST_3),
      didKeyVerificationMethod(notaryDid),
    ),
    principalDid,
    notaryDid,
  );

  // MIXED algorithms across one chain: §8.1 pins the algorithm per proof via
  // `cryptosuite`, not per envelope, and a verifier that resolved one algorithm
  // for the whole document would fail exactly here.
  const verified = await verifyEnvelope(serializeEnvelopeDocument(envelope), {
    now: NOW,
    requireMode: 'PrincipalSigned',
  });
  assert.equal(verified.attestationMode, 'PrincipalSigned');
});

test('a P-256 did:key round-trips through the compressed-point encoding the identifier carries', () => {
  const did = encodeDidKeyP256(RFC6979_A25_P256_COMPRESSED);
  // §8.4.3 names 0x1200 for P-256; the wire carries its unsigned-varint form,
  // which is why a P-256 did:key reads `zDn...` where Ed25519 reads `z6Mk...`.
  // Pinned because getting the varint wrong yields an identifier that decodes
  // nowhere else.
  assert.ok(did.startsWith('did:key:zDn'), `expected a zDn... P-256 did:key, got ${did}`);
});

test('JsonWebSignature2020: the §8.2 detached carriage mints and verifies, EdDSA and ES256 alike', async () => {
  const principalDid = encodeDidKeyP256(RFC6979_A25_P256_COMPRESSED);
  const notaryDid = encodeDidKeyEd25519(RFC8032_TEST_3.publicKey);
  const envelope = await mintChain(
    detachedJwsSigner(
      await p256SigningKey(),
      didKeyVerificationMethod(principalDid),
      'ecdsa-jcs-2019',
    ),
    detachedJwsSigner(
      await ed25519SigningKey(RFC8032_TEST_3),
      didKeyVerificationMethod(notaryDid),
      'eddsa-jcs-2022',
    ),
    principalDid,
    notaryDid,
  );
  const verified = await verifyEnvelope(serializeEnvelopeDocument(envelope), { now: NOW });
  assert.equal(verified.attestationMode, 'PrincipalSigned');
});

test('the §8.2 protected header is exactly what the spec fixes, and the payload segment is EMPTY', async () => {
  const principalDid = encodeDidKeyP256(RFC6979_A25_P256_COMPRESSED);
  const notaryDid = encodeDidKeyEd25519(RFC8032_TEST_3.publicKey);
  const method = didKeyVerificationMethod(principalDid);
  const envelope = await mintChain(
    detachedJwsSigner(await p256SigningKey(), method, 'ecdsa-jcs-2019'),
    ed25519DataIntegritySigner(
      await ed25519SigningKey(RFC8032_TEST_3),
      didKeyVerificationMethod(notaryDid),
    ),
    principalDid,
    notaryDid,
  );
  const proofs = Array.isArray(envelope.proof) ? envelope.proof : [envelope.proof];
  const segments = (proofs[0] as { proofValue: string }).proofValue.split('.');
  assert.equal(segments.length, 3);
  assert.equal(segments[1], '', 'a detached JWS carries no payload segment');
  const header = JSON.parse(
    new TextDecoder().decode(base64urlDecode(segments[0] as string)),
  ) as Record<string, unknown>;
  assert.deepEqual(header, {
    alg: 'ES256',
    kid: method,
    typ: 'aph+jws',
    cty: 'vc+ld+json',
    b64: false,
    crit: ['b64'],
  });
});

test('a JWS whose kid names a DIFFERENT key than the proof is refused', async () => {
  // Without this the header's `kid` and the proof's `verificationMethod` could
  // disagree, and a verifier would resolve one key while the signer used
  // another — an ambiguity an attacker chooses the resolution of.
  const principalDid = encodeDidKeyP256(RFC6979_A25_P256_COMPRESSED);
  const notaryDid = encodeDidKeyEd25519(RFC8032_TEST_3.publicKey);
  const wrongKid = detachedJwsSigner(
    await p256SigningKey(),
    'did:key:zDnaeSomeoneElse',
    'ecdsa-jcs-2019',
  );
  const method = didKeyVerificationMethod(principalDid);
  const envelope = await mintChain(
    // The signer writes the wrong kid into the header, then the proof block is
    // relabelled with the real verification method.
    { ...wrongKid, verificationMethod: method },
    ed25519DataIntegritySigner(
      await ed25519SigningKey(RFC8032_TEST_3),
      didKeyVerificationMethod(notaryDid),
    ),
    principalDid,
    notaryDid,
  );
  await assert.rejects(
    () => verifyProofAt(parseEnvelope(serializeEnvelopeDocument(envelope)), 0, {}),
    AphParseError,
  );
});

test('a JWS missing crit:["b64"] is refused, because b64:false could then be ignored', async () => {
  const principalDid = encodeDidKeyP256(RFC6979_A25_P256_COMPRESSED);
  const notaryDid = encodeDidKeyEd25519(RFC8032_TEST_3.publicKey);
  const envelope = await mintChain(
    detachedJwsSigner(
      await p256SigningKey(),
      didKeyVerificationMethod(principalDid),
      'ecdsa-jcs-2019',
    ),
    ed25519DataIntegritySigner(
      await ed25519SigningKey(RFC8032_TEST_3),
      didKeyVerificationMethod(notaryDid),
    ),
    principalDid,
    notaryDid,
  );
  const value = JSON.parse(serializeEnvelopeDocument(envelope)) as {
    proof: { proofValue: string }[];
  };
  const segments = (value.proof[0] as { proofValue: string }).proofValue.split('.');
  const header = JSON.parse(
    new TextDecoder().decode(base64urlDecode(segments[0] as string)),
  ) as Record<string, unknown>;
  delete header.crit;
  const rewritten = base64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
  (value.proof[0] as { proofValue: string }).proofValue = `${rewritten}..${segments[2] as string}`;
  await assert.rejects(
    () => verifyProofAt(parseEnvelope(JSON.stringify(value)), 0, {}),
    AphParseError,
  );
});

test('the ECDSA signature-encoding boundary converts both ways without changing the (r, s) pair', async () => {
  // SubtleCrypto produces and consumes IEEE P1363 (raw r||s); some deployed
  // signers put DER inside a JWS. The decoder accepts both and the producer
  // emits only P1363 — this pins that the conversion is lossless in both
  // directions, since a wrong one would silently corrupt a valid signature.
  const key = await p256SigningKey();
  const raw = await signEs256(key, new TextEncoder().encode('encoding boundary'));
  assert.equal(raw.length, 64);
  const der = p1363ToDer(raw);
  assert.equal(der[0], 0x30, 'a DER ECDSA signature opens with a SEQUENCE tag');
  assert.equal(bytesToHex(derToP1363(der)), bytesToHex(raw));
  // And the round-tripped form still verifies, which is the property that
  // actually matters to a recipient.
  const verifying = await p256VerifyingKey();
  assert.equal(
    await verifyEs256(verifying, derToP1363(der), new TextEncoder().encode('encoding boundary')),
    true,
  );
});

test('an ES256 envelope minted twice differs, which is why none is committed', async () => {
  const principalDid = encodeDidKeyP256(RFC6979_A25_P256_COMPRESSED);
  const notaryDid = encodeDidKeyEd25519(RFC8032_TEST_3.publicKey);
  const build = async () =>
    serializeEnvelopeDocument(
      await mintChain(
        es256DataIntegritySigner(await p256SigningKey(), didKeyVerificationMethod(principalDid)),
        ed25519DataIntegritySigner(
          await ed25519SigningKey(RFC8032_TEST_3),
          didKeyVerificationMethod(notaryDid),
        ),
        principalDid,
        notaryDid,
      ),
    );
  // The asymmetry with `ts_minted_artifact.test.ts` — which pins the Ed25519
  // artifact byte for byte — is a measured fact here rather than an omission a
  // reader has to notice for themselves.
  assert.notEqual(await build(), await build());
});
