/**
 * WHY THIS FILE EXISTS: admitting a valid envelope is half of interoperability.
 * The other half is refusing an invalid one WITH THE SAME CODE the reference
 * would emit, because §11's codes are what a recipient acts on: `APH_E011`
 * sends an operator to a human's key, `APH_E001` to a notary's, `APH_E012` to
 * a policy decision, and conflating them sends them to the wrong place. Every
 * expected code below was read out of the §11 table in `spec/aph-0.1.md`, not
 * out of another implementation's test suite.
 *
 * WHAT THEY PIN: tamper (both proofs), forged label (both directions),
 * downgrade refusal, chain-linkage defects, algorithm refusals, the window, the
 * body hash, the status trichotomy, and the strict-parse boundary — each with
 * the exact §11 code, or with the deliberate absence of one.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { base64urlEncode } from '../src/baseenc.js';
import { AphError, AphKeyUnavailableError, AphParseError } from '../src/errors.js';
import type { JsonObject } from '../src/jcs.js';
import type { DelegationMandate } from '../src/types.js';
import { parseEnvelope } from '../src/parse.js';
import { requireAttestationMode, verifyProofStructure } from '../src/structure.js';
import {
  checkCredentialStatus,
  verifyBodyHash,
  verifyEmbeddedMandate,
  verifyEnvelope,
} from '../src/verify.js';
import { readExample } from '../testkit/corpus.js';
import {
  GOLDEN_EVALUATION_INSTANT,
  GOLDEN_FILE,
  goldenSuppliedKeys,
} from '../testkit/golden.js';
import { RFC8032_TEST_3, ed25519KeyMaterial } from '../testkit/vectors.js';

/** A mutable deep copy of the golden as plain JSON, for surgery. */
function goldenValue(): JsonObject {
  return JSON.parse(readExample(GOLDEN_FILE)) as JsonObject;
}

function proofsOfValue(value: JsonObject): JsonObject[] {
  return value.proof as unknown as JsonObject[];
}

function policyOfValue(value: JsonObject): JsonObject {
  return (value.credentialSubject as JsonObject).policy as JsonObject;
}

/**
 * Collapses the golden to the single-object `proof` carriage of §7.1.11.
 *
 * `id` and `previousProof` go with the array form — a lone proof links to
 * nothing — so they are dropped here. Leaving them would make every test built
 * on this refuse for the wrong reason, which is worse than not testing at all.
 */
function collapseToLoneNotaryProof(value: JsonObject): void {
  const notary = { ...(proofsOfValue(value)[1] as JsonObject) };
  delete notary.id;
  delete notary.previousProof;
  value.proof = notary;
}

/** Runs the whole procedure and returns the §11 code it refused with. */
async function refusalCode(value: JsonObject): Promise<string> {
  try {
    await verifyEnvelope(JSON.stringify(value), {
      now: GOLDEN_EVALUATION_INSTANT,
      keys: goldenSuppliedKeys(),
    });
  } catch (error) {
    if (error instanceof AphError) return error.code;
    return `${(error as Error).name}: ${(error as Error).message}`;
  }
  return 'ADMITTED';
}

/** base64url of a JSON value — used only to build a DELIBERATELY malformed JWS. */
function base64urlJson(value: unknown): string {
  return base64urlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

test('APH_E011 — a tampered PRINCIPAL proof is a HUMAN-key failure, never a notary one', async () => {
  const value = goldenValue();
  // One character of the human's signature. §11 distinguishes E011 from E001
  // precisely so a forged authorization is not reported as notary
  // misconfiguration.
  const proof = proofsOfValue(value)[0] as JsonObject;
  const original = proof.proofValue as string;
  proof.proofValue = `z${original.slice(2)}A`;
  assert.equal(await refusalCode(value), 'APH_E011');
});

test('APH_E011 — tampering with the SIGNED PAYLOAD is caught by the principal proof first', async () => {
  const value = goldenValue();
  const communication = (value.credentialSubject as JsonObject).communication as JsonObject;
  communication.preview = 'prod rollout FAILED at 14:02 UTC';
  // §8.3.1 forbids proceeding to the notary proof once the principal's fails,
  // so a body edit surfaces as the human's signature not covering these bytes.
  assert.equal(await refusalCode(value), 'APH_E011');
});

test('APH_E001 — a tampered NOTARY countersignature is an envelope-signature failure', async () => {
  const value = goldenValue();
  const proof = proofsOfValue(value)[1] as JsonObject;
  const original = proof.proofValue as string;
  proof.proofValue = `z${original.slice(2)}A`;
  assert.equal(await refusalCode(value), 'APH_E001');
});

test('APH_E013 — the forged label: PrincipalSigned written above a single notary proof', () => {
  // The attack §7.1.11 exists to stop. A notary key alone can produce a lone
  // proof with proofPurpose assertionMethod and write the stronger label above
  // it; a verifier that trusted the label reports a forgery as the human's own
  // signature. Refused BEFORE any key is resolved.
  const value = goldenValue();
  collapseToLoneNotaryProof(value);
  policyOfValue(value).attestationMode = 'PrincipalSigned';
  assert.throws(() => verifyProofStructure(parseEnvelope(JSON.stringify(value))), {
    code: 'APH_E013',
  });
});

test('APH_E013 — the other direction: a two-element chain that claims to be NotaryAttested', () => {
  const value = goldenValue();
  policyOfValue(value).attestationMode = 'NotaryAttested';
  assert.throws(() => verifyProofStructure(parseEnvelope(JSON.stringify(value))), {
    code: 'APH_E013',
  });
});

test('APH_E013 — a chain whose head is NOT the human principal is not a principal proof', async () => {
  // The binding that gives the label meaning: the notary does not hold the
  // human's key, so a chain headed by the notary's own key proves nothing about
  // the human however its proofPurpose reads.
  const value = goldenValue();
  (proofsOfValue(value)[0] as JsonObject).verificationMethod =
    'did:web:notary.squillo.com#key-1';
  assert.equal(await refusalCode(value), 'APH_E013');
});

test('APH_E013 — a dangling previousProof breaks the chain linkage', async () => {
  const value = goldenValue();
  (proofsOfValue(value)[1] as JsonObject).previousProof =
    'urn:uuid:00000000-0000-4000-8000-0000dead0000';
  assert.equal(await refusalCode(value), 'APH_E013');
});

test('APH_E013 — the notary proof may not be dated before the principal proof it observed', async () => {
  const value = goldenValue();
  // §7.2.1: each signature covers only bytes that existed when it was made.
  (proofsOfValue(value)[1] as JsonObject).created = '2026-05-21T00:00:00Z';
  assert.equal(await refusalCode(value), 'APH_E013');
});

test('APH_E012 — the no-downgrade gate refuses a weaker attestation before doing work', () => {
  const value = goldenValue();
  collapseToLoneNotaryProof(value);
  delete policyOfValue(value).attestationMode;
  const envelope = parseEnvelope(JSON.stringify(value));
  // Absent means NotaryAttested (§7.1.7), so a PrincipalSigned policy refuses.
  assert.throws(() => requireAttestationMode(envelope, 'PrincipalSigned'), {
    code: 'APH_E012',
  });
  // The same envelope is structurally fine for a verifier that did not demand
  // the stronger mode: E012 is a policy refusal, not a defect in the envelope.
  assert.equal(verifyProofStructure(envelope), 'NotaryAttested');
});

test('APH_E010 — a DataIntegrityProof declaring no cryptosuite declares no algorithm', async () => {
  const value = goldenValue();
  delete (proofsOfValue(value)[0] as JsonObject).cryptosuite;
  // §8.1: reject any envelope omitting an algorithm declaration. Reported as
  // E010 and NOT as a parse error, because the code is what tells a producer
  // the algorithm was the problem.
  assert.equal(await refusalCode(value), 'APH_E010');
});

test('APH_E010 — a JWS protected header with alg:none is refused', async () => {
  const value = goldenValue();
  const proof = proofsOfValue(value)[0] as JsonObject;
  proof.type = 'JsonWebSignature2020';
  delete proof.cryptosuite;
  proof.proofValue = `${base64urlJson({ alg: 'none', kid: proof.verificationMethod })}..`;
  assert.equal(await refusalCode(value), 'APH_E010');
});

test('APH_E003 — an envelope evaluated outside its window is expired', async () => {
  // Well past validUntil plus the 60-second skew §8.3 step 6 recommends.
  await assert.rejects(
    () =>
      verifyEnvelope(readExample(GOLDEN_FILE), {
        now: '2027-01-01T00:00:00Z',
        keys: goldenSuppliedKeys(),
      }),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E003',
  );
});

test('APH_E003 — the skew tolerance is applied, so a verifier a few seconds fast still admits', async () => {
  // The complement of the test above: §8.3 step 6 RECOMMENDS 60 seconds, and a
  // verifier without it would refuse healthy traffic at every window edge.
  const verified = await verifyEnvelope(readExample(GOLDEN_FILE), {
    now: '2026-05-22T00:00:30Z',
    keys: goldenSuppliedKeys(),
  });
  assert.equal(verified.attestationMode, 'PrincipalSigned');
});

test('APH_E009 — a body that does not hash to bodySha256 is refused', async () => {
  const envelope = parseEnvelope(readExample(GOLDEN_FILE));
  await assert.rejects(
    () => verifyBodyHash(envelope, new TextEncoder().encode('not the body')),
    (error: unknown) => error instanceof AphError && error.code === 'APH_E009',
  );
});

test('APH_E008 — a credentialStatus this verifier cannot resolve is a REFUSAL, not a skip', () => {
  const value = goldenValue();
  value.credentialStatus = {
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: '7',
    statusListCredential: 'https://notary.squillo.com/status/1',
  };
  // §6.3.3.4's trichotomy has three outcomes and "I could not look" is not one
  // of them: an attacker who can make the status check FAIL must not thereby
  // get to choose that it is SKIPPED. The step is exercised directly because
  // the entry sits inside the signed bytes, so the signatures break first.
  const envelope = parseEnvelope(JSON.stringify(value));
  assert.throws(() => checkCredentialStatus(envelope), { code: 'APH_E008' });
});

test('a strict-parse failure carries NO §11 code and names the offending member', () => {
  const value = goldenValue();
  value.unknownTopLevelField = 'smuggled';
  // §11 has no parse code and inventing one would widen a closed set. The JSON
  // path is what a producer needs; "unknown field" without a name is not
  // actionable.
  assert.throws(
    () => parseEnvelope(JSON.stringify(value)),
    (error: unknown) => error instanceof AphParseError && error.path === '$.unknownTopLevelField',
  );
});

test('an unknown member NESTED inside credentialSubject is refused too', () => {
  const value = goldenValue();
  const communication = (value.credentialSubject as JsonObject).communication as JsonObject;
  communication.bodySha512 = 'smuggled';
  assert.throws(
    () => parseEnvelope(JSON.stringify(value)),
    (error: unknown) =>
      error instanceof AphParseError &&
      error.path === '$.credentialSubject.communication.bodySha512',
  );
});

test('§7.1.5 — a channel kind outside the closed set is refused, and the refusal names it', () => {
  // WHY: §7.1.5 closes the channel vocabulary, and a verifier that admitted a
  // word it has never seen would carry an authorization it cannot evaluate all
  // the way to a delivery decision. This is also the case that once split the
  // two implementations: the reference took `kind` as a bare string and passed
  // what this parser refused, so the same bytes got opposite verdicts.
  //
  // PINS: the refusal is a strict-parse failure and carries NO §11 code (§11
  // has none for a parse); the JSON PATH names the offending member; and the
  // message carries both the offending VALUE and the closed set, which is what
  // makes it actionable to the producer who has to fix it.
  const value = goldenValue();
  const channel = (value.credentialSubject as JsonObject).channel as JsonObject;
  channel.kind = 'carrier_pigeon';
  assert.throws(
    () => parseEnvelope(JSON.stringify(value)),
    (error: unknown) =>
      error instanceof AphParseError &&
      error.path === '$.credentialSubject.channel.kind' &&
      error.message.includes('"carrier_pigeon"') &&
      error.message.includes('closed set') &&
      error.message.includes('google_chat'),
  );
});

test('§7.1.6 — a content class outside the closed set is refused, and the refusal names it', () => {
  // WHY: the other half of the same repair. §7.1.6 closes the content-class
  // vocabulary, and it lived in prose while both implementations admitted any
  // string; a class no verifier defines is exactly how a producer routes past a
  // check keyed on one. PINS the same three facts as the channel case, on the
  // sibling member, so a fix applied to one field and not the other is caught.
  const value = goldenValue();
  const communication = (value.credentialSubject as JsonObject).communication as JsonObject;
  communication.contentClass = 'Digest';
  assert.throws(
    () => parseEnvelope(JSON.stringify(value)),
    (error: unknown) =>
      error instanceof AphParseError &&
      error.path === '$.credentialSubject.communication.contentClass' &&
      error.message.includes('"Digest"') &&
      error.message.includes('closed set'),
  );
});

test('§7.1.12 — a classification citing no vocabulary is refused on both sides of the weld', () => {
  // WHY: this implementation refused an empty `vocabularies` from its first
  // draft, and an audit found the Rust reference ACCEPTING the same bytes —
  // the divergence class this wave closed for allowedChannels, reintroduced
  // in a field one day old. The reference was tightened; this pin is the TS
  // half of the weld, so LOOSENING either side now goes red somewhere.
  // PINS: an actClassification whose vocabularies array is empty is refused
  // at the read, with the path naming the member.
  const value = goldenValue();
  (value.credentialSubject as JsonObject).actClassification = {
    vocabularies: [],
    labels: ['APH_ACT_ACCESS/ACCESS_GRANT'],
  };
  assert.throws(
    () => parseEnvelope(JSON.stringify(value)),
    (error: unknown) =>
      error instanceof AphParseError &&
      error.path === '$.credentialSubject.actClassification.vocabularies',
  );
});

test('§6.1 — an allowedChannels entry outside the closed set is refused at the READ', () => {
  // WHY: this member is the one place the closed channel set could be admitted
  // through a side door. §6.1's table spells it "array of strings", so this
  // parser took it as one — and an entry naming a channel nothing defines then
  // survived the parse and died at §7.1.7.1 step 4's membership test, which
  // answers `false`. That is the SAME answer a channel legitimately out of
  // scope produces: one refusal, two causes, and APH_E005 tells the reader to
  // widen a grant that is in fact corrupt.
  //
  // PINS: the refusal happens at the parse, before any verdict is computed; the
  // path names the offending ENTRY by index, not just the array; and the
  // message carries the value and the set. Refusing here is what keeps the
  // corrupt grant and the honest denial two different events.
  const value = goldenValue();
  const mandate = policyOfValue(value).delegationMandate as JsonObject;
  mandate.allowedChannels = ['slack', 'carrier_pigeon'];
  assert.throws(
    () => parseEnvelope(JSON.stringify(value)),
    (error: unknown) =>
      error instanceof AphParseError &&
      error.path === '$.credentialSubject.policy.delegationMandate.allowedChannels[1]' &&
      error.message.includes('"carrier_pigeon"') &&
      error.message.includes('closed set'),
  );
});

test('§7.4 recipientAddressing stays OPAQUE — a new channel field is not a protocol break', () => {
  const value = goldenValue();
  const channel = (value.credentialSubject as JsonObject).channel as JsonObject;
  (channel.recipientAddressing as JsonObject).someNewSlackField = 'fine';
  // The one deliberate exception to strict parsing. Without it every field a
  // channel vendor adds would break every verifier.
  assert.ok(parseEnvelope(JSON.stringify(value)));
});

test('a verification method with no key supplied is a CONFIGURATION failure, not APH_E014', async () => {
  // §8.4 discovery is out of scope here, so nothing was queried and nothing
  // answered. APH_E014 means a surface ANSWERED and published no key, which is
  // a different fact and a different remedy.
  await assert.rejects(
    () => verifyEnvelope(readExample(GOLDEN_FILE), { now: GOLDEN_EVALUATION_INSTANT }),
    (error: unknown) => error instanceof AphKeyUnavailableError,
  );
});

test('§7.1.7.1 — a mandate stapled from another grant is refused BEFORE its signature is consulted', async () => {
  // The attack: take any validly-signed mandate and attach it to an envelope it
  // does not govern. The three equalities of §7.1.7.1 step 3 are what close it,
  // and they must run FIRST — a signature check on a mandate that is not this
  // envelope's parent proves only that the signature is real.
  //
  // Exercised through `verifyEmbeddedMandate` rather than through the whole
  // procedure on purpose: the mandate sits INSIDE the envelope's signed bytes,
  // so editing it there breaks the principal proof and the refusal would come
  // from step 1c with the same code for a different reason. Calling the step
  // directly is the only way to prove the binding fired.
  const envelope = parseEnvelope(readExample(GOLDEN_FILE));
  const parent = envelope.credentialSubject.policy.delegationMandate;
  assert.ok(parent);
  const stapled: ReadonlyArray<readonly [string, DelegationMandate]> = [
    ['agentDid', { ...parent, agentDid: 'did:web:some-other-agent.example' }],
    [
      'humanPrincipalDid',
      { ...parent, humanPrincipalDid: 'did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy' },
    ],
    ['id', { ...parent, id: 'urn:uuid:00000000-0000-4000-8000-0000beef0000' }],
  ];
  for (const [field, mandate] of stapled) {
    await assert.rejects(
      () =>
        verifyEmbeddedMandate(envelope, mandate, ed25519KeyMaterial(RFC8032_TEST_3), {
          keys: goldenSuppliedKeys(),
        }),
      (error: unknown) => error instanceof AphError && error.code === 'APH_E011',
      `a mandate with the wrong ${field} must be refused`,
    );
  }
});

test('§7.1.1 — credentialStatus present as an explicit null is malformed, not absent', () => {
  const value = goldenValue();
  value.credentialStatus = null;
  // Emitting null instead of omitting would change the bytes of every
  // extension-unaware envelope and invalidate its signature.
  assert.throws(() => parseEnvelope(JSON.stringify(value)), AphParseError);
});
