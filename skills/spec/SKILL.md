---
name: spec
description: >-
  APH (Agent per Human) protocol crash course and reference. Use when working with
  APH, NotarizationEnvelope JSON, envelope validation or verification, notarization
  flows, a Delegation Mandate or Communication Mandate, the notary service, the
  "agent driver's license" model, APH error codes (APH_E001..APH_E015), signing
  profiles (eddsa-jcs-2022, ecdsa-jcs-2019, detached JWS), notary public-key
  discovery (did:key, did:web, DNS TXT), channel kinds, or the A2A notarization
  extension. Covers wire shape, state machines, closed enums, and how to run the
  reference Rust implementation and conformance suite.
---

# APH v0.1 — working crash course

APH (Agent per Human) notarizes outbound agent communications: a human-authorized
Notary Service issues a W3C Verifiable Credential 2.0 (`NotarizationEnvelope`) that
binds a specific outbound payload (by SHA-256), channel, agent, and policy decision
to a human principal's authority. The mental model is a **driver's license for
agents** (spec §1.1): the human is the issuing authority, the notary is the DMV,
every credential carries a bounded scope, and it is revocable and portable across
organizations via public key discovery.

## Repo map

- `spec/aph-0.1.md` — the normative spec. Key sections: §1.1 mental model, §5 Roles + Operations, §6 Mandates, §7 The Notarization Envelope, §8 Signing + Verification, §8.4 Notary Key Material + Public-Key Discovery, §9 Flow State Machines, §10 Composition with Adjacent Protocols, §11 Error Taxonomy.
- `spec/a2a-extension.md` — how agents advertise APH on an A2A AgentCard. Pins `APH_EXTENSION_URI = aph://extensions/notarization/v1` (exact byte equality, opaque, never dereferenced).
- `spec/security-considerations.md` — threat model: in-scope (replay, body tampering, mandate forgery, channel impersonation, alg downgrade, attestation-mode downgrade), out-of-scope (compromised notary key/device, phishing, transport security).
- `examples/` — 9 golden envelope JSON files (enumerated on disk): one per channel kind (7), one exercising the §7.5 registered extensions, and `principal_signed_envelope.json`. With `examples/README.md`. The first 8 are `NotaryAttested` (they carry no `attestationMode`, and absent means `NotaryAttested`) and their `proof.proofValue` strings are illustrative placeholders, NOT real signatures, with `bodySha256` the SHA-256 of the empty string — they exist for shape/round-trip validation only. `principal_signed_envelope.json` is the exception and the only one that verifies: it is `PrincipalSigned` and carries four real Ed25519 signatures made from RFC 8032 §7.1 public test seeds.
- `interpreters/rust/` — the reference Rust implementation, a cargo workspace with members: `aph-core` (protocol types + validation), `aph-conformance` (conformance suite), `aph-cli` (CLI; the binary is named `aph`), and `aph-ts` (wasm binding).

## Envelope wire shape (spec §7.1)

Top-level fields of a `NotarizationEnvelope` (all camelCase, strict parse):

| Field | Notes |
|---|---|
| `aphVersion` | MUST be `"0.1"` |
| `@context` | `["https://www.w3.org/ns/credentials/v2", "https://w3id.org/aph/v1"]`, in that order |
| `type` | MUST include `"VerifiableCredential"` and `"AgentSendAuthorizationCredential"` |
| `id` | `urn:uuid:` form |
| `issuer` | DID of the Notary Service |
| `validFrom` / `validUntil` | RFC 3339; verifiers enforce `validFrom <= now <= validUntil` (±60s skew) |
| `credentialSubject` | the notarized claim (below) |
| `linkedMandate` | optional / nullable; carries `ap2IntentMandateUri` for AP2 cross-links (§7.1.10). The reference implementation additionally accepts optional `ap2SignedPayloadB64` and `vaultMutation` extension fields not yet in the spec text (see sharp edge 3) |
| `credentialStatus` | optional, **OMITTED when absent — never `null`** (unlike `linkedMandate`), so a status-free envelope stays byte-identical to a pre-revocation one. A W3C `BitstringStatusListEntry` naming the PARENT DELEGATION MANDATE's revocation status, not the envelope's (§6.3.3.1). `statusListIndex` is a STRING, never a number |
| `proof` | a single object, OR a **proof chain array** — see Trust model below (§7.1.11) |

`credentialSubject` contains exactly six objects per spec v0.1 (§7.1.2–§7.1.9;
the reference implementation also accepts an optional `appleAurAcceptance`
extension — see sharp edge 3):

- `humanPrincipal` — `{id (DID), displayName}`
- `agent` — `{id (DID), agentCardUri?, displayName, version}`
- `channel` — `{kind, recipientAddressing}` (addressing shape is channel-specific and OPAQUE — see §7.4)
- `communication` — `{contentClass, bodySha256 (64 lowercase hex), bodySize, previewLines, preview (≤ 8192 bytes)}`
- `policy` — `{decision, matchedScope, attestationMode?, delegationMandate?, delegationMandateId?, actChain?}`. `attestationMode` is the trust-model field — read the Trust model section before describing any envelope. `delegationMandate` is the FULL embedded parent mandate (§7.1.7.1), not a reference
- `notarization` — `{notaryService {id, name, version, attestedDigest?, attestationUri?}, decisionTimestamp, decisionLatencyMs}`. The two attestation fields are self-asserted (§15.3) — a pointer to fetch and check, never evidence on their own

A complete worked example lives at spec §7.3.

## Closed enums

- **Channel kinds** (§7.1.5): `slack`, `email`, `discord`, `teams`, `whatsapp`, `google_chat`, `imessage`.
- **contentClass** (§7.1.6): `Reply`, `New`, `Mention`, `DM`, `Channel`, `BulkSend`, `Broadcast`.
- **Policy decisions** (§7.1.7): `AlwaysAllow`, `AskEveryTime`, `NeverAllow`. (`NeverAllow` is recorded but never yields an envelope.)
- **Proof types** (§7.1.11): `DataIntegrityProof` or `JsonWebSignature2020`.
- **Roles** (§5.1): `HumanPrincipal`, `AgentSender`, `NotaryService`, `ChannelAdapter`, `RecipientEndpoint`. **Operations** (§5.2): `IssueDelegationMandate`, `IssueCommunicationMandate`, `Notarize`, `Transport`, `Verify`, `Reject`.

### WARNING — two sharp edges

1. **Strict parsing.** Envelope-level deserialization is `deny_unknown_fields` (spec §7.1, §8.3 step 1): any unknown top-level or subject-level field is a hard parse failure. The ONE exception is `channel.recipientAddressing`, whose sub-fields are opaque and MUST NOT fail verification (§7.4).
2. **Channel-kind spelling is `google_chat`** (snake_case). Early drafts of
   the spec text spelled it `googleChat`; a 2026-08-12 erratum in §7.1.5
   pinned `google_chat` as normative because every published example and
   signed fixture emits that form. Old copies of the spec text may still show
   `googleChat` — the fixtures and the erratum win.
3. **Registered optional extensions (spec §7.5).** Three OPTIONAL,
   omitted-when-absent extension fields are registered in the spec:
   `credentialSubject.appleAurAcceptance` (§7.5.1),
   `linkedMandate.ap2SignedPayloadB64` (§7.5.2), and
   `linkedMandate.vaultMutation` (§7.5.3 — note its interior keys are
   snake_case by design). Verifiers MUST tolerate them; envelopes without
   them are byte-identical to pre-extension envelopes. The fixture
   `examples/slack_new_with_extensions_envelope.json` exercises all three.

## Mandates (spec §6)

- **DelegationMandate** (§6.1) — long-lived standing authority. Fields: `id` (urn:uuid), `humanPrincipalDid`, `agentDid`, `allowedChannels` (non-empty), `rateLimitPerHour?`, `validFrom` < `validUntil`, `principalSignature` (the HUMAN's own, over the JCS form minus BOTH signature fields — required, and the root of every credential issued under the mandate), `notarySignature` (over the JCS form minus `notarySignature`, so it countersigns what the human signed). Revocable by the human at any time (§6.3.1 model; §6.3.3 on-wire transport — a W3C Bitstring Status List v1.0 profile whose endpoint ORIGIN is derived from the notary's `did:web` and never read from the envelope). When an envelope carries `credentialStatus`, checking it is a verifier MUST: revoked ⇒ `APH_E015`, unresolvable ⇒ `APH_E008`, absent ⇒ skip. Short validity windows remain good practice as defense in depth.
- **CommunicationMandate** (§6.2) — per-message, single-use. Fields: `id`, `delegationMandateId?` (null for one-shot AskEveryTime), `humanPrincipalDid`, `agentDid`, `channelKind`, `recipientAddressing`, `contentClass`, `bodySha256`, `bodySize`, `policyDecision`, `issuedAt` < `expiresAt` (5 min recommended), `notarySignature`. If `delegationMandateId` is set, the parent must exist, be unexpired at `issuedAt`, NOT be revoked at `issuedAt` (§6.3.1, §6.3.3), and list `channelKind` in `allowedChannels`.

## State machines (spec §9)

**Human-present flow** (§9.1) — 7 states, `Delivered`/`Denied` terminal:

```
Drafted -> PendingDecision
PendingDecision -> Approved | Denied
Approved -> MandateIssued
MandateIssued -> EnvelopeIssued
EnvelopeIssued -> Delivered
```

**Human-not-present flow** (§9.2) — 5 states, gated by a matching unexpired
Delegation Mandate; `Delivered`/`Denied` terminal:

```
Drafted -> MandateIssued | Denied
MandateIssued -> EnvelopeIssued
EnvelopeIssued -> Delivered
```

Any other transition MUST be rejected with `APH_E002`.

## Error taxonomy (spec §11) — closed set of 15

| Code | Variant | Meaning |
|---|---|---|
| `APH_E001` | `InvalidEnvelopeSignature` | `proof.proofValue` failed against the resolved key over canonical envelope bytes |
| `APH_E002` | `InvalidFlowTransition` | State-machine transition not in the allowed set |
| `APH_E003` | `MandateExpired` | Mandate consulted past `expiresAt` / `validUntil` |
| `APH_E004` | `RoleViolation` | Party attempted an operation outside its §5 role |
| `APH_E005` | `ChannelNotAllowed` | Channel kind not in the Delegation Mandate's `allowedChannels` |
| `APH_E006` | `NotarySignatureInvalid` | Mandate-level `notarySignature` failed (distinct from envelope-level E001) |
| `APH_E007` | `HumanAuthenticationRequired` | AskEveryTime triggered but human unreachable |
| `APH_E008` | `NotaryServiceUnreachable` | Any protocol-mandated fetch from a notary-hosted surface failed: the service timed out, or a document it is contracted to serve (DID Document §8.4.4, status list §6.3.3) could not be reached, parsed, or validated |
| `APH_E009` | `EnvelopeBodyHashMismatch` | Recipient's SHA-256 of the body != `communication.bodySha256` |
| `APH_E010` | `UnsupportedAlgorithm` | Algorithm outside {`ES256`, `EdDSA`}, or `alg: none` |
| `APH_E011` | `PrincipalSignatureInvalid` | A signature made by the HUMAN's key failed: the principal proof of a chain, or an embedded mandate's `principalSignature`. Distinct from E001/E006, which are notary signatures |
| `APH_E012` | `AttestationModeRefused` | Verifier policy requires `PrincipalSigned` and the envelope is `NotaryAttested` (§8.3.1 step 1a). A refusal of the weaker claim, not an envelope defect |
| `APH_E013` | `ProofChainInvalid` | Malformed chain: wrong length, wrong `proofPurpose` per position, or `previousProof` missing/dangling/duplicated/cyclic (§7.1.11). Also what a forged `PrincipalSigned` label raises |
| `APH_E014` | `NotaryKeyNotPublished` | Nothing published at the queried discovery surface: no TXT record at the name, or the DID Document names no matching key. ABSENT, held distinct from E008 (offered-and-broke) |
| `APH_E015` | `MandateRevoked` | The parent Delegation Mandate's bit is SET in the notary's published revocation status list (§6.3.3). Signatures are still valid — a withdrawn authorization, not a forged one. Distinct from E003, which is authority that ran out on schedule |

## Trust model — WHO signs (the most important section here)

**The principal signs; the notary countersigns.** Get this backwards and you
will describe the protocol as something weaker than it is.

`policy.attestationMode` declares which of two shapes an envelope has.

**`PrincipalSigned`** — `proof` is a W3C VC 2.0 **proof chain**:

1. **Principal proof** — `proofPurpose: assertionMethod`,
   `verificationMethod` = the principal's DID URL. This IS the authorization.
2. **Notary proof** — `proofPurpose: authentication`, countersigning over
   the complete principal proof, so a notary cannot move a principal's
   signature onto a different envelope.

Each proof in a chain carries an `id`, and the notary proof carries
`previousProof` = the principal proof's `id`. **That linkage, not array
position, is what a verifier checks** (§7.1.11, §8.3.1 step 1e) — order is
rearrangeable by an intermediary; a signed reference is not.

**`NotaryAttested`** — a single notary proof, used in the human-not-present
flow where the human is asleep and cannot sign THIS message. Their
authorization instead lives in the Delegation Mandate they signed earlier,
which SHOULD travel embedded at `policy.delegationMandate` so a recipient can
verify the human's `principalSignature` offline (§7.1.7.1). **Without the
embedded mandate the human's authorization is not verifiable at all** — the
credential is then the notary's assertion alone, and you should say so.

`attestationMode` absent means `NotaryAttested`. **A verifier requiring
`PrincipalSigned` MUST refuse `NotaryAttested` — never silently accept the
weaker claim.**

Two consequences worth carrying:

- **A `did:key` principal needs no lookup.** The public key IS the
  identifier, so the verifying key ships inside the envelope and the
  principal proof verifies offline with no prior relationship. The
  trade-off: a `did:key` principal cannot rotate, because the key is the
  name. Rotatable principals use `did:web` or DNS TXT.
- **A notary cannot forge an authorization**, because it never holds the
  principal's key. That is why a Notary Service is infrastructure anyone
  may host, and why the question about a notary is code attestation
  (§15, k-of-3 authority over **content digests of published release
  artifacts**) rather than key custody. §15.2 deliberately does NOT say
  "reproducible" — nobody re-derives the digest, so an attestation binds
  the holders' word to an artifact rather than offering an independently
  checkable derivation. Note the stated limit too: attestation proves
  what was *published*, never what is *running*.

Canonicalization per proof (§7.2.1): the principal proof covers the
envelope with EVERY `proofValue` emptied; the notary proof covers it with the
principal `proofValue` present and its own emptied.

## Signing profiles + canonicalization (spec §7.2, §8.1, §8.2)

Two algorithms, both MUST be supported: `EdDSA` (Ed25519, RFC 8032 — recommended
default) and `ES256` (ECDSA P-256, RFC 7518 — required for AP2 interop). Reject
`alg: none` unconditionally.

Three concrete proof profiles:

1. `DataIntegrityProof` + `cryptosuite: "eddsa-jcs-2022"` — Ed25519; `proofValue` is multibase (base58btc).
2. `DataIntegrityProof` + `cryptosuite: "ecdsa-jcs-2019"` — ES256/P-256; same encoding.
3. `JsonWebSignature2020` — detached compact JWS in `proofValue`; protected header MUST carry `alg` (`ES256`|`EdDSA`), `kid` (verification-method DID URL), `typ: "aph+jws"`, `cty: "vc+ld+json"`, `b64: false`, `crit: ["b64"]`.

**The JCS rule:** the signed/verified bytes are the RFC 8785 (JCS) canonicalization
of the envelope with `proof.proofValue` stripped — the rest of the `proof` block
stays in place. Verification (§8.3): parse strictly, resolve the key from
`proof.verificationMethod`, strip `proofValue`, canonicalize, verify signature,
check time window, check algorithm allow-list, and (recommended) recompute the
body hash. **Settled normatively in §7.2.1: set `proofValue` to the empty string, do
NOT remove the member.** Earlier drafts called this implementation-dependent;
they are wrong and should not be quoted. Removing vs emptying produces
different JCS bytes, so the two conventions never verify each other.

Per-proof bases, which are W3C proof-chain semantics — each proof covers the
document plus every proof BEFORE it, never one after:

| Signing | Base |
|---|---|
| lone notary proof | its own `proofValue` emptied |
| principal proof (chain head) | `proof` is a ONE-ELEMENT ARRAY holding that proof, its `proofValue` emptied — discard the notary proof, keep the array form. `[{…}]` and `{…}` are different bytes, which is what stops a stripped chain from re-presenting as a valid lone proof |
| notary countersignature | both proofs, principal's `proofValue` complete, its own emptied |

This forces the issuance order: the notary prepares the envelope (including
`notarization`), the principal signs it, then the notary countersigns.
`decisionTimestamp <= principal.created <= notary.created`. Reverse it and
the principal would be signing bytes that do not exist yet.

## Notary key discovery (spec §8.4, resolution order §8.4.6)

1. **`did:key`** — offline: decode the multibase suffix of the DID itself
   (multicodec `0xed01` = Ed25519, `0x1200` = P-256). No network I/O.
2. **DNS TXT** — DKIM-style record at `_aph._notary.<domain>` (§8.4.5). Tag list:
   `v=APHv1` (required), `alg=ed25519|p256` (required), `k=<base64url key>`
   (required), optional `kid`, `did`, `notBefore`, `notAfter`. Multiple records =
   multiple keys; match `kid` to the `verificationMethod` fragment.
3. **`did:web`** — fetch `https://<domain>/.well-known/did.json` over validated
   TLS, find the `verificationMethod` entry whose `id` equals the full DID URL,
   decode `publicKeyMultibase`.

The order distinguishes **absent** from **broken** (§8.4.6): a mechanism that
is simply not published (no TXT record, no served `did.json`) ADVANCES the
verifier to the next one, and absence that is TERMINAL — the last mechanism in
the sequence, or a pinned mechanism with no successor — is `APH_E014`. A
mechanism that IS published and then fails (malformed record, unfetchable
document, key outside its validity window, unsupported algorithm) REFUSES on
the spot and never falls through — surfacing **the failure's own code**:
`APH_E008` unreachable, `APH_E003` outside the validity window, `APH_E010`
unsupported algorithm, and so on. Do not flatten those into one code. The two
fixed points: `APH_E014` means terminal ABSENCE and nothing else; `APH_E008`
means offered-and-unreachable and nothing else.

Key rotation requires overlapping publication windows (§8.4.7, 30-day minimum
recommended). The overlap is expressed by dated `notBefore`/`notAfter` tags on
the DNS TXT mechanism, and by PRESENCE on `did:web` — both keys in one
document, then the old one removed — because the DID Document schema carries
no per-key validity metadata.

A live reference publication surface exists at
`https://aph-notary.squillo.com/.well-known/did.json`
(`did:web:aph-notary.squillo.com`; until 2026-08-15 the same key published
as `did:web:aph-notary.squillo.workers.dev` — that host now serves nothing,
because a did:web identity is domain-bound and a retired domain must not
serve a mismatched document). While unprovisioned it answers HTTP 503 with
the typed refusal `{"available": false, "reason": …}` — that shape is the
normative degrade, not an outage. It publishes no DNS TXT record today, so
resolving it also exercises absence-advances live.

## HOW-TO

**Validate an envelope** (structural strict-parse only — signature, time
window, and body hash are NOT checked; from
`${CLAUDE_PLUGIN_ROOT}/interpreters/rust`):

```
cargo run -q -p aph-cli -- validate <path/to/envelope.json>
```

**Inspect an envelope:** Read the JSON and compare against the §7.1 tables above —
top-level fields, `@context` order, both `type` entries, the six
`credentialSubject` objects, closed-enum values, `bodySha256` = 64 lowercase hex,
proof shape. `jq` is handy for pulling `credentialSubject.channel.kind`,
`.communication.bodySha256`, and `.proof.cryptosuite`.

**Run the conformance suite** (from `${CLAUDE_PLUGIN_ROOT}/interpreters/rust`):

```
cargo test
```

This exercises the workspace default members (`aph-core`, `aph-conformance`,
`aph-cli`): golden envelope fixtures, contract tests, channel-binding specs, and
round-trips of the repo `examples/*.json`.

**Test the wasm/TS binding** (`aph-ts` sits OUTSIDE default-members, so plain
`cargo test` never reaches it — name it):

```
cargo test -p aph-ts          # native tests of the JSON-text boundary
wasm-pack test --node aph-ts  # the wasm32 smoke over the signed golden
```

The TS boundary is JSON **text in both directions** (never `JsValue`): a JS
number is always an f64, and the untagged single-object-or-chain `proof` union
is exactly where a widened integer could flip which arm deserializes. Exports:
`parseEnvelopeJson`, `serializeEnvelope`, `verifyProofStructure` (returns the
mode the STRUCTURE proves; forged `PrincipalSigned` label throws `APH_E013`),
`requireAttestationMode` (no-downgrade gate; throws `APH_E012`).

**Signed fixtures are never text-edited.** `examples/principal_signed_envelope.json`
carries four REAL Ed25519 signatures (RFC 8032 test seeds). To change it,
update the generator at
`interpreters/rust/aph-conformance/tests/principal_signed_example_test.rs`,
run its byte-identity test, and materialize the bytes it prints between the
`----8<----` cut lines — then re-run the suite green.

**Golden fixtures:** the repo-level `examples/*.json` files are the canonical
wire-shape fixtures (one per channel kind); the conformance crate under
`interpreters/rust` carries additional golden fixtures for its own suites.
Remember: example `proofValue`s are placeholders, so signature verification on
them is EXPECTED to fail — only shape validation is meaningful there.

## Going deeper

Read the actual spec files rather than trusting this summary for edge cases:
`spec/aph-0.1.md` (wire shape §7, signing §8, key discovery §8.4, flows §9,
errors §11), `spec/a2a-extension.md` (extension URI + AgentCard discovery flow),
`spec/security-considerations.md` (what APH does and does not defend against),
`examples/README.md` (what is fixed vs. varying across the 8 fixtures).
