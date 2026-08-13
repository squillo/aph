---
name: spec
description: >-
  APH (Agent per Human) protocol crash course and reference. Use when working with
  APH, NotarizationEnvelope JSON, envelope validation or verification, notarization
  flows, a Delegation Mandate or Communication Mandate, the notary service, the
  "agent driver's license" model, APH error codes (APH_E001..APH_E010), signing
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
- `spec/security-considerations.md` — threat model: in-scope (replay, body tampering, mandate forgery, channel impersonation, alg downgrade), out-of-scope (compromised notary key/device, phishing, transport security).
- `examples/` — 7 golden envelope JSON files, one per channel kind, plus `examples/README.md`. Their `proof.proofValue` strings are illustrative placeholders, NOT real signatures; `bodySha256` is the SHA-256 of the empty string. They exist for shape/round-trip validation only.
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
| `proof` | single proof block (§7.1.11) |

`credentialSubject` contains exactly six objects per spec v0.1 (§7.1.2–§7.1.9;
the reference implementation also accepts an optional `appleAurAcceptance`
extension — see sharp edge 3):

- `humanPrincipal` — `{id (DID), displayName}`
- `agent` — `{id (DID), agentCardUri?, displayName, version}`
- `channel` — `{kind, recipientAddressing}` (addressing shape is channel-specific and OPAQUE — see §7.4)
- `communication` — `{contentClass, bodySha256 (64 lowercase hex), bodySize, previewLines, preview (≤ 8192 bytes)}`
- `policy` — `{decision, matchedScope, delegationMandateId?, actChain?}`
- `notarization` — `{notaryService {id, name, version}, decisionTimestamp, decisionLatencyMs}`

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

- **DelegationMandate** (§6.1) — long-lived standing authority. Fields: `id` (urn:uuid), `humanPrincipalDid`, `agentDid`, `allowedChannels` (non-empty), `rateLimitPerHour?`, `validFrom` < `validUntil`, `notarySignature` (over the JCS form minus `notarySignature`). Revocable by the human at any time (§6.3.1 — conceptual model normative in v0.1; on-wire transport deferred to v0.2, so keep validity windows short).
- **CommunicationMandate** (§6.2) — per-message, single-use. Fields: `id`, `delegationMandateId?` (null for one-shot AskEveryTime), `humanPrincipalDid`, `agentDid`, `channelKind`, `recipientAddressing`, `contentClass`, `bodySha256`, `bodySize`, `policyDecision`, `issuedAt` < `expiresAt` (5 min recommended), `notarySignature`. If `delegationMandateId` is set, the parent must exist, be unexpired, and list `channelKind` in `allowedChannels`.

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

## Error taxonomy (spec §11) — closed set of 10

| Code | Variant | Meaning |
|---|---|---|
| `APH_E001` | `InvalidEnvelopeSignature` | `proof.proofValue` failed against the resolved key over canonical envelope bytes |
| `APH_E002` | `InvalidFlowTransition` | State-machine transition not in the allowed set |
| `APH_E003` | `MandateExpired` | Mandate consulted past `expiresAt` / `validUntil` |
| `APH_E004` | `RoleViolation` | Party attempted an operation outside its §5 role |
| `APH_E005` | `ChannelNotAllowed` | Channel kind not in the Delegation Mandate's `allowedChannels` |
| `APH_E006` | `NotarySignatureInvalid` | Mandate-level `notarySignature` failed (distinct from envelope-level E001) |
| `APH_E007` | `HumanAuthenticationRequired` | AskEveryTime triggered but human unreachable |
| `APH_E008` | `NotaryServiceUnreachable` | Remote notary timed out |
| `APH_E009` | `EnvelopeBodyHashMismatch` | Recipient's SHA-256 of the body != `communication.bodySha256` |
| `APH_E010` | `UnsupportedAlgorithm` | Algorithm outside {`ES256`, `EdDSA`}, or `alg: none` |

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
body hash. Note the §7.2 implementation note: whether `proofValue` is stripped
entirely vs. set to empty string must match between signer and verifier.

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

Never fall back from a stronger anchor to a weaker one mid-resolution; failure
escalates to rejection. Key rotation requires overlapping publication windows
(§8.4.7, 30-day minimum recommended).

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
`examples/README.md` (what is fixed vs. varying across the 7 fixtures).
