---
name: spec
description: >-
  APH (Agent per Human) protocol crash course and reference. Use when working with
  APH, NotarizationEnvelope JSON, envelope validation or verification, notarization
  flows, a Delegation Mandate or Communication Mandate, the notary service, the
  "agent driver's license" model, APH error codes (APH_E001..APH_E020), signing
  profiles (eddsa-jcs-2022, ecdsa-jcs-2019, detached JWS), notary public-key
  discovery (did:key, did:web, DNS TXT), channel kinds, or the A2A notarization
  extension. Also covers OPERATING a Notary Service — signing-key loss, pre-authorized
  rotation, status-list publication cadence, seed escrow, and the unregistered
  `aph://` / `_aph` conventions. Covers wire shape, state machines, closed enums,
  how to run the reference Rust implementation and conformance suite, and how to
  build a non-Rust implementation against the published vectors.
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
- `spec/security-considerations.md` — threat model: in-scope (replay, body tampering, mandate forgery, channel impersonation, alg downgrade, attestation-mode downgrade), out-of-scope (compromised notary key/device, key LOSS, publication-surface DoS, phishing, transport security).
- `spec/operations.md` — the operator runbook, and **non-normative**: what a Notary Service operator holds, what losing each piece costs, pre-authorized rotation, the publication-cadence deadlines, and the unregistered identifiers an adopter inherits. Where it and the spec disagree, the spec wins and the runbook is the defect.
- `examples/` — 14 golden envelope JSON files (enumerated on disk): one per channel kind (7 — the messaging seven; `service` and `squillo` have no golden yet), one exercising the §7.5 registered extensions, one carrying the §7.1.12 `actClassification` claim (citing the shipped guardrail bundle by its own digest), one carrying the §7.1.13 `audience` binding (RFC 0003 — and the one golden whose window is MINUTES, as §6.3 now says every single-act window should be), THREE signed vectors — one per signing path §8.1/§8.2 make MUST-support — and `ts_minted_envelope.json`, minted by the second implementation. With `examples/README.md`. Ten carry illustrative placeholder `proof.proofValue` strings, NOT real signatures, with `bodySha256` the SHA-256 of the empty string — they exist for shape/round-trip validation only, and they are `NotaryAttested` because they carry no `attestationMode` and absent means `NotaryAttested`. ⛔ Do NOT read "NotaryAttested" as "unsigned": ELEVEN files are `NotaryAttested` and one of those eleven, `detached_jws_envelope.json`, verifies. The four that verify: `principal_signed_envelope.json` (`PrincipalSigned`, four real Ed25519 `eddsa-jcs-2022` signatures from RFC 8032 §7.1 public test seeds, plus the embedded mandate), `es256_signed_envelope.json` (the same `PrincipalSigned` chain under `ecdsa-jcs-2019`, from the published RFC 6979 A.2.5 and RFC 7515 A.3.1 P-256 scalars), `detached_jws_envelope.json` (`NotaryAttested`, a `JsonWebSignature2020` compact detached JWS, verifiable offline from its own P-256 `did:key` issuer), and `ts_minted_envelope.json` (`PrincipalSigned`, four real Ed25519 signatures minted by `interpreters/typescript/` and verified by the Rust conformance suite; BOTH parties are `did:key` so it needs no supplied key, and it is the ONE example whose body binding is real — the complete body travels in `preview`).
- **Publishing a notary (§8.4):** `aph render-txt <did:key> [--kid K] [--domain D]` renders the §8.4.5 DNS TXT value (record NAME to stderr, value to stdout), and `aph render-did <did:web> <did:key#kid>…` renders the §8.4.4 DID Document, several keys for a §8.4.7 rotation overlap. Both delegate to `aph-core`'s renderers — the SAME code a verifier reads those forms with, so the two cannot drift. `aph render-vocab <bundle.json> [--domain D]` renders the §8.5.1 vocabulary digest record, reading `@snapp.integrity` from the bundle rather than recomputing it. ⛔ PUBLIC key material only: a `did:key` IS a public key; a signing seed must never reach a command line, where `ps` exposes it to every process on the host.
- `interpreters/rust/` — the reference Rust implementation, a cargo workspace with members: `aph-core` (protocol types + validation), `aph-conformance` (conformance suite), `aph-cli` (CLI; the binary is named `aph`), `aph-resolver` (the optional DNS TXT + `did:web` adapters, the only crate carrying HTTP/DNS deps), `aph-ts` (wasm binding), `aph-py` (pyo3 binding; Python module `aph`) and `aph-js-harness` (a TEST harness and NOT a fourth binding: it runs the TypeScript implementation's compiled crypto-free core under a second ECMAScript engine inside the cargo process). `aph-ts`, `aph-py` and `aph-js-harness` all sit outside `default-members` — the two bindings each need a toolchain the protocol crates do not, and the harness needs the TypeScript build output on disk — so plain `cargo test` reaches none of the three and each must be named with `-p`. The two bindings are held at export parity with each other, the Elixir binding, and the Go binding under `interpreters/go` — a FOUR-way contract.
- `interpreters/elixir/` — the THIRD binding (`aph-ex`): a mix app `aph` wrapping a rustler NIF at `native/aph_nif` that path-depends on `aph-core`. Its crate is EXCLUDED from the cargo workspace outright, not merely from `default-members`, because mix drives NIF builds and two build drivers on one member is a reliability defect. ⛔ Not an implementation and not a fourth verifier: zero cryptography on the Elixir side, every signature-touching operation across the NIF. `mix test` is the ONLY gate that exercises the term boundary — a NIF is Rust embedded in the BEAM, so `cargo test` never sees a term — which is why every NIF function is decode-string/call-core/encode-result and nothing more.
- `interpreters/go/` — the FOURTH binding: a pure-Go package running the reference as WebAssembly under wazero (no cgo, no C toolchain — the shim is `interpreters/rust/aph-wasm-abi`, a plain ptr/len ABI, deliberately NOT wasm-bindgen). Methods on a `*Runtime` handle (`New`/`Close` — the one idiom divergence, justified by the wasm instance lifecycle); errors carry the APH code via `errors.As`. ⛔ The committed `internal/wasm/aph.wasm` is the repo's ONE deliberate binary, VERIFIED not trusted: CI rebuilds it from the pinned toolchain with canonicalized paths and byte-diffs on every relevant push. Go's `encoding/json` widens to float64, so the JSON-text boundary rule applies here with its ORIGINAL rationale — the 2^53+1 tripwire is back in its original meaning.
- `interpreters/typescript/` — the SECOND implementation: full mint + verify, sharing no code with the Rust. Its own RFC 8785 canonicalizer, strict parser, §7.2.1 bases, base58btc and `did:key` codecs; every signature through WebCrypto. Node ≥ 20, zero runtime dependencies, `typescript` the only dev-time one. ⛔ It is NOT a binding and NOT wasm — do not confuse it with `aph-ts`. Independence of CODE, not of TEAM: same authors, so it proves the spec is implementable twice and not that it survives a stranger.

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

- **Channel kinds** (§7.1.5): `slack`, `email`, `discord`, `teams`, `whatsapp`, `google_chat`, `imessage`, `service` (RFC 0002 — a service endpoint an agent delivers a state-changing act to), `squillo` (RFC 0007 — an in-application messaging surface where a human reads in that application's client).
- **contentClass** (§7.1.6): `Reply`, `New`, `Mention`, `DM`, `Channel`, `BulkSend`, `Broadcast`, `Mutation` (RFC 0002 — this act changes state rather than carrying a message).
- **`actClassification`** (§7.1.12, optional, omitted when absent): what the sender says the act MEANS, against vocabularies both parties resolve independently (§8.5). `vocabularies` is a list because an OVERLAY is a separate published artifact with its own digest; `labels` is a list because one act carries verdicts from several families at once, each written `FAMILY/LABEL` — a bare label is a strict-parse refusal. ⚠ EMITTING it is version-gated: §7.1's parse is strict, so a verifier built before the field existed fails at strict parse, BELOW the error vocabulary. It proves which vocabulary the sender CITED, never that they classified correctly.
- **`audience`** (§7.1.13, optional, omitted when absent — RFC 0003): WHO may accept the envelope (`id`, a DID) and optionally on which delivery coordinates (`channelBinding`: `kind` from the closed set plus open coordinate members, compared member-by-member). Absence = a bearer credential by the producer's explicit choice. Paired with single-use (§8.3 step 8b: `id` is spent by acceptance, refused thereafter with E018) — single-use is per-verifier, audience narrows the verifiers to one, and neither is sufficient alone. ⚠ EMITTING is version-gated exactly as `actClassification`: strict parse fails BELOW the error vocabulary on a pre-RFC-0003 verifier.
- **`recipientClass`** (§7.1.5 on the channel block, optional — RFC 0005): who CONSUMES what lands, from the closed set `human`, `agent`. The second dimension the a2a_email request was really asking for — a refinement that must apply to every kind is not a kind. In a mandate, `allowedRecipientClasses` (§6.1) is the constraint a human could not previously write down ("email to PEOPLE"); under a constrained grant, declaring outside it OR declaring nothing refuses with E020. A sender's value is a CLAIM binding the honest-but-over-broad agent, not a hostile one. Same version-gated emission rule as its two optional siblings.
- **Policy decisions** (§7.1.7): `AlwaysAllow`, `AskEveryTime`, `NeverAllow`. (`NeverAllow` is recorded but never yields an envelope.) Closed as a TYPE in the reference (`PolicyDecision`) — an unrecognized value is a strict-parse refusal, same as the channel and content-class sets.
- **Proof types** (§7.1.11): `DataIntegrityProof` or `JsonWebSignature2020`.
- **Roles** (§5.1): `HumanPrincipal`, `AgentSender`, `NotaryService`, `ChannelAdapter`, `RecipientEndpoint`. **Operations** (§5.2): `IssueDelegationMandate`, `IssueCommunicationMandate`, `Notarize`, `Transport`, `Verify`, `Reject`.

### WARNING — three sharp edges

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
| `APH_E016` | `MandateRequired` | A human-not-present act (§9.2) with NO matching unexpired Delegation Mandate — nothing authorized this. Distinct from E007 (nobody was asked), E011 (the authorization presented is invalid), and E015 (it was withdrawn); reporting absence under any of those conflates absence with failure |
| `APH_E017` | `AudienceMismatch` | The envelope's `audience.id` (§7.1.13) is not this verifier, or a `channelBinding` member differs from the act's delivery coordinates — a member those coordinates LACK included, and "cannot determine my identity/the coordinates" included: §8.3 step 5a rejects rather than skips. An envelope without `audience` NEVER produces this code — absence is the producer's bearer-credential decision |
| `APH_E018` | `EnvelopeAlreadySpent` | This `id` was accepted before (§8.3 step 8b): the envelope is spent by acceptance and every later presentation is a replay, whoever presents it. PER-VERIFIER — says nothing about what other verifiers saw; audience binding is what narrows the set of verifiers to one |
| `APH_E019` | `EnvelopeWindowInvalid` | The envelope's OWN `validFrom`/`validUntil` judged against the verifier's clock (§8.3 step 6), unparseable-fails-closed included. Distinct from E003, which is a MANDATE consulted past its expiry — the standing miscite before this code existed |
| `APH_E020` | `RecipientClassNotAllowed` | The mandate constrains WHO may consume (`allowedRecipientClasses`, RFC 0005) and the envelope declares a class outside it — or NONE, which refuses too: a constraint escapable by omission is not a constraint. Distinct from E005 (the MEDIUM out of scope); this is the CONSUMER out of scope on an allowed medium |

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
no per-key validity metadata. That same overlap, used defensively — a successor
published *before* it is needed and left published — is the key-continuity
mechanism in the operator section below.

A live reference publication surface exists at
`https://aph-notary.squillo.com/.well-known/did.json`
(`did:web:aph-notary.squillo.com`; until 2026-08-15 the same key published
as `did:web:aph-notary.squillo.workers.dev` — that host now serves nothing,
because a did:web identity is domain-bound and a retired domain must not
serve a mismatched document). While unprovisioned it answers HTTP 503 with
the typed refusal `{"available": false, "reason": …}` — that shape is the
normative degrade, not an outage. It publishes no DNS TXT record today, so
resolving it also exercises absence-advances live.

## Operating a notary (`spec/operations.md`)

An operator holds four things, and the one that matters most is not the one
people name first.

**Domain control, not the signing key, is the root of publication authority.**
Both discovery mechanisms are anchored in domain ownership — §8.4.4 in the TLS
chain, §8.4.5 in DNS — and NEITHER is authenticated by the notary's signing key.
Whoever controls the domain can publish a new key; nobody else can, whatever key
they hold. So a lost signing key is a rotation nobody scheduled, while lost
registrar credentials are the genuinely unrecoverable case — and no escrow scheme
repairs that one, because the missing capability is publication, not signing.
Keeping the two credential stores independent is the cheapest and largest
mitigation available (runbook §2.3), and it costs no cryptography at all.

**Key loss has a six-minute fuse.** Nothing already signed is invalidated, and no
human's authority is touched — the notary never held a principal key, so a
`PrincipalSigned` envelope's authorization layer is untouched and what stopped is
the witness. What breaks fast is the revocation transport: the last published
status list ages out at 360s (below), and from that moment every status-carrying
envelope is refused `APH_E008` by every conformant verifier. Key loss is an
incident measured in minutes, not in the days a re-publication takes.

**Pre-authorized rotation is the recommended continuity mechanism** (runbook §3).
Generate a successor keypair on media separate from the signing host, publish
BOTH public keys continuously with distinct `kid`s, and keep signing with the
primary. Because verifiers already accept the successor, recovery becomes a
change to what the operator SIGNS with rather than to what the world can READ —
no document edit, no DNS propagation, no cache to wait out, and nothing that must
be done with a key that no longer exists.

⛔ **The `kid` on the record is only half of it — the SIGNER must emit the
`#kid` fragment in `proof.verificationMethod` BEFORE a second key is published
anywhere** (runbook §3.4 step 3). With two keys published and no fragment to
choose by, the two mechanisms fail differently and neither is acceptable:
`did:web` refuses with `APH_E014`, because the document declines to guess among
several keys rather than let its own ordering decide, while a DNS TXT verifier
has no `kid` to filter on and takes the FIRST record valid at that instant, in
resolver answer order — so about half of answers check a primary-signed envelope
against the successor's key. Both fail closed, but it is a verification outage
the continuity mechanism itself caused, and the DNS half is intermittent.
§8.4.7 bounds this ambiguity to a 30-day overlap; a permanently published
successor makes it permanent. Confirming that both keys RESOLVE does not detect
it — two keys resolve fine in exactly the broken state.

⛔ **Do not call the successor "pre-signed by the old key".** APH v0.1 defines no
signed rotation statement, and neither publication surface is key-authenticated.
The successor is pre-*authorized* by having been published under the operator's
domain control while the primary was healthy — the same authority that publishes
every APH key. Saying it was signed by the predecessor overstates what the wire
carries; a signed rotation attestation is a v0.2 question. Two honest costs:
two keys can sign for this identity for the WHOLE period rather than a 30-day
window, and an unrehearsed successor is an untested backup (runbook §3.6 is the
rehearsal, and it is not optional).

⛔ **This repository ships no secret-sharing code, deliberately — do not add
any.** An operator MAY split the seed *k*-of-*n* using an audited external tool
of their own choosing, holding every share themselves; runbook §4 states what
that buys (no single medium reconstructs the key; the SAME key is restored, so
nothing published changes) and what it costs (reconstruction assembles the whole
seed in one place at one moment, and share placement is the entire security of
the scheme). Implementing one here would be hand-rolled cryptography in the
highest-consequence place available: a subtly wrong sharing scheme does not fail
loudly — it leaks the key to a holder of fewer than *k* shares and the operator
never finds out. The decision to escrow at all, and in what form, is the
operator's; nothing in APH requires it.

### Publication cadence — the two deadlines

The §6.3.3.3 freshness bound is correct in direction and silent in arrival: a
publisher that quietly stops does not degrade, it works and works and then every
verifier in the world refuses at once. Both lines are measured from the published
document's own `validFrom`:

| Line | When | Binds | What it means |
|---|---|---|---|
| Republish deadline | `validFrom + 120s` | the publisher | **the alarm** — you are late, nothing is refused yet |
| Refusal cliff | `validFrom + 300s + 60s` skew | every verifier | **the outage** — `APH_E008` on every status-carrying envelope |

The gap — 360s − 120s = **240 seconds, four minutes** — is the entire warning
window, and it only helps someone looking at it. A publisher reads both distances
off the document it is about to serve rather than re-deriving either bound:

```rust
let credential = aph_core::parse_status_list_credential(&document)?;
let alarm = credential.seconds_until_republish_due(now)?; // negative once late
let cliff = credential.seconds_until_stale(now)?;         // negative once refused
```

Both are pure functions of the document and the instant you pass — `aph-core`
still reads no clock of its own, which is why `now` is an argument here exactly
as it is for `check_envelope_status`. **Negative is a distance, not an error:** a
monitor needs "how late am I", not only "too late", so these report a signed
distance where `check_freshness` reports a verdict. The interval constant is
`aph_core::credential_status::STATUS_REPUBLISH_INTERVAL_SECONDS`, so a publisher
never copies `120` out of prose. Runbook §5.2 carries an external `curl`/`jq`
monitor — run it from OUTSIDE the publisher's failure domain, because a monitor
sharing that domain goes quiet at exactly the moment it is needed and silence
reads as health. When the alarm fires, check whether the SIGNER is alive before
the publisher: a locked key store presents identically to a broken upload.

### Unregistered conventions an adopter inherits

APH v0.1 uses several identifiers that are conventions rather than
registrations. **Four of them can change what an adopter's software does**, and
those four do NOT share one status — §13 says something different about each, so
do not collapse them into a single "unregistered, coming in v0.2" claim when
advising an adopter. Three bullets, four identifiers: the first bullet holds
two, because the underscored labels and the scheme share a status exactly:

- `aph://` URI scheme and the `_aph` / `_aph._notary` underscored DNS labels —
  **the two §13 has written requests for**, drafted in `spec/registrations/`
  with submission pending. Used by convention in v0.1. Do not round this up to
  "registered" when advising: a draft is not a registration, neither name is
  APH's until IANA acts, and the name-ownership exposure is exactly what it was
  before the drafts existed. The DNS draft additionally leaves a wire-shape
  question open for the specification owner, so even its final label is not
  settled.
- `application/aph+ld+json` media type — **declined, not deferred.** §13 says
  v0.1 does NOT register a new media type and names the already-registered
  `application/vc+ld+json` as the conformant choice; the APH-specific type is
  an optional transport-routing indicator, and conformant verifiers MUST accept
  both. There is no v0.2 media-type registration on the roadmap to promise.
- `https://w3id.org/aph/v1` JSON-LD context — **not mentioned in §13 at all.**
  §7.1.1 requires it in every envelope and nothing currently serves it, so
  tooling that dereferences contexts will fail to fetch it.

Two more are unregistered and inert, which is why they sit outside the four:
the JWS protected-header `typ` value `aph+jws`, matched as a literal, and the
`urn:aph:schema:0.1:*` `$id`s on `spec/schemas/*.schema.json`, which are URNs
precisely so nothing fetches them. Six in total; four with a cost.

**None of them affects whether an envelope verifies.** A conformant TXT parser
refuses any record whose `v` tag is not `APHv1`, so a foreign record at a
colliding name is ignored rather than misread as a key. What is genuinely at risk
is name ownership — if `_aph` is later assigned elsewhere, APH moves and every
published record is reissued — and therefore what an adopter may promise their
own users about stability before v0.2. The operator runbook's §6 **tabulates the
four that carry a cost**, one row each with what a collision would cost, and
names the other two in prose beneath the table so the enumeration is complete
rather than convenient. It enumerates six and tabulates four; do not quote it as
a six-row table.

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
`aph-cli`, `aph-resolver`): golden envelope fixtures, contract tests, channel-binding specs,
round-trips of the repo `examples/*.json`, and the multi-party exchange e2e
below.

**The multi-party exchange e2e** (`aph-conformance/tests/`) is the only place
in this repository where two parties exchange anything — every other test is
one party validating fixtures. Nineteen tests across three suites plus a shared
harness (`tests/multi_party/mod.rs`), runnable alone with
`cargo test -p aph-conformance --test two_party_exchange --test
three_party_relay --test cross_notary_revocation`:

- **`two_party_exchange` (8)** — Bob's verifier resolves a stranger's key
  through the §8.4.6 chain and admits; then FOUR refusals, each proving a
  different gate and asserting its CODE: a foreign key at Alice's own DNS name
  resolves fine and dies at the signature check (`APH_E001`), the same bytes
  refuse when only the evaluation instant moves (`APH_E003`), a re-issued
  status list refuses (`APH_E015`), edited covered fields refuse (`APH_E011`).
  Plus: a broken DNS anchor never downgrades to the web origin (and the
  document is proven never fetched), and a key published in DNS preempts the
  document fetch.
- **`three_party_relay` (4)** — Alice → Bob → Carol with Bob verifying inbound
  AND issuing outbound: a verifier's own identity provably never enters what it
  admits, and Carol's verdict on Bob is independent of Bob's verdict on Alice
  in both directions.
- **`cross_notary_revocation` (7)** — Bob refuses by reading Alice's PUBLISHED,
  signature-verified status list, never her store. A forged list is rejected
  even when served from Alice's own origin, naming Alice as issuer, signed by a
  real published resolvable notary that simply is not Alice; replaying Alice's
  own older list cannot roll a revocation back; a status URL on another
  notary's origin is refused WITHOUT a fetch.

The harness is worth reading in its own right: `verify_inbound` is the §8.3 /
§8.3.1 recipient algorithm assembled end to end (mode gate → proof structure →
principal key and proof → notary key through the §8.4.6 chain at the
envelope's `decisionTimestamp` → notary proof → issuance order → embedded-
mandate binding → both §6.1 mandate signatures → validity window → step-8a
revocation), so an implementer building a verifier in any language can follow
it step for step. Party separation is structural, not asserted: each party has
its own keys, notary origin, and status index; the wire is two maps of TEXT;
an envelope crosses only as a JSON string the recipient re-parses. Every seed
is a single byte repeated 32 times and a tripwire test pins that, so real key
material substituted into the cast fails immediately.

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

**Test the Python binding** (`aph-py` sits OUTSIDE default-members for the
same reason — name it, and note it needs a Python distribution shipping a
shared libpython):

```
cargo test -p aph-py          # native tests of the JSON-text boundary, run under a live interpreter
```

Same boundary, same reason: envelopes cross as `str`, never as `dict`, because
a Python `float` is an IEEE-754 double exactly like a JS `number` and an
object route hands arm selection to a second deserializer. The exports are the
`aph-ts` four in snake_case — `parse_envelope_json`, `serialize_envelope`,
`verify_proof_structure`, `require_attestation_mode` — raising one exception,
`aph.AphError`, whose message leads with the `APH_E*` code so a Python caller
matches `APH_E013` exactly as a TS caller matches it.

**Test the Elixir binding** (a separate toolchain and a separate job; run it
from `interpreters/elixir/`, and note this is the ONLY gate that ever sees the
NIF term boundary — a rustler NIF is Rust embedded in the BEAM, so nothing
under `cargo test` can reach it):

```
mix deps.get                  # rustler, pinned tight to what the installed BEAM can build
mix test                      # compiles the NIF through cargo, then runs ExUnit
```

Same boundary, third time, and the BEAM is where the reasoning has to be
restated rather than reused: Erlang integers are arbitrary precision, so the
number-widening argument does not apply and a term route LOOKS safe — but a
map/list encoder still has to pick an arm of the untagged `proof` union with no
schema to consult. The exports are the same four in BEAM idiom —
`APH.parse_envelope_json/1`, `APH.serialize_envelope/1`,
`APH.verify_proof_structure/1`, `APH.require_attestation_mode/2` — answering
`{:ok, result} | {:error, code}` rather than raising, because a refused
envelope is an ordinary outcome there; the `APH_E*` code travels as the wire
string, so `APH_E013` is matched exactly as it is in the other three.

That parity is a contract, not a coincidence: an addition to any one binding is
unfinished until it lands in the others — a census test now counts every export surface against one roster — because bindings teaching different
things is how one protocol acquires several meanings. None is a second
implementation — that question is answered by `interpreters/typescript/`, which
shares no code with this workspace.

**The second implementation, and its honest scope.**
`interpreters/typescript/` is a full mint + verify implementation written from
`spec/aph-0.1.md` and the published examples: its own RFC 8785 canonicalizer,
strict parser, §7.2.1 bases, base58btc and `did:key` codecs, with every
signature through the runtime's WebCrypto. Run it with `cd
interpreters/typescript && npm install && npm run build && npm test`. It
cross-verifies with the Rust in BOTH directions as committed bytes — it admits
`examples/principal_signed_envelope.json`, and
`interpreters/rust/aph-conformance/tests/ts_minted_cross_verify.rs` fully
verifies `examples/ts_minted_envelope.json`, which it minted. Neither stack
invokes the other. ⛔ Two limits to state whenever it is cited: it is
independence of CODE and not of TEAM (same authors, so it does not prove the
document survives a stranger), and the committed cross-artifact is Ed25519
ONLY, because WebCrypto's ECDSA is randomized and exposes no RFC 6979 mode —
a TypeScript-minted ES256 envelope cannot be byte-pinned, so that path is
covered by verifying the Rust vector plus a mint-then-verify self-test.

**A specification contradiction the second implementation surfaced.** §6.1's
field table says a Delegation Mandate signature covers the canonical form
"MINUS" the signature members; §7.2.1 closes with "In every case the signer
sets the field to the empty string rather than removing the member". Those are
different JCS bytes and cannot both be right. The published bytes select
REMOVAL, pinned by
`interpreters/typescript/test/mandate_base_ambiguity.test.ts`, which also shows
the emptying reading does not verify. §7.2.1's closing sentence is correct for
`proofValue` and overreaches into the mandate bullet above it. Filed, not
fixed: the artifacts are what anyone has actually signed.

**Signed fixtures are never text-edited.** Three published examples carry REAL
signatures, each with its own generator under
`interpreters/rust/aph-conformance/tests/`:
`principal_signed_envelope.json` ← `principal_signed_example_test.rs`,
`es256_signed_envelope.json` ← `es256_signed_example_test.rs`,
`detached_jws_envelope.json` ← `detached_jws_example_test.rs` (the last two
share `tests/generator_support/mod.rs`). To change any of them, edit its
generator, run its byte-identity test, and materialize the bytes it prints
between the `----8<----` cut lines — then re-run the suite green.

`examples/ts_minted_envelope.json` is the fourth signed file and the one
exception to that recipe, because its generator is not Rust: it is minted by
`interpreters/typescript/scripts/mint_ts_envelope.ts`, so changing it means
editing `interpreters/typescript/testkit/ts_minted.ts` and running `npm run
build && npm run mint`, which rewrites the file in place. Its byte-identity
tripwire is `test/ts_minted_artifact.test.ts` on the TypeScript side, and
`ts_minted_cross_verify.rs` on the Rust side must stay green afterwards — that
is the whole point of the artifact.

**Golden fixtures:** the repo-level `examples/*.json` files are the canonical
wire-shape fixtures; the conformance crate under `interpreters/rust` carries
additional golden fixtures for its own suites. Remember which is which: the
EIGHT shape-only examples (seven channel kinds plus the §7.5 extensions file)
carry placeholder `proofValue`s, so signature verification on them is EXPECTED
to fail and only shape validation is meaningful there. The FOUR signed vectors
are the opposite — verification on them is expected to SUCCEED, and a failure
there is a real defect.

**Implement APH in another language.** README's *"Implementing APH in another
language"* section is the entry point and states the targets in order:

1. Point your PARSER at `examples/*.json` — 12 files, no toolchain. Unknown
   top-level or `credentialSubject`-level fields must be hard errors;
   `channel.recipientAddressing` is the one opaque exception.
2. Point your VERIFIER at the FOUR signed examples — no toolchain, three of
   them one per signing path §8.1/§8.2 make MUST-support and the fourth minted
   by a different implementation, every key a PUBLISHED test vector that
   authorizes nothing and that anyone can re-derive:
   - `principal_signed_envelope.json` — four real Ed25519 `eddsa-jcs-2022`
     signatures over RFC 8032 §7.1 TEST 2 (principal) and TEST 3 (notary)
     seeds. Reproducing all four means you have independently implemented
     RFC 8785, the §7.2.1 per-proof bases, §7.1.11 chain linkage, and the
     §7.1.7.1 embedded-mandate check.
   - `es256_signed_envelope.json` — the same `PrincipalSigned` chain under
     `ecdsa-jcs-2019`, from the RFC 6979 A.2.5 (principal) and RFC 7515 A.3.1
     (notary) P-256 scalars. `proofValue` is P1363 `r‖s`, multibase — never
     DER. Diff it against the Ed25519 file to see exactly what the second
     algorithm changes.
   - `detached_jws_envelope.json` — `JsonWebSignature2020`, a compact detached
     JWS over the SAME §7.2.1 base, `NotaryAttested`, verifiable offline from
     its own P-256 `did:key` issuer. Its protected header carries the six
     members §8.2 requires and a verifier MUST check them (§8.3 step 7) — that
     is what rejects `alg: none`. ⛔ Two deployed quirks are preserved
     deliberately: `"b64":false` + `"crit":["b64"]` while the payload IS
     base64url-encoded into the signing input, and a **DER** ES256 signature
     inside the token rather than RFC 7518's raw `r‖s`. Encoding follows the
     carriage, not the algorithm — the same crate emits `r‖s` for
     `ecdsa-jcs-2019`.
   - `ts_minted_envelope.json` — the same `PrincipalSigned` Ed25519 shape as
     the first file, but minted by `interpreters/typescript/` rather than by
     the Rust, so a third implementer checking against it is checking a
     document two independent codebases already agree on. Two properties make
     it the easiest first target: BOTH parties are `did:key`, so it verifies
     with no supplied key and no network, and its body binding is REAL — the
     complete body travels in `preview`, with `bodySize` its UTF-8 length and
     `bodySha256` its digest, so §8.3 step 8 is checkable from this one file.
     Same principal as the Ed25519 golden (RFC 8032 §7.1 TEST 2).

   ⛔ **Say why byte comparison is legitimate on the ES256 vectors**, because
   it looks wrong: most ECDSA is randomized, so a reader assumes two runs
   cannot match. The reference uses RFC 6979 DETERMINISTIC ECDSA — the nonce
   comes from the key and the message — which is the only reason those files
   can be byte-reproducible goldens. An implementer whose ES256 signer is
   randomized should compare by VERIFYING, not by diffing.
3. Point your PRODUCER at this repo's parser — the only target needing a Rust
   toolchain, and it does not make your emitter Rust:
   `your-impl emit-envelope | cargo run -q -p aph-cli -- validate -` (exit 0 =
   strict-parses; `1` names the offending field). Conversely
   `cargo run -q -p aph-cli -- golden <n>` prints fixture *n* (1-based) raw on
   stdout for piping into your own verifier.
4. Point your REVOCATION code at `spec/schemas/`, plus the §8.4.4 DID Document
   and the two §8.4.5 TXT records — both usable directly as parse vectors, to
   two different standards: the reference tests reassemble the TXT tag-lists
   **byte-for-byte**, while the DID Document is reproduced verbatim in content
   but **re-indented** (2 spaces in the spec, 4 in the Rust literal). Do not
   repeat "byte-for-byte" over both; JSON whitespace is not semantic, so the
   vector is no weaker, but the claim would be.
   `spec/schemas/README.md` names the three rules no JSON Schema can express.

⛔ **Quote the coverage GAPS too — overclaiming coverage is worse than admitting
one.** Every algorithm §8.1 requires now has a signed vector EXCEPT `alg: EdDSA`
carried inside a detached JWS — the fourth algorithm/carriage combination, which
the reference does not implement and refuses by name (`APH_E010`) rather than
mis-reporting as a bad signature, so there is nothing to publish for it. Ten
of the fourteen examples exercise SHAPE only (the seven channel files, the
§7.5 extensions file, and the §7.1.12/§7.1.13 field goldens); the other four
are the signed vectors above. §8.3's
BODY-HASH binding is exercised by TWO files, one end to end: the signed golden
attests the SHA-256 and exact byte length of the committed
`examples/principal_signed_body.txt` (the suite re-hashes it recipient-style,
and a one-byte-different body refuses with `APH_E009` — the refusal is the
test), and `ts_minted_envelope.json` binds the body it carries in `preview`.
TWELVE of the fourteen still pair the empty-string digest with a fictional
`bodySize` and are shape-only on this axis — including the ES256 and
detached-JWS vectors, which prove signatures, not bodies. The second implementation is also not an independent TEAM — same authors
as the Rust — so it closes "implementable twice" and not "survives a
stranger". The §6.3.3 vectors are Rust constants in
`aph-conformance/src/lib.rs` rather than loadable files. The status-list vectors
stop before the proof, so an implementation can pass every one of them while
having no proof check at all — the single failure that makes the mechanism
forgeable. (The REFERENCE implementation's proof check is pinned end to end by
the cross-notary exchange test, forged-list case included — but that is Rust
exercising Rust; a non-Rust implementer still has no proof VECTOR to check
against, so the gap stands for them.) The §8.4.5 printed TXT example's key bytes are not a valid curve
point, so it is a parse vector and never a verify vector. And there is no JSON
Schema for the envelope; §7.1 and the strict parser are the shape. README carries
this list in full — cite it rather than re-deriving it.

**Use APH in your own project.** Pick the crate by what it is allowed to
touch, because that boundary is deliberate:

| crate | what it does | network? |
|---|---|---|
| `aph-core` | types, strict parsing, validation, signing bases, the §6.3.3 status check | **never** — no HTTP, no DNS, no clock |
| `aph-resolver` | ready-made §8.4.5 DNS TXT + §8.4.4 `did:web` adapters over `aph-core`'s ports | yes — the ONLY crate that may carry them |
| `aph-cli` | the `aph` binary: `validate | inspect | golden` | no |
| `aph-ts` | the wasm/TS binding (JSON text in both directions) | no |
| `aph-py` | the pyo3/Python binding, module `aph` (same surface, same JSON-text boundary) | no |
| `interpreters/elixir` | not a workspace member: the rustler/BEAM binding, app `aph` (same surface, same JSON-text boundary, `{:ok, _} \| {:error, code}`) | no |
| `interpreters/typescript` | not a crate: the SECOND implementation, mint + verify on WebCrypto | **never** — parses bytes handed to it |

Most integrations want `aph-core` alone and supply their own transport by
implementing its two fetch ports; take `aph-resolver` only if you want the
batteries-included adapters. Depend on it either by version
(`aph-core = "0.1.0-alpha.1"` — a pre-release, so cargo will not
auto-select it and an adopter opts in on purpose while the spec reads draft) or, to track a specific commit,
`aph-core = { git = "https://github.com/squillo/aph", rev = "<sha>" }` — pin a
`rev`, never a bare branch, so a verifier's behaviour cannot change under it.

**Check whether a mandate has been revoked** (§6.3.3). The entry point is
`aph_core::credential_status::check_envelope_status`, and it asks the caller for
TWO things that are NOT oversights — each one exists to make a specific failure
impossible:

```rust
check_envelope_status(
  &envelope,
  &fetch,                // impl StatusCredentialFetch — your HTTP
  &expand_encoded_list,  // &dyn Fn(&[u8]) -> Result<Vec<u8>, AphError> — your gzip
  &issuer_key,           // ed25519_dalek::VerifyingKey — REQUIRED
  now_rfc3339,           // your clock
).await
```

- **`expand_encoded_list` is yours because this crate carries no compression
  dependency.** It links into a wasm binding and into a kernel that both pay for
  every byte, and inflating a gzip stream is a pure `&[u8] -> Vec<u8>` transform
  with no protocol content. Hand in whatever inflater you already have.
- ⛔ **`issuer_key` is REQUIRED, and that is the security property.** A status
  list nobody verified is an unauthenticated assertion about whether somebody's
  authority is still valid — an attacker who can answer for the status endpoint
  would otherwise flip a revoked mandate back to live, turning the mechanism
  built to ENFORCE revocation into the way a revoked agent proves it is fine.
  This crate shipped for exactly one commit with that check documented as a
  caller obligation instead of taken as an argument; documentation is the
  weakest rung, so it became a parameter. You cannot obtain a verdict without
  naming the key that authenticates it. Pass the SAME key you resolved to verify
  the envelope — the same notary signs both, and resolving twice is two chances
  to disagree.
- The clock is an argument for the same reason `aph-core` never reads one: the
  §6.3.3.3 freshness bound needs `now`, and a library that reads its own clock
  cannot be tested deterministically.

Outcomes: `Ok(Skipped)` when the envelope carries no `credentialStatus` (absent
is NOT "unrevoked" — enforcing a claim nobody made is not fail-closed),
`Ok(NotRevoked)` on a clear bit in a document whose proof verified, and `Err` for
everything else — `APH_E015` revoked, `APH_E008` unreachable or unauthenticated.
A cross-origin status URL is refused WITHOUT being fetched.

## Going deeper

Read the actual spec files rather than trusting this summary for edge cases:
`spec/aph-0.1.md` (wire shape §7, signing §8, key discovery §8.4, flows §9,
errors §11), `spec/a2a-extension.md` (extension URI + AgentCard discovery flow),
`spec/security-considerations.md` (what APH does and does not defend against),
`spec/operations.md` (running one: key loss §2, pre-authorized rotation §3,
threshold split §4, publication cadence §5, unregistered identifiers §6,
pre-flight checklist §7 — non-normative, the spec wins on conflict),
`examples/README.md` (what is fixed vs. varying across the 12 fixtures — eight
shape-only `NotaryAttested` files plus four signed ones: three vectors, one per
MUST-support signing path, and `ts_minted_envelope.json` from the second
implementation).
