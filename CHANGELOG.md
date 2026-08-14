# Changelog

All notable changes to APH (Agent per Human Notarization Protocol) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-draft] — 2026-05-21

### Added

- Initial public draft of the APH protocol specification.
- Canonical envelope shape (W3C Verifiable Credential 2.0).
- Two mandate types: `DelegationMandate` (ongoing) and `CommunicationMandate` (per-message).
- Five protocol roles: `HumanPrincipal`, `AgentSender`, `NotaryService`, `ChannelAdapter`, `RecipientEndpoint`.
- Two flow state machines: human-present (7 states) and human-not-present (5 states).
- A2A Agent Card extension descriptor (URI `aph://extensions/notarization/v1`).
- SD-JWT-VC profile pinning (draft-ietf-oauth-sd-jwt-vc-16, draft-ietf-oauth-selective-disclosure-jwt-22).
- 7 example envelope JSON files covering Slack, Email, Discord, Teams, WhatsApp, Google Chat, and iMessage channels.

### Added (revision 2026-05-21 — additive clarification within 0.1.0-draft)

- New §8.4 **Notary Key Material + Public-Key Discovery**. Defines the public/private keypair model for Notary Service operators and THREE publication mechanisms a verifier can use to resolve a notary's public key with NO prior trust relationship: (1) `did:key` self-describing decode, (2) `did:web` `.well-known/did.json` HTTPS resolution, (3) DNS TXT records at `_aph._notary.<domain>` (DKIM-style tag-list).
- §8.4.5 specifies the DNS TXT record name `_aph._notary.<domain>`, required tags (`v=APHv1`, `alg`, `k`), optional tags (`did`, `kid`, `notBefore`, `notAfter`), worked record examples, and verifier resolution flow.
- §8.4.6 defines verifier resolution order across mechanisms.
- §8.4.7 defines key rotation + overlap windows.
- §8.4.8 defines optional pinning + trust-on-first-use behavior for high-stakes verifiers.
- §13 IANA Considerations extended to reserve the underscore-prefixed DNS labels `_aph` and `_aph._notary` by convention (formal IANA registration deferred to v0.2).
- §14.1 normative references extended with `did:key`, `did:web`, RFC 1035, RFC 4034.
- §14.2 informative references extended with multicodec + multibase pointers.
- §8.3 step 2 cross-references §8.4 for resolution detail.

### Added (revision 2026-05-21b — driver's-license framing + revocation conceptual model within 0.1.0-draft)

- New §1.1 **Mental model — the agent's driver's license**. Frames APH credentials as drivers' licenses for agents, with the human as the issuing authority, the notary as the DMV, and bounded scope (channels, rate, time window, policy decision) directly analogous to license endorsements + restrictions + expiration. Establishes cross-jurisdiction portability (interstate-license framing) as a first-class property.
- New §1.1.1 **Concrete example** — two agents from different organizations negotiating a meeting across an A2A channel under APH, including notary-key resolution via `did:web` and DNS TXT (§8.4), revocation, and the recipient-side verification flow.
- §6.3 **Mandate lifecycle** rewritten. NEW §6.3.1 makes mandate revocation NORMATIVE in v0.1 at the conceptual layer (issuer-side `revoked` state, downstream issuance cutoff, recipient policy guidance, short-validity-window posture for v0.1). On-wire revocation transport (W3C Verifiable Credential Status List 2021 or equivalent) remains deferred to v0.2. NEW §6.3.2 makes expiration semantics explicit (no re-activation; new mandate required).
- §10.1 **A2A composition** expanded with explicit positioning ("A2A defines transport; APH defines the human authorization that rides on top") + back-reference to §1.1.1 worked example.
- §10.2 **AP2 composition** expanded with explicit positioning ("AP2 authorizes payment; APH authorizes the broader category of human-on-behalf-of actions, including the communication that surrounds a payment"). Adds the toll-booth / driver's-license / road-network framing of the A2A + AP2 + APH triad.
- §1 Abstract reworded to scope "outbound actions" more broadly than "outbound communications" — APH covers any human-authorized agent action, including messaging, scheduling, content authorship, and the communications surrounding payments.

### Added (revision 2026-08-12 — reference implementation + agent plugin within 0.1.0-draft)

- Reference Rust implementation under `interpreters/rust/` (cargo workspace):
  - `aph-core` — envelope wire types (strict `deny_unknown_fields` parsing), `DelegationMandate` / `CommunicationMandate`, both flow state machines, the role/operation permission matrix, the `APH_E001`–`APH_E010` error taxonomy, SD-JWT-VC profile pins, the A2A extension descriptor, and vendored signing helpers (RFC 8785-style JCS canonicalization, detached JWS, ES256 sign/verify).
  - `aph-conformance` — golden-envelope fixtures, contract tests, channel binding specs (email, media platforms, MCP), and a suite that strict-parses every envelope in `examples/`.
  - `aph-cli` — `aph validate | inspect | golden` command-line tool.
  - `aph-ts` — wasm binding exposing `parseEnvelopeJson` / `serializeEnvelope`.
- Agent-plugin packaging at the repo root (`.claude-plugin/` manifests, `skills/`, `commands/`) so agentic coding tools can install protocol knowledge, envelope validation, and conformance commands directly from this repository.
- CI: `rust-interpreter.yml` workflow running the interpreter test suite; sanitization checks rescoped to spec-owned paths.

### Added (revision 2026-08-12b — registered extensions + errata within 0.1.0-draft)

- New §7.5 **Registered optional extensions**: OPTIONAL, omitted-when-absent envelope fields pinned by the spec — `credentialSubject.appleAurAcceptance` (§7.5.1), `linkedMandate.ap2SignedPayloadB64` (§7.5.2), `linkedMandate.vaultMutation` (§7.5.3, snake_case interior pinned deliberately). §7.1.2 and §7.1.10 tables gained pointer rows. Extension-free envelopes remain byte-identical to pre-extension envelopes.
- New example `slack_new_with_extensions_envelope.json` (id `…0008`) exercising all three extensions; `examples/README.md` updated.
- **Erratum (§7.1.5, §6.2, §7.4)**: the Google Chat channel kind is `google_chat` (snake_case). Earlier draft text spelled it `googleChat`; every published example and signed fixture emits `google_chat`, so the snake_case form is normative.
- §1.1.1 worked example reworded per the industry-standard transport/payload split (A2A extensions via URI-namespaced `Message.metadata`, DIDComm v2 transport-independence, VC 2.0 rail-external delivery, DKIM/SMTP precedent): A2A is the transport carrying the envelope as extension metadata; `channel.kind` always names the end-delivery medium and never the agent-to-agent rail.

### Changed (revision 2026-08-12c — reference implementation hardening)

- `aph-core` now enforces `#![warn(missing_docs)]`; every public item carries documentation. Added crate README and publication metadata (keywords, categories, `rust-version`).
- `VaultMutationMandate` gained `deny_unknown_fields`, matching the strict-parsing contract every other envelope struct already had (§7.5.3 shape is pinned, so unknown keys inside it are now a hard error rather than silently dropped).
- Added `PartialEq`/`Eq` to `AphError`, `AgentExtension`, and both flow structs so consumers can compare them.
- CLI: `aph help` exits 0, output survives a closed pipe (`aph golden | head`), a corrupt fixture exits 1 instead of 0, and `inspect` now surfaces the security-relevant optional claims (vault mutation, AP2 links, AUR acceptance) instead of collapsing `linkedMandate` to "present".
- wasm binding emits plain JS objects (`json_compatible` serializer) rather than ES2015 `Map`s for the opaque `recipientAddressing` blob.
- Test suite expanded to 185 tests, each carrying a rationale comment stating what it pins and why. New coverage: JCS edge cases (empty containers, `-0`, exponent-range floats, integer extremes, duplicate keys, astral-plane key ordering, parser recursion limit), detached-JWS negative matrix (malformed arity, empty signature, tampered header, padded and raw-R||S signatures, payload length changes), base64url canonical-form rejection, 1 MiB signing, and RFC 6979 determinism.
- Corrected `jcs.rs` documentation that claimed strict RFC 8785 compliance and described a trailing-zero strip the code does not perform; both binding specs now mark their v0.2-candidate sections instead of contradicting the shipped envelope shape.

### Added (revision 2026-08-12d — documentation)

- Three runnable, self-narrating examples under `interpreters/rust/aph-core/examples/`: `parse_and_inspect` (strict parsing and reading a claim), `sign_and_verify` (canonicalize → detached JWS → verify → tamper-detection), and `mandates_and_flows` (scope checks, validity windows, both state machines, the permission matrix).
- `interpreters/rust/README.md` — workspace guide: crate roles, conformance corpora, CLI contract, and the two deliberate RFC divergences.
- `interpreters/rust/aph-core/README.md` — crate-level documentation.
- Root README gained a "Using the reference implementation (Rust)" section with worked code for verification, signature checking, and scope/consent enforcement, plus JavaScript/wasm and agent-plugin install instructions.
- `aph-core` is publishable to crates.io (`aph-core = "0.1"`). `aph-cli` and `aph-conformance` remain unpublished; the manifests record why.

### Added (revision 2026-08-13 — the principal signs; notary code attestation, within 0.1.0-draft)

APH is pre-production with no external adopters, so this correction lands **in place** rather than forking a version — there is one specification, `spec/aph-0.1.md`. Earlier drafts of §1.1/§3.1 promised that the human principal could sign directly while the wire format could not express it, which made every credential notary-attested in truth: a verifier learned that *a notary asserts* the human authorized an action, never that the human did.

- **§7.1.11 proof chains.** `proof` MAY be a single object or an array. As an array it is a W3C Verifiable Credentials 2.0 **proof chain** — a facility the data model already defines, not an APH invention — constrained to two roles: a principal proof carrying the authorization, then a notary countersignature covering the *complete* principal proof, so a notary cannot detach a principal's signature and re-attach it to a different envelope. Verifiers MUST verify in chain order.
- **§6.1 `DelegationMandate.principalSignature`** — the human's own signature over the standing grant, and the root of every credential issued under it. `notarySignature` now countersigns what the principal signed.
- **§7.1.7 `policy.attestationMode`** — closed enum, `PrincipalSigned` | `NotaryAttested`. **Absent means `NotaryAttested`**, so envelopes written before this revision remain valid and unambiguous. A verifier requiring `PrincipalSigned` MUST refuse `NotaryAttested` rather than silently accept the weaker claim, mirroring §8.4.6's no-downgrade rule for key discovery.
- **§7.1.7 `policy.delegationMandate` + new §7.1.7.1** — the complete parent mandate, embedded. In the human-not-present flow the human is asleep and cannot sign *this* message; `delegationMandateId` names their grant by **id only**, and an id is not verifiable. Embedding the mandate lets a recipient check the human's `principalSignature`, the granted scope, and the window entirely offline — closing the one hole that otherwise left the human's authorization asserted rather than proved.
- **New §7.2.1** — canonicalization base pinned per proof and per mandate signature, normatively, as the **empty string** rather than member removal. This settles the question earlier drafts left open, in the direction the reference implementation has always taken.
- **New §15 Notary Code Attestation** — a k-of-3 authority (any two of three holder keys) over content digests of published release artifacts, reusing Sigstore / in-toto / SLSA vocabulary rather than defining an APH schema. §15.7 states the limit **normatively**: an attestation proves what code was *published*, never what is *running*; any surface rendering an attestation badge MUST convey that, and a design implying otherwise is non-conformant.
- **§7.1.11 chain linkage.** Every proof in a chain carries an `id`; the notary proof carries `previousProof` naming the principal proof's `id`. Array position is a hint an intermediary can rearrange — the signed reference is the binding, and a verifier MUST reject a chain whose linkage is missing, dangling, or cyclic.
- **§7.3.1 worked `PrincipalSigned` example** — the same Slack reply as §7.3, with the mode declared, the parent mandate embedded, and the two-proof chain shown end to end.
- **§8.3.1** — amended verification: read the mode, resolve the principal key (free and offline for a `did:key` principal), verify the principal proof *before* the notary proof, and verify an embedded mandate when the envelope is notary-attested.

- **§7.2.1 issuance order is normative.** Each proof covers the document plus every proof *before* it and nothing after — W3C Data Integrity proof-chain semantics. So the notary **prepares** the complete envelope (including `notarization`), the principal signs *that*, and the notary countersigns. `decisionTimestamp <= principalProof.created <= notaryProof.created`. The principal's base carries its proof as a **one-element array**, which domain-separates it from a lone notary proof: a chain stripped of its countersignature therefore cannot be re-presented as a valid single-proof envelope. An earlier draft of this revision defined the principal's base as the whole envelope with every `proofValue` blanked, which is unconstructible: it would require the human to sign over the notary's proof object and decision timestamp, neither of which exists when the human signs.
- **§7.1.11 binds the label to the structure, both ways.** `attestationMode: PrincipalSigned` MUST accompany a two-element chain whose head verifies under a key resolving to `credentialSubject.humanPrincipal.id`; a chain MUST carry that label; a mismatch is rejected with `APH_E013`. Without this the mode is a self-asserted string — a notary key alone could write `PrincipalSigned` above a single notary proof whose `proofPurpose` is `assertionMethod`, indistinguishable by purpose from a principal proof.
- **§11 gains three error codes** (`APH_E011` principal signature invalid, `APH_E012` attestation mode refused, `APH_E013` proof chain invalid), so the closed taxonomy covers the rejections §8.3.1 now requires. `APH_E011` is deliberately distinct from `APH_E001` and `APH_E006`, which are both *notary* signatures: only `APH_E011` means the authorization itself is forged.
- **§15.5 defines how a verifier checks an attestation** — resolve all three authority keys through §8.4, fetch under the §8.4.4 transport rules, require two signatures from two *distinct* keys, bind the digest byte-for-byte, then apply local policy. §8.3.1 step 10 previously referenced a check the document never specified.
- **§7.1.9 declares `attestedDigest` and `attestationUri`**, which §15.3 lets a notary send. Parsing is strict, so a field a conformant notary may emit has to exist in the shape a conformant verifier parses.

- **§15.2 stops claiming reproducibility, and §15.6 names what blocks §15.** The subject of an attestation is a content digest of a *published release artifact*; the earlier wording said "reproducible build", which claims a determinism property APH does not require, does not test, and cannot deliver. The weaker property the digest does rest on is **publication closure** — the commit must be buildable from what is published alone. The consequence is now stated where a reader will look for it: an attestation says *these holders vouch that this digest is the release they published*, NOT *anyone can rebuild the source and derive this digest*. Without reproducibility a third party cannot re-derive it, so the mechanism binds the holders' word to an artifact rather than offering an independently checkable derivation. New **§15.6** lists the four preconditions that make §15 unimplementable today — the authority has no DID, the format is "one of three" (which is zero for an implementer), nothing is contracted to fetch an attestation document, and §11's closed taxonomy has no code for a failed check — and forbids advertising §15 support until all four are settled.

### Changed (revision 2026-08-13)

- **A Notary Service is now hostable by anyone.** It never holds the principal's key, so it cannot forge an authorization; its compromise costs availability and metadata, not credentials. The question about a notary becomes supply-chain (does it run published code) rather than custodial (is it trusted with a key) — which is what §15 exists to answer.
- **§3.1 prose reconciled** with the wire format, so the specification no longer promises a mode it cannot express.
- **§4, §5.2, §6.3, §8.2, §8.3, §8.4 and the security companion** were rewritten wherever they still taught the notary as the root signer — including §4's architecture diagram, which now shows the prepare / sign / countersign order, and `spec/security-considerations.md` §3.1, which previously said a leaked notary key lets an attacker "issue arbitrary envelopes under the human principal's name". It no longer can, except in the one shape where nothing the human signed is present: `NotaryAttested` with no embedded mandate. That residual risk is now stated where the claim used to be.
- **`spec/security-considerations.md` gains §2.6 attestation-mode downgrade**, the structural twin of §2.5's algorithm downgrade and strictly more consequential: `alg: none` costs a signature check, this costs the whole authorization claim.
- **`CONTRIBUTING.md` records the pre-production exception** that permits an in-place correction, and states when it expires — the first external adopter.

### Notes (revision 2026-08-13)

- **A `did:key` principal needs no key lookup** — the public key *is* the identifier, so the principal proof verifies offline with no publication and no prior relationship. Trade-off, stated wherever `did:key` is recommended: such a principal **cannot rotate**, because the key is the name. Rotatable identities use `did:web` or DNS TXT, which carry `kid`.
- The eight published example envelopes remain valid: they omit `attestationMode` and are therefore `NotaryAttested` by definition. A `PrincipalSigned` example lands with the implementation.
- ~~Implementation of the new fields is pending; the reference implementation currently ships the pre-revision shape.~~ *Discharged 2026-08-13, same day: `aph-core` ships the full revision — the `EnvelopeProofs` object-or-array union, per-role canonicalization bases (`crypto/proof_base.rs`), `sign_as_principal` / `countersign_as_notary`, and structural verification — and `examples/principal_signed_envelope.json` is the first published `PrincipalSigned` artifact, regenerated and byte-compared by conformance from RFC 8032 §7.1 public test seeds, with a negative twin proving the §7.2.1 array-form domain separation on the published bytes.*
- The N Lang **APH Spec Snapp** (`APH Spec/0.1.0/`) tracks the revision: `PolicyDescriptor` gains `attestation_mode` and the embedded `delegation_mandate`, `DelegationMandate` gains a required `principal_signature`, `EnvelopeProof` gains `id` and `previous_proof`, and mandates now load before the envelope that embeds them. Two new `nlang how` cards — *Attestation Mode* and *Proof Chain* — teach the corrected model, and each card's code is extracted from the type source so it cannot drift.

### Added (revision 2026-08-13, later the same day)

- **`APH_E014` `NotaryKeyNotPublished` joins the §11 taxonomy** (now fourteen codes). §8.4.6 made the absence/failure distinction normative — absence advances the resolution sequence, failure stops it — but the taxonomy itself had no word for terminal absence, so `aph-core`'s own boundary flattened "nothing is published here" into `APH_E008` "the service was unreachable" with only a message to tell them apart. Terminal DNS TXT absence and a fetched DID Document that names no matching key now surface `APH_E014`; `APH_E008` again means exactly what it says. §8.4.6 names the code at the terminal-absence clause; transport-level opacity for `did:web` fetch failures is unchanged (a fetched-but-keyless document reveals nothing an opaque transport error was protecting — the requester already reached the host).
- **The first `PrincipalSigned` example is published**: `examples/principal_signed_envelope.json`, the §7.3.1 worked example fully signed (chain form plus both §6.1 mandate signatures) from RFC 8032 §7.1 TEST 2 / TEST 3 public seeds, regenerated and byte-compared by conformance so it cannot drift from the signing code, with a negative twin proving the stripped countersignature verifies under no key.

### Fixed (revision 2026-08-13)

- **§6.1's worked example omitted `principalSignature`**, which its own field table marks required. The example and the validation rules now carry it, with the principal check ordered before the countersignature.
- **The embedded mandate was never bound to the envelope carrying it.** §7.1.7.1 and §8.3.1 step 1d now require `humanPrincipalDid`, `agentDid` and `id` to match the envelope's own values; without those equalities any validly-signed mandate could be stapled to any envelope.
- **§7.1.7.1 states what "within scope" does not cover** (a mandate constrains channel, rate and time — not recipients, not content class), what embedding discloses (the human's entire standing grant, to every recipient), and that a verifier must bound work on unauthenticated input (RECOMMENDED 64 KiB) because canonicalization precedes signature verification.
- **§15.1 requires the two threshold signatures to come from two distinct holder keys** — otherwise one compromised holder signs twice and k-of-3 silently degrades to 1-of-3.
- Stale canonicalization language ("strip", "minus `proof.proofValue`") removed from §8.2 and §8.3, which contradicted §7.2.1 and would have failed every signature a conformant signer produced.

### Changed (revision 2026-08-13b — worked-example ids + wasm JSON-text boundary)

- **The worked examples no longer share envelope ids with the published channel examples.** §7.3's envelope id is now `…00f0` (was `…0001`, which `slack_reply_envelope.json` also carries) and §7.3.1's — and therefore the signed golden `principal_signed_envelope.json`'s — is now `…00f3` (was `…0002`, which `email_reply_envelope.json` also carries). The `…00f1`/`…00f2` slots remain the golden's own proof ids, untouched. §7.3 and the Slack-reply example file were the same envelope; after this renumber they intentionally diverge. The golden's envelope proofs are re-signed because the id sits inside the signed bytes; its embedded mandate id (`…00d1`) collides with nothing published and is unchanged, so both §6.1 mandate signatures stand. The §7.3/§7.3.1 spec blocks keep their placeholder signatures — only ids change there.
- **The `aph-ts` wasm boundary is JSON text in BOTH directions.** `parseEnvelopeJson` takes a JSON string and returns the envelope re-emitted as canonical JSON text; `serializeEnvelope` takes JSON text instead of a `JsValue`. The `serde-wasm-bindgen` route (and dependency) is removed: a JS number is always an `f64`, and the untagged object-or-array `proof` union is exactly where a widened integer could silently change which arm deserializes — JSON text makes that impossible structurally. The crate gains its first tests: native round-trips of the signed `PrincipalSigned` golden (chain form) and a legacy envelope (single form), pinning both union arms and integer fidelity across the boundary.
- **`aph-ts` exports `verifyProofStructure` and `requireAttestationMode`**, wrapping the reference implementation's §7.1.11 structural check and §8.3.1 step-1a mode gate, so a TypeScript consumer can detect a forged `PrincipalSigned` label (`APH_E013`) and refuse an attestation-mode downgrade (`APH_E012`) with the same codes the Rust API raises.

### Changed (revision 2026-08-14 — CI reaches aph-ts)

- **CI finally runs the `aph-ts` tests.** `aph-ts` sits outside the workspace's `default-members`, so the interpreter workflow's bare `cargo test` never reached its tests; the workflow now runs `cargo test -p aph-ts` natively AND a new wasm32 smoke suite under Node (`wasm-pack test --node aph-ts`), which replaces the old type-check-only wasm step. The smoke test feeds the published `PrincipalSigned` golden through the real exported wasm functions — parse, structural verification, re-serialization, and the no-downgrade gate — pinning integer fidelity across the compiled boundary. The tag-gated publish workflow names `aph-ts` explicitly for the same reason.

### Notes

- This is a draft for community review. Wire shape may change before v0.1.0 final.
- JSON Schema files are deferred to v0.2.
- Conformance test vectors are deferred to v0.2.
