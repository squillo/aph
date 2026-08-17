# APH — Agent per Human Notarization Protocol

![The APH emblem — a human figure and an AI chip joined in an infinity loop inside a chained seal — surrounded by scenes of people from many cultures and walks of life working alongside robots and AI assistants: an elder signing a document with a robot, a family with tablets, clinicians, office workers at laptops, and a delivery drone, all linked by glowing network lines carrying padlock and document icons.](assets/aph-banner.jpg)

APH is an open protocol for cryptographically notarizing the actions an autonomous agent takes on behalf of a specific human, producing a W3C Verifiable Credential 2.0-shaped envelope that any downstream recipient can independently verify across vendors and across organizations.

## Mental model — the agent's driver's license

Think of an APH credential as an **agent's driver's license**:

- **A human (the issuing authority)** authorizes a specific agent to act on their behalf within bounded parameters — and **signs that authorization with their own key**.
- **A notary service (the DMV)** witnesses the decision, records when policy was evaluated, countersigns, and publishes its verification key so anyone can independently check the credential against the public record. Because it never holds the human's key, a notary **cannot forge an authorization** — which is why anyone may host one.
- **The license carries a scope** — which channels, which content classes, which recipients, how often, for how long.
- **The license is revocable** — the issuing human can pull it at any time.
- **The license is portable across jurisdictions** — like an interstate driver's license, an APH credential issued by one organization's notary is verifiable by any other organization's agent or system using only public standards. No bilateral integration required.

When an agent presents a notarized message, the recipient can verify, without trusting the sending agent's runtime or its identity provider, that:

1. A specific human authorized this specific action — proved either by the human's own signature on the envelope, or by their signature on the Delegation Mandate that authorized it, which travels embedded so the check stays offline. `policy.attestationMode` says which, so a recipient never has to guess.
2. The action falls within the scope of the human's standing delegation.
3. The notary that signed the license holds the private key it claims to hold (verifiable via DNS-anchored public key publication — see spec §8.4).
4. The license has not expired and has not been revoked (checkable against a status list the notary publishes at an endpoint derived from its own `did:web` — see spec §6.3.3).

## Where APH fits next to A2A and AP2

APH is a complement to Google's open agent protocols, not a replacement:

- **A2A (Agent2Agent)** — standardizes how two agents discover each other and exchange messages. APH attaches to A2A messages as a Verifiable Credential extension so the receiving agent can verify the sending agent actually has its human's permission for this specific action.
- **AP2 (Agentic Payments)** — standardizes how an agent obtains a human-signed mandate to make a payment. APH covers the broader case: any human-authorized action an agent takes, including but not limited to payment. AP2 and APH cross-link via the envelope's `linkedMandate` field so a single agent action can carry both a payment mandate AND a communication authorization.
- **APH (Agent per Human)** — the missing piece. Where A2A defines the transport and AP2 defines payment authorization, APH defines **per-action human authorization** — an agent's verifiable credential to act on a specific human's behalf for a specific task on a specific channel.

In one sentence: **A2A is the road network, AP2 is the toll booth, APH is the driver's license.**

## Concrete example — two agents negotiating a meeting

Alice's agent and Bob's agent are negotiating a meeting time over a public channel. Both agents act with autonomy within bounded parameters their humans set in advance. Each outbound message carries an APH envelope:

- Alice's agent emits an A2A message proposing 3 pm Tuesday, carrying its APH envelope as extension metadata under the `aph://extensions/notarization/v1` key (APH is transport-independent — the agent-to-agent rail is never the envelope's channel). The envelope is notarized by Squillo's notary on Alice's behalf, with `channel = email` (the medium the confirmed invite will land on), `contentClass = Reply`, `policy.matchedScope = per-channel`, and a `DelegationMandate` reference showing Alice pre-authorized her agent to schedule meetings for the next 30 days.
- Bob's agent verifies the APH envelope by resolving Squillo's notary public key (via `did:web` `.well-known/did.json` or via the `_aph._notary.squillo.com` DNS TXT record — both anchored in public infrastructure Bob doesn't need a Squillo account to read), then checks the signature, the time window, the scope, and the body hash.
- Bob's agent replies with a counter-proposal under its own APH envelope, notarized by Bob's organization's notary, which Alice's agent verifies the same way.
- Neither human is in the loop for the negotiation itself, but every action either agent takes is provably bound to a license its human issued ahead of time and can revoke at any time.

If Alice decides she no longer wants her agent scheduling on her behalf, she revokes the DelegationMandate: her notary stops issuing new CommunicationMandates against it immediately, and it sets the mandate's bit in the status list it publishes, so envelopes already referencing it fail verification on Bob's side too. Bob's agent resolves that status endpoint from Squillo's own `did:web` rather than from anything Alice's agent sent — an old envelope does not get to name a friendlier host to answer for it (spec §6.3.3). Short validity windows remain good practice as defense in depth: they bound the damage if Bob's agent cannot reach the status surface at all.

## What problem APH solves

- Agents can already act on behalf of humans, but recipients have no portable way to tell **if a human actually authorized this specific outbound message**.
- Existing protocols cover adjacent slices: A2A handles agent-to-agent transport, AP2 handles agent-initiated payment authorization, MCP handles tool-call typing — none binds a particular outbound message to a verifiable human keypair held on the human's device.
- APH closes that gap with a notarization step that runs locally on the sending side and produces a portable, verifiable credential the recipient can check without trusting the sending agent's runtime or its identity provider.

## Why "notarization"

A Notary Service is meaningful only if a **third party can independently verify** its signatures. APH therefore models notaries as a public/private keypair where the PUBLIC key is publishable like a DKIM or TLS key — anchored in DNS or HTTPS — so any verifier on the open internet can resolve it and check the signature with no prior trust relationship to the notary operator. See spec §8.4 for the three publication mechanisms (`did:key` offline, `did:web` `.well-known/did.json`, and DNS TXT at `_aph._notary.<domain>`).

## Status

**v0.1.0-draft** — protocol design phase, pre-production with no external adopters, so corrections land in place rather than forking a version. The specification text, the canonical envelope shape, and a small set of reference example envelopes are published here for community review. A reference Rust implementation lives in this repository under `interpreters/rust/` (wire types, flow state machines, signing helpers, and a conformance suite that validates the `examples/` envelopes).

Machine-readable artifacts exist for part of the surface, not all of it: `spec/schemas/` carries JSON Schemas for the two revocation shapes of §6.3.3 (there is none for the envelope itself — §7.1 plus the strict parser is the normative shape), and exactly one published envelope carries real signatures rather than placeholders. [Implementing APH in another language](#implementing-aph-in-another-language) states precisely what is and is not covered, because an implementer who over-trusts the vectors ships a verifier that passes them and fails a stranger.

Two conventions to know before you adopt: `aph://` (the extension-URI scheme) and `_aph._notary.<domain>` (the DNS key-publication name) are **conventions, not IANA registrations** — registration is deferred to v0.2 (spec §13). Neither affects whether an envelope verifies, and a conformant TXT parser refuses any record whose `v` tag is not `APHv1`, so a foreign record at a colliding name is ignored rather than misread as a key. What is genuinely at risk is name ownership: if those names are later assigned elsewhere, APH moves. [`spec/operations.md` §6](spec/operations.md) enumerates every unregistered identifier with the consequence of each.

## Relationship to other protocols

APH builds on the W3C Verifiable Credentials Data Model 2.0, JWS detached signatures (RFC 7515), JSON Canonicalization Scheme (RFC 8785), SD-JWT-VC (draft-ietf-oauth-sd-jwt-vc-16), and OAuth 2.0 Token Exchange (RFC 8693). It composes with — but does NOT replace — A2A (agent discovery and transport), AP2 (payment mandates), and MCP (tool-call typing). Where applicable, an APH envelope MAY ride alongside an AP2 IntentMandate via the envelope's `linkedMandate` field so that send-consent and payment-authorization are linkable but separately signed.

## Quick reference — the wire shape

A full schema lives under `spec/aph-0.1.md`. The example below is a complete v0.1 envelope notarizing a Slack reply. The same envelope shape applies across all supported channels (Email, Slack, Discord, Teams, WhatsApp, Google Chat, iMessage) with only the `credentialSubject.channel` block changing per channel.

```json
{
  "aphVersion": "0.1",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/aph/v1"
  ],
  "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
  "id": "urn:uuid:00000000-0000-4000-8000-0000000000f0",
  "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
  "validFrom": "2026-05-21T00:00:00Z",
  "validUntil": "2026-05-22T00:00:00Z",
  "credentialSubject": {
    "humanPrincipal": {
      "id": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
      "displayName": "Scott Wyatt"
    },
    "agent": {
      "id": "did:web:agent.squillo.com",
      "agentCardUri": "https://agent.squillo.com/.well-known/agent-card.json",
      "displayName": "Squillo Concierge",
      "version": "1.0"
    },
    "channel": {
      "kind": "slack",
      "recipientAddressing": {
        "teamId": "T01234567",
        "channelId": "C01234567",
        "parentTs": "1716249600.000100"
      }
    },
    "communication": {
      "contentClass": "Reply",
      "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "bodySize": 1842,
      "previewLines": 3,
      "preview": "Hey team — quick update on the deploy:\n• prod rollout finished at 14:02 UTC\n• no error spikes in the first hour"
    },
    "policy": {
      "decision": "AskEveryTime",
      "matchedScope": "per-channel",
      "delegationMandateId": null,
      "actChain": []
    },
    "notarization": {
      "notaryService": {
        "id": "did:web:notary.squillo.com",
        "name": "Squillo Notary Service",
        "version": "0.1.0"
      },
      "decisionTimestamp": "2026-05-21T00:00:01Z",
      "decisionLatencyMs": 1834
    }
  },
  "linkedMandate": null,
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
    "created": "2026-05-21T00:00:01Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3WgvA9JHkbV3qLZHcM4FxBp4xHfQVnVnPKKDdyazQwQGdGzxsRdmZWBxXwQvN6P2sLZbLP4HnRy9LcZdpFLLM6h"
  }
}
```

**This example is `NotaryAttested`** — it carries no `policy.attestationMode`,
and an absent field means `NotaryAttested` (spec §7.1.7). Read it as *a notary
asserts this human authorized this*: the single `proof` is the notary's, not
the human's. The stronger `PrincipalSigned` shape, where the human's own key
signs and the notary countersigns in a two-element proof chain, is at
[spec §7.3.1](spec/aph-0.1.md). Both are valid; a verifier must never report
the weaker one as the stronger.

The envelope ships on the wire in two simultaneous encodings:

1. **JSON-LD Verifiable Credential (above)** — full self-describing form used for archive, audit logs, and recipient-side full-fidelity verification.
2. **JWS detached compact** — short form carried in channel-native metadata (email header `APH-Attestation:`, Slack `blocks` metadata, etc.). The protected header pins `alg` (`EdDSA` or `ES256`), `kid`, `typ: aph+jws`, and `cty: vc+ld+json`. The payload is the JCS-canonicalized JSON-LD VC.

## Repo layout

```
aph/
  spec/
    aph-0.1.md          Specification text (v0.1 draft)
    a2a-extension.md    A2A AgentCard extension descriptor
    security-considerations.md   Threat model / security companion
  assets/
    aph-banner.jpg      README banner
  examples/
    slack_reply_envelope.json
    email_reply_envelope.json
    discord_dm_envelope.json
    teams_channel_envelope.json
    whatsapp_envelope.json
    google_chat_envelope.json
    imessage_envelope.json
  interpreters/
    rust/               Reference Rust implementation (cargo workspace)
      aph-core/         Wire types, mandates, flow state machines, signing helpers
      aph-conformance/  Golden-envelope + contract conformance suite, channel binding specs
      aph-cli/          `aph` binary: validate / inspect / golden (conformance fixtures)
      aph-resolver/     Optional DNS TXT + did:web fetch adapters (the only crate carrying HTTP/DNS deps)
      aph-ts/           wasm binding (parse/serialize for JS hosts)
      aph-core/examples/  Runnable, self-narrating usage examples
  APH Spec/
    0.1.0/              N Lang Specification Snapp (literate .n.md types)
      how/              Worked examples served by `nlang how --plugin aph`
  snapp/
    aph@0.1.0-alpha.1.json   Compiled Snapp bundle
  .claude-plugin/       Agent-plugin + marketplace manifests
  skills/               Agent skill: the protocol crash course (/aph:spec)
  commands/             Agent commands: /aph:validate, /aph:conformance
  .github/
    workflows/
      validate-examples.yml   JSON validity + sanitization checks
      rust-interpreter.yml    cargo test for interpreters/rust
  README.md
  LICENSE
  CONTRIBUTING.md
  CHANGELOG.md
```

## Using the reference implementation (Rust)

`aph-core` is the protocol library — wire types, mandates, the two flow state machines, the role matrix, the error taxonomy, and the signing helpers. It depends only on `serde`, `serde_json`, `thiserror`, `chrono`, `p256`, and `base64`.

```toml
[dependencies]
aph-core = "0.1.0-alpha.1"
```

### Verify an envelope you received

Parsing is strict by design (spec §7.1): an unknown field is a hard error, so a producer cannot smuggle a claim past a verifier that does not understand it.

```rust
let envelope: aph_core::NotarizationEnvelope = serde_json::from_str(received)?;

let subject = &envelope.credential_subject;
println!("{} authorized {} to send on {}",
    subject.human_principal.display_name,
    subject.agent.display_name,
    subject.channel.kind);
```

### Check a signature

The signature covers the *canonical* form of the envelope, not the JSON text it arrived as — which is what lets an envelope survive re-serialization by intermediaries. Strip the signature slot, canonicalize, then verify:

```rust
let mut unsigned = serde_json::to_value(&envelope)?;
unsigned["proof"]["proofValue"] = serde_json::json!("");

let canonical = aph_core::canonicalize_rfc8785(&unsigned);
let ok = aph_core::verify_detached_jws(&jws, canonical.as_bytes(), &notary_key);
```

Resolving `notary_key` from the issuer DID is the verifier's job (spec §8.4: `did:key` offline, DNS TXT at `_aph._notary.<domain>`, or `did:web`). `aph_core::discovery` ships that resolution split in two halves: the parsing and publication code is pure and offline (`dns_txt`, `did_document`, `publish`, and the `did:key` decode), while the DNS query and the HTTPS document fetch stay behind the two one-method traits in `discovery::ports` for your adapter to supply. `discovery::composer::resolve` drives them in the §8.4.6 order — `did:key`, then DNS TXT, then `did:web` — advancing on ABSENCE only, and never falling back to a weaker anchor after a failure.

### Enforce scope and consent

```rust
// Standing authority: does this mandate still cover this send?
if !mandate.is_valid_at(now) || !mandate.allows_channel("slack") {
    return Err(aph_core::AphError::channel_not_allowed("slack"));
}

// Human-present flow: authority cannot be minted without the human
// being asked — this transition is refused with APH_E002.
let mut flow = aph_core::HumanPresentNotarizationFlow::new(mandate_id);
flow.transition_to(aph_core::HumanPresentNotarizationState::MandateIssued)?; // Err
```

### Runnable examples

Each one narrates what it is doing as it runs:

```sh
cd interpreters/rust
cargo run -p aph-core --example parse_and_inspect    # strict parsing, reading a claim
cargo run -p aph-core --example sign_and_verify      # canonicalize -> sign -> verify -> tamper
cargo run -p aph-core --example mandates_and_flows   # scope, validity, both state machines
```

### Command line

```sh
cargo run -p aph-cli -- validate examples/slack_reply_envelope.json
cargo run -p aph-cli -- inspect  examples/slack_reply_envelope.json
cargo run -p aph-cli -- golden                       # list conformance fixtures
```

`validate` is a strict **structural** check — it does not verify signatures, time windows, or body hashes (spec §8.3 steps 2–8). Exit codes: `0` valid, `1` invalid, `2` usage.

### JavaScript / TypeScript

```sh
cd interpreters/rust && wasm-pack build aph-ts --target web
```

```js
import { parseEnvelopeJson, serializeEnvelope } from './pkg/aph_ts.js';
const envelope = parseEnvelopeJson(received);  // throws on invalid shape
```

### Conformance

`interpreters/rust/aph-conformance` carries golden fixtures, contract tests, and the three channel binding specs (email, chat platforms, MCP). It also validates every envelope in `examples/` against the implementation and asserts that what the implementation *emits* is value-identical to those published files — the check that catches serializer-side drift. See [interpreters/rust/README.md](interpreters/rust/README.md) for the full picture, including the two deliberate divergences from RFC 8785 and RFC 7518 that the tests deliberately pin.

## Implementing APH in another language

APH is only a protocol if a second implementation can be built from what is published here. This section is the entry point for that: what to point your own code at, in what order, and — just as importantly — what these artifacts do **not** prove.

### The four targets, and what each one proves

**1. Point your PARSER at `examples/*.json` (9 files, no toolchain required).** Every file must deserialize under a strict schema: unknown top-level or `credentialSubject`-level fields are hard errors (§7.1), and `channel.recipientAddressing` is the one exception whose sub-fields are opaque and MUST NOT fail (§7.4). If your parser accepts a field APH never defined, a producer can smuggle a claim past you.

**2. Point your VERIFIER at `examples/principal_signed_envelope.json` (no toolchain required).** This is the only published envelope carrying real signatures — four of them: two envelope proofs and two mandate signatures, all Ed25519 under the RFC 8032 §7.1 TEST 2 (principal) and TEST 3 (notary) public test seeds, which authorize nothing and which anyone can re-derive. A verifier that reproduces all four has independently implemented RFC 8785 canonicalization, the per-proof signing bases of §7.2.1, the proof-chain linkage of §7.1.11, and the embedded-mandate check of §7.1.7.1. Getting §7.2.1 wrong is the likeliest failure: `proofValue` is set to the **empty string**, not removed, and the principal proof covers `proof` as a **one-element array**.

**3. Point your PRODUCER at this repository's parser.** The CLI reads stdin, so nothing about your emitter has to be written in Rust:

```sh
your-implementation emit-envelope | cargo run -q -p aph-cli -- validate -
```

Exit `0` means your bytes strict-parse; `1` means they do not, with the serde error naming the field. Conversely, `cargo run -q -p aph-cli -- golden <n>` prints fixture *n* raw on stdout for piping into your own verifier. These two are the only targets that need a Rust toolchain.

**A worked recipient, when the vectors are not enough.** The four targets above
hand you artifacts; the multi-party exchange tests hand you the ALGORITHM.
`interpreters/rust/aph-conformance/tests/multi_party/mod.rs` assembles the §8.3
recipient procedure end to end in `verify_inbound` — mode gate, proof
structure, principal key and proof, notary key through the §8.4.6 chain at the
envelope's own `decisionTimestamp`, notary proof, issuance order,
embedded-mandate binding, both mandate signatures, validity window, and the
step-8a revocation check — driven by three suites in which two parties with
fully separate keys, notary origins, and stores exchange envelopes as JSON
text over a wire that carries nothing else. The refusal tests each assert a
specific error code, so they double as a map from "what an attacker changed"
to "which check refuses it". If you are implementing a verifier in another
language, read that harness the way you would read pseudocode in the spec —
except this copy compiles, and `cargo test -p aph-conformance` proves it.

**4. Point your revocation code at `spec/schemas/` and the spec's own printed records.** The two schemas constrain the §6.3.3 status entry and status list credential; `spec/schemas/README.md` states the three rules no JSON Schema can express (same-origin binding, issuer binding, proof and freshness). For key discovery, both the §8.4.4 DID Document and the two §8.4.5 DNS TXT records are usable directly as parse vectors, but they are reproduced to two different standards and the difference is worth stating: the reference tests reassemble the two TXT tag-lists **byte-for-byte** — a byte comparison would pass — while the DID Document is reproduced **verbatim in content but re-indented** (2 spaces in the spec, 4 in the Rust literal that holds it). JSON whitespace is not semantic, so nothing about the vector is weaker; only the claim is.

### What the vectors do NOT cover

Stated in full, because overclaiming coverage is worse than admitting a gap:

- **Only the Ed25519 path has a signed vector.** `ES256` / `ecdsa-jcs-2019` and the `JsonWebSignature2020` detached-JWS profile are both MUST-support in §8.1–§8.2, and neither has a published byte string anywhere in this repository to check an implementation against. Golden fixture 3 pins the `ecdsa-jcs-2019` *cryptosuite string*; its `proofValue` is a placeholder.
- **The eight `NotaryAttested` example files exercise shape only.** Their `proofValue`s are illustrative, so §8.3's signature step cannot be exercised against them. Signature verification on those files is *expected* to fail.
- **§8.3's body-hash binding is exercised by nothing at all — including target 2.** All *nine* examples carry `bodySha256` = the SHA-256 of the empty string next to a non-zero `bodySize`, and none publishes a message body, so there is nothing for a verifier to hash. This one is called out separately because the gap does not stop at the eight: `principal_signed_envelope.json` reproduces four real signatures and still cannot check a body hash. Target 2's four claimed properties are accurate and do not include it — but an implementer who passes target 2 has not tested §8.3's binding of an envelope to the bytes it describes.
- **The §6.3.3 revocation vectors are Rust constants, not files.** The accept / refuse-at-parse / refuse-at-binding entry sets and the refuse-document set live in `interpreters/rust/aph-conformance/src/lib.rs`, each paired with the rule it violates. They are readable without linking anything, but a non-Rust implementer has to read them out of the source rather than load a directory.
- **The status list vectors carry no proof.** They exercise every §6.3.3.3 rule up to the signature — issuer binding, purpose, vintage, freshness, and the MSB-first bit order — and stop there. An implementation that passes all of them may still have no proof check at all, which is the one failure that makes the whole mechanism forgeable. (The reference implementation's own proof check *is* pinned end to end by the cross-notary exchange test, forged-list case included — but that is Rust exercising Rust. A non-Rust implementer still has no proof vector to check against, so for them the gap stands.)
- **The §8.4.5 printed TXT example is a parse vector, not a verify vector.** Its 32 key bytes are not a valid Ed25519 curve point, so it round-trips through a parser and cannot check a signature.
- **There is no JSON Schema for the envelope.** §7.1 and the strict parser are the shape; a schema for it would be a third expression of the same rule.

### Reporting

If your implementation disagrees with a published artifact, the disagreement is worth filing either way: the specification is normative, the schemas and fixtures are not, and where they conflict the fixture is the defect. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Running a notary

Operating a Notary Service means holding a signing key, controlling the domain its `did:web` names, and republishing a revocation status list on a cadence tighter than the freshness bound verifiers enforce. [`spec/operations.md`](spec/operations.md) is the runbook for all three — what losing each one costs, the pre-authorized rotation that makes key loss survivable without any custodian, and the monitor that shows the republish deadline before it passes rather than after peers start refusing.

## Agent plugin

The repository is also an installable plugin for agentic coding tools, giving an agent working knowledge of the protocol plus envelope-validation and conformance commands:

```
/plugin marketplace add squillo/aph
/plugin install aph@aph-protocol
```

It provides the `/aph:spec` skill (a protocol crash course grounded in the spec sections), `/aph:validate`, and `/aph:conformance`.

For OpenAI Codex and any tool following the [agents.md](https://agents.md) convention, the repo root carries an `AGENTS.md` with orientation, CI-exact build/test commands, and the invariants — it points into the same `skills/spec/SKILL.md`, which follows the open Agent Skills format both ecosystems load, so both packs read one knowledge source.

## N Lang Specification Snapp

`APH Spec/0.1.0/` defines the protocol's JSON documents as [N Lang](https://squillo.com/nlang) types, compiled to `snapp/aph@0.1.0-alpha.1.json`. N Lang is a proprietary language by Squillo Inc., commercially licensable only through Squillo Inc.; the Snapp sources themselves are Apache-2.0 like the rest of this repository.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution process, scope, spec-change rules, and versioning policy.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Authors

Squillo, Inc.
