# APH — Agent per Human Notarization Protocol

![The APH emblem — a human figure and an AI chip joined in an infinity loop inside a chained seal — surrounded by scenes of people from many cultures and walks of life working alongside robots and AI assistants: an elder signing a document with a robot, a family with tablets, clinicians, office workers at laptops, and a delivery drone, all linked by glowing network lines carrying padlock and document icons.](assets/aph-banner.jpg)

APH is an open protocol for cryptographically notarizing the actions an autonomous agent takes on behalf of a specific human, producing a W3C Verifiable Credential 2.0-shaped envelope that any downstream recipient can independently verify across vendors and across organizations.

## Mental model — the agent's driver's license

Think of an APH credential as an **agent's driver's license**:

- **A human (the issuing authority)** authorizes a specific agent to act on their behalf within bounded parameters.
- **A notary service (the DMV)** issues the license, signs it, and publishes its verification key so anyone can independently check the license against the public record.
- **The license carries a scope** — which channels, which content classes, which recipients, how often, for how long.
- **The license is revocable** — the issuing human can pull it at any time.
- **The license is portable across jurisdictions** — like an interstate driver's license, an APH credential issued by one organization's notary is verifiable by any other organization's agent or system using only public standards. No bilateral integration required.

When an agent presents a notarized message, the recipient can verify, without trusting the sending agent's runtime or its identity provider, that:

1. A specific human authorized this specific action.
2. The action falls within the scope of the human's standing delegation.
3. The notary that signed the license holds the private key it claims to hold (verifiable via DNS-anchored public key publication — see spec §8.4).
4. The license has not expired and (when revocation transport is wired) has not been revoked.

## Where APH fits next to A2A and AP2

APH is a complement to Google's open agent protocols, not a replacement:

- **A2A (Agent2Agent)** — standardizes how two agents discover each other and exchange messages. APH attaches to A2A messages as a Verifiable Credential extension so the receiving agent can verify the sending agent actually has its human's permission for this specific action.
- **AP2 (Agentic Payments)** — standardizes how an agent obtains a human-signed mandate to make a payment. APH covers the broader case: any human-authorized action an agent takes, including but not limited to payment. AP2 and APH cross-link via the envelope's `linkedMandate` field so a single agent action can carry both a payment mandate AND a communication authorization.
- **APH (Agent per Human)** — the missing piece. Where A2A defines the transport and AP2 defines payment authorization, APH defines **per-action human authorization** — an agent's verifiable credential to act on a specific human's behalf for a specific task on a specific channel.

In one sentence: **A2A is the road network, AP2 is the toll booth, APH is the driver's license.**

## Concrete example — two agents negotiating a meeting

Alice's agent and Bob's agent are negotiating a meeting time over a public channel. Both agents act with autonomy within bounded parameters their humans set in advance. Each outbound message carries an APH envelope:

- Alice's agent emits an A2A message proposing 3 pm Tuesday, carrying its APH envelope as extension metadata under the `aph://extensions/notarization/v1` key (APH is transport-independent — the agent-to-agent rail is never the envelope's channel). The envelope is notarized by Squillo's notary on Alice's behalf, with `channel = email` (the medium the confirmed invite will land on), `contentClass = Reply`, `policy.matchedScope = per-channel`, and a `DelegationMandate` reference showing Alice pre-authorized her agent to schedule meetings for the next 30 days.
- Bob's agent verifies the APH envelope by resolving Squillo's notary public key (via `did:web` `.well-known/did.json` or via the `_aph._notary.squillo.io` DNS TXT record — both anchored in public infrastructure Bob doesn't need a Squillo account to read), then checks the signature, the time window, the scope, and the body hash.
- Bob's agent replies with a counter-proposal under its own APH envelope, notarized by Bob's organization's notary, which Alice's agent verifies the same way.
- Neither human is in the loop for the negotiation itself, but every action either agent takes is provably bound to a license its human issued ahead of time and can revoke at any time.

If Alice decides she no longer wants her agent scheduling on her behalf, she revokes the DelegationMandate: her notary stops issuing new CommunicationMandates against it immediately, and envelopes referencing it will fail verification on Bob's side once the on-wire revocation transport lands (v0.2). In v0.1 the spec compensates by recommending short validity windows, so the revocation gap stays small.

## What problem APH solves

- Agents can already act on behalf of humans, but recipients have no portable way to tell **if a human actually authorized this specific outbound message**.
- Existing protocols cover adjacent slices: A2A handles agent-to-agent transport, AP2 handles agent-initiated payment authorization, MCP handles tool-call typing — none binds a particular outbound message to a verifiable human keypair held on the human's device.
- APH closes that gap with a notarization step that runs locally on the sending side and produces a portable, verifiable credential the recipient can check without trusting the sending agent's runtime or its identity provider.

## Why "notarization"

A Notary Service is meaningful only if a **third party can independently verify** its signatures. APH therefore models notaries as a public/private keypair where the PUBLIC key is publishable like a DKIM or TLS key — anchored in DNS or HTTPS — so any verifier on the open internet can resolve it and check the signature with no prior trust relationship to the notary operator. See spec §8.4 for the three publication mechanisms (`did:key` offline, `did:web` `.well-known/did.json`, and DNS TXT at `_aph._notary.<domain>`).

## Status

**v0.1.0-draft** — protocol design phase. The specification text, the canonical envelope shape, and a small set of reference example envelopes are published here for community review. A reference Rust implementation lives in this repository under `interpreters/rust/` (wire types, flow state machines, signing helpers, and a conformance suite that validates the `examples/` envelopes). JSON Schema files and signed conformance test vectors are deferred to v0.2.

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
  "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
  "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
  "validFrom": "2026-05-21T00:00:00Z",
  "validUntil": "2026-05-22T00:00:00Z",
  "credentialSubject": {
    "humanPrincipal": {
      "id": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
      "displayName": "Scott Wyatt"
    },
    "agent": {
      "id": "did:web:agent.squillo.io",
      "agentCardUri": "https://agent.squillo.io/.well-known/agent-card.json",
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
        "id": "did:web:notary.squillo.io",
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
      aph-ts/           wasm binding (parse/serialize for JS hosts)
      aph-core/examples/  Runnable, self-narrating usage examples
    nlang/              N Lang type definitions (library Snapp)
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
aph-core = "0.1"
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

Resolving `notary_key` from the issuer DID is the verifier's job (spec §8.4: `did:key` offline, DNS TXT at `_aph._notary.<domain>`, or `did:web`). Key discovery is not yet implemented in this crate.

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

## Agent plugin

The repository is also an installable plugin for agentic coding tools, giving an agent working knowledge of the protocol plus envelope-validation and conformance commands:

```
/plugin marketplace add squillo/aph
/plugin install aph@aph-protocol
```

It provides the `/aph:spec` skill (a protocol crash course grounded in the spec sections), `/aph:validate`, and `/aph:conformance`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution process, scope, spec-change rules, and versioning policy.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Authors

Squillo, Inc.
