# APH — Agent per Human Notarization Protocol

![The APH emblem — a human figure and an AI chip joined in an infinity loop inside a chained seal — surrounded by scenes of people from many cultures and walks of life working alongside robots and AI assistants: an elder signing a document with a robot, a family with tablets, clinicians, office workers at laptops, and a delivery drone, all linked by glowing network lines carrying padlock and document icons.](assets/aph-banner.jpg)

APH is an open protocol for cryptographically notarizing the actions an autonomous agent takes on behalf of a specific human, producing a W3C Verifiable Credential 2.0-shaped envelope that any downstream recipient can independently verify across vendors and across organizations.

**▶ [Watch the explainer video](https://drive.google.com/file/d/1JSqeo4tzvxMWN8M3fe-V-dT8etBiBADb/view?usp=sharing)** — the driver's-license model and the verification story in plain language, before the spec makes them precise.

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

**v0.1.0-draft** — protocol design phase, pre-production with no external adopters, so corrections land in place rather than forking a version. The specification text, the canonical envelope shape, and a small set of reference example envelopes are published here for community review. A reference Rust implementation lives in this repository under `interpreters/rust/` (wire types, flow state machines, signing helpers, and a conformance suite that validates the `examples/` envelopes). A **second implementation** — sharing no code with it, written from the specification and the published examples — lives under `interpreters/typescript/`, and the two cross-verify each other's minted envelopes in both directions. It is independence of code and not of team: the same authors wrote both, so an outside implementation is still the thing that would test whether this document survives a stranger.

Machine-readable artifacts exist for part of the surface, not all of it: `spec/schemas/` carries JSON Schemas for the two revocation shapes of §6.3.3 (there is none for the envelope itself — §7.1 plus the strict parser is the normative shape), and exactly four published envelopes carry real signatures rather than placeholders — one for each signing path §8.1/§8.2 make MUST-support and this implementation supports, plus the one the TypeScript implementation minted. [Implementing APH in another language](#implementing-aph-in-another-language) states precisely what is and is not covered, because an implementer who over-trusts the vectors ships a verifier that passes them and fails a stranger.

Two conventions to know before you adopt: `aph://` (the extension-URI scheme) and `_aph._notary.<domain>` (the DNS key-publication name) are **conventions, not IANA registrations** — both requests are now **drafted** in [`spec/registrations/`](spec/registrations/) and **not submitted**, so nothing below has changed (spec §13). Submitting is a human act and deliberately not automated, which is why every place an identity would go is left blank: the scheme request's `Contact:` and `Change controller:` fields, and the requester IANA would correspond with about the DNS request — whose registry entry defines no contact field at all, though the submission still needs a person behind it. The DNS request additionally surfaces an open naming question for the specification owner to settle before it goes anywhere. Neither affects whether an envelope verifies, and a conformant TXT parser refuses any record whose `v` tag is not `APHv1`, so a foreign record at a colliding name is ignored rather than misread as a key. What is genuinely at risk is name ownership: if those names are later assigned elsewhere, APH moves. [`spec/operations.md` §6](spec/operations.md) enumerates every unregistered identifier with the consequence of each.

## Relationship to other protocols

APH builds on the W3C Verifiable Credentials Data Model 2.0, JWS detached signatures (RFC 7515), JSON Canonicalization Scheme (RFC 8785), SD-JWT-VC (draft-ietf-oauth-sd-jwt-vc-16), and OAuth 2.0 Token Exchange (RFC 8693). It composes with — but does NOT replace — A2A (agent discovery and transport), AP2 (payment mandates), and MCP (tool-call typing). Where applicable, an APH envelope MAY ride alongside an AP2 IntentMandate via the envelope's `linkedMandate` field so that send-consent and payment-authorization are linkable but separately signed.

## Quick reference — the wire shape

A full schema lives under `spec/aph-0.1.md`. The example below is a complete v0.1 envelope notarizing a Slack reply. The same envelope shape applies across all supported channels (Email, Slack, Discord, Teams, WhatsApp, Google Chat, iMessage, and `service` — a service endpoint an agent delivers a state-changing act to, per RFC 0002) with only the `credentialSubject.channel` block changing per channel.

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
    slack_reply_envelope.json          One per channel kind: shape only,
    email_reply_envelope.json          placeholder proofValues
    discord_dm_envelope.json
    teams_channel_envelope.json
    whatsapp_envelope.json
    google_chat_envelope.json
    imessage_envelope.json
    slack_new_with_extensions_envelope.json  The §7.5 optional extensions
    principal_signed_envelope.json     Signed: Ed25519, eddsa-jcs-2022
    es256_signed_envelope.json         Signed: ES256, ecdsa-jcs-2019
    detached_jws_envelope.json         Signed: JsonWebSignature2020
    ts_minted_envelope.json            Signed: Ed25519, minted by the TypeScript
                                       implementation and verified by the Rust
  interpreters/
    rust/               Reference Rust implementation (cargo workspace)
      aph-core/         Wire types, mandates, flow state machines, signing helpers
      aph-conformance/  Golden-envelope + contract conformance suite, channel binding specs
      aph-cli/          `aph` binary: validate / inspect / golden (conformance fixtures)
      aph-resolver/     Optional DNS TXT + did:web fetch adapters (the only crate carrying HTTP/DNS deps)
      aph-ts/           wasm binding (parse/serialize for JS hosts)
      aph-py/           pyo3 binding (the same surface, for Python hosts)
      aph-core/examples/  Runnable, self-narrating usage examples
    elixir/             rustler binding (the same surface, for BEAM hosts); its
                        NIF crate lives at native/aph_nif and is excluded from
                        the cargo workspace, because mix drives that build
    typescript/         SECOND implementation: mint + verify, from the spec alone
                        (no wasm, no binding — Node >= 20, WebCrypto, zero runtime deps)
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
      python.yml              cargo test for the Python binding
      elixir.yml              mix test for the Elixir binding
      typescript.yml          tsc + node --test for the second implementation
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
cargo run -p aph-cli -- help                         # usage, plus the --json contract
```

#### Publishing a notary's keys

The two §8.4 discovery surfaces are rendered by the same code a verifier reads
them with, so an operator never hand-writes either wire form:

```sh
# the DNS TXT value for a key (§8.4.5); --domain prints the record NAME on stderr
cargo run -p aph-cli -- render-txt did:key:z6Mk... --kid k1 --domain notary.example.com

# the DID Document (§8.4.4); each key is a did:key with its kid as the fragment
cargo run -p aph-cli -- render-did did:web:notary.example.com did:key:z6Mk...#k1
```

```sh
# the DNS TXT value publishing a vocabulary's digest (§8.5.1)
cargo run -p aph-cli -- render-vocab "snapp/aph_guardrails@0.1.0-alpha.1.json" --domain squillo.com
```

`render-did` takes several keys so a rotation overlap (§8.4.7) can be published
in one document. `render-vocab` READS the digest from the bundle's own
`@snapp.integrity` rather than recomputing it — two derivations of one fact
drift, and a drifted digest does not fail loudly: it publishes a value that
refuses bytes which are in fact correct. The record name goes to stderr and the value to stdout, so a
name cannot be captured into the record's content by a redirect.

**Both take PUBLIC key material only.** A `did:key` IS a public key; nothing
here accepts a signing seed, and nothing here should be extended to — a seed on
a command line is readable by every other process on the host.

`validate` is a strict **structural** check — it does not verify signatures, time windows, or body hashes (spec §8.3 steps 2–8). Exit codes: `0` valid, `1` invalid, `2` usage.

#### Reading the verdict from a build

`validate --json` writes **one** JSON object to stdout and nothing to stderr. The exit codes are unchanged, so a gate may read the code, the object, or both — one call produces both and they cannot disagree. Without `--json` every byte the tool writes is what it has always written.

```sh
$ cargo run -q -p aph-cli -- validate --json examples/slack_reply_envelope.json
{"ok":true,"id":"urn:uuid:00000000-0000-4000-8000-000000000001","issuer":"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"}
```

An unrecognized value in one of §7.1's **closed vocabularies** — a channel kind, a content class — is the refusal downstream implementations ask about most, so it names itself and hands back the whole set rather than leaving you to find it:

```sh
$ your-minter emit-envelope | cargo run -q -p aph-cli -- validate --json -
{"ok":false,"layer":"parse","reason":"closed_set","message":"invalid envelope: `squillo` is not in the closed set {slack, email, …} at line 27 column 23","field":"credentialSubject.channel.kind","value":"squillo","allowed":["slack","email","…"]}
```

The set is abbreviated **here** on purpose: §7.1's vocabularies widen by design, and a copy of a closed vocabulary sitting in prose teaches the wrong set the moment one does. The object carries the whole current set every time it refuses, and `aph help` prints it — this page deliberately does not.

| field | present when | meaning |
| --- | --- | --- |
| `ok` | always | `true` exactly when the envelope strict-parsed. Mirrors the exit code. |
| `id`, `issuer` | `ok: true` | which envelope was admitted. |
| `layer` | `ok: false` | which layer refused: `parse` or `io`. |
| `reason` | `ok: false` | `closed_set`, `malformed`, or `unreadable`. |
| `message` | `ok: false` | byte-for-byte the line the same run prints to stderr without `--json`. |
| `field` | `reason: closed_set` | dotted **wire** path of the offending field, ready to paste into a search of your own document. |
| `value` | `reason: closed_set` | the value that is not in the set. |
| `allowed` | `reason: closed_set` | the complete set, in spec order — so your error message never hard-codes the vocabulary. |

**There is deliberately no `APH_E` code in this object.** A closed-vocabulary value is refused at strict parse — spec §8.3 step 1, *below* the protocol's closed sixteen-code error taxonomy — so reporting one would invent a code the specification does not define, and a consumer routing on it would be routing on fiction. `layer` names where the refusal came from instead. This is the same reading the second implementation applies, and the reason `ChannelKind::from_str` returns a plain message rather than an `AphError`.

**Exit `2` is a usage error, not a verdict.** A missing input argument prints usage on stderr and emits no JSON, because nothing was read and `{"ok":false}` would tell a gate an envelope had been refused.

**Stability.** The fields above keep their names and their meanings. New fields and new `reason` values may be added, so branch on `ok` first and treat an unrecognized `reason` as a refusal — never as a pass. `aph help` prints this same contract, so a consumer who has the binary does not need this page.

#### Gate your own envelopes in your own CI

`validate` reads stdin as `-`, so nothing about your minter has to be written in Rust. Build the binary once, put it on `PATH`, then pipe one envelope per run and let the exit code fail the build:

```sh
cargo build --release -p aph-cli     # once; the binary lands at target/release/aph
your-minter emit-envelope | aph validate -
```

That one line is the whole gate. To also say **why** it failed — which is what turns an unknown-value refusal into a fix instead of a question — read the `--json` object with `jq`:

```bash
#!/usr/bin/env bash
# scripts/aph-gate.sh — fails the build unless the envelope just minted strict-parses.
set -uo pipefail

verdict=$(your-minter emit-envelope | aph validate --json -)
status=$?
verdict=${verdict:-null}          # the minter itself failed; keep jq well-fed

case "$status" in
  0) echo "admitted: $(jq -r .id <<<"$verdict")"; exit 0 ;;
  2) echo "aph: usage error — the command line is wrong, not the envelope"; exit 2 ;;
esac

case "$(jq -r '.reason // "no-verdict"' <<<"$verdict")" in
  closed_set)
    printf 'refused: %s = "%s" is not one of %s\n' \
      "$(jq -r .field    <<<"$verdict")" \
      "$(jq -r .value    <<<"$verdict")" \
      "$(jq -c .allowed  <<<"$verdict")" ;;
  no-verdict) echo "refused: your minter produced no envelope to validate" ;;
  *)          echo "refused: $(jq -r .message <<<"$verdict")" ;;
esac
exit 1
```

Nothing in it is CI-vendor-specific; it is one step wherever your build runs:

```yaml
- name: APH envelope gate
  run: ./scripts/aph-gate.sh
```

Two notes worth the ten seconds. `pipefail` makes `status` the *minter's* code when the minter is what failed, which is why `verdict` is normalized to `null` before `jq` ever sees it. And a `closed_set` refusal is not a defect in this tool: §7.1's vocabularies are closed by design, a conformant verifier MUST reject a value it does not recognize, and adding a value is a MINOR version event that carries a producer rule with it — see [CONTRIBUTING.md](CONTRIBUTING.md#versioning).

### JavaScript / TypeScript

```sh
cd interpreters/rust && wasm-pack build aph-ts --target web
```

```js
import { parseEnvelopeJson, serializeEnvelope } from './pkg/aph_ts.js';
const envelope = parseEnvelopeJson(received);  // throws on invalid shape
```

### Python

```sh
cd interpreters/rust/aph-py && maturin build --release
```

```python
import json, aph
envelope = json.loads(aph.parse_envelope_json(received))  # raises aph.AphError on invalid shape
```

### Elixir / BEAM

```sh
cd interpreters/elixir && mix deps.get && mix test
```

```elixir
{:ok, normalized} = APH.parse_envelope_json(received)   # {:error, code} on invalid shape
{:ok, mode} = APH.verify_proof_structure(received)      # "PrincipalSigned" | "NotaryAttested"
:ok = APH.require_attestation_mode(received, "PrincipalSigned")
```

Refusals are `{:error, message}` rather than exceptions — on the BEAM a refused
envelope is an ordinary outcome — and a protocol refusal's message leads with
its `APH_E*` code, so a caller matches `APH_E013` there exactly as a TypeScript
caller matches it on the thrown message. Not published to hex.pm: see
[interpreters/elixir/README.md](interpreters/elixir/README.md).

`aph-ts`, `aph-py`, the Elixir binding and the Go binding (`interpreters/go` —
pure Go, running the reference as WebAssembly under wazero with no cgo; its
committed wasm artifact is byte-diffed against a pinned-toolchain rebuild on
every push) are four **bindings of this one
reference implementation**, held at export parity — the same four operations,
the same semantics, the same error identity, each in its language's idiom —
under a standing rule that an addition to any one is unfinished until it lands
in the other two, so they cannot drift into teaching different things. All
three cross the FFI as JSON text in both directions, because the envelope's
`proof` union is untagged and an object round-trip hands arm selection to a
second deserializer. None is a second implementation, and none is evidence that
one can be built: see [interpreters/rust/aph-py/README.md](interpreters/rust/aph-py/README.md).

## The second implementation (TypeScript)

[`interpreters/typescript/`](interpreters/typescript/README.md) is a complete
APH v0.1 implementation — **mint and verify** — written from `spec/aph-0.1.md`
and the published `examples/`. It shares no code with the Rust: its own
RFC 8785 canonicalizer, its own strict parser, its own §7.2.1 signing bases,
its own base58btc and `did:key` codecs, signatures through the runtime's
WebCrypto. Node ≥ 20, no runtime dependencies, and the TypeScript compiler is
the only dev-time one.

```sh
cd interpreters/typescript && npm install && npm run build && npm test
```

**What it proves, and what it does not.** It proves the specification is
implementable **twice from its own text** — the definitional gap the three
bindings cannot close, because all three are bindings of the one reference. It is
independence of **CODE, not of TEAM**: the same authors wrote both, so it is
not evidence that the document survives a stranger. The invitation below still
stands, and an outside implementation remains the missing half.

**Cross-verification runs in both directions, as committed bytes.** The
TypeScript admits `examples/principal_signed_envelope.json` — all four Rust-made
Ed25519 signatures — and refuses tampered, downgraded and forged-label variants
with the §11 codes §11 assigns them. In the other direction it mints
`examples/ts_minted_envelope.json`, which
`interpreters/rust/aph-conformance/tests/ts_minted_cross_verify.rs` verifies in
full: strict parse, §7.1.11 structure, §7.2.1 issuance order, §7.1.7.1 mandate
bindings, and all four of its signatures. Neither stack invokes the other —
there is no Node in cargo and no cargo in Node, only files.

**The committed cross-artifact is Ed25519 only, and the reason is worth
stating.** Ed25519 is deterministic in both stacks, so its bytes can be pinned.
WebCrypto's ECDSA is randomized and exposes no RFC 6979 mode, so a TypeScript
ES256 envelope cannot be byte-pinned at all; ES256 is covered one-directionally
instead — the TypeScript verifies this repository's deterministic
`ecdsa-jcs-2019` vector, and mint-then-verifies its own inside a single run.

**It has already disagreed with the spec once, which is the point.** §6.1's
field table and §7.2.1's closing sentence give contradictory rules for the
Delegation Mandate signing bases (remove the signature members, or empty them);
the published bytes select removal, and the contradiction is now pinned by a
test rather than absorbed by an implementer. Details in
[interpreters/typescript/README.md](interpreters/typescript/README.md).

### Conformance

`interpreters/rust/aph-conformance` carries golden fixtures, contract tests, and the three channel binding specs (email, chat platforms, MCP). It also validates every envelope in `examples/` against the implementation and asserts that what the implementation *emits* is value-identical to those published files — the check that catches serializer-side drift. See [interpreters/rust/README.md](interpreters/rust/README.md) for the full picture, including the two deliberate divergences from RFC 8785 and RFC 7518 that the tests deliberately pin.

## Implementing APH in another language

APH is only a protocol if a second implementation can be built from what is published here. This section is the entry point for that: what to point your own code at, in what order, and — just as importantly — what these artifacts do **not** prove.

### The four targets, and what each one proves

**1. Point your PARSER at `examples/*.json` (12 files, no toolchain required).** Every file must deserialize under a strict schema: unknown top-level or `credentialSubject`-level fields are hard errors (§7.1), and `channel.recipientAddressing` is the one exception whose sub-fields are opaque and MUST NOT fail (§7.4). If your parser accepts a field APH never defined, a producer can smuggle a claim past you.

**2. Point your VERIFIER at the four signed envelopes (no toolchain required).** Three cover the signing paths §8.1 and §8.2 make MUST-support, so a verifier can be checked against every path it is required to implement rather than only the default one; the fourth was minted by a different implementation entirely. Every key in all four is a PUBLISHED test vector — they authorize nothing, and anyone can re-derive them from the RFC that prints them.

- **`examples/principal_signed_envelope.json` — Ed25519 / `eddsa-jcs-2022`, four signatures.** Two envelope proofs and two mandate signatures, under the RFC 8032 §7.1 TEST 2 (principal) and TEST 3 (notary) public test seeds. A verifier that reproduces all four has independently implemented RFC 8785 canonicalization, the per-proof signing bases of §7.2.1, the proof-chain linkage of §7.1.11, and the embedded-mandate check of §7.1.7.1. Getting §7.2.1 wrong is the likeliest failure: `proofValue` is set to the **empty string**, not removed, and the principal proof covers `proof` as a **one-element array**.
- **`examples/es256_signed_envelope.json` — ES256 / `ecdsa-jcs-2019`, two proofs.** The same `PrincipalSigned` chain on the other curve, so diffing it against the file above shows exactly what §8.1's second algorithm changes. The principal key is the RFC 6979 Appendix A.2.5 sample scalar, the notary key is the `d` of the RFC 7515 Appendix A.3.1 ES256 JWK. `proofValue` here is **P1363 `r‖s`** (64 bytes, multibase) per the suite definition, never DER. It embeds no mandate — the Ed25519 file is the §7.1.7.1 vector.
- **`examples/detached_jws_envelope.json` — `JsonWebSignature2020`, one proof.** §8.2's other proof format: a compact detached JWS in `proofValue` over the **same** §7.2.1 base. It is `NotaryAttested` and its `issuer` is the notary's own P-256 `did:key`, so it verifies **offline from itself** with no network and no prior trust relationship. Its protected header carries the six members §8.2 requires, and a verifier MUST check them (§8.3 step 7) — that is what rejects `alg: none`. ⛔ Two deployed quirks travel with this format and are preserved deliberately: the header declares `"b64":false` with `"crit":["b64"]` while the payload is nevertheless base64url-encoded into the signing input, and the ES256 signature *inside* the token is **DER**, not the raw `r‖s` RFC 7518 specifies. A standards-pure RFC 7518 signer will produce a token this vector's verifier rejects; the encoding follows the carriage, not the algorithm.

- **`examples/ts_minted_envelope.json` — Ed25519 / `eddsa-jcs-2022`, four signatures, minted by the SECOND implementation.** The same `PrincipalSigned` shape as the first file, produced by `interpreters/typescript/` rather than by the Rust — so a third implementer checking against it is checking a document two independent codebases already agree on. Two differences from the Ed25519 golden make it the easier first target: **both** parties are `did:key`, so it verifies with no supplied key and no network at all, and its body binding is REAL — the complete body travels in `preview`, `bodySize` is its UTF-8 length and `bodySha256` is its digest, so §8.3 step 8 is checkable from this one file. Same principal as the golden (RFC 8032 §7.1 TEST 2), so the two DIDs can be checked against each other and against the RFC.

**Byte comparison is valid on the ES256 vectors, and here is why that is not obvious.** Most ECDSA is randomized: sign the same bytes twice, get two different signatures, both correct. An implementer who assumes that will read a byte-for-byte comparison against an ECDSA vector as a mistake. It is not one here — the reference uses **RFC 6979 deterministic ECDSA**, where the nonce is derived from the key and the message, so these files are byte-reproducible. If your own ES256 signer is randomized your envelopes are still valid; they simply will not equal these byte for byte, so compare by *verifying* rather than by diffing.

**3. Point your PRODUCER at this repository's parser.** The CLI reads stdin, so nothing about your emitter has to be written in Rust:

```sh
your-implementation emit-envelope | cargo run -q -p aph-cli -- validate -
```

Exit `0` means your bytes strict-parse; `1` means they do not, with the serde error naming the field. Conversely, `cargo run -q -p aph-cli -- golden <n>` prints fixture *n* raw on stdout for piping into your own verifier. These two are the only targets that need a Rust toolchain.

Add `--json` and that refusal becomes something your build can branch on instead of something a person has to read — `reason` tells a closed-vocabulary refusal apart from generic malformed JSON, and for a closed set the object carries the offending `value` and the whole `allowed` set:

```sh
your-implementation emit-envelope | cargo run -q -p aph-cli -- validate --json -
```

**Wire this into your CI the day you start minting, not the day something breaks.** The copy-pasteable gate is [Gate your own envelopes in your own CI](#gate-your-own-envelopes-in-your-own-ci); the field-by-field shape and its stability commitment are in [Reading the verdict from a build](#reading-the-verdict-from-a-build). Three separate downstream implementations have asked what an unrecognized closed-vocabulary value meant; in every case the tool already answered it, and in every case nobody had run it. A guarantee that only a human at a terminal can reach is not reachable from a build.

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

- **Every algorithm §8.1 requires has a signed vector except `EdDSA` inside a JWS.** `examples/es256_signed_envelope.json` publishes `ecdsa-jcs-2019` (two `PrincipalSigned` proofs, P1363 `r‖s` in `proofValue`) and `examples/detached_jws_envelope.json` publishes `JsonWebSignature2020` (one `NotaryAttested` proof, verifiable offline from its own `did:key` issuer). What remains uncovered is the fourth combination — `alg: EdDSA` carried in a detached JWS. §8.1 makes it MUST-support; the reference implementation does not implement it, refuses it by name (`APH_E010`) rather than mis-reporting it as a bad signature, and therefore has no vector to publish. Golden fixture 3 still pins only the `ecdsa-jcs-2019` *cryptosuite string* with a placeholder `proofValue`; the published example, not that fixture, is the vector.
- **Eight of the twelve example files exercise shape only.** The seven channel files and the §7.5 extensions file carry illustrative `proofValue`s, so §8.3's signature step cannot be exercised against them and verification on those eight is *expected* to fail. The other four are the signed vectors in target 2.
- **§8.3's body-hash binding is exercised by two files — one of them end to end, refusal included.** `examples/principal_signed_envelope.json` now attests the SHA-256 and exact byte length of the committed `examples/principal_signed_body.txt`: the conformance suite re-hashes that file the way a recipient does, checks the pair under the golden's four real signatures, and proves that a one-byte-different body refuses with `APH_E009` specifically. `examples/ts_minted_envelope.json` binds the body it carries in `preview`. The other ten examples still pair `bodySha256` = the SHA-256 of the empty string with a fictional `bodySize` — a combination no body can satisfy — and are shape-only on this axis; that includes the ES256 and detached-JWS vectors, which prove signatures, not bodies. An implementer who wants step 8 tested points their verifier at the golden AND its body file together.
- **The second implementation is not an independent TEAM.** `interpreters/typescript/` shares no code with the Rust and cross-verifies with it in both directions, which closes the "is this document implementable twice?" question. It does not close "does this document survive a reader who cannot ask the authors what they meant" — same authors, both times. That gap can only be closed from outside, which is what the Reporting section below is for.
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
