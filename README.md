# APH — Agent per Human Notarization Protocol

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

- Alice's agent emits a message proposing 3 pm Tuesday. The envelope is notarized by Squillo's notary on Alice's behalf, with `channel = a2a`, `contentClass = Reply`, `policy.matchedScope = per-channel`, and a `DelegationMandate` reference showing Alice pre-authorized her agent to schedule meetings on this channel for the next 30 days.
- Bob's agent verifies the APH envelope by resolving Squillo's notary public key (via `did:web` `.well-known/did.json` or via the `_aph._notary.squillo.io` DNS TXT record — both anchored in public infrastructure Bob doesn't need a Squillo account to read), then checks the signature, the time window, the scope, and the body hash.
- Bob's agent replies with a counter-proposal under its own APH envelope, notarized by Bob's organization's notary, which Alice's agent verifies the same way.
- Neither human is in the loop for the negotiation itself, but every action either agent takes is provably bound to a license its human issued ahead of time and can revoke at any time.

If Alice decides she no longer wants her agent scheduling on her behalf, she revokes the DelegationMandate; subsequent envelopes from her agent referencing that mandate will fail verification on Bob's side.

## What problem APH solves

- Agents can already act on behalf of humans, but recipients have no portable way to tell **if a human actually authorized this specific outbound message**.
- Existing protocols cover adjacent slices: A2A handles agent-to-agent transport, AP2 handles agent-initiated payment authorization, MCP handles tool-call typing — none binds a particular outbound message to a verifiable human keypair held on the human's device.
- APH closes that gap with a notarization step that runs locally on the sending side and produces a portable, verifiable credential the recipient can check without trusting the sending agent's runtime or its identity provider.

## Why "notarization"

A Notary Service is meaningful only if a **third party can independently verify** its signatures. APH therefore models notaries as a public/private keypair where the PUBLIC key is publishable like a DKIM or TLS key — anchored in DNS or HTTPS — so any verifier on the open internet can resolve it and check the signature with no prior trust relationship to the notary operator. See spec §8.4 for the three publication mechanisms (`did:key` offline, `did:web` `.well-known/did.json`, and DNS TXT at `_aph._notary.<domain>`).

## Status

**v0.1.0-draft** — protocol design phase. The specification text, the canonical envelope shape, and a small set of reference example envelopes are published here for community review. A reference implementation is under development in a separate workspace. JSON Schema files and conformance test vectors are deferred to v0.2.

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
  examples/
    slack_reply_envelope.json
    email_reply_envelope.json
    discord_dm_envelope.json
    teams_channel_envelope.json
    whatsapp_envelope.json
    google_chat_envelope.json
    imessage_envelope.json
  .github/
    workflows/
      ci.yml            JSON validity checks for examples
  README.md
  LICENSE
  CONTRIBUTING.md
  CHANGELOG.md
```

## Install

APH is currently a specification — there is no library to install yet. A reference Rust implementation is under development; this repository carries the spec text and example envelopes only.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution process, scope, spec-change rules, and versioning policy.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Authors

Squillo, Inc.
