# APH v0.1 — Agent per Human Notarization Protocol

**Version:** 0.1.0
**Status:** Final for v0.1 (cut 2026-08-29)
**Date:** 2026-05-21
**Repository:** `github.com/squillo/aph`
**License:** Apache-2.0

---

## 0. Status of This Document

This is v0.1.0 of the APH (Agent per Human) protocol specification, FINAL for the 0.1 line as of 2026-08-29. The pre-production exception under which accepted revisions landed in place inside the draft ENDS with this cut: from here, normative changes are versioned — additive minors within 0.x per CONTRIBUTING.md's rules, and the v0.2 line (`rfcs/README.md` names its planned contents) for anything larger. Per SemVer 0.x semantics, breaking changes remain possible BETWEEN minor versions before v1.0, but never again in place within a published one. The maintainer is Squillo, Inc.; the source of truth lives at `github.com/squillo/aph`. Implementers SHOULD pin a release tag or commit hash. Feedback, errata, and conformance reports are welcome via repository issues and pull requests; the RFC process (`rfcs/README.md`) is the change path.

---


> ### THE 0.1 CUT — 2026-08-29
>
> This document is FINAL for v0.1. Twenty error codes, four closed
> vocabularies welded across every populator, replay closed (audience +
> single-use), the revocation transport live, six-operation parity across
> four language bindings, and a corpus whose fourteen goldens are minted
> through committed, determinism-checked seams. Everything the 0.1 line
> deliberately left out is the v0.2 line: RFC 0001 (rotation attestation),
> JSON Schema, published test vectors. Decided by the sole maintainer —
> deliberately solo within the Squillo organization, ruled 2026-08-29 and
> recorded rather than implied.

> ### Revision 2026-08-29 — replay closed, the second axis, and a corpus that practices what §6.3 preaches
>
> Two more accepted RFCs land in place under the pre-production exception.
> **RFC 0003** ends the bearer-replay era: `audience` (§7.1.13) names who may
> accept, §8.3 gains the audience step (5a, `APH_E017`) and the single-use
> step (8b, `APH_E018` — an envelope is SPENT by acceptance, per-verifier),
> the envelope's own window finally has its code (`APH_E019`, ending the
> `APH_E003` miscite this project's own implementations were shipping), and
> §1's "Replay-resistant" bullet is now TRUE rather than aspirational. The
> published corpus was regenerated to minutes-order windows — every one of
> the 24-hour windows the RFC indicted is gone, signed vectors re-minted.
> **RFC 0005** adds the second axis the `a2a_email` request was really asking
> for: `recipientClass` on the channel block and `allowedRecipientClasses` on
> the Delegation Mandate (closed set `human`, `agent`; `APH_E020`), so "my
> agent may send email to PEOPLE" is finally a constraint a recipient can
> check rather than a hope. §11 grows to twenty codes. Emission of every new
> member stays version-gated (§10.1).

> ### Revision 2026-08-28 — meaning: two channel kinds, a content class, and the vocabulary surfaces
>
> Three accepted RFCs land in place under the pre-production exception, all
> answering one day's implementer reports. **RFC 0002** adds `service` to
> §7.1.5 and `Mutation` to §7.1.6 — a service endpoint an agent delivers a
> state-changing act to IS the end-delivery medium, so naming it honours
> §1.1.1 rather than bending it. **RFC 0007** adds `squillo`, an
> in-application messaging surface where a human reads in that application's
> client — a peer of `slack` and `discord`, requested for cross-organization
> interop and NOT the membership-scope value of the same spelling that
> RFC 0004 permanently refused. **RFC 0006** adds §7.1.12
> `actClassification` — what a sender says an act MEANS, against vocabularies
> both parties resolve independently — and §8.5, which publishes a
> vocabulary's digest at `_aph._vocab.<domain>` in the same tag-list shape
> §8.4.5 uses for keys.
>
> One rule binds all three, and it is load-bearing rather than courtesy:
> §7.1's parse is strict, so a verifier built before a value or field existed
> does not ignore it — it fails at strict parse, below the protocol's own
> error vocabulary. A producer MUST NOT emit any of these until it has reason
> to believe the recipient understands them (§10.1). The versioning rule they
> ride on was also corrected: a new closed-vocabulary value is MINOR at every
> series, never PATCH, because an addition that turns a working verifier into
> a refusing one is not a patch.

> ### Revision 2026-08-15 — the revocation transport
>
> This draft made revocation normative (§6.3.1) and then left a recipient no
> way to observe one. The issuing human could pull a Delegation Mandate, the
> notary would stop issuing against it, and a third party holding an envelope
> issued the hour before had no mechanism — none — for learning any of that.
> The only mitigation on offer was "keep validity windows short", which is
> advice about how long to be wrong for.
>
> That is fixed in this revision, in place. New **§6.3.3 Revocation transport**
> profiles W3C Bitstring Status List v1.0: the envelope MAY carry a
> `credentialStatus` entry (new §7.1.1 row) naming the parent Delegation
> Mandate's position in a status list the notary publishes, and §8.3 step 8a
> makes checking it a verifier **MUST** whenever the entry is present.
> §6.3.1 item 3's recipient `MAY` is promoted accordingly, §6.2's validation
> list gains revocation beside expiry, and §11 gains `APH_E015`
> `MandateRevoked` at last position.
>
> **The status endpoint's origin is DERIVED from the notary's `did:web`, never
> taken from the envelope.** A URL the envelope chose would let whoever holds
> an old envelope also choose the host that answers "has this been revoked" —
> and an attacker's host always answers no. When an envelope carries a status
> URL it MUST be same-origin with the derived endpoint or the envelope is
> refused unfetched.
>
> **What did NOT change:** every published example envelope in `examples/`
> parses and round-trips exactly as before, and the one carrying real
> signatures still verifies against them. `credentialStatus` is
> omitted-when-absent and MUST NOT be emitted as `null`, so an envelope that
> offers no status reference is byte-identical to a pre-revocation envelope
> and every existing signature stands.

> ### Revision 2026-08-13 — the principal signs
>
> This draft previously described a protocol in which the **Notary Service**
> held the only signing key that mattered, while §1.1 and §3.1 promised that
> the human principal could sign **directly**. The wire format could not
> express that, so every credential was in truth notary-attested: a verifier
> learned that *a notary asserts* the human authorized an action, never that
> the human did.
>
> That is fixed in this revision, in place. APH is pre-production with no
> external adopters, so there is one specification rather than a version
> fork. The changes are §6.1 `principalSignature`, §7.1.7 `attestationMode`,
> §7.1.7 `delegationMandate` embedding, §7.1.11 proof chains linked by
> `previousProof`, §7.2.1 the canonicalization base per proof, §7.3.1 a
> worked `PrincipalSigned` example, amended §8.3 verification, and new §15
> Notary Code Attestation.
>
> **What did NOT change:** the eight published example envelopes in
> `examples/` parse and verify exactly as before. `attestationMode` absent
> means `NotaryAttested`, which is what they always were.
>
> **Consequence worth stating plainly:** a Notary Service can no longer forge
> an authorization, because it never holds the principal's key. That is what
> makes a notary ordinary infrastructure **anyone may host**, and it is why
> §15 asks about its *code* rather than its *key custody*.

## 1. Abstract

APH (Agent per Human) defines a wire protocol for cryptographically notarizing actions an autonomous agent takes on behalf of a human principal. Each notarized action carries a Verifiable Credential — issued by a Notary Service under one of three human-configured policy decisions (`AlwaysAllow`, `AskEveryTime`, `NeverAllow`) — that binds the action's payload to the human's keypair, the agent's identity, the channel transport, and the policy context. APH is transport-agnostic: envelopes ride alongside the action itself on whatever channel the agent uses (email, chat, messaging, voice, agent-to-agent), so that any recipient — regardless of vendor or organization — can independently verify that a specific human authorized this specific action. APH complements adjacent protocols (A2A for agent-to-agent transport, AP2 for payment authorization, MCP for tool exposure, W3C VC 2.0 for credential format) without replacing any of them. Where A2A defines the transport and AP2 defines payment authorization, APH defines per-action human authorization — the agent's verifiable license to act on a specific human's behalf for a specific task on a specific channel.

---

## 1.1 Mental model — the agent's driver's license

APH credentials function as **drivers' licenses for agents**. The metaphor maps directly to the protocol structure:

- **The issuing authority is the human principal.** Like a state issuing a license, the human is the only party with the authority to grant an agent permission to act on their behalf. The human's signature (directly or transitively via the Notary Service capturing explicit attestation) is the root of every APH credential.
- **The notary service is the DMV.** It runs the human's policy, captures attestation when required, signs the credential with its own keypair, and publishes its public verification key via DNS or HTTPS so any recipient can independently confirm the signature is genuine (§8.4). The notary does NOT decide whether to issue — it executes the human's pre-declared policy.
- **Every credential carries a bounded scope.** A Delegation Mandate names the channels the agent may operate on (`allowedChannels`), the rate at which it may act (`rateLimitPerHour`), the time window during which authority is valid (`validFrom` … `validUntil`), and the policy decision the human selected (`AlwaysAllow` / `AskEveryTime` / `NeverAllow`). A Communication Mandate further binds a single action to a specific outbound payload hash. Like a driver's license that authorizes operating a specific class of vehicle in specific places, APH credentials authorize specific actions on specific channels.
- **The license is revocable at any time, and a recipient can see it.** The issuing human can revoke a Delegation Mandate before its `validUntil`. Both halves are normative in this version of the spec: the revocation model itself (§6.3.1) and the on-wire transport a third-party recipient uses to observe a revocation at verification time (§6.3.3, a status list the notary publishes at an endpoint derived from its own `did:web`). Like a licence the roadside check actually queries, not one whose suspension only the issuing office knows about.
- **The license is portable across jurisdictions.** Like an interstate driver's license, an APH credential issued by one organization's notary is verifiable by any other organization's agent or system using only public standards (W3C VC 2.0, RFC 8785, RFC 7515, RFC 8032, DNS). No bilateral integration, no shared identity provider, no out-of-band trust establishment. The notary's public key is published in DNS or at a `.well-known` URI; any recipient on the open internet can resolve it.
- **The license is independently auditable.** Every credential is a self-contained Verifiable Credential. Recipients store them in their own audit logs. Disputes can be resolved by re-verifying the credential against the notary's published key — by the recipient, by a third-party auditor, or by a regulator — without ever contacting the notary.
- **Replay is the RECIPIENT'S ledger obligation in v0.1, and this specification says so rather than implying otherwise.** A valid envelope presented twice verifies twice: nothing in the credential itself makes a second presentation distinguishable from the first. What bounds replay today is the recipient's own consumed-envelope ledger (recording accepted `id`s for at least the validity window) together with the short windows §6.3.2 already binds. Audience binding and protocol-level single-use are designed in RFC 0003 (Draft) and are NOT yet normative — `APH_E017` is registered ahead of that RFC so early implementations emit a stable code — and until they land, an implementation MUST NOT describe an APH envelope as replay-proof.

The notarization step matters precisely because it produces a third-party-verifiable artifact. A signed action without public-key publication is closed signing; a signed action with publicly-anchored public keys is notarization. APH is the latter.

### 1.1.1 Concrete example — two agents negotiating

Alice's agent and Bob's agent are negotiating a meeting time. Both agents are acting with autonomy within bounded parameters their humans set in advance.

The negotiation rides A2A, and APH is transport-independent: each A2A message carries its APH envelope as extension metadata under the URI-namespaced key `aph://extensions/notarization/v1`, declared as an `AgentExtension` in each AgentCard (§10.1). The envelope's `channel` block always describes the end-delivery medium — one of the closed §7.1.5 kinds — never the agent-to-agent rail, mirroring how DKIM signs the message independently of the SMTP hops that relay it.

1. Alice opens her agent and grants it a Delegation Mandate scoped to channel `email` — the medium the confirmed meeting invite will ultimately land on — content class `Reply` and `New`, valid for 30 days, with `rateLimitPerHour = 12`. Squillo's notary signs the mandate and persists it to Alice's local store.
2. Alice's agent drafts the first message: "How about 3 pm Tuesday?" The agent sends it under an APH envelope notarized by Squillo's notary on Alice's behalf, with `credentialSubject.policy.delegationMandateId` pointing at the just-issued mandate.
3. Bob's agent receives the envelope. Bob's agent has never previously transacted with Squillo. It resolves Squillo's notary public key via `did:web:notary.squillo.com` (fetching `https://notary.squillo.com/.well-known/did.json`) OR via the `_aph._notary.squillo.com` DNS TXT record. Both publication mechanisms are anchored in public infrastructure Bob does not need a Squillo account to read.
4. Bob's agent verifies the envelope signature, validates the time window, confirms the body hash matches the received payload, confirms the scope permits this channel + content class, and accepts the message.
5. Bob's agent replies under its own APH envelope, notarized by Bob's organization's notary. Alice's agent verifies the reply using the same flow.
6. Neither human is in the loop for the negotiation itself, but every action either agent takes is provably bound to a credential its human issued ahead of time and can revoke at any time.

If Alice changes her mind and revokes the Delegation Mandate, Squillo's notary records the revocation and sets the mandate's bit in the status list it publishes. Squillo's notary stops issuing new Communication Mandates against the mandate immediately, and Bob's agent — which resolved the status endpoint from Squillo's own `did:web`, not from anything Alice's agent sent — refuses subsequent envelopes referencing it with `APH_E015` (§6.3.3). Short validity windows (RECOMMENDED: hours-to-days, not weeks-to-months) remain good practice as defense in depth: they bound the damage if Bob's agent cannot reach the status surface at all.

---

## 2. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they appear in all capitals as shown here.

The following terms are used throughout this specification:

- **Human Principal** — the natural person on whose behalf an outbound communication is sent. Holds a long-lived asymmetric keypair (typically Ed25519) bound to a DID.
- **Agent (Sender)** — software, typically backed by an LLM, drafting the outbound message on the human's behalf. Identified by a DID and OPTIONALLY by an A2A AgentCard URI.
- **Notary Service** — the service that runs the human's local policy, captures attestation when required, and issues the verifiable credential carried by the envelope.
- **Channel Adapter** — the transport-layer plugin (Slack, Email, Discord, Teams, WhatsApp, Google Chat, iMessage, etc.) that carries the notarized message over its native protocol.
- **Recipient Endpoint** — the far-end software (mail client, chat client, agent runtime, archival system) that verifies the credential before displaying or accepting the message.
- **Delegation Mandate** — a long-lived authorization issued by a Human Principal to an Agent for a bounded scope of channels, recipient patterns, and content classes. May be referenced by many Communication Mandates.
- **Communication Mandate** — a per-message authorization issued by the Notary Service for a single outbound payload. Optionally references a parent Delegation Mandate.
- **Notarization Envelope** — the W3C Verifiable Credential 2.0-shaped object carrying the notarized claim. The on-wire artifact.
- **Notary Decision** — the human-configured policy outcome for an outbound message: `AlwaysAllow`, `AskEveryTime`, or `NeverAllow`. Despite the name, this is a standing **mode**, not the verdict on any single act: what was decided about a specific act is carried by the state the envelope was issued from (§9), and by the envelope's existence itself — an envelope can only exist if `Approved` was reached.
- **Verifiable Credential (VC)** — as defined in W3C Verifiable Credentials Data Model 2.0.
- **DID** — Decentralized Identifier, as defined in W3C DID Core 1.0.
- **JCS** — JSON Canonicalization Scheme, as defined in RFC 8785.
- **JWS** — JSON Web Signature, as defined in RFC 7515.

---

## 3. Design Goals + Non-Goals

### 3.1 Design Goals

APH v0.1 is designed to meet the following goals:

- **Human-attested.** Every notarized message binds to a verifiable signature derived from a key held by the human principal — directly via the principal's own proof on the envelope (§7.1.11), or via the principal's signature on the Delegation Mandate that authorized it (§6.1), which travels embedded in the envelope so a recipient can check it offline (§7.1.7.1). The Notary Service countersigns; it never substitutes for the principal.
- **Local-first decision.** The `AlwaysAllow` / `AskEveryTime` / `NeverAllow` policy is evaluated on the human's device or under the human's direct control. Notarization does not require an authorization server.
- **Recipient-verifiable across vendors.** A recipient running entirely different software from the sender MUST be able to verify the credential using only public standards (W3C VC 2.0, RFC 8785, RFC 7515, RFC 8032).
- **Transport-agnostic.** APH envelopes ride on the channel's native metadata surface (email header, chat block metadata, message attachment). APH does not define a new transport.
- **Replay-resistant.** Each envelope binds to a specific outbound payload via a body hash and a time window, MAY name the one recipient entitled to accept it (`audience`, §7.1.13), and is spent by acceptance: a verifier records the envelope `id` when it commits to the act and refuses any later presentation of the same `id` (§8.3 step 8b, `APH_E018`). Single-use is per-verifier — recipients share no state — which is why audience binding and the single-use record are load-bearing together (RFC 0003).
- **Composable.** APH composes cleanly with A2A (advertised as an agent extension), AP2 (cross-linked mandates), MCP (exposed as a tool), W3C VC 2.0 (envelope shape), and SD-JWT-VC (selective-disclosure compact form).
- **No vendor lock-in.** All required cryptographic primitives are IETF or W3C standards. Implementations MAY be written against any conformant library.

### 3.2 Non-Goals

APH v0.1 is explicitly NOT:

- A replacement for A2A, AP2, or MCP. APH composes with them; it does not subsume them.
- An agent discovery or registry protocol. Agent identity is bound externally via A2A AgentCard and DID Documents.
- A payment authorization protocol. Payment authorization is the domain of AP2.
- A chat or transport protocol. APH does not define how bytes move between endpoints.
- An identity provider. APH consumes identity (DIDs, AgentCards) but does not issue or manage identifiers.
- A content moderation system. APH attests that a human authorized a message; it does not evaluate the message's content.
- A general credential-status service. v0.1 DOES define a revocation transport (§6.3.3), but only for the one artifact whose lifecycle needs it: the Delegation Mandate. There is no status for individual envelopes, none for Communication Mandates (single-use and already consumed, §6.3.1), and no suspension purpose — §6.3.2 forbids re-activation, so a reversible status would describe a lifecycle APH does not have.

---

## 4. Architecture

APH defines five protocol roles and six operations. The Human Principal authorizes the Agent (sometimes ahead of time via a Delegation Mandate, sometimes per-message via an AskEveryTime prompt); the Notary Service issues a Notarization Envelope binding the human's attestation to a specific outbound payload; the Channel Adapter carries the envelope over its native transport; the Recipient Endpoint independently verifies the envelope.

The Notary Service is a logical role; in v0.1 it is typically co-located on the same device as the Human Principal. A notary holds ONLY its own keypair; the human principal's signing key never leaves the principal's control (§6.1, §7.1.11). That is what makes a notary hostable by anyone — a remote notary is not an escrow of the human's authority, and a compromised notary cannot forge one (§15).

```
+----------------+   1. sign mandate       +----------------+
| HumanPrincipal | ----------------------> | NotaryService  |
|                |    (principalSignature) |                |
|                |                         |                |
|                | <---------------------- |                |
|                |   2. prepared envelope  |                |
|                |                         |                |
|                | ----------------------> |                |
|                |   3. principal proof    +-------+--------+
+----------------+                                 |
                                                   | 4. countersign
                                                   v
+----------------+   draft message    +----------------+
|  AgentSender   | -----------------> | ChannelAdapter |
+----------------+                    +-------+--------+
                                              |
                                              | transport
                                              v
                                       +----------------+
                                       | RecipientEnd-  |
                                       | point          |
                                       +----------------+
```

The Agent Sender drafts the outbound message and submits a notarization request to the Notary Service. The Notary Service consults the Human Principal's local policy and (if required by `AskEveryTime`) prompts the human.

On a positive decision the notary **prepares** the complete envelope, including its own `notarization` metadata (step 2). In `PrincipalSigned` mode the principal's key then signs that prepared envelope (step 3) and the notary countersigns the result (step 4) — the order §7.2.1 requires, because each signature can only cover bytes that already exist. In `NotaryAttested` mode steps 2 and 3 collapse: the human is not present to sign, their authority instead rides in the Delegation Mandate they signed at step 1, which SHOULD be embedded (§7.1.7.1), and the notary signs alone.

Either way the notary returns the envelope to the Agent Sender, which hands it together with the original payload to the Channel Adapter. The Channel Adapter transmits both over the channel's native transport. The Recipient Endpoint verifies the envelope's proofs, time window, and body hash against the received payload before accepting or displaying the message.

---

## 5. Roles + Operations

### 5.1 Party Roles

APH defines five formal party roles. Each role is constrained to a specific set of operations.

- **`HumanPrincipal`** — allowed operations: `IssueDelegationMandate`, `IssueCommunicationMandate`. The natural person authorizing outbound communications.
- **`AgentSender`** — allowed operations: `IssueCommunicationMandate`. The agent drafting the message; participates in mandate issuance by initiating notarization requests.
- **`NotaryService`** — allowed operations: `Notarize`, `Reject`. The service that signs envelopes (on positive decisions) or returns errors (on negative decisions).
- **`ChannelAdapter`** — allowed operations: `Transport`. The transport plugin carrying the envelope alongside the payload over the channel's native protocol.
- **`RecipientEndpoint`** — allowed operations: `Verify`. The far-end consumer that checks the envelope before accepting the message.

A single piece of software MAY play more than one role. For example, a desktop client typically combines `AgentSender`, `NotaryService`, and `ChannelAdapter` in a single process; a recipient mail server typically plays `RecipientEndpoint` alone. Role separation in this specification is logical, not architectural.

### 5.2 Operations

APH defines six operations. Each operation is performed by a specific role (or set of roles) as enumerated in §5.1.

- **`IssueDelegationMandate`** — A Human Principal grants an Agent ongoing authority to send messages on specified channels within a bounded scope (recipient patterns, content classes, expiry). The mandate is signed by the human principal and countersigned by the Notary Service and persisted for later reference.
- **`IssueCommunicationMandate`** — Either the Human Principal (via an AskEveryTime decision) or the Agent Sender (via reference to a valid Delegation Mandate) initiates a per-message authorization. The Notary Service produces the mandate.
- **`Notarize`** — The Notary Service signs a `NotarizationEnvelope` carrying the mandate plus the bound outbound payload's metadata. Produces the on-wire artifact.
- **`Transport`** — The Channel Adapter carries the envelope alongside the payload over the channel's native transport. The exact carriage mechanism (header, block metadata, attachment) is channel-specific.
- **`Verify`** — The Recipient Endpoint validates the envelope's signature, time window, algorithm allow-list, and (RECOMMENDED) the body hash against the received payload. Produces a verification result.
- **`Reject`** — The Notary Service or Recipient Endpoint refuses to proceed. Produces an error code from the APH error taxonomy (see §11) and (in the Notary case) does NOT emit an envelope.

---

## 6. Mandates

APH defines two mandate types: the long-lived `DelegationMandate` and the per-message `CommunicationMandate`. Mandates are JSON objects with deterministic field naming (camelCase wire form), `serde`-style strict typing (unknown fields rejected), and a notary signature that binds the canonical (JCS) form of the mandate excluding the signature field itself.

### 6.1 DelegationMandate

A `DelegationMandate` is issued by a Human Principal (via the Notary Service) and grants an Agent ongoing authority to send messages within a bounded scope. A single Delegation Mandate MAY be referenced by many Communication Mandates over its validity window.

Fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Mandate identifier in `urn:uuid:` form. MUST be globally unique. |
| `humanPrincipalDid` | string | yes | DID of the human principal granting authority. |
| `agentDid` | string | yes | DID of the agent receiving authority. |
| `allowedChannels` | array of strings | yes | Channel kinds permitted (e.g., `["slack", "email"]`). |
| `allowedRecipientClasses` | array of strings | no | Recipient classes permitted, from the closed set `human`, `agent` (RFC 0005) — the constraint a human could not previously write down: mail to PEOPLE versus unattended machine-to-machine traffic on the same medium. ABSENT means unconstrained (which every pre-RFC-0005 grant is, and keeps its signed bytes intact); an EMPTY array is a coherent grant allowing no consumer at all, and is not the same statement. |
| `rateLimitPerHour` | unsigned integer | no | Optional per-hour send rate cap. Omitted or `null` means unlimited. |
| `validFrom` | RFC 3339 string | yes | "Valid from" timestamp. |
| `validUntil` | RFC 3339 string | yes | "Valid until" timestamp. |
| `principalSignature` | string | yes | **Multibase signature by the PRINCIPAL's own key** over the JCS-canonical form of this struct MINUS both signature fields. This is the human's actual grant of authority and the root of every credential issued under this mandate. |
| `notarySignature` | string | yes | Multibase- or base64url-encoded signature over the JCS-canonical form of this struct MINUS the `notarySignature` field (with `principalSignature` PRESENT). The notary countersigns what the principal signed. |

Worked-example JSON:

```json
{
  "id": "urn:uuid:8d3f0e1a-2b4c-4d5e-9f6a-1234567890ab",
  "humanPrincipalDid": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
  "agentDid": "did:web:agent.example.com",
  "allowedChannels": ["slack", "email"],
  "rateLimitPerHour": 30,
  "validFrom": "2026-05-21T00:00:00Z",
  "validUntil": "2026-06-21T00:00:00Z",
  "principalSignature": "z5Kd8y...base58btc-signature-by-the-HUMAN...",
  "notarySignature": "z3sQXc...base58btc-countersignature-by-the-notary..."
}
```

Validation rules:

- `id` MUST be a globally unique `urn:uuid:` value.
- `validFrom` MUST be lexicographically less than `validUntil`.
- `allowedChannels` MUST contain at least one entry.
- When `allowedRecipientClasses` is present, a verifier checking an envelope against this mandate MUST refuse (`APH_E020`) an envelope whose `channel.recipientClass` is outside the granted set — or ABSENT, because a constraint escapable by omission is not a constraint (§7.1.7.1).
- `principalSignature` MUST verify against the verification method resolved from `humanPrincipalDid`. This check comes FIRST: a countersignature over an unverifiable grant proves nothing.
- `notarySignature` MUST verify against the issuing Notary Service's published verification method.
- Implementations MUST reject mandates with unknown fields (strict deserialization).

### 6.2 CommunicationMandate

A `CommunicationMandate` is issued per outbound message. It MAY reference a parent `DelegationMandate` (the standing-authority case) or stand alone (the AskEveryTime case). The mandate binds the outbound payload by hash, the channel and recipient addressing, and the policy decision that produced it.

Fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Mandate identifier in `urn:uuid:` form. |
| `delegationMandateId` | string | no | Parent `DelegationMandate.id`, or `null` for one-shot AskEveryTime flow. |
| `humanPrincipalDid` | string | yes | DID of the human principal (restated for tamper-detect). |
| `agentDid` | string | yes | DID of the agent sender (restated). |
| `channelKind` | string | yes | Channel kind (`slack`, `email`, `discord`, `teams`, `whatsapp`, `google_chat`, `imessage`, `service`, `squillo`). |
| `recipientAddressing` | JSON object | yes | Channel-shaped addressing payload (opaque to APH core; see §6.4). |
| `contentClass` | string | yes | Content classification. The SAME closed enum as the envelope's `communication.contentClass` (§7.1.6): `Reply`, `New`, `Mention`, `DM`, `Channel`, `BulkSend`, `Broadcast`, `Mutation` — and it MUST equal the value the resulting envelope carries. *(Erratum 2026-08-23: this row previously read "etc.", leaving a required, signed field open while §7.1.6 closed it — two conformant notaries could have emitted values the other rejects, and neither would have been wrong.)* |
| `bodySha256` | string | yes | SHA-256 hex digest of the outbound message body bytes (64 lowercase hex chars). |
| `bodySize` | unsigned integer | yes | Body size in bytes. |
| `policyDecision` | string | yes | The policy outcome that produced this mandate: `AlwaysAllow`, `AskEveryTime`, `NeverAllow`. (A `NeverAllow` mandate is recorded but does NOT result in an envelope.) **This field records the human's standing configuration, NOT the outcome of this act** — the outcome is carried by the state the artifact was issued from (§9). On an `AskEveryTime` path the value stays `AskEveryTime` after the human approves; what asserts the approval is that the mandate exists at all, since §9.1 admits no path to `MandateIssued` that does not pass through `Approved`. |
| `issuedAt` | RFC 3339 string | yes | Issuance timestamp. |
| `expiresAt` | RFC 3339 string | yes | Expiry timestamp. |
| `notarySignature` | string | yes | Signature over the JCS-canonical form MINUS `notarySignature`. |

Worked-example JSON:

```json
{
  "id": "urn:uuid:1d8a4c2b-3e5f-4a6b-8c7d-9e0f1a2b3c4d",
  "delegationMandateId": "urn:uuid:8d3f0e1a-2b4c-4d5e-9f6a-1234567890ab",
  "humanPrincipalDid": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
  "agentDid": "did:web:agent.example.com",
  "channelKind": "slack",
  "recipientAddressing": {
    "teamId": "T01234567",
    "channelId": "C01234567"
  },
  "contentClass": "Reply",
  "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "bodySize": 1842,
  "policyDecision": "AlwaysAllow",
  "issuedAt": "2026-05-21T14:00:00Z",
  "expiresAt": "2026-05-21T14:05:00Z",
  "notarySignature": "z3sQXc...base58btc-encoded-signature..."
}
```

Validation rules:

- `bodySha256` MUST be exactly 64 lowercase hex characters.
- `bodySize` MUST be a non-negative integer.
- `policyDecision` MUST be one of the three enumerated values.
- `expiresAt` MUST be greater than `issuedAt`. v0.1 RECOMMENDS a short expiry (5 minutes default) to bound replay windows.
- If `delegationMandateId` is non-null, the referenced Delegation Mandate MUST exist, MUST be unexpired at `issuedAt`, MUST NOT be revoked at `issuedAt` (§6.3.1, §6.3.3), and MUST list `channelKind` in its `allowedChannels`. Expiry and revocation are the two ways standing authority ends — one on schedule, one by the human's decision — and a rule that named only the first would let a notary issue against authority its own records show was withdrawn.

### 6.3 Mandate lifecycle

A Delegation Mandate is issued and signed by the Human Principal (`principalSignature`), countersigned by the Notary Service (`notarySignature`), and persisted to the human's local store. Its validity window is bounded by `validFrom` and `validUntil`. A Communication Mandate is issued at outbound-action time; it MAY reference a Delegation Mandate (the standing-authority path) or stand alone (the AskEveryTime path). Communication Mandates are single-use: one Communication Mandate per outbound action. A Communication Mandate carries the notary's signature alone; a Delegation Mandate carries the human's `principalSignature` with the notary's countersignature over it, so the standing grant is rooted in the human's key rather than the notary's (§6.1).

#### 6.3.1 Revocation — conceptual model

A Delegation Mandate is REVOCABLE by the issuing Human Principal at any time before its `validUntil`. Revocation is the corollary of the driver's-license framing: a license that cannot be pulled is not a license. This subsection defines the model — who may revoke, and what a revocation means for mandates and envelopes already issued. §6.3.3 defines the on-wire transport by which a third-party recipient observes one.

The conceptual revocation model is:

1. **Issuer-side state.** The Notary Service tracks, for every Delegation Mandate it has signed, a `revoked: bool` state and a `revokedAt: RFC 3339 string` timestamp (set when revoked, absent otherwise). The Notary Service exposes a revocation operation to the Human Principal; calling it sets `revoked = true` and stamps `revokedAt = now`.
2. **Effect on downstream Communication Mandates.** A Notary Service MUST NOT issue a new Communication Mandate referencing a revoked Delegation Mandate. A Communication Mandate signed before its parent Delegation Mandate was revoked remains cryptographically valid; the revocation cuts off issuance of NEW mandates rather than invalidating existing signatures.
3. **Effect on issued envelopes.** Envelopes already in flight when the parent mandate is revoked remain verifiable as signed credentials — the signatures are genuine and stay genuine. What ended is the authority behind them. **A Recipient Endpoint that receives an envelope carrying a `credentialStatus` reference (§7.1.1) MUST resolve that reference and MUST reject the envelope when the parent Delegation Mandate is revoked** (`APH_E015`, §6.3.3, §8.3 step 8a). This is a MUST rather than the recipient policy earlier drafts left it as: a transport nobody is obliged to consult protects nobody, and expiry in the next subsection (§6.3.2) already binds verifiers with a MUST — an authority that ran out on schedule and an authority the human deliberately pulled cannot carry opposite normative force. When an envelope carries NO status reference the recipient has been offered no claim to check, and §6.3.3.4 case 1 governs.
4. **Revocation transport.** Defined normatively in §6.3.3: the notary publishes a status list credential at an endpoint derived from its own `did:web`, and each envelope issued under a mandate carries that mandate's position in the list. Short validity windows (RECOMMENDED: hours to days, not weeks to months, for MANDATES — an ENVELOPE authorizing a single act SHOULD carry a window on the order of minutes, per RFC 0003: a window bounds replay without preventing it, and the single-use record of §8.3 step 8b shrinks with the windows a verifier accepts) remain RECOMMENDED as defense in depth — they bound the exposure of a recipient that cannot reach the status surface at all, and of one whose deployment predates this revision.

A Communication Mandate is single-use and conceptually "consumed" by issuing the corresponding envelope; revocation of a Communication Mandate has no practical meaning (the envelope has either been issued or it has not). Revocation applies to Delegation Mandates only.

#### 6.3.2 Expiration

When `now > validUntil`, a Delegation Mandate is EXPIRED. A Notary Service MUST NOT issue a new Communication Mandate referencing an expired Delegation Mandate. Verifiers MUST reject envelopes whose Communication Mandate's `delegationMandateId` resolves to an expired Delegation Mandate (when the verifier has access to that lookup).

A Delegation Mandate that has reached its `validUntil` cannot be "re-activated" — the human must issue a new mandate with a new `id` and new validity window.

#### 6.3.3 Revocation transport (normative)

§6.3.1 makes revocation normative and §6.3.2 makes expiry normative, but only expiry is observable from an envelope alone. This subsection specifies the on-wire mechanism by which a third-party Recipient Endpoint — one with no account at the notary and no prior relationship with the principal — learns at verification time that a Delegation Mandate has been revoked.

APH profiles **W3C Bitstring Status List v1.0** (§14.1). This specification defines the derivation, the binding, the freshness bound and the allocation discipline; the bitstring encoding, the entry shape and the list credential shape are the W3C profile's and are not restated here. The vintage is pinned rather than left as "or equivalent" because the entry's `type` value is signed wire content under §7.1's strict parse: two implementations reading different vintages of the same idea would both look conformant and would never interoperate — the same failure §7.2 warns about for `proofValue`.

##### 6.3.3.1 The status entry on the envelope

The envelope carries the entry as the OPTIONAL top-level `credentialStatus` field (§7.1.1). Its shape is the W3C `BitstringStatusListEntry`:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | no | Identifier for this status entry. Omitted when absent. |
| `type` | string | yes | MUST be `"BitstringStatusListEntry"`. Closed value. |
| `statusPurpose` | string | yes | MUST be `"revocation"` (§6.3.3.5). Closed value set of exactly one member. |
| `statusListIndex` | string | yes | This mandate's position in the list, as a base-10 integer **in a JSON string** — never a JSON number (§6.3.3.6). |
| `statusListCredential` | string | yes | Absolute `https:` URL of the status list credential. MUST be same-origin with the derived status endpoint (§6.3.3.2). |

No JSON-LD context term is added by this revision: `BitstringStatusListEntry` and its members are defined by `https://www.w3.org/ns/credentials/v2`, which every APH envelope already lists first in `@context` (§7.1.1). Choosing this vintage is therefore also what keeps the context array unchanged.

**Whose status this is — an APH profile of the W3C field, stated because it narrows the default reading.** In W3C VC 2.0, `credentialStatus` describes the status of *the credential carrying it*. In APH it describes the status of the **parent Delegation Mandate** named by `credentialSubject.policy.delegationMandateId`. The narrowing follows from §6.3.1: revocation applies to Delegation Mandates only, and an envelope already issued stays cryptographically valid whatever happens afterwards. A verifier applying the default reading would be answering a question APH never asks.

An envelope carrying `credentialStatus` MUST also carry a non-null `credentialSubject.policy.delegationMandateId`. An envelope violating this is rejected under §7.1's strict-parse rule at §8.3 step 1: a status reference with nothing to be the status *of* is malformed, not merely unhelpful, and admitting it would leave a verifier checking a bit whose subject it cannot name.

##### 6.3.3.2 The derived endpoint, and why the envelope does not choose it

The **derived status endpoint** is computed from the notary's own identifier and is never read out of the envelope's status entry:

1. Take `credentialSubject.notarization.notaryService.id` (§7.1.9) — the DID of the notary that issued and countersigned the mandate. If it is not a `did:web` identifier, no status endpoint is derivable; §6.3.3.4 states the consequence.
2. Apply §8.4.4 step 2's rule — percent-decode the method-specific identifier, prefix `https://`, and map colons to path segments — then suffix `/.well-known/aph-status.json` in place of `/.well-known/did.json`. The result is the derived status endpoint.
3. A notary that publishes any revocation status MUST serve its default status list credential at that endpoint, over TLS validating against the verifier's trust store under §8.4.4 step 3.

**Same-origin binding.** When the envelope's entry carries `statusListCredential`, that URL MUST use the `https:` scheme and MUST be same-origin — identical scheme, host and port — with the derived status endpoint. A verifier encountering a cross-origin or non-`https:` value MUST reject the envelope and MUST NOT fetch the named URL.

The rule reads like paranoia until the attack is named. The authority for "is this mandate revoked" is the notary that issued the mandate, and that notary's identity is anchored in a domain (§8.4.4's trust model). If the envelope could name the host answering the revocation question, then whoever holds an old envelope also chooses that host — and a host of the attacker's choosing always answers *not revoked*. Deriving the origin puts the answer back with the party whose key signed the mandate. Same-origin deliberately permits a **different path**, which is how a notary with more than one list points at the second one; the path is the notary's to choose because it is behind the notary's own TLS name, and the origin is not the envelope's to choose at all.

##### 6.3.3.3 The status list credential

The document served at the derived endpoint (or at a same-origin path named by `statusListCredential`) is a `BitstringStatusListCredential` per the W3C profile, with `credentialSubject.statusPurpose` equal to `"revocation"` and `credentialSubject.encodedList` holding the compressed, base64url-encoded bitstring.

- **Issuer binding.** Its `issuer` MUST be the same notary DID the endpoint was derived from in §6.3.3.2 step 1. Same-origin alone does not make a document authoritative — a host may serve many documents — so the list must also be signed by the notary whose mandate is in question.
- **Proof.** The credential is secured under §8.1/§8.2 and its verification method resolves through §8.4 exactly as an envelope proof does. v0.1 signs it with the notary's ordinary signing key. This specification does not express per-key proof purposes in a published DID Document, so a key added *only* for status would also be accepted for envelope signing; minting one is therefore an authority widening this revision declines to make.
- **Freshness (normative).** A verifier MUST NOT accept a status list credential whose issuance (`validFrom`) is more than **5 minutes** before `now`, allowing the same 60-second clock-skew tolerance as §8.3 step 6. A notary that publishes status MUST re-issue and republish at an interval no greater than **2 minutes**, so a conformant verifier always finds a credential inside the bound. A cached copy MUST expire at or before the freshness bound; RECOMMENDED verifier cache TTL is 60 seconds.

  *Why five minutes.* The mitigation this transport replaces (§6.3.1 item 4) is a short validity window, RECOMMENDED at hours-to-days. A staleness bound measured in hours would cost a network fetch and buy nothing — the mandate would usually have expired before the stale answer changed. Five minutes is the interval this specification already treats as "prompt" (§6.2's default Communication Mandate expiry), and it is at least twelve times tighter than the tightest window the short-window mitigation recommends. Checking status therefore strictly improves on not checking it, which is the property that justifies making the check a MUST.

##### 6.3.3.4 The trichotomy — absent, unresolvable, revoked

A Recipient Endpoint evaluates status at §8.3 step 8a in exactly three outcomes:

1. **Absent — skip.** The envelope carries no `credentialStatus`. No claim was offered, and enforcing a claim nobody made is not fail-closed, it is fail-arbitrary: it would refuse every conformant pre-revision envelope. The verifier advances, the same way §8.4.6 has *absence* advance the discovery sequence. A verifier MAY additionally be configured to REQUIRE a status reference and refuse envelopes offering none — that is policy, not protocol, in the shape of §8.3.1 step 10, and a verifier that does not require it remains conformant.
2. **Present and unresolvable — MUST reject the envelope, with `APH_E008`.** The reference was offered and the verifier could not establish the status from it. Every one of the following is this case: the notary's `notaryService.id` is not a `did:web`, so no origin can be derived and the same-origin rule cannot be satisfied; the derived origin could not be reached; TLS validation failed; the document was absent, oversized, or unparseable; its proof did not verify; its `issuer` was not the derived notary; its `statusPurpose` was not `revocation`; its list is too short to contain `statusListIndex`; or the credential is staler than §6.3.3.3's bound. This is §8.4.6's *published and failed* one level up, and it carries the same reasoning: an attacker who can make the status check **fail** must not thereby get to choose that it is **skipped**.
3. **Revoked — MUST reject the envelope, with `APH_E015`.** The bit at `statusListIndex` is `1`. A bit of `0` means not revoked, and verification continues.

*Why one code covers all of case 2.* Fetch, TLS, parse, proof, issuer, purpose and freshness failures all surface `APH_E008`, whose §11 meaning covers any protocol-mandated fetch from a notary-hosted surface. The verifier's action is identical in every one of them — reject — and so is the operator's remediation: repair the notary's status surface. Implementations SHOULD log which specific cause fired, because an investigator needs it; the protocol code does not distinguish them because no recipient acts differently on the distinction. Note the boundary with `APH_E014`: that code means a *discovery surface* answered and published no key, which advances the §8.4.6 sequence. There is no sequence to advance here — the status surface has no alternate mechanism — so terminal absence of a status document the envelope pointed at is a failure, not an absence.

##### 6.3.3.5 `statusPurpose` is `revocation`, and an unrecognized purpose is a failure

The `statusPurpose` value set is CLOSED at exactly one member, `"revocation"`. Bitstring Status List's other defined purpose, `"suspension"`, is deliberately excluded: suspension is reversible, and §6.3.2 forbids re-activation. A mandate whose authority has ended cannot be brought back — the human issues a new mandate with a new `id`. Admitting a reversible purpose would put a lifecycle in the transport that the mandate itself does not have, and a recipient would eventually be asked to un-refuse an envelope this specification says stays refused.

An unrecognized or excluded `statusPurpose` is a FAILURE, never something to ignore. It is rejected under §7.1's strict-parse rule at §8.3 step 1, exactly as an unrecognized `channelKind` or `policyDecision` is — the value set is closed in the same sense theirs are. A verifier MUST NOT treat a purpose it does not recognize as "no status claim was made": a producer could then disable the check on any verifier simply by writing a word that verifier has never seen, which turns the closed set into an opt-out.

##### 6.3.3.6 `statusListIndex` is a string, and an index is never reused

`statusListIndex` is a **string** holding a base-10 integer. Producers MUST NOT emit it as a JSON number, and verifiers MUST NOT parse it through a floating-point type. In many runtimes every JSON number is an IEEE-754 double, which silently rounds integers past 2^53 — and a rounded index does not raise a parse error, it reads a **different bit**. The verifier then answers, with full confidence, a question about some other mandate. The string form makes that failure unconstructible rather than merely unlikely, which is the same reason §7.1's other identifiers are strings.

**Index reuse is PROHIBITED.** Once a notary has allocated index *i* in a given status list to a Delegation Mandate, *i* MUST NOT be allocated to any other mandate — not after the first mandate expires, not after it is revoked, not when the list is re-issued, and not when the same principal and agent re-enroll. Allocation is permanent, append-only, and survives re-enrollment of an existing mandate record.

The index travels inside the signed bytes of every envelope issued under that mandate, and those envelopes outlive the mandate: recipients keep them for audit and re-verify them in disputes (§1.1). Reassigning *i* silently re-points every one of those stored envelopes at an unrelated mandate. Both directions are wrong. If the replacement mandate is later revoked, envelopes whose own authority was never withdrawn become permanently refused. If it is not revoked, envelopes issued under authority that WAS withdrawn are laundered back into acceptance. Neither is detectable at the recipient: the bytes are unchanged and the signature still verifies, so nothing looks wrong.

When a list is exhausted the notary publishes a NEW status list credential at a NEW path on the SAME origin and allocates from it. The old list MUST remain published and served for as long as any envelope referencing it may still be verified. Retiring a list that live envelopes still point at is the same defect one step removed: those envelopes become permanently unresolvable, which under §6.3.3.4 case 2 makes them permanently rejected.

---

## 7. The Notarization Envelope

The `NotarizationEnvelope` is the canonical on-wire artifact. It is a W3C Verifiable Credential 2.0 of type `AgentSendAuthorizationCredential`, secured with either a Data Integrity Proof or a detached JWS, carried as a single proof or as a two-element proof chain (§7.1.11). The envelope embeds the credential subject (which carries the equivalent of a Communication Mandate plus contextual metadata about the agent, channel, and decision) and a single `proof` block carrying the notary signature.

### 7.1 Top-level shape

The envelope is a JSON-LD object with the following top-level shape. All field names use camelCase. Strict deserialization (unknown fields rejected) is REQUIRED.

#### 7.1.1 `NotarizationEnvelope` (top-level)

The outermost object.

| Field | Type | Required | Description |
|---|---|---|---|
| `aphVersion` | string | yes | APH protocol version pin. MUST be `"0.1"` for this draft. |
| `@context` | array of strings | yes | JSON-LD context array. MUST begin with the W3C VC 2.0 context `"https://www.w3.org/ns/credentials/v2"` followed by `"https://w3id.org/aph/v1"`. |
| `type` | array of strings | yes | JSON-LD type array. MUST include `"VerifiableCredential"` AND `"AgentSendAuthorizationCredential"`. |
| `id` | string | yes | Envelope identifier in `urn:uuid:` form. |
| `issuer` | string | yes | DID of the party issuing the credential: the **human principal** in `PrincipalSigned` mode, the **Notary Service** in `NotaryAttested` mode (§7.1.7). A verifier MUST NOT infer the signer from this field — each proof's `verificationMethod` is authoritative, and `issuer` is metadata. |
| `validFrom` | RFC 3339 string | yes | Envelope validity start. |
| `validUntil` | RFC 3339 string | yes | Envelope validity end. |
| `credentialSubject` | object | yes | The notarized claim (see §7.1.2). |
| `linkedMandate` | object or null | no | Optional cross-protocol mandate link (see §7.1.10). Omit or set to `null` when absent. |
| `credentialStatus` | object | no | Revocation status reference for the **parent Delegation Mandate** (see §6.3.3). **OMITTED when absent — MUST NOT be emitted as `null`**, unlike `linkedMandate` above. An envelope carrying no status reference is therefore byte-identical to a pre-revocation envelope, so extension-unaware fixtures and their signatures remain valid (the §7.5 guarantee, applied to a core field). Declared here rather than only in §6.3.3 for the same reason §7.1.9's attestation fields are: §7.1 parses strictly, so a field a notary may send MUST appear in the shape a verifier parses, or conformant verifiers would reject conformant notaries. |
| `proof` | object OR array of objects | yes | Cryptographic proof (see §7.1.11). A single object is a notary proof. An array is a two-element W3C proof chain: the principal's proof, then the notary's countersignature. |

#### 7.1.2 `CredentialSubject`

The notarized claim. Wraps the human principal, agent, channel, communication descriptor, policy descriptor, and notarization metadata into a single subject object.

| Field | Type | Required | Description |
|---|---|---|---|
| `humanPrincipal` | object | yes | See §7.1.3. |
| `agent` | object | yes | See §7.1.4. |
| `channel` | object | yes | See §7.1.5. |
| `communication` | object | yes | See §7.1.6. |
| `policy` | object | yes | See §7.1.7. |
| `notarization` | object | yes | See §7.1.8. |
| `appleAurAcceptance` | object | no | Registered optional extension; omitted when absent. See §7.5.1. |
| `audience` | object | no | Who may accept this envelope, and optionally on which delivery coordinates. Omitted when absent — absence is the producer's decision to issue a bearer credential. See §7.1.13. |
| `actClassification` | object | no | What the sender says this act MEANS, against independently published vocabularies. Omitted when absent. See §7.1.12. |

#### 7.1.3 `HumanPrincipalRef`

Identifies the human principal.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | DID of the human principal. Typically a `did:key`. |
| `displayName` | string | yes | Human-readable name for UI display. |

#### 7.1.4 `AgentRef`

Identifies the agent sender.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | DID of the agent. Typically a `did:web`. |
| `agentCardUri` | string | no | Optional URL to the agent's A2A AgentCard. |
| `displayName` | string | yes | Human-readable name for UI display. |
| `version` | string | yes | Agent software version string. |

#### 7.1.5 `ChannelDescriptor`

Identifies the channel transport and recipient addressing.

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | string | yes | One of the closed channel-kind enum values: `slack`, `email`, `discord`, `teams`, `whatsapp`, `google_chat`, `imessage`, `service`, `squillo`. New channel kinds are additive in 0.x minor versions. *(Erratum 2026-08-12: earlier drafts spelled this value `googleChat`; every published example and signed fixture emits `google_chat`, so the snake_case form is normative.)* |
| `recipientAddressing` | JSON object | yes | Channel-shaped opaque addressing payload. The exact field set is channel-specific; see §7.4 for per-channel shapes. |
| `recipientClass` | string | no | Who CONSUMES what lands there, from the closed set `human`, `agent` (RFC 0005). OPTIONAL, omitted when absent — absence means the producer makes no claim, and every envelope minted before this field existed is byte-identical. ⚠ Emitting is version-gated, same structural rule as §7.1.12/§7.1.13: a producer MUST NOT emit it until it has reason to believe the recipient understands it (§10.1). |

`kind` names the END-DELIVERY MEDIUM — where the message lands for its human
recipient — and never the subsystem that emitted it, the agent-to-agent rail
that relayed it (§1.1.1), or an internal permission scope that authorized it.
Those are different axes, and a value from one of them placed in `kind` makes
an envelope look channel-bound while binding nothing a recipient can act on.
Where a sender's own routing concept has no entry in the enum above, the
closure already decides the question: the correct value is the kind naming the
medium the message ultimately delivers on, not a coinage for the routing
concept.

WHO consumes the message is the other axis, and it is `recipientClass`, not a
kind (RFC 0005). The generalization test that ruled it: a refinement that must
be applied to every member of a set — `a2a_email`, `a2a_slack`, `a2a_teams`, …
— is not a member of that set but a second dimension wearing a member's
clothes, and encoding it as members doubles the vocabulary at every
refinement. Two orthogonal values compose instead: `kind: email` +
`recipientClass: agent` is unattended machine consumption of ordinary mail. A
recipient class asserted by the sender is a CLAIM, not a proof — it constrains
an honest-but-over-broad agent, which is the actual threat (one's own agent
doing more than one meant), and does not constrain a hostile one. What binds
it in a mandate is the human's own signature over `allowedRecipientClasses`
(§6.1).

Requesting a new value for this or any other closed vocabulary in §7.1 is an
ordinary change request, not a private extension: open an RFC
(`rfcs/README.md`). The set is closed against unrecognized values so that a
verifier refuses what it does not know, and extensible through that process so
the vocabulary can still grow — the closure governs what a VERIFIER does with
an unknown value, while additivity governs how the SET changes. Both hold at
once. A vendor arm carrying an arbitrary string was considered for exactly
this purpose and rejected in `rfcs/0004-vendor-extension-channel-kind.md`,
because it would let a producer disable a recipient's check by writing a word
that recipient has never seen.

#### 7.1.6 `CommunicationDescriptor`

Binds the outbound payload.

| Field | Type | Required | Description |
|---|---|---|---|
| `contentClass` | string | yes | Content classification. Closed enum: `Reply`, `New`, `Mention`, `DM`, `Channel`, `BulkSend`, `Broadcast`, `Mutation`. New classes are additive in 0.x. |
| `bodySha256` | string | yes | SHA-256 hex digest of the outbound body bytes (64 lowercase hex chars). |
| `bodySize` | unsigned integer | yes | Body size in bytes. |
| `previewLines` | unsigned integer | yes | Number of lines included in `preview`. |
| `preview` | string | yes | Truncated preview of the outbound body for UI display. MUST NOT exceed `MAX_BODY_PREVIEW_BYTES` (8192 bytes for v0.1). |

#### 7.1.7 `PolicyDescriptor`

Describes the policy decision context.

| Field | Type | Required | Description |
|---|---|---|---|
| `decision` | string | yes | Policy outcome. Closed enum: `AlwaysAllow`, `AskEveryTime`, `NeverAllow`. **Records the human's standing configuration, NOT the verdict on this act** — the verdict is carried by the state the envelope was issued from (§9.1 admits no path to `EnvelopeIssued` that bypasses `Approved`), so an `AskEveryTime` envelope truthfully carries `AskEveryTime` after the human said yes. Implementations that read this field as a per-act decision have shipped real defects; do not. |
| `matchedScope` | string | yes | Scope of the matched policy rule (e.g., `per-channel`, `per-recipient`, `global`, `per-content-class`). |
| `delegationMandateId` | string or null | no | Parent `DelegationMandate.id` if a standing authority matched; `null` otherwise. **The null case is normative, not incidental:** an envelope issued from the human-not-present flow (§9.2) MUST carry a non-null `delegationMandateId` — that flow is gated on a matching Delegation Mandate, so there is always one to name. A verifier MUST therefore read a null or absent `delegationMandateId` as the human-present flow (§9.1): *a human personally approved this specific act.* Before this rule, absence was ambiguous between "one-shot approval" and "standing authority, mandate not recorded" — which erased exactly the distinction this protocol exists to carry. |
| `attestationMode` | string | see below | Closed enum: `PrincipalSigned` \| `NotaryAttested`. REQUIRED when the envelope carries a principal proof (§7.1.11). **When absent, the envelope is `NotaryAttested`** — so envelopes written before this revision remain valid and unambiguous. |
| `delegationMandate` | object or null | no | The **complete parent `DelegationMandate`**, embedded. See §7.1.7.1 — this is what lets a recipient verify the human's authorization offline in the human-not-present flow. |
| `actChain` | array of strings | no | OAuth 2.0 Token Exchange (RFC 8693) `act` chain. Each element is a DID string identifying a delegated principal. Empty array if unused. **Element order is normative: root delegate FIRST, most recent actor LAST, and the human principal is never an element** (the human is `humanPrincipal`; restating them here would be a second spelling of an identity the signature already covers). Declared because this array is inside the signed bytes: RFC 8693's nested `act` claim flattens in either direction, and two producers choosing opposite orders would sign different bytes for the same delegation chain. |

##### 7.1.7.1 Why the delegation is embedded

In the human-not-present flow (§9.2) the human is asleep, so no principal
proof can be made over *this message*. The human's authorization lives in
the Delegation Mandate they signed earlier, and `delegationMandateId` names
it — by **id only**.

An id is not verifiable. A recipient holding only the envelope cannot fetch
that mandate, cannot check its `principalSignature`, and therefore cannot
confirm the human authorized anything at all. The chain of trust is asserted
by the notary rather than proved.

Embedding the mandate closes that, with no new resolution mechanism, no
network round-trip, and no new type:

1. Verify the envelope's notary proof — *this notary issued this message*.
2. Verify the embedded mandate's `principalSignature` against the
   principal's key (free for a `did:key` principal, §8.4.3) — *this human
   granted this authority*.
3. Confirm the mandate is **this** envelope's parent: its
   `humanPrincipalDid` MUST equal `credentialSubject.humanPrincipal.id`,
   its `agentDid` MUST equal `credentialSubject.agent.id`, and its `id` MUST
   equal `policy.delegationMandateId` when that field is present. Without
   these three equalities the embedded mandate proves only that *some* human
   granted *some* agent *something*, and an attacker could staple any
   validly-signed mandate to any envelope.
4. Confirm `channel.kind` is in the mandate's `allowedChannels`, and that
   the envelope's `validFrom` falls inside the mandate's window — *this
   message is within what was granted*.

All four checks are offline.

**What "within scope" does and does not cover.** A Delegation Mandate
constrains channel, rate, and time — nothing else. It cannot express a
recipient allow-list or a content class, so step 4 is a channel-and-window
check and MUST NOT be described as more. A deployment needing per-recipient
or per-content-class limits enforces them at the notary, where the policy
lives, and the envelope records the outcome in `policy.matchedScope`.

**Privacy.** An embedded mandate discloses the human's entire standing grant
— every allowed channel, the rate limit, the full window — to every
recipient of a single message. That is why embedding is SHOULD and not MUST:
a `PrincipalSigned` envelope needs no embedded mandate at all, and a
principal who considers their grant sensitive should prefer that mode. A
future selective-disclosure profile (§14) can redact mandate fields; this
revision has no such mechanism, and a recipient sees the whole grant.

**Bounds.** Mandates are small — nine fields — so the cost is bytes rather
than a protocol round-trip. Because canonicalization happens *before*
signature verification, a verifier MUST bound the work it does on
unauthenticated input: reject an envelope larger than a configured maximum
(RECOMMENDED: 64 KiB) before canonicalizing it, and reject an embedded
mandate carrying unknown fields under the same strict-parse rule as the
envelope itself (§7.1).

#### 7.1.8 `NotarizationMetadata`

Describes the notarization event.

| Field | Type | Required | Description |
|---|---|---|---|
| `notaryService` | object | yes | See §7.1.9. |
| `decisionTimestamp` | RFC 3339 string | yes | Wall-clock timestamp the notary made its decision. |
| `decisionLatencyMs` | unsigned integer | yes | Milliseconds elapsed between notarization request and decision. |

#### 7.1.9 `NotaryServiceRef`

Identifies the notary service.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | DID of the notary service. |
| `name` | string | yes | Human-readable notary name. |
| `version` | string | yes | Notary software version string. |
| `attestedDigest` | string | no | Content digest of the attested release this notary reports running (§15.3). Omitted when the notary makes no attestation claim. |
| `attestationUri` | string | no | Where the k-of-3 attestation for that digest may be fetched (§15.3). |

The two attestation fields are declared here, not only in §15, because §7.1 requires strict deserialization: a field a notary may send MUST appear in the shape a verifier parses, or conformant verifiers would reject conformant notaries.

#### 7.1.10 `LinkedMandate`

Optional cross-protocol mandate link. Forward-extensible: new sister-protocol cross-links are added as new optional fields in this object.

| Field | Type | Required | Description |
|---|---|---|---|
| `ap2IntentMandateUri` | string or null | no | Optional URI pointing at an AP2 `IntentMandate` for cross-linked payment authorization. v0.1 reserves this field; producers MAY emit it; verifiers MUST tolerate `null`. |
| `ap2SignedPayloadB64` | string or null | no | Registered optional extension. See §7.5.2. |
| `vaultMutation` | object | no | Registered optional extension; omitted when absent. See §7.5.3. |

#### 7.1.11 `EnvelopeProof`

The cryptographic proof block. Two proof types are supported:
`DataIntegrityProof` (W3C Verifiable Credential Data Integrity) and
`JsonWebSignature2020` (detached JWS).

**`proof` MAY be a single object or an array of proof objects.** When it is
an array, it is a W3C Verifiable Credentials 2.0 **proof chain** — a facility
the data model already defines, not an APH invention — constrained to exactly
two roles:

| Position | `proofPurpose` | `verificationMethod` | Covers (§7.2.1) |
|---|---|---|---|
| 1 — **principal proof** | `assertionMethod` | the **principal's** DID URL — which MUST resolve to `credentialSubject.humanPrincipal.id` | the envelope with `proof` a ONE-ELEMENT ARRAY holding this proof, its `proofValue` emptied (§7.2.1) |
| 2 — **notary proof** | `authentication` | the **notary's** DID URL | the envelope carrying BOTH proofs, the principal's `proofValue` complete and its own emptied |

The principal proof is the authorization; its absence means no party proved
the human agreed. The notary proof is a **countersignature**: because it
covers the principal proof, a notary cannot detach a principal's signature
and re-attach it to a different envelope, nor substitute a different
authorization beneath its own signature. It attests three things and no
more — that policy was evaluated, when the decision occurred, and that the
notary observed *this exact* principal proof.

**Each proof in a chain MUST carry an `id`, and the notary proof MUST carry
`previousProof` naming the principal proof's `id`.** Array position alone is
not the linkage: W3C Data Integrity defines a proof chain by `previousProof`,
and a verifier that trusted order alone would accept a chain whose proofs
were reordered by an intermediary. A verifier MUST reject a chain whose
`previousProof` does not resolve to a proof present in the same chain.

Verifiers MUST verify in chain order. A notary proof that verifies over a
principal proof that does not itself verify is worthless, and accepting it
would be the defect the chain exists to prevent.

**The label and the structure MUST agree, and a verifier MUST enforce it in
both directions** (`APH_E013`):

- `attestationMode: "PrincipalSigned"` MUST accompany a two-element chain
  whose first proof's `verificationMethod` resolves to
  `credentialSubject.humanPrincipal.id`. A verifier MUST reject the label on
  any other structure — including a single proof, a chain whose head is the
  notary's key, or a chain of any other length.
- A two-element chain MUST carry `attestationMode: "PrincipalSigned"`. A
  verifier MUST reject a chain labelled otherwise, or unlabelled.
- A single-object `proof` is a notary proof, and the envelope is
  `NotaryAttested` (§7.1.7).

Without this rule `attestationMode` is a **self-asserted string**: a holder
of a notary key could write `PrincipalSigned` above a single notary proof
whose `proofPurpose` is `assertionMethod` — indistinguishable from a
principal proof by purpose alone — and a verifier that trusted the label
would report a forged authorization as the human's own signature. The
binding to `humanPrincipal.id` is what closes it, because the notary does
not hold that key.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | in a chain | Identifier for this proof, unique within the envelope (e.g. `urn:uuid:...`). Required when `proof` is an array; omitted for a single-object `proof`, which has nothing to link to. |
| `type` | string | yes | Either `"DataIntegrityProof"` or `"JsonWebSignature2020"`. |
| `cryptosuite` | string | no | Required when `type` is `"DataIntegrityProof"`. One of `"eddsa-jcs-2022"` (Ed25519) or `"ecdsa-jcs-2019"` (ES256/p256). Omitted for `JsonWebSignature2020`. |
| `verificationMethod` | string | yes | DID URL referencing the verifying key. E.g., `did:key:z6Mk...#z6Mk...`. |
| `created` | RFC 3339 string | yes | Proof creation timestamp. |
| `proofPurpose` | string | yes | `"assertionMethod"` for a principal proof; `"authentication"` for a notary countersignature. A single-object `proof` uses `"assertionMethod"` for wire compatibility. |
| `previousProof` | string | in the notary proof of a chain | The `id` of the proof this one countersigns. Present on the notary proof; absent on the principal proof, which is the head of the chain. |
| `proofValue` | string | yes | Signature bytes. Multibase-encoded for `DataIntegrityProof`; compact detached-JWS string for `JsonWebSignature2020`. |

### 7.2 Canonical JSON form

APH uses RFC 8785 (JSON Canonicalization Scheme, "JCS") to produce the byte sequence that is actually signed and verified.

The signing procedure is:

1. Construct the complete envelope JSON object with all fields populated EXCEPT `proof.proofValue`. The `proof` block MUST be present with all other proof fields populated; only `proofValue` is the placeholder.
2. Apply JCS canonicalization (RFC 8785) to the entire envelope, including the `proof` block (with empty `proofValue` or with `proofValue` absent — see implementation note).
3. Sign the canonical byte sequence using the algorithm pinned by `cryptosuite` (for `DataIntegrityProof`) or the JWS protected header `alg` (for `JsonWebSignature2020`).
4. Insert the resulting signature into `proof.proofValue` and emit the envelope.

The verification procedure is the inverse:

1. Parse the received envelope.
2. Take a working copy and set `proof.proofValue` to the empty string, leaving the rest of the `proof` block intact and the member present (§7.2.1). When verifying the principal proof of a chain, first discard every other proof, so the working copy carries the principal proof alone — as a one-element array, not as a bare object (§7.2.1).
3. Apply JCS canonicalization to the working copy.
4. Verify the original `proof.proofValue` against the canonical bytes using the public key resolved from `verificationMethod`.

**Implementation note.** This question is now settled normatively in §7.2.1: the signer sets `proofValue` to the **empty string** and does NOT remove the member. Earlier drafts left it implementation-dependent; they should not be followed, because JCS over an object with the member absent and JCS over the same object with the member empty produce different bytes, and two implementations that chose differently would never verify each other's signatures. Implementations SHOULD treat this as a fixable interop bug if it surfaces.

#### 7.2.1 Canonicalization base per proof (normative)

Ambiguity in a canonicalization base is how interoperability dies, so each
base is stated exactly:

These are W3C Data Integrity proof-chain semantics: **each proof covers the
document plus every proof that precedes it, and nothing that follows it.**
A base that included a later proof would be unconstructible — a signer cannot
sign bytes that do not exist yet.

- **Principal proof (first in the chain).** JCS-canonicalize the envelope
  with `proof` set to a **one-element ARRAY** holding that proof alone — the
  notary proof is NOT yet present — and its own `proofValue` set to the
  empty string `""`. A verifier reconstructs this base by discarding every
  proof except the principal's, keeping the array form, and emptying its
  `proofValue`.

  The array form is normative and load-bearing: `"proof": [{…}]` and
  `"proof": {…}` canonicalize to different bytes, which **domain-separates**
  a principal proof from a lone notary proof. Were the object form used
  here, an intermediary could strip the notary proof from a `PrincipalSigned`
  envelope and re-present the result as a valid single-proof envelope — the
  signature would still verify, and the recipient would read the human's own
  proof as a notary attestation. With the array form the stripped envelope is
  a one-element chain, which §7.1.11 rejects.
- **Notary proof (second in the chain).** JCS-canonicalize the envelope with
  `proof` as the two-element array, the principal proof's `proofValue`
  **present and complete**, and the notary proof's own `proofValue` set to
  `""`.
- **Lone notary proof (no chain).** JCS-canonicalize the envelope with that
  proof's `proofValue` set to `""`.
- **Mandates.** `principalSignature` covers the form minus **both**
  signature fields; `notarySignature` covers the form minus itself, with
  `principalSignature` present.

In every case the signer sets the field to the **empty string** rather than
removing the member. This settles the question earlier drafts left open, in
the direction the reference implementation has always taken. Removing a
proof from the *array* is different from emptying a member, and both rules
apply: the principal's base contains one proof object, not two with one
blanked.

**Issuance order follows from this, and is normative.** The principal signs
the envelope the notary has already prepared:

1. The Notary Service evaluates policy and **prepares the complete
   envelope**, including `credentialSubject.notarization` — the decision
   timestamp, the latency, its own identity.
2. The **principal signs** that envelope, producing the first proof. Its
   `created` MUST NOT precede `notarization.decisionTimestamp`.
3. The **notary countersigns**, producing the second proof over everything
   including the principal's. Its `created` MUST NOT precede the principal
   proof's.

A verifier SHOULD check that ordering and MUST NOT accept a chain whose
notary proof is dated before the principal proof it claims to have observed.
The order is not stylistic: reverse steps 1 and 2 and the principal would
have to sign notary-produced fields that do not exist yet, which is exactly
the circularity these bases are written to avoid.

### 7.3 Worked example

The following is a complete v0.1 Slack-reply envelope demonstrating a thread-reply notarization with an `AskEveryTime` decision and an Ed25519 Data Integrity Proof:

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

#### 7.3.1 Worked example — `PrincipalSigned`

The same send, in the mode where the **human's own key** signed the envelope.
Three things differ from §7.3: `policy.attestationMode` declares the mode,
`policy.delegationMandate` carries the parent grant so the human's signature
on it verifies without a fetch, and `proof` is a two-element chain linked by
`previousProof`.

Signature values below are placeholders — this example is illustrative, not a
test vector. Signed conformance vectors ship with the reference
implementation.

```json
{
  "aphVersion": "0.1",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/aph/v1"
  ],
  "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
  "id": "urn:uuid:00000000-0000-4000-8000-0000000000f3",
  "issuer": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
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
      "previewLines": 1,
      "preview": "prod rollout finished at 14:02 UTC"
    },
    "policy": {
      "decision": "AlwaysAllow",
      "matchedScope": "per-channel",
      "attestationMode": "PrincipalSigned",
      "delegationMandateId": "urn:uuid:00000000-0000-4000-8000-0000000000d1",
      "delegationMandate": {
        "id": "urn:uuid:00000000-0000-4000-8000-0000000000d1",
        "humanPrincipalDid": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
        "agentDid": "did:web:agent.squillo.com",
        "allowedChannels": ["slack"],
        "rateLimitPerHour": 20,
        "validFrom": "2026-05-20T00:00:00Z",
        "validUntil": "2026-05-22T00:00:00Z",
        "principalSignature": "z<multibase-signature-by-the-human-over-this-mandate>",
        "notarySignature": "z<multibase-countersignature-by-the-notary>"
      },
      "actChain": []
    },
    "notarization": {
      "notaryService": {
        "id": "did:web:notary.squillo.com",
        "name": "Squillo Notary Service",
        "version": "0.1.0"
      },
      "decisionTimestamp": "2026-05-21T00:00:00Z",
      "decisionLatencyMs": 12
    }
  },
  "linkedMandate": null,
  "proof": [
    {
      "id": "urn:uuid:00000000-0000-4000-8000-0000000000f1",
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "verificationMethod": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy#z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
      "created": "2026-05-21T00:00:01Z",
      "proofPurpose": "assertionMethod",
      "proofValue": "z<multibase-signature-by-the-HUMAN-over-the-principal-base>"
    },
    {
      "id": "urn:uuid:00000000-0000-4000-8000-0000000000f2",
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "verificationMethod": "did:web:notary.squillo.com#key-1",
      "created": "2026-05-21T00:00:02Z",
      "proofPurpose": "authentication",
      "previousProof": "urn:uuid:00000000-0000-4000-8000-0000000000f1",
      "proofValue": "z<multibase-countersignature-by-the-NOTARY-over-the-notary-base>"
    }
  ]
}
```

Read the two proofs as two different claims. The first says *"I, this human,
authorize this send"* — and because the principal is a `did:key`, a recipient
verifies it with no lookup, no publication, and no prior relationship with
anyone. The second says *"I, this notary, evaluated policy at this instant
and observed exactly that authorization"* — and because it covers the
complete principal proof, the notary cannot move the human's signature onto
a different envelope.

Note the `issuer` here is the **human**, not the notary. In `PrincipalSigned`
mode the human is the issuing authority in substance as well as in prose;
the notary is a witness.

The three timestamps ascend, and that is required rather than incidental
(§7.2.1): the notary decided at `:00`, the human signed the prepared
envelope at `:01`, and the notary countersigned what the human signed at
`:02`. Each signature covers only bytes that existed when it was made.

### 7.4 Per-channel recipient addressing shapes

The `channel.recipientAddressing` field is a JSON object whose exact shape is determined by `channel.kind`. v0.1 defines the following shapes:

- **`slack`** — `teamId`, `channelId`, optional `parentTs` (for thread replies), optional `userId` (for DMs).
- **`email`** — `to` (array of RFC 5322 addresses), optional `cc`, optional `bcc`, optional `inReplyTo` (Message-ID).
- **`discord`** — either `userId` (DM) or `channelId` (channel post).
- **`teams`** — `tenantId`, `teamId`, `channelId`.
- **`whatsapp`** — `phoneE164` (E.164-formatted phone number).
- **`google_chat`** — `spaceId`.
- **`imessage`** — either `appleId` or `phoneE164`.

Recipient endpoints SHOULD treat unknown `recipientAddressing` fields as opaque and MUST NOT fail verification on their presence (the strict-deserialization rule applies to the envelope-level fields, not to channel-shaped subordinate payloads).

### 7.5 Registered optional extensions

The envelope-level strict-deserialization rule (§7.1) rejects arbitrary unknown fields, so extensibility flows through a small set of REGISTERED extension fields: OPTIONAL, omitted-when-absent fields whose names and wire shapes are pinned by this section. Producers MAY emit them. Verifiers MUST accept envelopes carrying them and MUST NOT fail verification on their presence; a verifier that does not implement an extension's semantics treats its payload as opaque (but still signature-covered — extension fields participate in canonicalization like any other field, §7.2). An envelope carrying no extension fields is byte-identical to a pre-extension envelope, so extension-unaware fixtures and signatures remain valid.

Extensions are vendor-originated but protocol-registered: each entry records its origin. Promoting an extension to a core field, or retiring one, is a minor-version event (Appendix A).

v0.1 registers three extensions.

#### 7.1.12 `ActClassification`

What the sender says this act MEANS, in terms of one or more vocabularies both parties can resolve independently (§8.5). Optional: an envelope making no such claim omits the field entirely and is byte-identical to one written before the field existed, so every signature over those bytes stays valid.

| Field | Type | Required | Description |
|---|---|---|---|
| `vocabularies` | array of object | yes | Every vocabulary the verdict depended on, in fold order — non-empty, because labels resolve against the vocabularies that define them. An empty array is a strict-parse rejection: an envelope making no claim omits `actClassification` entirely, and an object present but citing nothing is malformed rather than minimal. See below. |
| `labels` | array of string | yes | The family-qualified labels this act carries, each written `FAMILY/LABEL`. |

Each entry of `vocabularies`:

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | The vocabulary's name, as its published bundle declares it. |
| `version` | string | yes | The version, as its published bundle declares it. |
| `digest` | string | yes | The bundle's integrity digest, VERBATIM — the same `sha256-…` string the bundle carries, never a re-encoding of it. |

**Both members are arrays, for different reasons, and neither is arbitrary.** `labels` because one act carries verdicts from several families at once — what kind of act it is, how reversible, how wide its blast radius — and carrying one would discard the verdicts a recipient's policy most wants. `vocabularies` because an OVERLAY is a separate published artifact with its own digest: a classifier that ran against a base and a tightening overlay was produced by two artifacts, and naming only one would put a false statement inside a signature.

**A label MUST be family-qualified.** A bare `ACCESS_GRANT` names nothing — the family is what scopes it, and two vocabularies may both define the same bare word. An unqualified label is a strict-parse rejection under §7.1's rule, at §8.3 step 1.

**The digest is what makes the reference checkable.** Without it a citation points at whatever the publisher serves today, and a publisher — or anyone who compromises their origin — could change what a signed envelope meant after it was signed. A recipient that resolves the vocabulary MUST refuse it when the fetched bytes do not match the digest: absent and corrupt are not the same event.

**⚠ Emitting this field is version-gated, and the rule is load-bearing rather than courtesy.** §7.1's parse is strict: a verifier built before this field existed does not ignore it — it fails at strict parse, BELOW the protocol's own error vocabulary, so the failure is not even reportable as an APH error code. A producer MUST NOT emit `actClassification` until it has reason to believe the recipient understands it. The AgentCard extension declaration (§10.1) is the existing discovery mechanism for forming that belief.

**What a recipient does with it.** A recipient that recognizes the vocabulary and the labels MAY apply policy to them. A recipient that does not MUST treat the envelope exactly as it would have without the field: the classification is additional information, never a precondition, and its absence never changes a verdict.

**What this proves, and what it does not.** It proves WHICH VOCABULARY THE SENDER CITED, inside the signature. It does NOT prove the sender classified correctly — a sender can label a funds transfer as a scheduling proposal and sign it. What the binding buys is that a DISAGREEMENT becomes visible where a MISUNDERSTANDING was invisible: two parties now mean the same thing by a word, and a recipient can check the claim against the payload it accompanies. Implementations MUST NOT present it as integrity of classification.

#### 7.5.1 `credentialSubject.appleAurAcceptance` (object, omitted when absent)

Origin: Apple on-device foundation-model integration (vendor extension). Attests that the human principal accepted Apple's Acceptable Use Requirements (AUR) on the notarizing device before the agent produced this communication with an on-device model.

| Field | Type | Required | Description |
|---|---|---|---|
| `userId` | string | yes | User-scoped DID for whom acceptance was recorded. |
| `deviceId` | string | yes | Device-scoped opaque identifier; acceptance is recorded per `(userId, deviceId)` pair. |
| `aurVersionHash` | string | yes | SHA-256 hex of the accepted AUR snapshot text. |
| `acceptedAt` | string | yes | RFC 3339 acceptance timestamp. |
| `documentKind` | string | yes | `"foundation_models_framework_aur"`; discriminator kept open for future legal documents. |

#### 7.5.2 `linkedMandate.ap2SignedPayloadB64` (string or null)

Origin: AP2 cross-linking (§10.2). Base64 of an AP2-signed payload for commerce-impacting actions, so send-consent (APH) and payment authorization (AP2) travel together while remaining separately signed. Producers emitting a `linkedMandate` object MAY include it; verifiers MUST tolerate `null`.

#### 7.5.3 `linkedMandate.vaultMutation` (object, omitted when absent)

Origin: cross-vault permission federation (vendor extension). Binds the envelope to a vault-mutation mandate when the notarized action changes vault state.

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | object | yes | Internally tagged discriminator object: `{"kind": "<variant>", ...variant fields}` where `<variant>` is one of `WriteInto` (`dest_vault_id`), `ShareFrom` (`src_vault_id`), `CrossVaultPromote` (`artifact_id`), `Redelegate` (`downstream_grantee_id`), `Revoke` (no fields), `BridgeStageTransition` (`from_stage`, `to_stage`), `Custom` (`snapp_id`, `mutation_slug`). |
| `grant_scope_id` | string | yes | Identifier of the grant scope the mutation executes under. |
| `ap2_signed_payload_b64` | string | no | Omitted when absent. AP2-signed payload for commerce-impacting mutations. |

Interior key-casing note: the `vaultMutation` object's interior keys are `snake_case` (`grant_scope_id`, `dest_vault_id`, …), not the envelope's `camelCase`. This mirrors the originating implementation byte-for-byte and is pinned deliberately: re-canonicalizing an already-signed envelope MUST NOT change its bytes.

---

#### 7.1.13 `Audience`

Who may accept this envelope (RFC 0003). OPTIONAL, omitted when absent: an
envelope without it is byte-identical to one written before the field
existed, every signature over those bytes stays valid, and absence is the
producer's DECISION to issue a bearer credential — available as an explicit
choice rather than as the silent default, which was the defect.

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string (DID) | yes | The DID of the endpoint entitled to accept this envelope. §8.3 step 5a compares it against the verifier's own identity and refuses on difference (`APH_E017`). |
| `channelBinding` | object | no | Restates the delivery coordinates the envelope authorizes, so an envelope addressed to one channel cannot be spent on another. `kind` is REQUIRED within it and drawn from the closed set (§7.1.5); every other member is channel-shaped coordinate data, compared member-by-member against the act's coordinates. A member the act's coordinates lack is a mismatch — a constraint that cannot be checked is refused, not skipped. |

```json
"audience": {
  "id": "did:web:ssot.example.com",
  "channelBinding": { "kind": "slack", "teamId": "T01234567", "channelId": "C01234567" }
}
```

The check this feeds is a COMPARISON, not cryptography: it binds acceptance
to a named party, and what that buys is that a captured envelope — from a
message archive, a relay hop, a debug log — stops being a reusable
authorization against ANY recipient. What it does not buy is anything about
the one recipient it names, and an envelope with no `audience` remains a
bearer credential in every hand that holds it.

**⚠ Emitting this field is version-gated** for the same structural reason as
`actClassification` (§7.1.12): §7.1's parse is strict, so a verifier built
before this field existed fails an envelope carrying it at STRICT PARSE,
below the protocol's own error vocabulary. A producer MUST NOT emit
`audience` until it has reason to believe the recipient understands it; the
AgentCard extension declaration (§10.1) is the existing mechanism for
forming that belief.

## 8. Signing + Verification

### 8.1 Supported algorithms

APH v0.1 implementations MUST support BOTH of the following signing algorithms for the envelope `proof` block:

- **`ES256`** — ECDSA over the P-256 curve with SHA-256, as defined in RFC 7518. This algorithm is REQUIRED for AP2 interop and SHOULD be used when the human principal's key material is held in a curve-P-256 device key store.
- **`EdDSA`** — Edwards-curve Digital Signature Algorithm over Ed25519, as defined in RFC 8032. This algorithm is REQUIRED for compatibility with Ed25519 device-key fleets and is RECOMMENDED as the default for v0.1.

Verifiers:

- MUST accept both `ES256` and `EdDSA`.
- MUST reject `alg: none` and any envelope omitting an algorithm declaration.
- SHOULD reject any algorithm not in the supported set; implementations MAY include vendor-specific algorithms behind explicit opt-in but MUST NOT do so in default conformant mode.

The algorithm identifier is carried either in the `EnvelopeProof.cryptosuite` field (for `DataIntegrityProof`, where `eddsa-jcs-2022` implies EdDSA and `ecdsa-jcs-2019` implies ES256) or in the JWS protected header `alg` field (for `JsonWebSignature2020`).

### 8.2 Proof block formats

APH v0.1 accepts two `proof` block formats:

**Data Integrity Proof.** Preferred for envelopes intended for archival and full-fidelity recipient-side verification. Uses W3C Verifiable Credential Data Integrity with one of:

- `cryptosuite: "eddsa-jcs-2022"` for Ed25519 signatures, OR
- `cryptosuite: "ecdsa-jcs-2019"` for ES256 signatures.

JCS canonicalization (RFC 8785) is applied to the envelope minus `proof.proofValue` before signing. The signature bytes are multibase-encoded (base58btc) and placed in `proof.proofValue`.

**JsonWebSignature2020 (detached JWS).** Preferred for on-wire short-form carriage on channels with limited metadata capacity (email headers, chat block metadata fields). Uses RFC 7515 §A.5 detached JWS over the JCS-canonicalized envelope with `proof.proofValue` set to the empty string — the §7.2.1 base, identical to the Data Integrity case. "Minus" is not "empty": earlier drafts said minus, and an implementation that removed the member would produce bytes no conformant verifier reproduces. The JWS protected header MUST include:

- `alg`: `"ES256"` or `"EdDSA"`.
- `kid`: the verification method DID URL.
- `typ`: `"aph+jws"`.
- `cty`: `"vc+ld+json"`.
- `b64`: `false`.
- `crit`: `["b64"]`.

The compact JWS form (header.signature, with empty payload) is placed in `proof.proofValue`.

### 8.3 Verification steps

A Recipient Endpoint MUST execute the following verification steps before accepting the message:

1. **Parse the envelope.** Reject if any REQUIRED field is missing or if the parser encounters an unknown field at the envelope level (forward-compatibility behavior: fail fast on spec drift). Per-channel `recipientAddressing` sub-fields are opaque and not subject to strict deserialization.
2. **Resolve the verification method.** Use the DID URL in `proof.verificationMethod` to obtain the notary public key. The resolver MUST support at least one of the publication mechanisms defined in §8.4 (`did:key` offline decode, `did:web` `.well-known/did.json`, or DNS TXT). Production verifiers SHOULD support all three. See §8.4 for the full resolution flow, key rotation rules, and trust models.
3. **Build the base for THIS proof (§7.2.1).** Take a working copy of the envelope and set the proof's own `proofValue` to the empty string — do NOT remove the member. For a lone notary proof that is the whole rule. In a chain: for the **principal** proof, discard the notary proof so `proof` is a ONE-ELEMENT ARRAY holding the principal's alone (§7.2.1 — the array form is normative; collapsing it to an object changes the bytes); for the **notary** proof, keep both with the principal's `proofValue` complete. Never include a proof that comes *after* the one being verified — it did not exist when that signature was made.
4. **Canonicalize.** Apply JCS (RFC 8785) to the working copy.
5. **Verify the signature.** Validate `proof.proofValue` against the canonical bytes using the public key from step 2 and the algorithm pinned by `proof.cryptosuite` or the JWS protected header `alg`.

   5a. **Audience check (RFC 0003).** When `credentialSubject.audience` is present, the verifier MUST compare `audience.id` against its own identity and MUST reject with `APH_E017` when they differ. When `audience.channelBinding` is present, the verifier MUST additionally compare each member it names — `kind` included — against the delivery coordinates of the act it is being asked to perform, and MUST reject on any mismatch, a member those coordinates lack included. A verifier that cannot determine its own identity, or the act's coordinates while a `channelBinding` is present, MUST reject rather than skip the step: a check a verifier may skip when inconvenient is not a check. An envelope with no `audience` member skips this step — absence is the producer's decision to issue a bearer credential (§7.1.13). Sub-numbered per this section's idiom (see step 8a's note).
6. **Validate the time window.** Confirm `validFrom <= now <= validUntil` where `now` is the verifier's current wall clock. Allow a small clock-skew tolerance (RECOMMENDED: 60 seconds). Failure — either side, or an unparseable timestamp, which fails closed — is `APH_E019`, the envelope's OWN window judged against the verifier's clock; `APH_E003` remains a *mandate* consulted past its expiry, and the two were conflated in practice until this code existed.
7. **Validate the algorithm.** Confirm the algorithm is in the supported set (`ES256` or `EdDSA`). Reject `alg: none`. Reject any vendor-specific algorithm not explicitly opted into.
8. **Validate the body hash (conditional MUST).** When the recipient has the actual outbound body bytes — the channel transport delivered both the envelope and the payload — it MUST compute SHA-256 over the body, compare against `credentialSubject.communication.bodySha256`, and reject on mismatch with `APH_E009`. When the body is NOT available to the verifier (a metadata-only relay, a stored envelope inspected after the payload was consumed), the step is SKIPPED AND RECORDED: the verifier notes that body binding was not checked, and MUST NOT report or imply that the payload was verified against its hash. A skip silently folded into a pass would let a metadata-only hop launder an unverified body as a verified one, which is the confusion this step exists to prevent. *(Revised from RECOMMENDED on an implementer report: an unconditional-looking recommendation was being read as "optional even when the bytes are in hand", which is the one case it must never be.)*

   8a. **Validate revocation status (§6.3.3).** If the envelope carries `credentialStatus`, derive the status endpoint from the notary's `did:web` (§6.3.3.2), bind any carried `statusListCredential` same-origin against it, obtain and verify the status list credential, and reject the envelope if the bit at `statusListIndex` is set (`APH_E015`) or if status could not be established at all (`APH_E008`). If the envelope carries no `credentialStatus`, skip this step (§6.3.3.4 case 1). Placed after the local checks deliberately: this is the only step that may cost a network round-trip, so every cheap reason to reject has already been taken. Numbered `8a` rather than renumbered into the list because §8.3.1 references steps 9 and 10 by number, and the sub-numbered insertion is this section's own idiom for adding a step without moving them.

   8b. **Single-use (RFC 0003).** The envelope is spent by acceptance: the verifier MUST record `id` at the moment it commits to the act — acceptance in the RFC 5321 §6.1 sense — and MUST reject any later presentation of the same `id` with `APH_E018`. Recording at the commit moment, not before, means a crash between check and act cannot spend the envelope twice, and a verifier that rejects for any OTHER reason has not consumed it. The record MUST be retained at least until the envelope's `validUntil` has passed and MAY be discarded thereafter, because step 6 already refuses the envelope from then on — retention is bounded by the longest window a verifier accepts, which is one more reason windows are minutes (§6.3). Where the record lives is deliberately unspecified: a single process may use a set, a cluster needs shared state, a notary MAY offer a burn endpoint. The obligation is per-verifier — two independent verifiers each accept once, because strangers share no state — which is exactly the gap the audience check (step 5a) closes, and why neither mechanism is sufficient alone.

9. **Emit the verified credential.** If all checks pass, the recipient MAY render a "Notarized" badge in its UI, store the verified credential for audit, and accept the message.

If any step fails, the verifier MUST reject the envelope and SHOULD emit the appropriate error code from §11.

#### 8.3.1 Verifying a proof chain

Insert after step 1 (strict parse):

1a. **Read `attestationMode`** (§7.1.7; absent means `NotaryAttested`). A
    verifier whose policy requires `PrincipalSigned` MUST refuse any other
    value **now** with `APH_E012`, rather than discovering the weakness
    after doing work.
    There is no silent downgrade from a stronger attestation to a weaker
    one, for the same reason §8.4.6 forbids downgrading key discovery: an
    attacker who can defeat the weak path will always present the weak path.
    The label is **not** evidence on its own: confirm it matches the proof
    structure per §7.1.11 and reject a mismatch with `APH_E013` — a notary
    key alone can write `PrincipalSigned` above a single notary proof.

Steps 1b, 1c and 1e apply ONLY when the envelope is `PrincipalSigned`
(equivalently: when `proof` is an array). A `NotaryAttested` envelope has no
principal proof and no chain, so it skips to 1d.

1b. **Resolve the principal's key.** For a `did:key` principal, decode it
    from the identifier — offline, no network (§8.4.3). Otherwise resolve
    per §8.4.

1c. **Verify the principal proof** over the §7.2.1 principal base — the
    envelope with the notary proof discarded and the principal's own
    `proofValue` emptied. Its `verificationMethod` MUST resolve to
    `credentialSubject.humanPrincipal.id`; a proof made by any other key is
    not the principal's proof, whatever its `proofPurpose` says. Failure is
    `APH_E011`. A verifier MUST NOT proceed to the notary proof on failure:
    a countersignature cannot rescue an unauthorized envelope.

1d. **If `NotaryAttested` and a `delegationMandate` is embedded**, verify its
    `principalSignature` (failure is `APH_E011`) and confirm this envelope
    falls within the granted scope and window (§7.1.7.1) — the mandate's
    `humanPrincipalDid` MUST equal `credentialSubject.humanPrincipal.id`,
    its `agentDid` MUST equal `credentialSubject.agent.id`, the envelope's
    channel MUST be in `allowedChannels` (else `APH_E005`), when the mandate
    carries `allowedRecipientClasses` the envelope's `channel.recipientClass`
    MUST be present and in that set (else `APH_E020` — declared-outside and
    declared-nothing both refuse, and the code is distinct from `APH_E005`
    because the MEDIUM being out of scope and the CONSUMER being out of scope
    are different repairs), and the
    envelope's window MUST fall inside the mandate's (else `APH_E003`).
    Without those bindings an attacker could staple any validly-signed
    mandate to any envelope. Absent an embedded mandate, the human's
    authorization is **not verifiable** by this recipient, and the recipient
    SHOULD treat the credential as the notary's assertion alone.

1e. **Check the chain linkage.** The notary proof's `previousProof` MUST
    equal the principal proof's `id` (§7.1.11). Position in the array is a
    hint; `previousProof` is the binding. Reject a chain whose linkage is
    missing, dangling, or cyclic with `APH_E013`.

Steps 2 through 9 then proceed for the **notary proof**, unchanged.

Add after step 9:

10. **Attestation policy (OPTIONAL).** A verifier MAY require that the notary
    advertise a code attestation valid under §15 and refuse otherwise. This
    is policy, not protocol: a verifier that does not check it remains
    conformant.

### 8.4 Notary Key Material + Public-Key Discovery

A Notary Service operates on a public/private keypair. The PRIVATE key MUST be held under the Notary Service operator's exclusive control and is used to sign the NOTARY's proof on every envelope it notarizes — the single `proof` of a `NotaryAttested` envelope, or the second, countersigning proof of a `PrincipalSigned` chain — and the `notarySignature` field of any Delegation or Communication Mandate the notary mints. It never produces a `principalSignature` or a principal proof; those come from the human's key alone. The PUBLIC key MUST be discoverable by ANY third-party verifier WITHOUT a prior trust relationship with the Notary Service or its operator.

Public-key discoverability is the property that makes APH function as a notarization protocol rather than as a closed signing system. A recipient that has never previously transacted with the notary MUST be able to resolve the public key, verify the signature, and accept the credential — analogous to how a TLS client can verify a server certificate against a publicly-anchored chain of trust without contacting the server's operator out-of-band.

This section defines the publication mechanisms a Notary Service MUST and MAY support, the record formats those mechanisms use, and the resolution flow a verifier follows to obtain a notary public key.

#### 8.4.1 Public/Private key separation

The Notary Service operator's responsibilities are:

- Generate a long-lived Ed25519 or P-256 keypair using a secure RNG and standard parameters (RFC 8032 for Ed25519, NIST FIPS 186-4 for P-256).
- Store the PRIVATE key in hardware (HSM) where available, or in operating-system-protected key storage (Keychain, TPM, Secure Enclave) otherwise. The PRIVATE key MUST NOT leave the controlled boundary except to produce a signature.
- Publish the PUBLIC key via at least one of the mechanisms in §8.4.2.
- Periodically rotate the keypair per §8.4.7 and overlap publication windows so verifiers see a continuous valid set.

The public key is encoded according to the binding DID method or publication mechanism:

- For `did:key`, the public key bytes are embedded directly in the DID identifier (multicodec + multibase per the `did:key` method specification). No external lookup is required.
- For `did:web`, the public key appears in the `verificationMethod` array of the DID Document resolved at the well-known URI.
- For DNS TXT publication, the public key is encoded as a base64url-encoded string in the TXT record value (see §8.4.5).

#### 8.4.2 Publication mechanisms — overview

APH v0.1 defines THREE publication mechanisms, in increasing order of operational complexity. A conformant Notary Service MUST support at least one; production-grade deployments SHOULD support at least two of the three for defense in depth.

| Mechanism | Anchor | Verifier action | When to use |
|---|---|---|---|
| `did:key` (§8.4.3) | Self-describing — key bytes embedded in DID | Decode in-process, no I/O | Self-issued or pinned-key notaries; air-gapped verification |
| `did:web` (§8.4.4) | HTTPS — `.well-known/did.json` at the notary's web origin | HTTPS GET, parse JSON, locate `verificationMethod[i]` matching the DID URL fragment | Mainstream production notaries with a public web origin |
| DNS TXT (§8.4.5) | DNS — TXT record at `_aph._notary.<domain>` | DNS query, parse tag-list | Defense-in-depth alongside `did:web`; survives website outages; independent of HTTPS origin |

#### 8.4.3 `did:key` — self-describing

A notary with DID `did:key:z6Mk...` carries its own public key bytes in the DID identifier itself. No external lookup is required.

Verifier action:

1. Parse the DID URL from `proof.verificationMethod`. Example: `did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV`.
2. Decode the multibase-encoded suffix (`z6Mk...`) to recover the multicodec + raw public key bytes. The multicodec prefix `0xed01` indicates Ed25519; `0x1200` indicates P-256 (per the multicodec registry).
3. Use the raw public key bytes to verify the signature with the algorithm pinned in `proof.cryptosuite` or the JWS protected header `alg`.

Trust model: The verifier trusts whatever produced the DID URL in `proof.verificationMethod`. There is no out-of-band check that the notary "owns" this `did:key`; possession of the private key is the only proof. `did:key` is RECOMMENDED for self-issued notaries (e.g., an individual operator running a personal notary service) and for air-gapped recipient environments. It is NOT RECOMMENDED as the sole anchor for production multi-tenant notaries; pair with §8.4.4 or §8.4.5.

#### 8.4.4 `did:web` — HTTPS well-known DID Document

A notary with DID `did:web:notary.example.com` publishes a DID Document at:

```
https://notary.example.com/.well-known/did.json
```

The DID Document contains the notary's `verificationMethod` array, each entry binding a key id (the DID URL fragment) to a public key encoded in `publicKeyMultibase` or `publicKeyJwk` form. Example:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:notary.example.com",
  "verificationMethod": [
    {
      "id": "did:web:notary.example.com#k1",
      "type": "Multikey",
      "controller": "did:web:notary.example.com",
      "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"
    }
  ],
  "assertionMethod": ["did:web:notary.example.com#k1"]
}
```

Verifier action:

1. Parse the DID URL from `proof.verificationMethod`. Extract the DID-method-specific identifier (the part after `did:web:`) and the fragment (the part after `#`).
2. Construct the well-known URL by percent-decoding the identifier and prefixing `https://` and suffixing `/.well-known/did.json`. Per the `did:web` method, colons in the identifier map to path segments.
3. Fetch the URL over TLS. The TLS certificate MUST validate against the verifier's trust store; certificate failure is a fatal verification error.
4. Parse the JSON DID Document.
5. Locate the `verificationMethod` entry whose `id` matches the full DID URL from step 1.
6. Decode the `publicKeyMultibase` (or `publicKeyJwk`) field to recover the raw public key bytes.
7. Use the raw public key bytes to verify the signature.

Trust model: The verifier trusts the TLS certificate authority chain that validated the notary's web origin. This anchors notary identity to domain ownership — the same trust property that backs TLS, OAuth issuer URLs, and BIMI logo publication.

#### 8.4.5 DNS TXT — DKIM-style publication

A notary MAY publish its public key in a DNS TXT record at a well-known sub-name. This mechanism is analogous to DKIM (RFC 6376) and provides:

- **Domain-level chain of custody** anchored in DNS (and, where deployed, DNSSEC).
- **Survival when the website is down** — DNS resolution does not depend on the notary's HTTP origin being reachable.
- **Independent verifiability** for recipients that do not (or cannot) speak HTTPS to the notary's origin (e.g., constrained gateways, edge appliances).

TXT record name: `_aph._notary.<domain>` where `<domain>` is the registrable domain of the notary's `did:web` identifier (or, for notaries without a `did:web`, the domain operationally controlled by the notary operator).

TXT record value: a tag-list of semicolon-separated `key=value` pairs. The tag-list format is intentionally aligned with DKIM (RFC 6376 §3.6.1) for operator familiarity.

Required tags:

- `v` — protocol version literal `APHv1`.
- `alg` — signing algorithm. One of `ed25519` or `p256`.
- `k` — public key bytes, base64url-encoded (RFC 7515 §2; no padding).

Optional tags:

- `did` — the full DID URL this key entry is bound to (e.g., `did:web:notary.example.com#k1`). When present, it ties the DNS-published key to a specific DID Document entry.
- `notBefore` — RFC 3339 timestamp before which this key MUST NOT be considered valid. Verifiers MUST reject if `now < notBefore`.
- `notAfter` — RFC 3339 timestamp after which this key MUST NOT be considered valid. Verifiers MUST reject if `now > notAfter`.
- `kid` — opaque key identifier matching the fragment of `proof.verificationMethod`. When present, allows a single DNS name to disambiguate multiple keys.

Example TXT record (single key):

```
_aph._notary.notary.example.com.  IN  TXT  "v=APHv1; alg=ed25519; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw"
```

Example TXT record (key with rotation window):

```
_aph._notary.notary.example.com.  IN  TXT  "v=APHv1; alg=ed25519; kid=k1; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw; notBefore=2026-05-21T00:00:00Z; notAfter=2027-05-21T00:00:00Z"
```

Multiple keys MAY coexist as multiple TXT records at the same name (one record per active key). Verifiers MUST iterate all returned TXT records and select the one whose `kid` matches the DID URL fragment from `proof.verificationMethod`, then validate `notBefore <= now <= notAfter` if present, then attempt signature verification.

Verifier action:

1. Parse the DID URL from `proof.verificationMethod`. Extract the registrable domain. For `did:web`, this is the identifier; for `did:key`, this discovery path is not applicable — use §8.4.3.
2. Query the authoritative DNS for the TXT record(s) at `_aph._notary.<domain>`. Where DNSSEC is deployed, the resolver MUST validate the DNSSEC chain; DNSSEC failure SHOULD raise a verification warning but is NOT a fatal error for v0.1 (a stricter profile is deferred to v0.2).
3. For each returned TXT record:
   a. Parse the tag-list. Reject records with missing required tags or with `v` other than `APHv1`.
   b. If `kid` is present and the DID URL has a fragment, accept only the record whose `kid` matches the fragment.
   c. Validate `notBefore <= now <= notAfter` if both are present.
   d. Decode `k` (base64url) into raw public key bytes.
   e. Attempt signature verification using the algorithm pinned by `alg` and the recovered key bytes.
4. If verification succeeds against any record, accept the envelope. If all records fail, the envelope is rejected.

Trust model: The verifier trusts the DNS resolution chain and, where deployed, DNSSEC. The notary operator anchors notary identity to domain ownership in the same way DKIM anchors email signing keys to sending-domain ownership.

#### 8.4.6 Verifier resolution order

When multiple publication mechanisms are present on a single envelope, verifiers SHOULD attempt resolution in the following order:

1. **`did:key` (offline)** — if `proof.verificationMethod` is a `did:key` URL, decode in-process and skip all network I/O.
2. **DNS TXT (§8.4.5)** — if the DID method permits and the operator has published a TXT record, query DNS. This is faster than HTTPS in many environments and survives HTTP-origin outages.
3. **`did:web` HTTPS (§8.4.4)** — if `did:web`, fetch `.well-known/did.json` as the final fallback.

A verifier MAY pin a preferred mechanism per notary (typically via configuration or via prior successful resolution).

**Absence is not failure, and the distinction is normative.** An ordered list and a no-downgrade rule only coexist if a verifier can tell the two apart:

- **Not published** — no TXT record exists at `_aph._notary.<domain>`, or no `did.json` is served. That mechanism is simply not offered, and the verifier advances to the next one in the list. When absence is *terminal* — the last mechanism in the sequence, or a pinned mechanism with no successor — the error is `APH_E014` (§11), never `APH_E008`.
- **Published and failed** — the lookup errored, the record is malformed, the signature does not verify, the key is outside its validity window, or the algorithm is unsupported. The verifier **MUST reject the envelope** rather than advance, surfacing the failure's own code (`APH_E008` unreachable, `APH_E003` window, `APH_E010` algorithm, …).

The second rule is what makes the ordering safe. Without it, an attacker who can make a stronger mechanism *fail* — a DNS outage they cause, a record they corrupt — thereby chooses which anchor the verifier trusts, and choosing the anchor is an identity decision rather than a reachability one. **A verifier MUST NOT silently fall back from a stronger anchor to a weaker one after a failure; failures escalate to envelope rejection.**

Implementations whose resolution interface cannot distinguish absence from failure MUST document that limitation, because on such an interface the ordering above is a preference and not a control.

#### 8.4.7 Key rotation + overlap

Notary Service operators rotating a key MUST:

1. Publish the NEW key alongside the OLD key (multiple TXT records OR multiple `verificationMethod` entries in the DID Document) for a minimum overlap window. RECOMMENDED minimum overlap: 30 days.
2. Continue signing envelopes with the OLD key during the overlap window; do NOT switch the active signing key on day zero.
3. After the overlap window, switch the active signing key to the NEW key and set the OLD key's `notAfter` to a timestamp inside the overlap window.
4. Keep the OLD key's record visible (with a past `notAfter`) for a further window (RECOMMENDED 1 year) so verifiers checking older envelopes can still resolve the historical key.

Verifiers MUST consult the `notBefore`/`notAfter` window of the TXT record (or, for DID Documents, the per-`verificationMethod` validity metadata if present) and accept any envelope where the signing key was valid at the envelope's `decisionTimestamp`.

**Expressing the overlap on the `did:web` mechanism.** Steps 3 and 4 above are written in the dated form that only the DNS TXT mechanism carries: `notBefore` and `notAfter` are §8.4.5 tags. The §8.4.4 DID Document schema defines no per-key validity metadata, and this specification deliberately does NOT add any — the document stays a plain DID Document that any conformant `did:web` resolver can read. On `did:web`, therefore, rotation overlap is **presence-based**:

- **The overlap window IS both keys appearing in one document.** The operator adds the NEW key as a second `verificationMethod` entry alongside the OLD one, and both remain resolvable for the whole overlap window. The RECOMMENDED 30-day minimum of step 1 is unchanged.
- **Retirement IS removal.** After the overlap window the operator REMOVES the OLD `verificationMethod` entry from the document. Step 3's `notAfter` and step 4's further-visibility window have no `did:web` expression; an operator who wants step 4's historical-resolution property MUST also publish DNS TXT, which is where the dated form lives.
- **An identity publishing ONLY `did:web` rotates by add-then-remove.** This is the ordinary case for an operator serving a document from a host whose DNS zone they do not control (a subdomain on a shared platform, say), who therefore cannot publish any record at `_aph._notary.<domain>`. Such an operator is conformant: steps 3 and 4 bind only where the mechanism can express them.

Consequences for verifiers. The `notBefore`/`notAfter` check stated above applies to whatever mechanism actually published validity metadata; a `did:web` key that publishes none is valid exactly while it is present in the document, and its absence from the document is absence in the §8.4.6 sense, not failure. Because presence is the only signal, a verifier pinning a key under §8.4.8 MUST re-pin during the overlap window: once the OLD entry is removed it is unresolvable, and an envelope signed under it before removal can no longer be checked against the published document.

#### 8.4.8 Trust-on-first-use + pinning

Recipient applications that store a notary's resolved public key after the first successful verification MAY pin the key locally and prefer the pinned copy on subsequent verifications. Pinning is OPTIONAL in v0.1 and is RECOMMENDED for high-stakes verifiers (e.g., compliance-recording systems) that want to detect notary-key compromise via mismatch with the pinned copy.

When pinned-vs-published mismatch occurs, verifiers SHOULD raise a warning, SHOULD validate the envelope against BOTH the pinned key and the currently-published key, and MUST treat mismatch with both as a fatal verification failure.

### 8.5 Vocabulary publication (normative)

§8.4 resolves a notary's KEY from a party with no prior relationship. Publishing a vocabulary is the same problem with a different payload — so it takes the same shape rather than a second discovery story with its own failure modes.

#### 8.5.1 The DNS TXT record

TXT record name: `_aph._vocab.<domain>`, where `<domain>` is the registrable domain of the publisher.

Required tags, in this order, separated by `"; "`:

| Tag | Value |
|---|---|
| `v` | `APHv1`, as §8.4.5 |
| `n` | the vocabulary's name, as its bundle declares it |
| `ver` | the vocabulary's version, as its bundle declares it |
| `h` | the bundle's integrity digest, VERBATIM |

```
_aph._vocab.example.com.  IN  TXT  "v=APHv1; n=aph_guardrails; ver=0.1.0-alpha.1; h=sha256-y6E/EGldCz2ogpVB7wlnS5orbnAjcCpoUBaDietJmXA="
```

A publisher serving several vocabularies publishes several TXT records at the one name. A resolver selects on `n` and `ver` together, and **MUST refuse rather than guess** when two records claim the same `n`+`ver` pair with different digests: ambiguity about which bytes a name refers to is corruption, not a coin flip.

A record MUST fit a single 255-byte character-string. A digest split across strings would need a concatenation rule, and a concatenation rule nobody implements identically is an interop bug waiting for its first stranger.

#### 8.5.2 What this surface does NOT provide

Stated because the omission is easy to miss and expensive to assume.

**DNS is not append-only.** A publisher can change the record, and a resolver sees only what it is served. This surface answers *what digest does this publisher name TODAY* — it is not a history, it does not establish what the publisher said last week, and it does not prevent a publisher showing one digest to one party and a different digest to another. Implementations MUST NOT describe it as providing either property.

**The failure mode is benign, which is why an unauthenticated lookup is acceptable here at all.** A spoofed or stale record yields a digest that does not match the bytes it names, and those bytes are then refused. The worst outcome is denial, never substitution: an attacker who controls the DNS answer can stop a verifier resolving a vocabulary, and cannot make it accept a different one. That asymmetry holds only because the digest carries the integrity, which is why the digest is required and this record is not.

#### 8.5.3 Resolution posture

A verifier that cannot resolve a vocabulary treats its labels as unrecognized and proceeds under §7.1.12 — absence advances. A verifier that resolves a vocabulary whose bytes do not match the cited digest MUST refuse the classification: absent and corrupt are not the same event, the same distinction §8.4.6 draws for keys and §6.3.3.4 draws for status.

**Resolution SHOULD happen out of band, on a cadence, rather than on receipt of an envelope.** A fetch triggered by inbound traffic is an outbound request made by a verifier while it verifies, and it carries every hazard that implies: server-side request forgery against internal addresses, a slow origin becoming a denial of service on the verify path, and a publisher learning when traffic classified against its vocabulary arrives. A digest-pinned cache has none of these. Implementations that do fetch MUST apply the same outbound controls §6.3.3 requires for status-list retrieval, and MUST NOT open a second, laxer path.

---

## 9. Flow State Machines

APH defines two flow state machines corresponding to the two notarization paths. The "human-present" flow applies when the human principal is at the device and an `AskEveryTime` decision can prompt them interactively. The "human-not-present" flow applies when the human is not reachable and a standing Delegation Mandate is consulted instead.

### 9.1 Human-present flow

The human-present notarization flow has seven states (six progress states and one terminal-denial state).

States:

- **`Drafted`** — Agent has prepared a message and submitted a notarization request.
- **`PendingDecision`** — Notary Service has displayed the approval prompt to the human.
- **`Approved`** — Human approved (matched an `AlwaysAllow` rule OR positively responded to an `AskEveryTime` prompt).
- **`MandateIssued`** — Notary Service issued the Communication Mandate.
- **`EnvelopeIssued`** — Notary Service signed and emitted the Notarization Envelope.
- **`Delivered`** — Terminal: envelope handed to Channel Adapter and accepted for transport.
- **`Denied`** — Terminal: human denied the prompt OR matched a `NeverAllow` rule.

Allowed transitions:

```
Drafted ---> PendingDecision
PendingDecision ---> Approved
PendingDecision ---> Denied
Approved ---> MandateIssued
MandateIssued ---> EnvelopeIssued
EnvelopeIssued ---> Delivered
```

Both `Delivered` and `Denied` are terminal.

**`PendingDecision` produces NO wire artifact, normatively.** A held request
has no mandate, no envelope, and no APH representation of any kind; how an
implementation stores its pending prompts is implementation-local and outside
this specification. This is stated rather than left silent because the
pressure it resolves is real: signing something is easier than representing
"held", and an artifact minted from `PendingDecision` would assert — by its
very existence, since no transition reaches `MandateIssued` except through
`Approved` — an approval that has not happened. The truth an envelope carries
is structural before it is textual: possession of a well-formed envelope IS
the claim that `Approved` was reached, whatever any field says.

### 9.2 Human-not-present flow

The human-not-present flow has five states (four progress states and one terminal-denial state). It is gated by a matching unexpired Delegation Mandate.

States:

- **`Drafted`** — Agent has prepared a message and submitted a notarization request referencing a Delegation Mandate.
- **`MandateIssued`** — Notary Service validated the Delegation Mandate and issued the Communication Mandate.
- **`EnvelopeIssued`** — Notary Service signed and emitted the envelope.
- **`Delivered`** — Terminal: envelope handed to the Channel Adapter.
- **`Denied`** — Terminal: no matching unexpired Delegation Mandate, OR a scope mismatch, OR a matched `NeverAllow` rule. The no-mandate and scope-mismatch arrivals surface as `APH_E016 MandateRequired` (§11); a matched `NeverAllow` is the configured refusal, not an error.

Allowed transitions:

```
Drafted ---> MandateIssued
Drafted ---> Denied
MandateIssued ---> EnvelopeIssued
EnvelopeIssued ---> Delivered
```

Both `Delivered` and `Denied` are terminal.

Implementations MUST reject any transition not enumerated above and SHOULD return `APH_E002` (invalid flow transition) for diagnostic purposes.

---

## 10. Composition with Adjacent Protocols

APH is designed to compose cleanly with adjacent agent and credential protocols. v0.1 defines the following composition profiles.

### 10.1 A2A (Agent2Agent)

A2A defines how two agents discover each other and exchange messages. APH attaches to A2A messages as a Verifiable Credential extension so the receiving agent can verify the sending agent actually holds its human's permission for this specific action. Without APH, A2A messages carry no portable, third-party-verifiable proof of human authorization; with APH, every A2A message can be independently audited back to a human-issued mandate.

APH advertises support via an A2A AgentCard extension declaration. The extension URI is:

```
aph://extensions/notarization/v1
```

When an agent advertises APH support, it adds an `AgentExtension` declaration to `AgentCard.capabilities.extensions` with the URI above, a short description, and `required: false`. Recipient agents that wish to require notarization MAY set `required: true` on their side. Refer to the companion document `a2a-extension.md` for the full descriptor and integration example. The driver's-license framing applies directly: an agent's APH credential is the credential a receiving agent checks before granting the sending agent's request, the way an officer checks a driver's license at a traffic stop.

A worked end-to-end example of two agents negotiating across organizations under APH appears in §1.1.1.

### 10.2 AP2 (Agentic Payments Protocol)

AP2 defines how an agent obtains a human-signed mandate to make a payment. APH and AP2 are complementary: AP2 authorizes payment, APH authorizes the broader category of human-on-behalf-of actions (including communication, scheduling, content creation, and the actions that surround a payment). An APH envelope MAY ride alongside an AP2 IntentMandate by setting `linkedMandate.ap2IntentMandateUri` to the IntentMandate's URI; the two credentials together let a recipient verify both that a payment was authorized AND that the surrounding communication carrying the payment instruction was itself authorized. APH does NOT replace AP2 — payment authorization remains in AP2's IntentMandate / CartMandate / PaymentMandate chain. Both protocols share canonicalization (JCS) and signing primitives.

In the driver's-license framing: AP2 is the toll booth (specifically authorizes paying for road use); APH is the underlying driver's license (the general license to operate); A2A is the road network itself.

### 10.3 MCP (Model Context Protocol)

APH is orthogonal to MCP. An MCP server MAY play the role of a `RecipientEndpoint` and verify APH envelopes on incoming agent-initiated calls before executing the requested tool. APH is NOT required to expose itself as an MCP server, but a Notary Service implementation MAY do so to make notarization discoverable as a tool callable from any MCP-aware host. Recommended tool surface:

- `aph.request_consent` — initiate the human-present flow and return either an `EnvelopeIssued` outcome or a `Denied` outcome.
- `aph.notarize_send` — bundle consent + envelope issuance for callers that already hold the outbound payload.

### 10.4 SD-JWT-VC (Selective Disclosure JWT VC)

APH envelopes MAY be transported as SD-JWT-VCs to support selective disclosure (e.g., disclosing "Alice consented" to a recipient without disclosing Alice's full policy ruleset). The APH SD-JWT-VC profile pins:

- Base spec: `draft-ietf-oauth-selective-disclosure-jwt-22`.
- VC spec: `draft-ietf-oauth-sd-jwt-vc-16`.
- `typ` header: `dc+sd-jwt`.

These draft versions are pinned for v0.1 to make N+1 newer-draft breakage explicit. Implementations SHOULD update the pinned versions in coordinated minor-version bumps.

### 10.5 OAuth 2.0 Token Exchange (RFC 8693)

The `policy.actChain` field in the envelope is compatible with RFC 8693 `act` claim chains. Each element is a DID string identifying a delegated principal in the chain. A typical chain is `[human-did, agent-did]`; longer chains MAY appear when a sub-agent acts on behalf of a primary agent. Verifiers MAY use the chain to enforce delegation policies at the recipient boundary.

### 10.6 W3C Verifiable Credentials 2.0

The Notarization Envelope IS a W3C Verifiable Credential 2.0. Existing VC verifier libraries can parse and verify APH envelopes natively. The credential type `AgentSendAuthorizationCredential` is APH-specific; the `@context` declaration `https://w3id.org/aph/v1` resolves to the APH JSON-LD context (publication of the context document is deferred to repository-side infrastructure tooling).

### 10.7 W3C DIDs

APH identifies both the human principal and the agent via DIDs. v0.1 implementations MUST support `did:key` (offline-resolvable). Implementations SHOULD support `did:web` for organization-bound agents. Other DID methods (`did:plc`, `did:ion`, `did:peer`) MAY be supported as conformance-test-only secondary methods.

---

## 11. Error Taxonomy

APH defines a closed set of twenty error codes for v0.1. Implementations MUST use the codes below when emitting protocol-level errors and SHOULD include the `suggestedResolution` text (or a localized equivalent) in user-facing error displays.

| Code | Variant | Meaning | Suggested resolution |
|---|---|---|---|
| `APH_E001` | `InvalidEnvelopeSignature` | The envelope's `proof.proofValue` did not verify against the resolved public key over the canonical envelope bytes. | Verify the notary signing key matches `verificationMethod`; re-sign and retry. |
| `APH_E002` | `InvalidFlowTransition` | A state machine transition attempted that is not in the allowed-transition set for the current state. | Check the APH notarization flow state machine in §9 and align the implementation. |
| `APH_E003` | `MandateExpired` | A Communication Mandate or Delegation Mandate was consulted past its `expiresAt` / `validUntil`. | Issue a fresh mandate with a future expiry. |
| `APH_E004` | `RoleViolation` | A party attempted an operation not enumerated for its role in §5. | Confirm the party holds the correct `AphPartyRole` for the operation. |
| `APH_E005` | `ChannelNotAllowed` | The requested channel kind was not in the Delegation Mandate's `allowedChannels` list. | Grant the channel scope on the Delegation Mandate, or re-issue under AskEveryTime. |
| `APH_E006` | `NotarySignatureInvalid` | The notary's signature did not verify (distinct from `APH_E001`: this is the mandate-level signature, not the envelope-level signature). | Verify the notary's published JWK matches the `verificationMethod`; re-issue the mandate. |
| `APH_E007` | `HumanAuthenticationRequired` | An AskEveryTime path was triggered but the human was not reachable for interactive prompt. | Prompt the human, or wait until the human is reachable. An implementation MAY hold the request for later review; any such hold is implementation-local and produces no APH artifact (§9.1). |
| `APH_E008` | `NotaryServiceUnreachable` | A protocol-mandated fetch from a notary-hosted surface did not succeed: a remote notary service did not respond within the configured timeout, or a document the notary is contracted to serve could not be reached, parsed, or validated — a DID Document under §8.4.4, or a revocation status list credential under §6.3.3.4 case 2 (which folds TLS, parse, proof, issuer, purpose and freshness failures into this one code because the verifier's action and the operator's remedy are identical in all of them). Deliberately distinct from `APH_E014`, which means the surface answered and published nothing. | Check the notary endpoint's health and the surface it is contracted to serve; retry with exponential backoff. |
| `APH_E009` | `EnvelopeBodyHashMismatch` | The recipient computed a SHA-256 over the actual outbound body that did not match `communication.bodySha256`. | Re-hash the body and compare against the envelope; investigate transport corruption or tampering. |
| `APH_E010` | `UnsupportedAlgorithm` | The envelope declared a signing algorithm not in the supported set, or `alg: none`. | Use one of `ES256` or `EdDSA`; reject `alg: none`. |
| `APH_E011` | `PrincipalSignatureInvalid` | A signature made by the HUMAN's key did not verify: the principal proof of a chain (§8.3.1 step 1c), or an embedded Delegation Mandate's `principalSignature` (step 1d). Distinct from `APH_E001` and `APH_E006`, which are both notary signatures — a verifier that conflated them would report a forged authorization as a notary misconfiguration. | Confirm the principal's key resolved from `humanPrincipalDid` matches `verificationMethod`; re-sign with the human's key. |
| `APH_E012` | `AttestationModeRefused` | The verifier's policy requires `PrincipalSigned` and the envelope is `NotaryAttested` (§8.3.1 step 1a). Not a defect in the envelope — a refusal to accept the weaker claim. | Re-issue in `PrincipalSigned` mode, or relax the verifier's policy deliberately and in the open. |
| `APH_E013` | `ProofChainInvalid` | The proof chain is malformed: wrong length, wrong `proofPurpose` for a position, or a `previousProof` that is missing, dangling, duplicated, or cyclic (§7.1.11, §8.3.1 step 1e). | Emit exactly two proofs, principal first, with the notary proof's `previousProof` naming the principal proof's `id`. |
| `APH_E014` | `NotaryKeyNotPublished` | No notary key is published at the queried discovery surface: the DNS TXT name carries no APH record (or none matching the named `kid`), or a fetched DID Document names no key under the queried fragment (§8.4.5, §8.4.4). Deliberately distinct from `APH_E008`, which means the surface could not be REACHED — §8.4.6's no-downgrade rule turns on exactly this distinction (absence advances the resolution sequence; failure stops it), and a taxonomy that flattened the two would force every implementation's error surface to flatten them again. | Publish the key at the queried surface, or direct verifiers to a surface the notary actually publishes to. |
| `APH_E015` | `MandateRevoked` | The parent Delegation Mandate's bit is SET in the revocation status list the issuing notary publishes (§6.3.3): the human withdrew the standing authority this envelope was issued under. The envelope's signatures are still valid — this is a withdrawn authorization, not a forged one, and reporting it as a signature failure would send an operator to inspect key material when the answer is a human decision. Deliberately distinct from `APH_E003`, which is authority that ran out on schedule rather than authority that was pulled. | Obtain a fresh Delegation Mandate from the human principal; a revoked mandate cannot be re-activated (§6.3.2). |
| `APH_E016` | `MandateRequired` | A human-not-present notarization (§9.2) was attempted with no matching, unexpired Delegation Mandate — nothing authorized this act. Deliberately distinct from THREE neighbours, because the remedies differ completely: `APH_E007` is *nobody was asked* (an AskEveryTime human was unreachable — remedy: reach the human); this code is *nothing authorized this* (remedy: the human mints a mandate); `APH_E011` is *the authorization presented is invalid* (remedy: inspect the mandate and its signatures); `APH_E015` is *the authorization was withdrawn*. Reporting an ABSENT mandate under any of those conflates absence with failure, and the distinction between the two is load-bearing everywhere else in this specification (§8.4.6). | Issue a Delegation Mandate covering this channel and scope, or route the act through the human-present flow (§9.1). |
| `APH_E017` | `AudienceMismatch` | The envelope names an audience that is not this verifier: `credentialSubject.audience.id` differs from the verifier's own identity, or a present `audience.channelBinding` member differs from the delivery coordinates of the act being performed (RFC 0003 §1's step, quoted: *"A verifier that cannot determine its own identity MUST reject rather than skip the step"*). *(This code was registered ahead of RFC 0003 under Appendix A's additive-codes rule; the RFC is now Accepted and the field is §7.1.13, so the head start is discharged.)* An envelope with no `audience` member never produces this code: absence is the producer's decision to issue a bearer credential. | Deliver the envelope to the endpoint it names, or re-issue naming the intended recipient. |
| `APH_E018` | `EnvelopeAlreadySpent` | The envelope was already accepted once: §8.3 step 8b's single-use record holds this `id`, and a second presentation is a replay by definition, whoever presents it. The record is per-verifier — this code says nothing about what OTHER verifiers have seen. | Mint a fresh envelope for a new act; acceptance consumes an envelope by design. |
| `APH_E019` | `EnvelopeWindowInvalid` | The envelope's own validity window fails against the verifier's clock (§8.3 step 6): `validFrom` is in the future, `validUntil` is in the past, or a timestamp is unparseable (which fails closed). Deliberately distinct from `APH_E003`, a *mandate* consulted past its expiry — before this code, implementations refusing an expired envelope had to invent a refusal or miscite `APH_E003`. | Mint a fresh envelope with a current window; single-act windows should be minutes, not hours (§6.3). |
| `APH_E020` | `RecipientClassNotAllowed` | The mandate constrains who may consume (`allowedRecipientClasses`, RFC 0005) and the envelope declares a recipient class outside the grant — or none at all, which refuses for the same reason: a constraint the envelope lets nobody check would be escapable by omission. Distinct from `APH_E005`: that is the MEDIUM out of scope, this is the CONSUMER out of scope on an allowed medium. | Declare the recipient class the act actually has, or ask the principal for a grant that covers it. |

---

## 12. Security Considerations

A full threat model is published as the companion document `security-considerations.md` in this repository. In summary: APH binds a human-issued credential to a specific outbound message body hash inside a bounded time window, making both replay attacks and post-issuance tampering independently detectable at the recipient boundary. Recipient Endpoints MUST validate the time window, MUST enforce the algorithm allow-list (rejecting `alg: none` and unrecognized algorithms), MUST resolve the revocation status of any envelope that carries a `credentialStatus` reference (§6.3.3), and SHOULD validate the body hash against the actual received payload bytes when available. Notary Service operators are responsible for protecting the notary's signing key with the same care they would apply to any production credential-issuance key.

---

## 13. IANA Considerations

**Media type.** APH envelopes are W3C Verifiable Credentials and use the existing `application/vc+ld+json` media type registered by W3C. v0.1 does NOT register a new media type. Implementations that need a distinct media-type indicator for transport routing MAY use the unregistered `application/aph+ld+json` by convention, but conformant verifiers MUST accept both.

**URI scheme.** APH defines the `aph://` URI scheme for protocol-level extension URIs (e.g., the A2A extension URI `aph://extensions/notarization/v1`). Formal IANA registration of the `aph://` URI scheme is **drafted — `spec/registrations/uri-scheme-aph.md` carries a complete provisional request per the RFC 7595 §7.4 template, and submission is pending.** A draft is not a registration: the scheme is unregistered, and the name is not APH's, until IANA acts. v0.1 uses the scheme by convention only, similar to how `did:` was used in early DID drafts prior to formal registration. Implementations MUST treat `aph://` URIs as opaque identifiers and MUST NOT attempt to dereference them as URLs.

**DNS underscore-prefixed sub-name.** APH §8.4.5 publishes notary public keys at `_aph._notary.<domain>`. v0.1 reserves the underscore-prefixed labels `_aph` and `_aph._notary` by convention. Formal registration in the IANA "Underscored and Globally Scoped DNS Node Names" registry is **drafted — `spec/registrations/dns-underscored-aph.md` carries the request per RFC 8552 §4.1.1, and submission is pending.** A draft is not a registration: the labels are unregistered, and the names are not APH's, until the designated expert acts. The underscore-prefix convention follows established practice in DKIM (`_domainkey`), DMARC (`_dmarc`), and TLSA (`_<port>._<proto>`). One consequence of that registry's rules is not obvious from the sentence above and is worked through in the draft: RFC 8552 registers only the underscored label **closest to the root**, which for `_aph._notary.<domain>` is `_notary`. `_aph` sits subordinate to it — the position a DKIM selector occupies — and is not separately registrable, because APH defines no record directly at `_aph.<domain>`. It does not need to be: that registry gives each registered global name a distinct subordinate namespace, so registering `_notary` carries `_aph` with it. The reservation of `_aph` above is therefore honoured derivatively, as a consequence of holding `_notary` rather than as an independent claim on the label — which also means the first party to register `_notary` owns the namespace `_aph` lives in.

**A SECOND underscored name, for vocabulary publication.** §8.5.1 publishes vocabulary digests at `_aph._vocab.<domain>`. By the same rule, the registrable label there is `_vocab`, not `_aph` — so this is a **separate** registration and not an addendum to the first: holding `_notary` grants the namespace beneath `_notary` and nothing beneath `_vocab`. v0.1 reserves `_vocab` by convention on the same terms; the request is **drafted** at `spec/registrations/dns-underscored-aph-vocab.md`, and submission is pending. The same caveat applies with the same force: a draft is not a registration, and the label is not APH's until the designated expert acts. That draft also records the alternative that was declined — naming the surfaces `_notary._aph` and `_vocab._aph` would have put `_aph` in the registrable position and cost one entry instead of two, and was rejected because `_aph._notary` is already published in live DNS and shipped in released code.

---

## 14. References

### 14.1 Normative

The following references are normative for APH v0.1:

- W3C Verifiable Credentials Data Model 2.0 (W3C Recommendation).
- RFC 7515 — JSON Web Signature (JWS).
- RFC 7518 — JSON Web Algorithms (JWA).
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA).
- RFC 8785 — JSON Canonicalization Scheme (JCS).
- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels.
- RFC 8174 — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
- BCP 14 — RFC 2119 + RFC 8174 combined.
- `draft-ietf-oauth-sd-jwt-vc-16` — Selective Disclosure JWT VC (active IETF draft).
- `draft-ietf-oauth-selective-disclosure-jwt-22` — Selective Disclosure JWT base spec (active IETF draft).
- W3C Decentralized Identifiers (DIDs) v1.0 (W3C Recommendation).
- W3C Verifiable Credential Data Integrity 1.0 (W3C Recommendation).
- W3C Bitstring Status List v1.0 (W3C Recommendation) — the status-list vintage §6.3.3 profiles for revocation transport. The vintage is pinned, not offered as one of several: `credentialStatus.type` is signed wire content under §7.1's strict parse, so an implementation reading a different vintage of the same idea would look conformant and never interoperate.
- W3C DID Method `did:key` — self-describing DID method (W3C Community Group spec).
- W3C DID Method `did:web` — domain-anchored DID method (W3C Community Group spec).
- RFC 1035 — Domain Names: Implementation and Specification.
- RFC 4034 — Resource Records for the DNS Security Extensions (DNSSEC).
- The Multicodec Registry — multicodec.io (informative — public key prefix table for `did:key`).
- The Multibase Specification — IETF Internet-Draft (informative — encoding for `publicKeyMultibase`).

### 14.2 Informative

The following references are informative:

- RFC 8693 — OAuth 2.0 Token Exchange.
- Google Agent2Agent (A2A) Protocol — agent-to-agent transport.
- Google Agentic Payments Protocol (AP2) — agent-initiated payment authorization.
- Model Context Protocol (MCP) — agent tool exposure.
- RFC 6376 — DomainKeys Identified Mail (DKIM) Signatures (informative — domain-level analog).
- RFC 8617 — Authenticated Received Chain (ARC) Protocol (informative — relay-chain analog).
- RFC 9635 — Grant Negotiation and Authorization Protocol (GNAP).
- C2PA 2.4 Specification — Content Provenance and Authenticity (informative — composable for media-bearing envelopes).
- DIF DIDComm v2 — DID-to-DID messaging (informative — alternative transport).

---

## 15. Notary Code Attestation

A Notary Service that cannot forge authorizations (§7.1.11) may be hosted by
anyone. That raises a different question — **is this notary running the
software the protocol published?** — and §15 answers it with a supply-chain
attestation rather than a claim about key custody.

### 15.1 The authority

The APH protocol authority publishes attestations under a **k-of-3
threshold**: three holder keys, of which any **two** valid signatures
constitute a valid attestation. Two is deliberate: one lost key must not halt
releases, and one compromised key must not be able to ship alone.

The two signatures MUST be made by **two distinct holder keys**. A verifier
MUST reject an attestation carrying two signatures that verify against the
same key — otherwise a single compromised holder satisfies the threshold by
signing twice, and k-of-3 degrades to 1-of-3 without anyone noticing.

**The authority's identity is not yet assigned, and §15 cannot be
implemented until it is.** A verifier resolves the three holder keys the way
it resolves any other APH key material — but it must first know WHOSE keys to
resolve, and that identifier is a constant of this specification, not a
per-deployment configuration value. A mechanism whose trust root each
verifier picks for itself has no trust root. The constant is `TBD` in this
revision; §15.7 lists it as the first precondition.

Once assigned, the three authority public keys are published through the §8.4 mechanisms
like any other APH key material, and are subject to §8.4.7 rotation with
overlap.

### 15.2 The subject

An attestation is over a **content digest of a published release artifact**
— the artifact, not a version string. A version string is a claim about an
artifact; a digest *is* the artifact.

**The word this section deliberately does not use is "reproducible."** An
earlier draft said "a content digest of a reproducible build," and that
claims more than the mechanism delivers. Bit-for-bit reproducibility is a
separate and much stronger property — a claim about the determinism of a
toolchain — and APH does not require it, does not test it, and MUST NOT be
read as implying it.

The weaker property the digest does rest on is **publication closure**: the
commit the artifact was built from must be buildable from what is published
alone, so that the artifact corresponds to a fetchable state of the world
rather than to one machine's disk. That is the bar an attestation can
actually be held to today.

The consequence is worth stating plainly, because it is the difference
between what this mechanism proves and what a reader will assume it proves:

- **What an attestation says.** *These holders vouch that this digest is the
  release they published.*
- **What it does NOT say.** *Anyone can rebuild the source and derive this
  digest independently.*

Without reproducibility a third party cannot re-derive the digest, so the
attestation is a statement about the **holders' word**, cryptographically
bound to an artifact, not an independently checkable derivation. That is
still worth having — it makes substitution detectable and gives a verifier
something to pin — but a design that presents it as independent verification
is non-conformant with §15.6.

### 15.3 What a notary advertises

A notary MAY declare what it is running, in
`credentialSubject.notarization.notaryService` (declared normatively in
§7.1.9, because strict parsing means a field a notary may send must exist in
the shape a verifier parses):

| Field | Type | Required | Description |
|---|---|---|---|
| `attestedDigest` | string | no | Content digest of the attested release this notary **reports** running. |
| `attestationUri` | string | no | Where the k-of-3 attestation for that digest may be fetched. |

**Both fields are self-asserted.** They are a claim made by the same party
whose honesty is in question, inside a document that party signed. A
verifier that reads `attestedDigest` and concludes the notary runs that code
has learned nothing an adversarial notary could not have written. The fields
are useful only as a *pointer*: fetch the attestation at `attestationUri`,
verify k-of-3 over the digest, and confirm the digest is one you accept.
Even then the conclusion is bounded by §15.7 — that this code was published,
not that it is running.

### 15.4 Reuse, not invention

Attestation format, transparency logging, and provenance vocabulary SHOULD
reuse existing supply-chain standards — Sigstore, in-toto attestations, and
SLSA provenance — rather than defining an APH-specific schema. APH's
contribution is the k-of-3 authority and the binding into `notaryService`,
not a new signature envelope.

### 15.5 How a verifier checks one

§8.3.1 step 10 lets a verifier require an attestation. This is what that
check is, end to end:

1. **Read the claim.** Take `attestedDigest` and `attestationUri` from
   `credentialSubject.notarization.notaryService` (§7.1.9). Both are
   self-asserted (§15.3); nothing is established yet.
2. **Resolve the authority keys.** Obtain the three APH attestation-authority
   public keys through the §8.4 mechanisms, exactly as a notary key is
   obtained: `did:web` at the authority's domain, or a DNS TXT record, with
   the §8.4.6 no-downgrade rule applying unchanged. A verifier that cannot
   resolve all three MUST fail the check rather than proceed with fewer —
   two-of-two is not two-of-three.
3. **Fetch the attestation** at `attestationUri` under the same transport
   rules §8.4.4 imposes on `did:web` resolution (HTTPS only, no cross-host
   redirects, bounded size and time). A fetch failure is a failed check, not
   a passed one.
4. **Verify the threshold.** The attestation MUST carry at least two valid
   signatures over the digest, made by **two distinct** authority keys
   (§15.1). Reject two signatures from one key.
5. **Bind it to the claim.** The digest the attestation covers MUST equal
   `attestedDigest` byte-for-byte. An attestation over a different digest
   proves something true about some other release.
6. **Apply the verifier's own policy.** Is this digest one the verifier
   accepts — a known release, not withdrawn, not older than a floor it has
   set? The protocol does not answer this; it only makes the question
   answerable.

A failure at any step means the attestation requirement is unmet. It does
NOT by itself invalidate the envelope: the signatures verified in §8.3 are
unaffected, and a verifier that does not require attestation remains
conformant (§8.3.1 step 10).

### 15.6 What is not yet decided (and therefore blocks §15)

§15 is specified but **not implementable**, and this section says why in
terms a reader can check off rather than leaving the gap to be discovered
during an implementation attempt. Four preconditions:

1. **The authority identifier.** §15.1's holder keys have no DID. Until this
   specification names one, step 2 of §15.5 has nothing to resolve.
2. **The attestation format.** §15.4 says to reuse Sigstore, in-toto, or
   SLSA provenance "where possible." Three choices are zero choices for an
   implementer: two conformant verifiers would parse different documents and
   neither would be wrong. One MUST be pinned, with its profile.
3. **A transport for the attestation.** §15.5 step 3 fetches
   `attestationUri` under §8.4.4's rules, but §8.4's ports exist to fetch
   *key material* — nothing in this specification is contracted to fetch an
   attestation document. Either §8.4.4's surface is widened or a fetch
   mechanism is named here.
4. **An error code.** §11 is a closed taxonomy of sixteen. A failed
   attestation check maps to none of them, so a conformant implementation
   cannot report it. Either a code is added at last position or §15 states
   which existing code it reuses and why.

Until all four are settled, an implementation MUST NOT advertise §15 support,
and a verifier MUST NOT be configured to *require* an attestation it has no
defined way to obtain or to reject.

### 15.7 The limit (normative)

**An attestation proves what code was published. It does not prove what code
is running.**

Absent hardware-backed remote attestation, an operator can publish an
attested digest and execute something else. §15 raises the cost of operating
a malicious notary and narrows the population of plausible ones; it does not
make a remote notary honest.

Implementations MUST NOT present an attestation as a guarantee of honest
execution, and any user-facing surface rendering an attestation badge MUST
convey this limit. A design implying otherwise is non-conformant with this
section.

This is also why a principal proof matters more than any attestation: the
principal proof is verified by mathematics and requires no assumption about
what a remote process is executing.

---

## Appendix A: Versioning

APH follows Semantic Versioning 2.0.

- **v0.x.y** — draft. Wire shape, signing profiles, and state machines MAY change in incompatible ways between any two v0.x.y releases. Implementations SHOULD pin to a specific commit hash.
- **v1.0.0** — first stable release. The wire shape, signing profile set, and state machines defined at v1.0.0 are stable. Breaking changes to the envelope shape, the supported algorithm set, or the state machines MUST bump the major version.
- **v1.x.y (minor)** — backward-compatible additions. New channel kinds, new content classes, new optional fields under `linkedMandate`, and new error codes MAY be added in minor versions.
- **v1.x.y (patch)** — clarifications and editorial fixes only. No wire-shape changes.

Version compatibility is signaled by the envelope-level `aphVersion` field. Verifiers MUST reject envelopes with an `aphVersion` they do not support.

---

## Appendix B: Future Work

The following items are deferred from v0.1 and will be addressed in subsequent versions:

- **JSON Schema files.** Formal JSON Schema definitions for `NotarizationEnvelope`, `DelegationMandate`, and `CommunicationMandate` will be published under `spec/schemas/` and used by the conformance suite for automated validation.
- **Conformance test vectors.** A repository-side conformance harness will publish signed test vectors for both `ES256` and `EdDSA`, both `DataIntegrityProof` and `JsonWebSignature2020` proof formats, and all seven channel kinds.
- **Status for artifacts other than the Delegation Mandate.** §6.3.3 defines revocation status for Delegation Mandates only. Status for individual envelopes and for Communication Mandates is deliberately out of scope in v0.1 (§6.3.1: a Communication Mandate is single-use and consumed by issuance, and an issued envelope stays a valid record of what was authorized). Either would need its own purpose and its own list, and neither has a demonstrated use ahead of a first external adopter.
- **A per-key proof purpose in the published DID Document.** §8.4.4's document schema records no purpose per key, so a status-only signing key would also be accepted for envelope signing (§6.3.3.3). Expressing purposes would let a notary hold a narrower key for status publication.
- **A signed key-rotation attestation.** §8.4.7 rotates by publishing two keys, and the authority to publish either of them is domain control rather than key control (§8.4.4, §8.4.5). A statement in which the OUTGOING key names its successor would let a verifier check that a successor was *named by its predecessor* rather than merely *served from the same origin*. A non-normative design draft is published as `rfcs/0001-rotation-attestation.md` (RFC 0001); it proposes concrete shapes for both §8.4 publication surfaces and is equally explicit about what the mechanism cannot buy — a stolen current key signs a rotation too, and a verifier meeting an identity for the first time has nothing to chain from, so the mechanism upgrades continuity and not genesis. v0.1 defines no such statement and no verifier is required to look for one.
- **IANA registration of the `aph://` scheme and the underscored DNS labels.** Formal registration of both will be pursued for v0.2, and complete requests are already written: `spec/registrations/uri-scheme-aph.md` fills the RFC 7595 §7.4 provisional template for the scheme, and `spec/registrations/dns-underscored-aph.md` prepares the "Underscored and Globally Scoped DNS Node Names" entry for the §8.4.5 publication name. Neither has been submitted, and a draft is not a registration: both names remain conventions, and unowned, until IANA acts — §13 carries the standing and the collision exposure, which the drafts do not reduce. One question v0.2 must settle rather than inherit is raised by the DNS draft: RFC 8552 registers only the underscored label closest to the root, which for `_aph._notary.<domain>` is `_notary`, so the deployed name stakes a generic noun and holds `_aph` derivatively, and whether to keep that shape or invert it to `_notary._aph` is left to the specification owner.
- **N Lang static-type schema.** A companion statically-typed schema (machine-readable) will be published alongside the JSON Schema for implementations that want static-type guarantees.
- **Selective-disclosure conformance.** Full SD-JWT-VC profile conformance vectors, including key-binding JWTs and disclosed-field selection, will be added once the underlying IETF drafts stabilize.
- **Email-header IETF draft.** An Internet-Draft proposing an `APH-Attestation:` email header for SMTP carriage will be submitted to the appropriate IETF working group.
- **Media-bearing envelopes.** A profile for emitting C2PA `aph.send_authorization` assertions when the outbound message carries generated media is planned for v1.1.

---

End of APH v0.1 specification.
