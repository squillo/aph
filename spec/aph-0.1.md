# APH v0.1 — Agent per Human Notarization Protocol

**Version:** 0.1.0-draft
**Status:** Draft, open for community review
**Date:** 2026-05-21
**Repository:** `github.com/squillo/aph`
**License:** Apache-2.0

---

## 0. Status of This Document

This is a v0.1.0-draft of the APH (Agent per Human) protocol specification, published for community review. The wire shape, signing profiles, and state machines defined here MAY change in incompatible ways before v0.1.0 final. The maintainer of this draft is Squillo, Inc.; the source of truth lives at `github.com/squillo/aph`. Implementers SHOULD pin to a specific commit hash while v0.1 is in draft and SHOULD expect breaking changes before v1.0. Feedback, errata, and conformance reports are welcome via repository issues and pull requests.

---

## 1. Abstract

APH (Agent per Human) defines a wire protocol for cryptographically notarizing actions an autonomous agent takes on behalf of a human principal. Each notarized action carries a Verifiable Credential — issued by a Notary Service under one of three human-configured policy decisions (`AlwaysAllow`, `AskEveryTime`, `NeverAllow`) — that binds the action's payload to the human's keypair, the agent's identity, the channel transport, and the policy context. APH is transport-agnostic: envelopes ride alongside the action itself on whatever channel the agent uses (email, chat, messaging, voice, agent-to-agent), so that any recipient — regardless of vendor or organization — can independently verify that a specific human authorized this specific action. APH complements adjacent protocols (A2A for agent-to-agent transport, AP2 for payment authorization, MCP for tool exposure, W3C VC 2.0 for credential format) without replacing any of them. Where A2A defines the transport and AP2 defines payment authorization, APH defines per-action human authorization — the agent's verifiable license to act on a specific human's behalf for a specific task on a specific channel.

---

## 1.1 Mental model — the agent's driver's license

APH credentials function as **drivers' licenses for agents**. The metaphor maps directly to the protocol structure:

- **The issuing authority is the human principal.** Like a state issuing a license, the human is the only party with the authority to grant an agent permission to act on their behalf. The human's signature (directly or transitively via the Notary Service capturing explicit attestation) is the root of every APH credential.
- **The notary service is the DMV.** It runs the human's policy, captures attestation when required, signs the credential with its own keypair, and publishes its public verification key via DNS or HTTPS so any recipient can independently confirm the signature is genuine (§8.4). The notary does NOT decide whether to issue — it executes the human's pre-declared policy.
- **Every credential carries a bounded scope.** A Delegation Mandate names the channels the agent may operate on (`allowedChannels`), the rate at which it may act (`rateLimitPerHour`), the time window during which authority is valid (`validFrom` … `validUntil`), and the policy decision the human selected (`AlwaysAllow` / `AskEveryTime` / `NeverAllow`). A Communication Mandate further binds a single action to a specific outbound payload hash. Like a driver's license that authorizes operating a specific class of vehicle in specific places, APH credentials authorize specific actions on specific channels.
- **The license is revocable at any time.** The issuing human can revoke a Delegation Mandate before its `validUntil`. The conceptual revocation model is normative in this version of the spec (§6.3); the on-wire revocation transport (status list / status credential) is deferred to v0.2.
- **The license is portable across jurisdictions.** Like an interstate driver's license, an APH credential issued by one organization's notary is verifiable by any other organization's agent or system using only public standards (W3C VC 2.0, RFC 8785, RFC 7515, RFC 8032, DNS). No bilateral integration, no shared identity provider, no out-of-band trust establishment. The notary's public key is published in DNS or at a `.well-known` URI; any recipient on the open internet can resolve it.
- **The license is independently auditable.** Every credential is a self-contained Verifiable Credential. Recipients store them in their own audit logs. Disputes can be resolved by re-verifying the credential against the notary's published key — by the recipient, by a third-party auditor, or by a regulator — without ever contacting the notary.

The notarization step matters precisely because it produces a third-party-verifiable artifact. A signed action without public-key publication is closed signing; a signed action with publicly-anchored public keys is notarization. APH is the latter.

### 1.1.1 Concrete example — two agents negotiating

Alice's agent and Bob's agent are negotiating a meeting time over a shared channel. Both agents are acting with autonomy within bounded parameters their humans set in advance.

1. Alice opens her agent and grants it a Delegation Mandate scoped to channel `a2a`, content class `Reply` and `New`, valid for 30 days, with `rateLimitPerHour = 12`. Squillo's notary signs the mandate and persists it to Alice's local store.
2. Alice's agent drafts the first message: "How about 3 pm Tuesday?" The agent sends it under an APH envelope notarized by Squillo's notary on Alice's behalf, with `credentialSubject.policy.delegationMandateId` pointing at the just-issued mandate.
3. Bob's agent receives the envelope. Bob's agent has never previously transacted with Squillo. It resolves Squillo's notary public key via `did:web:notary.squillo.io` (fetching `https://notary.squillo.io/.well-known/did.json`) OR via the `_aph._notary.squillo.io` DNS TXT record. Both publication mechanisms are anchored in public infrastructure Bob does not need a Squillo account to read.
4. Bob's agent verifies the envelope signature, validates the time window, confirms the body hash matches the received payload, confirms the scope permits this channel + content class, and accepts the message.
5. Bob's agent replies under its own APH envelope, notarized by Bob's organization's notary. Alice's agent verifies the reply using the same flow.
6. Neither human is in the loop for the negotiation itself, but every action either agent takes is provably bound to a credential its human issued ahead of time and can revoke at any time.

If Alice changes her mind and revokes the Delegation Mandate, Squillo's notary records the revocation; subsequent envelopes from Alice's agent referencing that mandate fail verification on Bob's side once the revocation transport (v0.2) is wired. In v0.1 the recovery posture is to use short validity windows (RECOMMENDED: hours-to-days, not weeks-to-months) so revocation gaps are small.

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
- **Notary Decision** — the human-configured policy outcome for an outbound message: `AlwaysAllow`, `AskEveryTime`, or `NeverAllow`.
- **Verifiable Credential (VC)** — as defined in W3C Verifiable Credentials Data Model 2.0.
- **DID** — Decentralized Identifier, as defined in W3C DID Core 1.0.
- **JCS** — JSON Canonicalization Scheme, as defined in RFC 8785.
- **JWS** — JSON Web Signature, as defined in RFC 7515.

---

## 3. Design Goals + Non-Goals

### 3.1 Design Goals

APH v0.1 is designed to meet the following goals:

- **Human-attested.** Every notarized message binds to a verifiable signature derived from a key held by the human principal (directly via the principal's key, or transitively via the Notary Service's key after explicit human attestation).
- **Local-first decision.** The `AlwaysAllow` / `AskEveryTime` / `NeverAllow` policy is evaluated on the human's device or under the human's direct control. Notarization does not require an authorization server.
- **Recipient-verifiable across vendors.** A recipient running entirely different software from the sender MUST be able to verify the credential using only public standards (W3C VC 2.0, RFC 8785, RFC 7515, RFC 8032).
- **Transport-agnostic.** APH envelopes ride on the channel's native metadata surface (email header, chat block metadata, message attachment). APH does not define a new transport.
- **Replay-resistant.** Each envelope binds to a specific outbound payload via a body hash, a time window, and a unique envelope identifier.
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
- A revocation list infrastructure. v0.1 omits mandate revocation; v0.2 will address it.

---

## 4. Architecture

APH defines five protocol roles and six operations. The Human Principal authorizes the Agent (sometimes ahead of time via a Delegation Mandate, sometimes per-message via an AskEveryTime prompt); the Notary Service issues a Notarization Envelope binding the human's attestation to a specific outbound payload; the Channel Adapter carries the envelope over its native transport; the Recipient Endpoint independently verifies the envelope.

The Notary Service is a logical role; in v0.1 it is typically co-located on the same device as the Human Principal. Future profiles MAY define a remote escrow notary (multi-signature, off-device) but v0.1 assumes a local notary holding the human's signing key.

```
+----------------+     issue mandate       +----------------+
| HumanPrincipal | ----------------------> | NotaryService  |
+----------------+                         +-------+--------+
                                                   |
                                                   | sign envelope
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

The Agent Sender drafts the outbound message and submits a notarization request to the Notary Service. The Notary Service consults the Human Principal's local policy and (if required by `AskEveryTime`) prompts the human. On a positive decision, the Notary Service signs the envelope and returns it to the Agent Sender, which hands it together with the original payload to the Channel Adapter. The Channel Adapter transmits both over the channel's native transport. The Recipient Endpoint verifies the envelope's signature, time window, and body hash against the received payload before accepting or displaying the message.

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

- **`IssueDelegationMandate`** — A Human Principal grants an Agent ongoing authority to send messages on specified channels within a bounded scope (recipient patterns, content classes, expiry). The mandate is signed by the Notary Service on behalf of the human and persisted for later reference.
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
| `rateLimitPerHour` | unsigned integer | no | Optional per-hour send rate cap. Omitted or `null` means unlimited. |
| `validFrom` | RFC 3339 string | yes | "Valid from" timestamp. |
| `validUntil` | RFC 3339 string | yes | "Valid until" timestamp. |
| `notarySignature` | string | yes | Multibase- or base64url-encoded signature over the JCS-canonical form of this struct MINUS the `notarySignature` field. |

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
  "notarySignature": "z3sQXc...base58btc-encoded-signature..."
}
```

Validation rules:

- `id` MUST be a globally unique `urn:uuid:` value.
- `validFrom` MUST be lexicographically less than `validUntil`.
- `allowedChannels` MUST contain at least one entry.
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
| `channelKind` | string | yes | Channel kind (`slack`, `email`, `discord`, `teams`, `whatsapp`, `googleChat`, `imessage`). |
| `recipientAddressing` | JSON object | yes | Channel-shaped addressing payload (opaque to APH core; see §6.4). |
| `contentClass` | string | yes | Content classification (`Reply`, `New`, `Mention`, `DM`, `Channel`, etc.). |
| `bodySha256` | string | yes | SHA-256 hex digest of the outbound message body bytes (64 lowercase hex chars). |
| `bodySize` | unsigned integer | yes | Body size in bytes. |
| `policyDecision` | string | yes | The policy outcome that produced this mandate: `AlwaysAllow`, `AskEveryTime`, or `NeverAllow`. (A `NeverAllow` mandate is recorded but does NOT result in an envelope.) |
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
- If `delegationMandateId` is non-null, the referenced Delegation Mandate MUST exist, MUST be unexpired at `issuedAt`, and MUST list `channelKind` in its `allowedChannels`.

### 6.3 Mandate lifecycle

A Delegation Mandate is issued by the Human Principal, signed by the Notary Service, and persisted to the human's local store. Its validity window is bounded by `validFrom` and `validUntil`. A Communication Mandate is issued at outbound-action time; it MAY reference a Delegation Mandate (the standing-authority path) or stand alone (the AskEveryTime path). Communication Mandates are single-use: one Communication Mandate per outbound action. Both mandate types are bound by the Notary Service signature.

#### 6.3.1 Revocation — conceptual model

A Delegation Mandate is REVOCABLE by the issuing Human Principal at any time before its `validUntil`. Revocation is normative in v0.1 even though the on-wire revocation transport is deferred. Revocation is the corollary of the driver's-license framing: a license that cannot be pulled is not a license.

The conceptual revocation model is:

1. **Issuer-side state.** The Notary Service tracks, for every Delegation Mandate it has signed, a `revoked: bool` state and a `revokedAt: RFC 3339 string` timestamp (set when revoked, absent otherwise). The Notary Service exposes a revocation operation to the Human Principal; calling it sets `revoked = true` and stamps `revokedAt = now`.
2. **Effect on downstream Communication Mandates.** A Notary Service MUST NOT issue a new Communication Mandate referencing a revoked Delegation Mandate. A Communication Mandate signed before its parent Delegation Mandate was revoked remains cryptographically valid; the revocation cuts off issuance of NEW mandates rather than invalidating existing signatures.
3. **Effect on issued envelopes.** Envelopes already in flight when the parent mandate is revoked remain verifiable as signed credentials. Recipient policy MAY treat envelopes whose parent Delegation Mandate is currently revoked as suspect even if cryptographically valid; v0.1 leaves this policy to the recipient.
4. **Revocation transport.** v0.1 does NOT specify how a third-party recipient discovers that a mandate has been revoked. Implementations that need recipient-side revocation before v0.2 SHOULD use short validity windows (RECOMMENDED: hours to days, not weeks to months) so revocation gaps are bounded. v0.2 will define a status credential (W3C Verifiable Credential Status List 2021) or equivalent transport so recipients can pull revocation state at verification time.

A Communication Mandate is single-use and conceptually "consumed" by issuing the corresponding envelope; revocation of a Communication Mandate has no practical meaning (the envelope has either been issued or it has not). Revocation applies to Delegation Mandates only.

#### 6.3.2 Expiration

When `now > validUntil`, a Delegation Mandate is EXPIRED. A Notary Service MUST NOT issue a new Communication Mandate referencing an expired Delegation Mandate. Verifiers MUST reject envelopes whose Communication Mandate's `delegationMandateId` resolves to an expired Delegation Mandate (when the verifier has access to that lookup).

A Delegation Mandate that has reached its `validUntil` cannot be "re-activated" — the human must issue a new mandate with a new `id` and new validity window.

---

## 7. The Notarization Envelope

The `NotarizationEnvelope` is the canonical on-wire artifact. It is a W3C Verifiable Credential 2.0 of type `AgentSendAuthorizationCredential`, secured with either a Data Integrity Proof or a detached JWS. The envelope embeds the credential subject (which carries the equivalent of a Communication Mandate plus contextual metadata about the agent, channel, and decision) and a single `proof` block carrying the notary signature.

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
| `issuer` | string | yes | DID of the Notary Service issuing the credential. |
| `validFrom` | RFC 3339 string | yes | Envelope validity start. |
| `validUntil` | RFC 3339 string | yes | Envelope validity end. |
| `credentialSubject` | object | yes | The notarized claim (see §7.1.2). |
| `linkedMandate` | object or null | no | Optional cross-protocol mandate link (see §7.1.10). Omit or set to `null` when absent. |
| `proof` | object | yes | Cryptographic proof block (see §7.1.11). |

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
| `kind` | string | yes | One of the closed channel-kind enum values: `slack`, `email`, `discord`, `teams`, `whatsapp`, `googleChat`, `imessage`. New channel kinds are additive in 0.x minor versions. |
| `recipientAddressing` | JSON object | yes | Channel-shaped opaque addressing payload. The exact field set is channel-specific; see §7.4 for per-channel shapes. |

#### 7.1.6 `CommunicationDescriptor`

Binds the outbound payload.

| Field | Type | Required | Description |
|---|---|---|---|
| `contentClass` | string | yes | Content classification. Closed enum: `Reply`, `New`, `Mention`, `DM`, `Channel`, `BulkSend`, `Broadcast`. New classes are additive in 0.x. |
| `bodySha256` | string | yes | SHA-256 hex digest of the outbound body bytes (64 lowercase hex chars). |
| `bodySize` | unsigned integer | yes | Body size in bytes. |
| `previewLines` | unsigned integer | yes | Number of lines included in `preview`. |
| `preview` | string | yes | Truncated preview of the outbound body for UI display. MUST NOT exceed `MAX_BODY_PREVIEW_BYTES` (8192 bytes for v0.1). |

#### 7.1.7 `PolicyDescriptor`

Describes the policy decision context.

| Field | Type | Required | Description |
|---|---|---|---|
| `decision` | string | yes | Policy outcome. Closed enum: `AlwaysAllow`, `AskEveryTime`, `NeverAllow`. |
| `matchedScope` | string | yes | Scope of the matched policy rule (e.g., `per-channel`, `per-recipient`, `global`, `per-content-class`). |
| `delegationMandateId` | string or null | no | Parent `DelegationMandate.id` if a standing authority matched; `null` otherwise. |
| `actChain` | array of strings | no | OAuth 2.0 Token Exchange (RFC 8693) `act` chain. Each element is a DID string identifying a delegated principal. Empty array if unused. |

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

#### 7.1.10 `LinkedMandate`

Optional cross-protocol mandate link. Forward-extensible: new sister-protocol cross-links are added as new optional fields in this object.

| Field | Type | Required | Description |
|---|---|---|---|
| `ap2IntentMandateUri` | string or null | no | Optional URI pointing at an AP2 `IntentMandate` for cross-linked payment authorization. v0.1 reserves this field; producers MAY emit it; verifiers MUST tolerate `null`. |

#### 7.1.11 `EnvelopeProof`

The cryptographic proof block. v0.1 supports two proof types: `DataIntegrityProof` (W3C Verifiable Credential Data Integrity) and `JsonWebSignature2020` (detached JWS).

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | yes | Either `"DataIntegrityProof"` or `"JsonWebSignature2020"`. |
| `cryptosuite` | string | no | Required when `type` is `"DataIntegrityProof"`. One of `"eddsa-jcs-2022"` (Ed25519) or `"ecdsa-jcs-2019"` (ES256/p256). Omitted for `JsonWebSignature2020`. |
| `verificationMethod` | string | yes | DID URL referencing the verifying key. E.g., `did:key:z6Mk...#z6Mk...`. |
| `created` | RFC 3339 string | yes | Proof creation timestamp. |
| `proofPurpose` | string | yes | Always `"assertionMethod"` for APH. |
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
2. Take a working copy and strip `proof.proofValue` (leaving the rest of the `proof` block intact).
3. Apply JCS canonicalization to the working copy.
4. Verify the original `proof.proofValue` against the canonical bytes using the public key resolved from `verificationMethod`.

**Implementation note.** Whether to strip `proof.proofValue` entirely or to substitute an empty string is implementation-dependent and MUST be consistent between signer and verifier. Conformance test vectors will pin a single convention before v0.1.0 final. Implementations SHOULD treat this as a fixable interop bug if it surfaces.

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

### 7.4 Per-channel recipient addressing shapes

The `channel.recipientAddressing` field is a JSON object whose exact shape is determined by `channel.kind`. v0.1 defines the following shapes:

- **`slack`** — `teamId`, `channelId`, optional `parentTs` (for thread replies), optional `userId` (for DMs).
- **`email`** — `to` (array of RFC 5322 addresses), optional `cc`, optional `bcc`, optional `inReplyTo` (Message-ID).
- **`discord`** — either `userId` (DM) or `channelId` (channel post).
- **`teams`** — `tenantId`, `teamId`, `channelId`.
- **`whatsapp`** — `phoneE164` (E.164-formatted phone number).
- **`googleChat`** — `spaceId`.
- **`imessage`** — either `appleId` or `phoneE164`.

Recipient endpoints SHOULD treat unknown `recipientAddressing` fields as opaque and MUST NOT fail verification on their presence (the strict-deserialization rule applies to the envelope-level fields, not to channel-shaped subordinate payloads).

---

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

**JsonWebSignature2020 (detached JWS).** Preferred for on-wire short-form carriage on channels with limited metadata capacity (email headers, chat block metadata fields). Uses RFC 7515 §A.5 detached JWS over the JCS-canonicalized envelope minus `proof.proofValue`. The JWS protected header MUST include:

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
3. **Strip the proof value.** Take a working copy of the envelope and remove `proof.proofValue`.
4. **Canonicalize.** Apply JCS (RFC 8785) to the stripped working copy.
5. **Verify the signature.** Validate `proof.proofValue` against the canonical bytes using the public key from step 2 and the algorithm pinned by `proof.cryptosuite` or the JWS protected header `alg`.
6. **Validate the time window.** Confirm `validFrom <= now <= validUntil` where `now` is the verifier's current wall clock. Allow a small clock-skew tolerance (RECOMMENDED: 60 seconds).
7. **Validate the algorithm.** Confirm the algorithm is in the supported set (`ES256` or `EdDSA`). Reject `alg: none`. Reject any vendor-specific algorithm not explicitly opted into.
8. **Validate the body hash (RECOMMENDED).** If the recipient has access to the actual outbound body bytes (the channel transport delivered both the envelope and the payload), compute SHA-256 over the body and compare against `credentialSubject.communication.bodySha256`. Reject on mismatch with error `APH_E009`.
9. **Emit the verified credential.** If all checks pass, the recipient MAY render a "Notarized" badge in its UI, store the verified credential for audit, and accept the message.

If any step fails, the verifier MUST reject the envelope and SHOULD emit the appropriate error code from §11.

### 8.4 Notary Key Material + Public-Key Discovery

A Notary Service operates on a public/private keypair. The PRIVATE key MUST be held under the Notary Service operator's exclusive control and is used to sign every envelope's `proof.proofValue` and the `notarySignature` field of any Delegation or Communication Mandate the notary mints. The PUBLIC key MUST be discoverable by ANY third-party verifier WITHOUT a prior trust relationship with the Notary Service or its operator.

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

A verifier MAY pin a preferred mechanism per notary (typically via configuration or via prior successful resolution). A verifier MUST NOT silently fall back from a stronger anchor to a weaker one mid-resolution; failures escalate to envelope rejection.

#### 8.4.7 Key rotation + overlap

Notary Service operators rotating a key MUST:

1. Publish the NEW key alongside the OLD key (multiple TXT records OR multiple `verificationMethod` entries in the DID Document) for a minimum overlap window. RECOMMENDED minimum overlap: 30 days.
2. Continue signing envelopes with the OLD key during the overlap window; do NOT switch the active signing key on day zero.
3. After the overlap window, switch the active signing key to the NEW key and set the OLD key's `notAfter` to a timestamp inside the overlap window.
4. Keep the OLD key's record visible (with a past `notAfter`) for a further window (RECOMMENDED 1 year) so verifiers checking older envelopes can still resolve the historical key.

Verifiers MUST consult the `notBefore`/`notAfter` window of the TXT record (or, for DID Documents, the per-`verificationMethod` validity metadata if present) and accept any envelope where the signing key was valid at the envelope's `decisionTimestamp`.

#### 8.4.8 Trust-on-first-use + pinning

Recipient applications that store a notary's resolved public key after the first successful verification MAY pin the key locally and prefer the pinned copy on subsequent verifications. Pinning is OPTIONAL in v0.1 and is RECOMMENDED for high-stakes verifiers (e.g., compliance-recording systems) that want to detect notary-key compromise via mismatch with the pinned copy.

When pinned-vs-published mismatch occurs, verifiers SHOULD raise a warning, SHOULD validate the envelope against BOTH the pinned key and the currently-published key, and MUST treat mismatch with both as a fatal verification failure.

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

### 9.2 Human-not-present flow

The human-not-present flow has five states (four progress states and one terminal-denial state). It is gated by a matching unexpired Delegation Mandate.

States:

- **`Drafted`** — Agent has prepared a message and submitted a notarization request referencing a Delegation Mandate.
- **`MandateIssued`** — Notary Service validated the Delegation Mandate and issued the Communication Mandate.
- **`EnvelopeIssued`** — Notary Service signed and emitted the envelope.
- **`Delivered`** — Terminal: envelope handed to the Channel Adapter.
- **`Denied`** — Terminal: no matching unexpired Delegation Mandate, OR a scope mismatch, OR a matched `NeverAllow` rule.

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

APH defines a closed set of ten error codes for v0.1. Implementations MUST use the codes below when emitting protocol-level errors and SHOULD include the `suggestedResolution` text (or a localized equivalent) in user-facing error displays.

| Code | Variant | Meaning | Suggested resolution |
|---|---|---|---|
| `APH_E001` | `InvalidEnvelopeSignature` | The envelope's `proof.proofValue` did not verify against the resolved public key over the canonical envelope bytes. | Verify the notary signing key matches `verificationMethod`; re-sign and retry. |
| `APH_E002` | `InvalidFlowTransition` | A state machine transition attempted that is not in the allowed-transition set for the current state. | Check the APH notarization flow state machine in §9 and align the implementation. |
| `APH_E003` | `MandateExpired` | A Communication Mandate or Delegation Mandate was consulted past its `expiresAt` / `validUntil`. | Issue a fresh mandate with a future expiry. |
| `APH_E004` | `RoleViolation` | A party attempted an operation not enumerated for its role in §5. | Confirm the party holds the correct `AphPartyRole` for the operation. |
| `APH_E005` | `ChannelNotAllowed` | The requested channel kind was not in the Delegation Mandate's `allowedChannels` list. | Grant the channel scope on the Delegation Mandate, or re-issue under AskEveryTime. |
| `APH_E006` | `NotarySignatureInvalid` | The notary's signature did not verify (distinct from `APH_E001`: this is the mandate-level signature, not the envelope-level signature). | Verify the notary's published JWK matches the `verificationMethod`; re-issue the mandate. |
| `APH_E007` | `HumanAuthenticationRequired` | An AskEveryTime path was triggered but the human was not reachable for interactive prompt. | Prompt the human, or wait until the human is reachable; alternatively, fall back to a Deferred-for-Review queue. |
| `APH_E008` | `NotaryServiceUnreachable` | A remote notary service did not respond within the configured timeout. | Check the notary endpoint's health; retry with exponential backoff. |
| `APH_E009` | `EnvelopeBodyHashMismatch` | The recipient computed a SHA-256 over the actual outbound body that did not match `communication.bodySha256`. | Re-hash the body and compare against the envelope; investigate transport corruption or tampering. |
| `APH_E010` | `UnsupportedAlgorithm` | The envelope declared a signing algorithm not in the supported set, or `alg: none`. | Use one of `ES256` or `EdDSA`; reject `alg: none`. |

---

## 12. Security Considerations

A full threat model is published as the companion document `security-considerations.md` in this repository. In summary: APH binds a human-issued credential to a specific outbound message body hash inside a bounded time window, making both replay attacks and post-issuance tampering independently detectable at the recipient boundary. Recipient Endpoints MUST validate the time window, MUST enforce the algorithm allow-list (rejecting `alg: none` and unrecognized algorithms), and SHOULD validate the body hash against the actual received payload bytes when available. Notary Service operators are responsible for protecting the notary's signing key with the same care they would apply to any production credential-issuance key.

---

## 13. IANA Considerations

**Media type.** APH envelopes are W3C Verifiable Credentials and use the existing `application/vc+ld+json` media type registered by W3C. v0.1 does NOT register a new media type. Implementations that need a distinct media-type indicator for transport routing MAY use the unregistered `application/aph+ld+json` by convention, but conformant verifiers MUST accept both.

**URI scheme.** APH defines the `aph://` URI scheme for protocol-level extension URIs (e.g., the A2A extension URI `aph://extensions/notarization/v1`). Formal IANA registration of the `aph://` URI scheme is deferred to v0.2. v0.1 uses the scheme by convention only, similar to how `did:` was used in early DID drafts prior to formal registration. Implementations MUST treat `aph://` URIs as opaque identifiers and MUST NOT attempt to dereference them as URLs.

**DNS underscore-prefixed sub-name.** APH §8.4.5 publishes notary public keys at `_aph._notary.<domain>`. v0.1 reserves the underscore-prefixed labels `_aph` and `_aph._notary` by convention. Formal registration in the IANA "Underscored and Globally Scoped DNS Node Names" registry is deferred to v0.2. The underscore-prefix convention follows established practice in DKIM (`_domainkey`), DMARC (`_dmarc`), and TLSA (`_<port>._<proto>`).

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
- **Mandate revocation.** A revocation list or status-credential mechanism will be defined in v0.2 for explicit invalidation of long-lived Delegation Mandates ahead of their `validUntil`.
- **`aph://` URI scheme registration.** Formal IANA registration of the `aph://` URI scheme will be pursued for v0.2.
- **N Lang static-type schema.** A companion statically-typed schema (machine-readable) will be published alongside the JSON Schema for implementations that want static-type guarantees.
- **Selective-disclosure conformance.** Full SD-JWT-VC profile conformance vectors, including key-binding JWTs and disclosed-field selection, will be added once the underlying IETF drafts stabilize.
- **Email-header IETF draft.** An Internet-Draft proposing an `APH-Attestation:` email header for SMTP carriage will be submitted to the appropriate IETF working group.
- **Media-bearing envelopes.** A profile for emitting C2PA `aph.send_authorization` assertions when the outbound message carries generated media is planned for v1.1.

---

End of APH v0.1 specification.
