# APH A2A Extension Descriptor

> Companion to `spec/aph-0.1.md`. Defines how an agent advertises APH (Agent
> per Human) support on its A2A AgentCard, and how a verifier discovers it.

## 1. Overview

Agents that support APH advertise it on their A2A AgentCard via a standard
`AgentExtension` declaration. Recipient endpoints — including endpoints
operated by a different vendor than the sending agent — discover APH support
by scanning `agent_card.extensions` for an entry whose `uri` equals the
APH extension URI pinned in §2. Discovery is a one-time, out-of-band step
performed when a recipient first encounters an unknown agent; the result
can be cached for the lifetime of the AgentCard.

The descriptor itself carries no protocol parameters in v0.1. Its presence
signals support; the wire format and verification rules live in the main
APH specification.

## 2. Extension URI

The pinned URI for the APH notarization extension is:

```
aph://extensions/notarization/v1
```

Reference implementations MUST declare this as a single string constant
(for example `APH_EXTENSION_URI`) and MUST NOT construct it from
substrings at call sites. The URI is opaque in v0.1: it is not
dereferenceable, and verifiers MUST NOT attempt to resolve it. It serves
as a stable discriminator only.

The `aph://` scheme is reserved for APH protocol identifiers. v0.2 may
move to a dereferenceable `https://w3id.org/aph/v1` URI (see §6).

## 3. Descriptor shape

The descriptor uses the standard A2A `AgentExtension` shape:

```json
{
  "uri": "aph://extensions/notarization/v1",
  "description": "APH (Agent per Human) outbound communication notarization",
  "required": false
}
```

Field-by-field:

- `uri` — the extension URI. MUST equal the pinned constant in §2 byte for
  byte. Verifiers compare with exact string equality (no normalization,
  no case folding).
- `description` — human-readable description used by recipient UIs when
  surfacing extension lists to operators. The recommended value is the
  string shown above; implementations MAY localize it but SHOULD keep the
  English form available as a fallback.
- `required` — whether the agent REQUIRES recipients to verify APH
  envelopes before accepting messages from this agent. Set to `false` for
  v0.1 because most recipient endpoints still need permissive fallback
  behavior during the rollout window. `true` is permitted but uncommon;
  agents that set `true` MUST be prepared for recipients with no APH
  support to reject their messages outright.

## 4. Worked example: AgentCard with APH

A complete A2A AgentCard JSON document declaring APH alongside one other
extension might look like:

```json
{
  "name": "Example Outreach Agent",
  "description": "Drafts and sends outbound messages on behalf of a single human principal.",
  "url": "https://agents.example.test/outreach",
  "version": "1.4.2",
  "capabilities": {
    "streaming": true,
    "push_notifications": false
  },
  "skills": [
    {
      "id": "reply_to_thread",
      "name": "Reply to thread",
      "description": "Compose a reply in an existing email or chat thread."
    },
    {
      "id": "send_new_message",
      "name": "Send new message",
      "description": "Send a new outbound message on a configured channel."
    }
  ],
  "extensions": [
    {
      "uri": "https://example.test/extensions/threading/v2",
      "description": "Example threading hints extension",
      "required": false
    },
    {
      "uri": "aph://extensions/notarization/v1",
      "description": "APH (Agent per Human) outbound communication notarization",
      "required": false
    }
  ]
}
```

Notes on the example:

- The `extensions` array is order-independent. Verifiers MUST locate the
  APH entry by `uri` equality, not by array position.
- The `url` shown is in the reserved `example.test` TLD; it is not a
  resolvable production endpoint.
- The `capabilities` and `skills` fields are illustrative only; APH places
  no constraints on their contents.

## 5. Discovery flow

The recipient-side discovery flow is:

1. A Recipient Endpoint receives an inbound message claiming to come from
   an Agent.
2. The endpoint fetches the agent's AgentCard from the agent's
   `/.well-known/agent-card.json` URL (or any equivalent A2A AgentCard
   discovery mechanism the endpoint already supports).
3. The endpoint scans `agent_card.extensions[]` for an entry where
   `uri == "aph://extensions/notarization/v1"`.
4. If the entry is found, the endpoint enables APH envelope verification
   for subsequent messages from this agent. The endpoint MAY cache this
   determination for the configured AgentCard lifetime.
5. If the entry is absent and the recipient's deployment policy REQUIRES
   APH (for example a regulated-industry deployment), the endpoint
   REJECTS messages from the agent and SHOULD log the rejection for
   audit.
6. If the entry is absent and the recipient's deployment policy is
   permissive, the endpoint MAY display a "Not notarized" UI indicator
   and proceed to deliver the message under the recipient's existing
   trust rules.

A recipient endpoint that receives an APH envelope on the wire from an
agent whose AgentCard does NOT declare the extension SHOULD treat the
envelope as advisory rather than authoritative, because the agent has
not committed to supporting the protocol across all of its outbound
traffic.

## 6. Future Work

The following items are NOT in scope for v0.1 and are tracked for v0.2 or
later:

- v0.2 — Dereferenceable URI. The `aph://` scheme will be retained as an
  alias, and a parallel `https://w3id.org/aph/v1` URI will resolve to a
  JSON-LD context document describing the extension and its parameters.
- v0.2 — Extension parameter set. The descriptor will gain an optional
  `params` object whose keys MAY include `supported_algorithms` (closed
  enum, e.g. `["ES256", "EdDSA"]`), `min_envelope_version`, and a
  `discovery_endpoint` URL the recipient MAY query for richer agent
  metadata.
- v0.2 — Relationship to W3C VC API discovery. The descriptor will
  document the mapping between APH's extension entry and the W3C VC API
  Service Discovery mechanism so a single AgentCard can simultaneously
  advertise APH and a generic VC verifier.
- v0.2 — Multi-version coexistence. The scheme for an agent that supports
  both `aph://extensions/notarization/v1` and a future
  `aph://extensions/notarization/v2` will be specified, including the
  recipient's selection algorithm.
