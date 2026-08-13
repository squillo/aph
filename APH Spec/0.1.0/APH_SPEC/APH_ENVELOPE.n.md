---
section: "APH Specification"
name: "APH Notarization Envelope"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Notarization Envelope

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.


The credential itself: a W3C Verifiable Credential 2.0-shaped document that
binds one outbound agent action to the human authorization behind it (§7).

## Why every prop matters

A verifier does not trust the envelope's text. It re-canonicalizes the
document and checks the signature over the resulting bytes. Every prop below
is therefore part of what was signed, and adding, removing, or renaming one
describes a *different* credential than the one deployed notaries issue.

Wire names are camelCase and N Lang props are snake_case; the mapping is
mechanical (`aphVersion` → `aph_version`). One wire key has no identifier
form at all and is noted where it appears: `@context`. The `type` array is
spelled exactly as it appears on the wire, since N Lang permits `type` as a
prop name.

## The envelope

`aphVersion` pins the protocol revision, and a verifier rejects a version it
does not support. The `@context` and `type` arrays make the document a
Verifiable Credential to generic tooling. `issuer` names the notary whose
key verifies the proof, which is where key discovery starts.

```nlang
mod blocks NotarizationEnvelope {
  props {
    aph_version: str,
    // Wire: `@context`.
    context: Directional<str>,
    type: Directional<str>,
    // `urn:uuid:` identifier for this envelope.
    id: str,
    // DID of the notary that issued and signed the credential.
    issuer: str,
    // RFC 3339 validity window. Short windows are the v0.1 substitute for
    // on-wire revocation, which is deferred to v0.2.
    valid_from: str,
    valid_until: str,
    credential_subject: CredentialSubject,
    #[optional(true)]
    linked_mandate: LinkedMandate,
    proof: EnvelopeProof,
  }
}
```

## The claim

`credentialSubject` is the notarized claim: who authorized what, on which
channel, under which policy, attested by which notary (§7.1.2).

```nlang
mod blocks CredentialSubject {
  props {
    human_principal: HumanPrincipalRef,
    agent: AgentRef,
    channel: ChannelDescriptor,
    communication: CommunicationDescriptor,
    policy: PolicyDescriptor,
    notarization: NotarizationMetadata,
    // Registered optional extension (§7.5.1).
    #[optional(true)]
    apple_aur_acceptance: AppleAurAcceptanceClaim,
  }
}
```

### Human principal

The person on whose behalf the agent acted (§7.1.3). `display_name` exists
for consent prompts and audit logs, where a bare DID would be unreadable.

```nlang
mod blocks HumanPrincipalRef {
  props {
    // DID of the human principal.
    id: str,
    display_name: str,
  }
}
```

### Agent

The agent that produced the communication (§7.1.4). `agent_card_uri` is
optional because not every agent publishes an A2A Agent Card, and requiring
one would exclude agents that are otherwise perfectly notarizable.

```nlang
mod blocks AgentRef {
  props {
    // DID of the agent, typically `did:web:`.
    id: str,
    #[optional(true)]
    agent_card_uri: str,
    display_name: str,
    version: str,
  }
}
```

### Channel

Where the message is going (§7.1.5). `kind` is one of the closed channel
kinds; `recipient_addressing` is deliberately opaque (§7.4) so a new channel
can be supported without changing this type. Verifiers MUST NOT fail on
addressing sub-fields they do not recognize — the strict-parsing rule
applies to envelope-level fields, not to this payload.

```nlang
mod blocks ChannelDescriptor {
  props {
    kind: str,
    recipient_addressing: Positional,
  }
}
```

### Communication

What was sent (§7.1.6). `body_sha256` is the load-bearing field: it binds
this credential to one specific message body, so a signature cannot be
reused to authorize different content. A mismatch is `APH_E009`.

`preview` carries a short excerpt so the human sees what they are approving
at decision time rather than approving an opaque hash.

```nlang
mod blocks CommunicationDescriptor {
  props {
    content_class: str,
    // SHA-256 of the body: 64 lowercase hex characters.
    body_sha256: str,
    body_size: u64,
    preview_lines: u32,
    preview: str,
  }
}
```

### Policy

The authorization decision and the scope that produced it (§7.1.7).
`delegation_mandate_id` is absent for a one-shot `AskEveryTime` grant, where
the human approved this single send directly rather than in advance.

`act_chain` is an RFC 8693 act chain of DIDs — the evidence trail showing
which principal acted for whom when authority passed through more than one
hop.

```nlang
mod blocks PolicyDescriptor {
  props {
    decision: str,
    matched_scope: str,
    #[optional(true)]
    delegation_mandate_id: str,
    act_chain: Directional<str>,
  }
}
```

### Notarization metadata

Which notary decided, when, and how long it took (§7.1.8).
`decision_latency_ms` is audit evidence: a decision returned in a handful of
milliseconds is unlikely to have involved a human reading anything.

```nlang
mod blocks NotarizationMetadata {
  props {
    notary_service: NotaryServiceRef,
    // RFC 3339 decision timestamp.
    decision_timestamp: str,
    decision_latency_ms: u64,
  }
}
```

### Notary service

Identity of the notary (§7.1.9), used to resolve its verification key
(§8.4).

```nlang
mod blocks NotaryServiceRef {
  props {
    id: str,
    name: str,
    version: str,
  }
}
```

## Linked mandates

Cross-protocol links carried alongside the send authorization (§7.1.10).
This is how a single agent action can carry both a payment authorization and
a communication authorization while keeping them separately signed.

```nlang
mod blocks LinkedMandate {
  props {
    // URI of an AP2 IntentMandate.
    #[optional(true)]
    ap2_intent_mandate_uri: str,
    // Registered optional extension (§7.5.2).
    #[optional(true)]
    ap2_signed_payload_b64: str,
    // Registered optional extension (§7.5.3).
    #[optional(true)]
    vault_mutation: VaultMutationMandate,
  }
}
```

## The proof

The signature block (§7.1.11, §8.2), either a W3C Data Integrity Proof or a
detached JWS. `cryptosuite` is absent for the JWS form. `proof_purpose` is
always `assertionMethod` for APH.

`proof_value` is a multibase base58btc signature over the canonical form of
the envelope with `proofValue` itself set to the empty string — a signature
cannot cover itself, and emptying rather than removing the member is the
convention the reference implementation pins.

```nlang
mod blocks EnvelopeProof {
  props {
    // DataIntegrityProof or JsonWebSignature2020.
    type: str,
    #[optional(true)]
    cryptosuite: str,
    // DID URL of the key, including its fragment.
    verification_method: str,
    created: str,
    proof_purpose: str,
    proof_value: str,
  }
}
```

## Registered extensions

Optional, omitted-when-absent fields whose names and shapes the
specification pins (§7.5). Verifiers MUST tolerate them. An envelope
carrying none of them is byte-identical to a pre-extension envelope, so
existing signatures stay valid.

### Apple AUR acceptance

Attests that the human accepted Apple's Acceptable Use Requirements on the
notarizing device before an on-device model produced the communication
(§7.5.1).

```nlang
mod blocks AppleAurAcceptanceClaim {
  props {
    user_id: str,
    device_id: str,
    // SHA-256 hex of the accepted AUR snapshot text.
    aur_version_hash: str,
    accepted_at: str,
    document_kind: str,
  }
}
```

### Vault mutation

Binds the envelope to a vault-mutation mandate when the notarized action
changes vault state (§7.5.3).

The variants are internally tagged on the wire under the key `kind`. A type
definition carries either props or enums but never both, so they live in
their own container beside the mandate and the prop references them by
qualified path.

```nlang
mod blocks VaultMutation {
  enum VaultMutationKind {
    WriteInto { dest_vault_id: str },
    ShareFrom { src_vault_id: str },
    CrossVaultPromote { artifact_id: str },
    Redelegate { downstream_grantee_id: str },
    Revoke,
    BridgeStageTransition { from_stage: str, to_stage: str },
    Custom { snapp_id: str, mutation_slug: str },
  }
}
```

The interior keys here are snake_case while the envelope around them is
camelCase. That asymmetry is deliberate: it is the deployed wire shape, and
re-canonicalizing an already-signed envelope must not change its bytes.

```nlang
mod blocks VaultMutationMandate {
  props {
    kind: $::*::VaultMutation::VaultMutationKind,
    grant_scope_id: str,
    #[optional(true)]
    ap2_signed_payload_b64: str,
  }
}
```
