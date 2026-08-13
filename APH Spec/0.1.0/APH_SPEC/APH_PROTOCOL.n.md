---
section: "APH Specification"
name: "APH Protocol Vocabularies"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Protocol — Roles, Vocabularies, Flows, Errors

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.


The closed value sets the protocol's JSON documents may carry, plus the two
notarization state machines and the error taxonomy.

These are declared as real enumerations rather than as prose beside a `str`
prop, so a consumer of this Snapp gets exhaustiveness from the type system
instead of a comment they have to trust.

## Party roles

Five roles participate in a notarization (§5.1). The separation between them
is the whole point of the design: a `HumanPrincipal` issues authority but
cannot notarize, and a `NotaryService` attests decisions but cannot issue
authority. Collapsing those two would let one party both grant a permission
and vouch for it, which destroys third-party verifiability — the property
the protocol exists to provide.

```nlang
mod blocks Roles {
  enum AphPartyRole {
    HumanPrincipal,
    AgentSender,
    NotaryService,
    ChannelAdapter,
    RecipientEndpoint,
  }
```

### Operations

The six operations a role may be permitted (§5.2). Every operation is
assigned to at least one role, and the assignment is what the permission
matrix checks before an action proceeds.

```nlang
  enum AphOperation {
    IssueDelegationMandate,
    IssueCommunicationMandate,
    Notarize,
    Transport,
    Verify,
    Reject,
  }
}
```

## Closed vocabularies

Value sets carried by envelope props (§7.1). Each is closed: a verifier that
meets an unrecognized value rejects the envelope rather than guessing.

### Channel kinds

The delivery media APH v0.1 defines (§7.1.5).

`google_chat` is snake_case while its siblings are single words. That is not
an oversight: an erratum pinned the snake_case spelling because every
published example and every signed fixture emits it, and changing it now
would invalidate credentials already in the field.

```nlang
mod blocks Vocabulary {
  enum ChannelKind {
    Slack,
    Email,
    Discord,
    Teams,
    Whatsapp,
    GoogleChat,
    Imessage,
  }
```

### Content class

How the communication relates to its conversation (§7.1.6). A recipient can
apply different policy to an unsolicited `New` message than to a `Reply`.

```nlang
  enum ContentClass {
    Reply,
    New,
    Mention,
    Dm,
    Channel,
    BulkSend,
    Broadcast,
  }
```

### Attestation mode

Who proved the authorization (§7.1.7) — the most consequential distinction
in the protocol. `PrincipalSigned` means the human's own key signed the
envelope; `NotaryAttested` means a notary asserts the human agreed, which is
strictly weaker. An ABSENT `attestationMode` on the wire means
`NotaryAttested`, so a verifier requiring the stronger mode must check for
it explicitly rather than assume.

```nlang
  enum AttestationMode {
    PrincipalSigned,
    NotaryAttested,
  }
```

### Policy decision

What the human decided (§7.1.7). `NeverAllow` is recorded as a decision but
never yields an envelope — a refusal is auditable precisely because it is
written down rather than inferred from an absence.

```nlang
  enum PolicyDecision {
    AlwaysAllow,
    AskEveryTime,
    NeverAllow,
  }
```

### Cryptosuites

The proof suites for the Data Integrity proof form (§8.2). `eddsa-jcs-2022`
is the default and the one every published example declares; the ES256 suite
exists for interoperability with ecosystems standardized on P-256.

```nlang
  enum Cryptosuite {
    EddsaJcs2022,
    EcdsaJcs2019,
  }
}
```

## Notarization flows

Two state machines, chosen by whether the human is present to decide.
Implementations MUST reject any transition the machine does not enumerate,
and SHOULD report `APH_E002` when they do.

### Human present

Seven states (§9.1). The ordering carries the security property:
`MandateIssued` is reachable only through `PendingDecision`, which is what
makes it structurally impossible to mint authority without having asked the
human. `Delivered` and `Denied` are terminal.

```nlang
mod blocks HumanPresentFlow {
  enum HumanPresentNotarizationState {
    Drafted,
    PendingDecision,
    Approved,
    MandateIssued,
    EnvelopeIssued,
    Delivered,
    Denied,
  }
}
```

### Human not present

Five states (§9.2), with no `PendingDecision` — the human decided in advance
by issuing a Delegation Mandate. The notary can still refuse, so `Drafted`
reaches `Denied` without any human interaction.

```nlang
mod blocks HumanNotPresentFlow {
  enum HumanNotPresentNotarizationState {
    Drafted,
    MandateIssued,
    EnvelopeIssued,
    Delivered,
    Denied,
  }
}
```

## Error taxonomy

Exactly ten codes, `APH_E001` through `APH_E010`, in declaration order
(§11). The set is closed and the numbering is part of the contract: other
implementations branch on these strings, so a duplicate or a renumbering
would make two distinct failures indistinguishable to a remote verifier.

```nlang
mod blocks Errors {
  enum AphErrorCode {
    // APH_E001 — envelope proof did not verify.
    InvalidEnvelopeSignature,
    // APH_E002 — a flow was driven along an edge it does not define.
    InvalidFlowTransition,
    // APH_E003 — mandate outside its validity window.
    MandateExpired,
    // APH_E004 — role may not perform the attempted operation.
    RoleViolation,
    // APH_E005 — channel outside the delegation's allowedChannels.
    ChannelNotAllowed,
    // APH_E006 — a mandate's notarySignature did not verify.
    NotarySignatureInvalid,
    // APH_E007 — a human decision is required and was not obtained.
    HumanAuthenticationRequired,
    // APH_E008 — the notary could not be reached.
    NotaryServiceUnreachable,
    // APH_E009 — delivered body does not match the attested hash.
    EnvelopeBodyHashMismatch,
    // APH_E010 — algorithm outside the allow-list; alg:none always.
    UnsupportedAlgorithm,
  }
}
```

## Key discovery

How a verifier recovers a notary's public key with no prior trust
relationship (§8.4). This is what makes an APH credential checkable by a
stranger rather than only within one vendor's walls.

### Mechanisms

Tried in preference order (§8.4.6), and there is no silent fallback from a
stronger mechanism to a weaker one. `did:key` is first because it needs no
network at all: the public key IS the identifier, so the check is entirely
offline.

```nlang
mod blocks Discovery {
  enum KeyDiscoveryMechanism {
    // Self-describing, offline (§8.4.3).
    DidKey,
    // DKIM-style TXT record at `_aph._notary.<domain>` (§8.4.5).
    DnsTxt,
    // `/.well-known/did.json` over TLS (§8.4.4).
    DidWeb,
  }
```

### Key algorithms

The algorithm travels WITH the key rather than being inferred from its
length, so a verifier never guesses which primitive to apply.

```nlang
  enum KeyAlgorithm {
    Ed25519,
    P256,
  }
}
```

### DNS TXT key record

One key published as a DKIM-style tag-list at `_aph._notary.<domain>`
(§8.4.5). The trust model is domain ownership, exactly as DKIM anchors email
signing keys to the sending domain.

Required tags are `v`, `alg`, and `k`. The optional tags disambiguate and
bound the key: `kid` is matched against the fragment of the proof's
`verificationMethod`, which is what makes rotation unambiguous while an old
and a new key are published side by side.

```nlang
mod blocks AphTxtKeyRecord {
  props {
    // Tag `v`. Literal "APHv1".
    version: str,
    // Tag `alg`. "ed25519" or "p256".
    alg: str,
    // Tag `k`. Public key bytes, base64url without padding.
    k: str,
    // Tag `kid`. Matches the verificationMethod fragment.
    #[optional(true)]
    kid: str,
    // Tag `did`. Full DID URL this entry is bound to.
    #[optional(true)]
    did: str,
    // Tag `notBefore`. RFC 3339.
    #[optional(true)]
    not_before: str,
    // Tag `notAfter`. RFC 3339.
    #[optional(true)]
    not_after: str,
  }
}
```
