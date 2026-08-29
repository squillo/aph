---
section: "APH Specification"
name: "APH Mandates"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Mandates

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.


The two documents that carry authority (§6). A Delegation Mandate is
standing authority a human grants an agent; a Communication Mandate is
single-use authority for one specific message.

A Delegation Mandate is signed **by the human** and countersigned by the
notary; a Communication Mandate is signed by the notary alone, because in the
human-not-present flow the human is asleep and cannot sign each message. A signature never covers itself, but the
two on a Delegation Mandate do not cover the same bytes:
`principal_signature` covers the JCS-canonical form minus **both** signature
fields, and `notary_signature` covers it minus **only itself**, with
`principal_signature` present. That asymmetry is what makes the notary's
signature a countersignature over what the human actually signed rather than
a second, independent claim (§6.1).

## Delegation Mandate

Standing authority: which channels, for how long, at what rate (§6.1).
Issued once, referenced by many Communication Mandates.

`allowed_channels` is the scope check that produces `APH_E005`: a channel
not in this list is refused, so an agent granted Slack access cannot quietly
send email.

`valid_until` deserves particular attention. Expiry is the *primary*
revocation mechanism in v0.1, because on-wire revocation transport is
deferred to v0.2 — the notary stops issuing against a revoked mandate
immediately, but a recipient has no way to learn of the revocation until the
mandate lapses. That is why the specification recommends short windows,
hours to days rather than weeks to months.

```nlang
mod blocks DelegationMandate {
  props {
    // `urn:uuid:` mandate identifier.
    id: str,
    // DID of the human granting authority.
    human_principal_did: str,
    // DID of the agent receiving it.
    agent_did: str,
    // Channel kinds this mandate permits. Non-empty.
    allowed_channels: Directional<str>,
    // Recipient classes the human granted (§6.2, RFC 0005). Optional and
    // absent-when-unconstrained: this struct is SIGNED, and absence keeps
    // every previously signed grant's canonical bytes intact. An EMPTY
    // list is a coherent grant allowing no consumer at all — a different
    // statement, and one a principal may sign on purpose.
    #[optional(true)]
    allowed_recipient_classes: Directional<str>,
    // Sends per hour; absent means unlimited.
    #[optional(true)]
    rate_limit_per_hour: u32,
    // RFC 3339 validity window.
    valid_from: str,
    valid_until: str,
    // The HUMAN's own signature over the canonical form minus both
    // signature fields (§6.1). This is the root of every credential
    // issued under this mandate: without it, no party has proved the
    // human granted anything.
    principal_signature: str,
    // The notary's countersignature over the canonical form minus this
    // field — so it covers `principal_signature` and cannot be detached
    // from what the human actually signed.
    notary_signature: str,
  }
}
```

## Communication Mandate

Single-use authority for one message, bound to its body by hash (§6.2).

`delegation_mandate_id` is absent for a one-shot `AskEveryTime` decision,
where the human approved this single send directly and no standing authority
exists to reference.

The principal and agent DIDs are restated here rather than only referenced
through the parent. That redundancy is deliberate: it lets a verifier detect
a mandate that has been re-pointed at a different parent.

`body_sha256` is what makes this mandate single-use in substance rather than
only by convention — it authorizes one specific body, not any body. The
specification recommends a five-minute `expires_at`.

```nlang
mod blocks CommunicationMandate {
  props {
    id: str,
    #[optional(true)]
    delegation_mandate_id: str,
    // Restated for tamper detection.
    human_principal_did: str,
    agent_did: str,
    channel_kind: str,
    // Channel-shaped, opaque to the protocol (§7.4).
    recipient_addressing: Positional,
    content_class: str,
    // SHA-256 of the body: 64 lowercase hex characters.
    body_sha256: str,
    body_size: u64,
    policy_decision: str,
    issued_at: str,
    expires_at: str,
    notary_signature: str,
  }
}
```

## Lifecycle

Revocation is normative at the conceptual layer in v0.1 (§6.3.1): a notary
tracks a revoked state per Delegation Mandate and MUST NOT issue new
Communication Mandates against a revoked or expired parent. Signatures
already issued remain cryptographically valid — revoking authority does not
retroactively unsign anything, which is why short validity windows carry so
much weight.

Expiration is final (§6.3.2). An expired mandate is not re-activated; a new
mandate must be issued.
