# A2A + APH — an agent authorizing a database change

> **Status: illustrative draft, NOT a conformant example.** Two fields in
> `envelope.json` carry `PLACEHOLDER_NOT_CONFORMANT_SEE_RFC_0002` because APH
> v0.1 has no wire value for them, and the proof is a literal placeholder
> string rather than a signature. Read [RFC 0002](../../rfcs/0002-service-act-channel.md)
> before building against this. Every *other* field here is normative v0.1.

This example shows one agent asking another agent to mutate a record in a
system of record, with the request carrying portable proof that a specific
human authorized that specific change.

## The shape

A2A is the rail. APH is the license the rail carries.

```
Scott ──grants mandate──▶ Scott's agent
                              │
                              │  A2A  message/send
                              │  Message.metadata["aph://extensions/notarization/v1"]
                              ▼
                         SSoT agent ──verifies envelope──▶ applies mutation
                                          │
                                          └─ resolves notary key from
                                             did:web:notary.squillo.com
                                             (no Squillo account needed)
```

Nothing in the verification path belongs to the sender. The SSoT service
resolves the notary's key from public naming it can reach on its own, so a
stranger can check the claim without a relationship to the issuer.

## Files

| File | What it is |
|---|---|
| `agent-card.json` | The **recipient's** A2A AgentCard, declaring the APH extension with `required: true` — this service refuses un-notarized mutations. |
| `mutation-body.json` | The exact bytes the envelope commits to. `sha256` = `e530d871…88803e2`, 205 bytes. |
| `a2a-message-send.json` | The A2A JSON-RPC request, envelope riding in `Message.metadata` under the URI-namespaced key. |
| `envelope.json` | The APH envelope authorizing the mutation. |

## Why `required: true` here

`spec/a2a-extension.md` §3 sets `required: false` as the v0.1 default, because
most recipients still need permissive fallback during rollout. A
system-of-record mutation endpoint is the case where `true` is right: there is
no meaningful "deliver it anyway, flagged as unverified" behavior for a write.
Per §5 step 5, a recipient whose policy requires APH rejects and logs.

## What the recipient MUST do, in order

Per spec §8.3. The order matters — each step assumes the previous one held.

1. **Strict-parse** the envelope. Unknown fields are a failure, not a warning (§7.1).
2. **Resolve the notary key** via §8.4.6 discovery order: `did:key` → DNS TXT → `did:web`. Absence advances to the next mechanism; *failure* refuses.
3. **Verify the signature** over the JCS canonicalization (RFC 8785).
4. **Check the time window** — `validFrom` / `validUntil`. This example uses 15 minutes; a mutation authorization should be short.
5. **Check revocation** — resolve the status endpoint from the notary's own `did:web`, never from anything the sender supplied. `APH_E015` on a revoked mandate (§6.3.3).
6. **Recompute `bodySha256` over the received bytes** and compare. This is the step that makes the authorization non-transferable to a different change. **Hash what arrived — never re-serialize the parsed object**, or a canonicalization difference silently breaks the binding.
7. **Check `attestationMode`.** For a write, require `PrincipalSigned` if you want the human's own key on it; absent means `NotaryAttested` (§7.1.7). A verifier that requires `PrincipalSigned` MUST refuse `NotaryAttested` up front rather than discovering the weaker claim later.
8. **Apply the mutation** only if every step above passed.

## The `linkedMandate.vaultMutation` binding

The mutation semantics are already normative — §7.5.3 registers
`linkedMandate.vaultMutation` for exactly the case where "the notarized action
changes vault state." The `Custom` variant carries application-defined shapes:

```json
"vaultMutation": {
  "kind": { "kind": "Custom", "snapp_id": "ssot.me", "mutation_slug": "customer.update" },
  "grant_scope_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
}
```

**Casing warning (§7.5.3):** this object's interior keys are `snake_case`
(`grant_scope_id`, `mutation_slug`) while the rest of the envelope is
`camelCase`. That is pinned deliberately — it mirrors the originating
implementation byte-for-byte, and re-canonicalizing an already-signed envelope
MUST NOT change its bytes. Do not "fix" it.

## What does NOT work yet

`credentialSubject.channel` is required, and its `kind` is a **closed** enum of
seven human-messaging platforms (`slack`, `email`, `discord`, `teams`,
`whatsapp`, `google_chat`, `imessage`). `communication.contentClass` is closed
too (`Reply`, `New`, `Mention`, `DM`, `Channel`, `BulkSend`, `Broadcast`).

A record mutation is neither. There is no honest value to put in either field,
so this example puts a placeholder that cannot be mistaken for a real one
rather than borrowing `email` and pretending. [RFC 0002](../../rfcs/0002-service-act-channel.md)
proposes the additive fix.

## Governance note for integrators

Per [`CONTRIBUTING.md`](../../CONTRIBUTING.md), APH's pre-production exception
— corrections landing in place without a version bump — expires when someone
outside this repository ships an artifact that **asserts wire facts**: code
that mints, parses, or verifies an envelope, or a schema carrying
`aphVersion` / `attestationMode` / `bodySha256` / an `APH_E*` code as data.

If you are building against this example, **tell us before you ship that**, not
after. An exception that expires on an event nobody reports is one that expired
silently.
