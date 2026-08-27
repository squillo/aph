# RFC 0002 — A service-act channel binding

- **Status:** Draft
- **Issue:** _(to be opened via `.github/ISSUE_TEMPLATE/rfc.yml`)_
- **Spec sections touched:** §7.1.5 (`ChannelDescriptor`), §7.1.6 (`CommunicationDescriptor`), §7.4 (per-channel addressing shapes); non-normative §1.1.1

## The problem

APH v0.1 cannot express an act that terminates at a **service** rather than at
a human reader.

`credentialSubject.channel` is required, and §7.1.5 closes `kind` to seven
human-messaging platforms: `slack`, `email`, `discord`, `teams`, `whatsapp`,
`google_chat`, `imessage`. `credentialSubject.communication.contentClass` is
required and §7.1.6 closes it to seven message shapes: `Reply`, `New`,
`Mention`, `DM`, `Channel`, `BulkSend`, `Broadcast`.

An agent asking another agent to mutate a record in a system of record fits
neither enum. There is no conformant envelope for it.

This is not a hypothetical. §7.5.3 already registers
`linkedMandate.vaultMutation` "when the notarized action changes vault state,"
with a `Custom { snapp_id, mutation_slug }` variant for application-defined
mutations. The protocol therefore **already models the act** — it just cannot
describe where the act lands. An envelope carrying a `vaultMutation` today must
still name a messaging channel that is not involved, which makes a signed field
false in order to satisfy a required one.

The first external integration to hit this is the A2A record-mutation example
in `examples/a2a-database-change/`, which currently carries explicit
non-conformant placeholders rather than borrow `email` and misrepresent itself.

## The design

Two additive enum entries and one addressing shape.

**1. `§7.1.5` — add `service` to the channel-kind enum.**

```
slack | email | discord | teams | whatsapp | google_chat | imessage | service
```

This does not violate §1.1.1's rule that `channel.kind` names the *end-delivery
medium and never the agent-to-agent rail*. It honors it. When an agent asks a
service to change state, the service endpoint **is** the end-delivery medium;
A2A remains the rail, exactly as SMTP remains the rail under DKIM. The value is
`service`, not `a2a`, precisely so this distinction cannot blur — naming the
rail would be the mistake §1.1.1 forbids.

**2. `§7.4` — the `service` addressing shape.**

| Field | Type | Required | Description |
|---|---|---|---|
| `serviceEndpoint` | string | yes | Absolute `https://` URL of the endpoint the act is delivered to. |
| `resourceId` | string | yes | Opaque service-scoped identifier of the resource being acted on. |
| `operation` | string | yes | Service-scoped operation name (e.g. `customer.update`). |

`serviceEndpoint` MUST be `https://`. A verifier MUST refuse an envelope whose
`serviceEndpoint` origin differs from the origin it received the act on: an
authorization to write to one service must not be replayable against another.
This mirrors the same-origin binding §6.3.3 already applies to status URLs.

**3. `§7.1.6` — add `Mutation` to the `contentClass` enum.**

Distinguishes "this act changes state" from the seven message shapes. Three
real mechanisms carry that distinction — and one that does not, named here so
nobody reaches for it. The per-act Communication Mandate carries a required
`contentClass` (§6.2) drawn from the same closed enum, which MUST equal the
value the resulting envelope carries — so every notarized mutation is
recorded as a mutation at both the mandate and the envelope layer, inside the
signature. Recipients can apply policy by content class (§7.1.6), refusing
`Mutation` from counterparties they only accept messages from. And
standing-authority separation comes from `allowedChannels`: a Delegation
Mandate that omits `service` cannot authorize a service act at all. What a
Delegation Mandate can NOT do — deliberately, per §7.1's design statement
("channel, rate, and time — nothing else") — is constrain by content class, so the
separation "a human who let their agent send email has not thereby let it
modify records" is enforced at the channel boundary, not the content-class
boundary. This RFC does not change that.

## Alternatives considered

**Borrow an existing channel kind.** Rejected. It puts a false statement inside
the signature. The signed field would say `email` about an act with no email in
it, and every downstream audit would inherit the lie.

**Make `channel` optional when `vaultMutation` is present.** Rejected. It
creates two envelope shapes a verifier must branch on, and it removes the
*destination* from the signed material precisely when the destination matters
most — a write. Replay to a different endpoint becomes undetectable.

**A new top-level `act` block parallel to `communication`.** Rejected for v0.2
as too large a change for the demonstrated need, and it would duplicate
`bodySha256` / preview machinery that already works unchanged. Worth
revisiting if service acts grow fields that have no communication analogue;
noted rather than dismissed.

**`a2a` as the kind name.** Rejected — it names the rail, which §1.1.1
forbids, and it would be wrong for a service act delivered over plain HTTPS
with no A2A involved.

## Compatibility

**Additive; not breaking.** Both changes add values to closed enums.

- An envelope minted yesterday is unaffected — no existing field changes shape,
  and canonical bytes of existing envelopes are untouched.
- A verifier that **correctly implements §7.1's closed sets** refuses an
  envelope with `kind: "service"` under the strict-parse rule, exactly as it
  refuses any unrecognized channel kind. That is the intended conservative
  failure: an old verifier does not silently accept an act it cannot describe.
  The independent TypeScript implementation behaves this way today.
- **The v0.1 Rust reference implementation does not implement those closed
  sets** — it types `channel.kind` and `communication.contentClass` as
  unvalidated strings — so it, and the four language bindings built on it,
  will silently **accept** a `service` envelope rather than refuse it. Closing
  that gap is a stated prerequisite of this RFC: the closed-set enforcement
  MUST land in the reference implementation before or with this widening, or
  the addition ships as a live interop split in which two conformant-claiming
  verifiers reach opposite verdicts on the same bytes.
- Because acceptance-versus-refusal is therefore implementation-dependent in
  v0.1 as deployed, the producer rule is load-bearing, not courtesy:
  producers MUST NOT emit `service` until they have reason to believe the
  recipient understands it — the AgentCard extension declaration (§10.1) is
  the existing discovery mechanism for that. Until enforcement lands
  everywhere, this rule is the only thing preventing an un-updated verifier
  from acting on an envelope it cannot describe.

Per the maintainers' ruling under CONTRIBUTING.md's pre-production exception,
this change lands **in place in the 0.1 specification** — no version fork —
recorded as a dated revision entry in the CHANGELOG and the spec's revision
banner. One inconsistency is noted for separate repair rather than silently
resolved here: CONTRIBUTING.md's SemVer table calls an additive value PATCH
at 0.x, while §7.1.5 says new channel kinds are "additive in 0.x minor
versions." Whichever wording wins, it should win explicitly, in its own
change.

## Security considerations

**Scope escalation is the live threat, and its gate is `allowedChannels`.** A
Delegation Mandate cannot constrain by content class (§7.1), so the moment
`service` exists, adding it to a mandate's `allowedChannels` is what converts
a messaging grant into a write grant — categorically more dangerous authority
acquired by a one-word change to a familiar list. Implementations MUST surface
that distinction in the human-facing grant UI: a consent screen that lists
`service` among messaging channels without distinguishing it invites a human
to grant write access believing they granted send access. The per-act record
does carry the distinction — the Communication Mandate's and envelope's
`contentClass: "Mutation"` are both inside the signature — but that is audit
trail, not consent; the consent moment is the channel grant.

**Replay across services** is addressed by the `serviceEndpoint` same-origin
rule above, and is the reason `serviceEndpoint` is required rather than
optional.

**Short windows matter more here.** §1.1.1 recommends hours-to-days validity
for messaging. A service act SHOULD use minutes: the act is idempotency-
sensitive, and there is no human reading it who would notice something wrong.

**No new key material, no new discovery path, no new signing rule.** The
verification order (§8.3) and discovery order (§8.4.6) are untouched.

## What this deliberately does not do

- **Does not define a mutation semantics vocabulary.** `operation` is an opaque
  service-scoped string. §7.5.3's `vaultMutation` already carries structured
  mutation kinds for implementations that want them; this RFC does not compete
  with it.
- **Does not make the service endpoint dereferenceable by the verifier.** No
  verifier is asked to call `serviceEndpoint` — it is compared, never fetched.
- **Does not address idempotency or exactly-once delivery.** An APH envelope
  authorizes an act; it does not guarantee the act happened once. Services
  needing that keep their own idempotency keys, and `expectedRevision`-style
  optimistic concurrency belongs in the body, where `bodySha256` already
  covers it.
- **Does not add a channel kind for voice, SMS, or any other human medium.**
  Those are separate cases with separate addressing shapes.
