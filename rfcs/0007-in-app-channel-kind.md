# RFC 0007 — A channel kind for an in-application messaging surface

*`squillo`, beside `discord` — a peer, not a layer across it.*

- **Status:** Accepted
- **Author:** Scott Wyatt
- **Issue:** [#4](https://github.com/squillo/aph/issues/4)
- **Spec sections touched:** §7.1.5 (`ChannelDescriptor.kind`), §6.2
  (`CommunicationMandate.channelKind`).

## Decision

**Accepted 2026-08-28**, by the sole maintainer, the same day it was
requested.

**Read the limitations before the reasoning; they are unusual and a reader is
entitled to weigh them.**

- **The applicant and the registry owner are the same organization.** This
  document adds a vendor's own name to a vocabulary that vendor maintains.
  RFC 0004 — published earlier the same day — states that a request from the
  authoring organization gets *more* scrutiny than an outside one, and that a
  variant would not be minted by fiat. This was decided by one person, who is
  that organization, with no second reviewer, hours after that sentence was
  written.
- **What would have made it right, and was not done:** an independent
  reviewer. The project's second-maintainer requirement is open and unfilled.
  The decision was taken anyway, deliberately and on the record, rather than
  deferred until it could be reviewed.
- **What partly mitigates it:** the technical case is the one that would be
  granted to any outside vendor, stated below in a form an outsider can check
  rather than take on trust. The requester explicitly declined an open vendor
  arm, offered to drop the claim entirely if refused, and reported no urgency.
  And the status quo it replaces — borrowing `email` for a path that never
  touches mail — is something this project already rejected in writing at
  RFC 0002, so leaving it in place was itself non-conformant.
- **What does not mitigate it:** none of that changes the fact that the first
  vendor added to this registry after it was closed was the registry's own. A
  later maintainer who finds this uncomfortable is reading it correctly.

**The structural fix is not another RFC.** A vendor registry curated by a
vendor is awkward however carefully each entry is argued, and this project
already has provisional IANA registration drafts prepared. Moving the
channel-kind vocabulary to a registry this organization does not own is the
answer to the category of problem this decision is an instance of, and it
should not wait for the next applicant to raise it.

## The problem

An implementer runs two agent-to-agent paths. After applying §7.1.5's axis
rule per site, they diverge:

- One delivers over ordinary mail into a real mailbox. `email` is correct and
  settled.
- The other maps channel verbs onto **their own in-application messaging
  surface**, where a human reads the message in their client. It is not mail.
  It is none of the other six. And it is not `service`: RFC 0002 drew that
  line precisely, and a service act terminates at a service endpoint while
  this terminates at a **human reader**.

So that path currently carries `email`, which parses, verifies, and is false —
it names a medium the message never touches. **This project already rejected
exactly that**, in RFC 0002's own alternatives:

> **Borrow an existing channel kind.** Rejected. It puts a false statement
> inside [the signature].

Leaving the status quo would mean telling an implementer to keep doing the
thing we refused to do ourselves.

### Why this is reach, not bookkeeping

The strongest form of the request is not "let us label our own traffic." It
is that **a user's agent should be able to hold an APH-notarized conversation
with another organization's agent on this medium, and have the recipient's
verifier make a real §8.3.1 step-4 decision about it.**

Today that cannot be expressed conformantly. Either the envelope names a
medium that is not involved — a false signed field, the defect RFC 0002
exists to remove — or the traffic stays outside APH altogether.

That reframes the question. **Every kind in §7.1.5 exists so that a recipient
can decide about traffic on that medium.** A medium carrying real cross-
organization agent-to-human messages, with no entry in the vocabulary, is
reach the protocol does not have — not a convenience the vendor lacks.

## The design

**One additive value: `squillo`.**

```
slack | email | discord | teams | whatsapp | google_chat | imessage
      | service | squillo
```

It names the medium where an application's own messaging surface delivers a
message to a human reading it in that application's client — the same
category of fact `slack`, `discord`, and `teams` already name.

### The generalization test, which is the part worth checking

The test that killed `a2a_email` in RFC 0005 was decomposition: if recipient
class belonged in `kind`, then `a2a_slack`, `a2a_discord`, `a2a_teams` and the
rest all follow, so the set does not grow by one — it **doubles**, and doubles
again for the next refinement. A refinement that must be applied to every
member of a set is not a member of that set.

**This does not decompose.** `squillo` sits *beside* `discord` as a peer, not
*across* the set as a modifier. It adds one member to a set six of whose seven
members are already vendor in-application surfaces. The set grows by one and
stays the same shape.

### Why a concrete vendor name rather than a generic `in_app`

A generic value was drafted and rejected, and the reasoning is recorded
because it is the closer call of the two:

**`kind` is where a recipient's policy decision reads.** A recipient whose
policy accepts one application's in-app surface but not another's could not
express that against a generic value — it would have to descend into the
addressing block to recover a distinction `kind` exists to carry. The existing
six are concrete vendor names precisely *because* recipient policy differs by
vendor, and a generic bucket would be a regression dressed as tidiness.

The argument for a generic value was fairness of registry growth: each
addition is a flag day for deployed verifiers, and charging the ecosystem one
per vendor while the curator is a vendor is a cost this project should be
reluctant to impose. That concern is real and it survives this decision — but
it is an argument for **moving the registry**, not for making its entries less
useful. Answering a governance problem by degrading the wire is the wrong
trade, and the Decision block above names the actual fix.

## Alternatives considered

**A generic `in_app` kind.** Rejected, per above: it moves a policy decision
off `kind` and into addressing, for every recipient, to spare the registry a
growth problem that belongs elsewhere. Available again if a future maintainer
weighs it differently.

**Keep borrowing `email`.** Rejected — a false statement inside a signature,
per RFC 0002's own alternatives.

**Rule it off-spec; the implementer drops the channel claim.** Offered by the
requester and genuinely workable. Rejected because the path delivers a real
message to a real human on a real medium, and a vocabulary that cannot name
that is incomplete — the gap would recur for every application with an in-app
surface, which is an argument for admitting the category rather than refusing
its first member.

**Reviving the original `"squillo"` value as it was used.** Not what this is,
and the distinction is load-bearing. That value was a membership SCOPE sitting
in the `kind` field — an axis error, correctly and permanently refused in
RFC 0004. This is the DELIVERY MEDIUM, a different fact that happens to share
a name. The requester's SMTP path stays `email`.

## Compatibility

**Additive; MINOR at 0.x**, per CONTRIBUTING's corrected rule — a new
closed-vocabulary value is additive for the producer and **refusing** for any
consumer that has not updated, which is more than a patch's worth of
consequence.

An envelope minted before this is unaffected; no existing field changes shape;
canonical bytes of existing envelopes are untouched.

**The producer rule is load-bearing, not courtesy.** A producer MUST NOT emit
`squillo` until it has reason to believe the recipient understands it. §7.1's
sets are closed and the reference models them as types, so an un-updated
verifier does not "verify but not understand" — it fails at strict parse,
before the protocol's own error vocabulary is reachable. The AgentCard
extension declaration (§10.1) is the existing mechanism for forming that
belief.

## Security considerations

**This interacts with the channel-confusion threat, and improves the status
quo.** A recipient's policy may differ by medium. Today an in-app act arrives
labelled `email`, so a recipient applying mail-specific policy applies it to
something that is not mail. Naming the medium truthfully lets that policy be
correct; it does not create a new exposure.

**It does not create a way to widen a grant.** A Delegation Mandate that omits
`squillo` cannot authorize an act on that medium, exactly as before. Adding a
kind adds a thing a grant may name, never a thing a grant implies. This is
also why the axis error it replaces mattered: a mandate granting a membership
scope could not authorize an envelope naming a medium, and the mismatch
surfaced as a refusal of the sender's own traffic.

**The claim is a sender's assertion, as every channel kind is.** `squillo` is
not proof that delivery occurred in that application, any more than `email` is
proof that mail was sent. It binds what the sender said the medium was, so a
recipient can check it against the addressing block and against what arrived.

## What this deliberately does not do

It does not define a per-channel addressing shape for §7.4. One implementer
exists, and a shape drawn from a single implementation generalizes badly; that
belongs in a follow-up once there is a second. It does not touch
`ContentClass`. It does not rule that a generic in-application value is
unavailable later, nor that other vendors' surfaces are — both remain ordinary
requests.

And it does not resolve the structural question its own Decision block raises:
this vocabulary should live in a registry its curator does not also apply to.
