# RFC 0005 — Recipient class: who is on the other end of the medium

- **Status:** Draft
- **Issue:** raised by an implementer building an agent-to-agent transport
  over ordinary mail, as a request for an eighth channel kind. The kind is
  refused here; the problem behind it is not, and this document proposes the
  shape that does answer it.
- **Spec sections touched:** §7.1.5, §6.2, §7.1.7 — none of them yet. Draft.

## The problem

A human grants an agent a Delegation Mandate carrying
`allowedChannels: ["email"]`, picturing something specific: *my agent may send
email on my behalf.* §8.3.1 step 4 checks the envelope's channel against that
list, and the grant does what she expects.

Then the same agent begins conducting **unattended machine-to-machine
conversations with other organizations' agents**, over ordinary mail, at
machine rate, while she is asleep. Every one of those messages is `email`.
Every one satisfies her mandate. Nothing on the wire distinguishes them from
the mail she had in mind, because at the level `kind` operates, they are not
different: the bytes land in a real mailbox at a real MX either way.

**That is a consent-granularity defect, and it is a real one.** The mandate is
the artifact where a human's authority is written down. If it cannot express
a distinction the human plainly intends, the mandate over-grants — silently,
and in exactly the direction that favours the machine.

The implementer who reported this proposed the natural fix: an eighth channel
kind, `a2a_email`, so that agent mail and human mail carry different values in
`kind` and a mandate can grant one without the other. They pre-empted the
obvious objection carefully — §1.1.1 says the `channel` block names the
end-delivery medium and never the agent-to-agent rail — and argued that
`a2a_email` names a **recipient class of the email medium**, not the rail,
since the mail is genuinely delivered either way. That framing is correct as
far as it goes, and it is why this needed a real answer rather than a reflex.

## The design

**Refuse the eighth kind. Add the second dimension instead.**

The argument against `a2a_email` is not that recipient class is unimportant.
It is that recipient class is not a *kind*, and the generalization test shows
it immediately:

> If recipient class belongs in `kind`, then `a2a_slack`, `a2a_discord`,
> `a2a_teams`, `a2a_whatsapp`, `a2a_google_chat`, and `a2a_imessage` all
> follow, because an agent can be the consumer on any of them. The set does
> not grow by one. It doubles, and it doubles again for the next refinement
> anyone proposes.

**A refinement that must be applied to every member of a set is not a member
of that set. It is a second dimension wearing a member's clothes.** Encoding
it as a member multiplies the vocabulary, forces every verifier to learn a
combinatorial set instead of two orthogonal ones, and makes the two facts —
*which medium* and *who consumes it* — inseparable at the point where a
recipient wants to reason about exactly one of them.

So the proposal is a separate, orthogonal value: a **recipient class**,
carried beside `kind` rather than inside it, and constrainable in a mandate
the same way `allowedChannels` constrains the medium. Two values, composing:

```
channel.kind            = email          (the medium: where it lands)
channel.recipientClass  = agent          (the consumer: who reads it)
```

and in the mandate, a grant that says what Alice meant:

```
allowedChannels        = ["email"]
allowedRecipientClasses = ["human"]
```

That mandate authorizes her agent to send her mail and refuses the unattended
inter-organization traffic, which is the distinction she had in mind and
could not previously write down. It also composes with all seven kinds at
once: the same grant shape works for a human-only Slack grant without anyone
adding `a2a_slack`.

**This is deliberately left as a shape rather than a specified field.** The
open questions below are real, and settling them by fiat inside the document
that proposes the mechanism is how a design acquires decisions nobody
reviewed.

## Alternatives considered

**`a2a_email` as an eighth kind.** Refused, per the generalization test above.
The framing that motivated it — recipient class is a property of the medium's
consumer, not of the rail — is accepted, and is exactly why the value belongs
on its own axis rather than fused into the medium's name.

**Leave it off-spec; let each deployment gate consent locally.** This is what
the reporting implementer offered as their fallback, calling it cheaper and
entirely acceptable, and it is a genuinely reasonable position. It is not
adopted as the *answer* because the mandate is the artifact a recipient
inspects to learn what a human authorized, and a constraint enforced only in
one sender's local policy is invisible to every recipient and absent from the
signed record. A consent boundary that no verifier can see is not a consent
boundary; it is a promise. That said, deployments MAY gate locally today, and
should, since this RFC is a draft and nothing here is implementable yet.

**Overload `contentClass`.** Rejected. `contentClass` classifies the message
(`Reply`, `New`, `Broadcast`, …), not its consumer, and the same axis error
this RFC is about would simply move one field to the left.

**A boolean `unattended` flag.** Rejected as under-expressive at the moment of
definition. The distinction being drawn is about *who or what consumes the
message*, and a boolean fixes the answer at two before anyone has argued that
two is the right number.

## Compatibility

Nothing here is implementable yet, and no envelope's validity changes.

When something does land, the version consequence is the sharp part, and it
is sharper now than it would have been a month ago. §7.1.5's vocabularies are
CLOSED, and the reference implementation now models them as types: an older
verifier meeting a value it does not know does not "verify but not
understand" — it fails at strict parse, **before the protocol's own error
vocabulary is reachable**. The reporting implementer identified this
precisely, and it generalizes past their request:

> **Without a version-gated emission rule, adding any new closed-vocabulary
> value is a flag day for every deployed verifier.**

Any concrete form of this proposal therefore owes a rollout rule — when a
producer may begin emitting the new value, and how a recipient that cannot
parse it is told what happened — before it owes wire text. An optional field
that is simply absent for older producers is the obvious candidate, since an
absent field is the one shape every existing verifier already handles
correctly, but that is an argument to have in this RFC's issue and not a
decision to record here.

## Security considerations

This interacts directly with the mandate-scope threat, and improves it: a
mandate that can express recipient class can refuse a class of traffic the
human never contemplated, which is a strictly narrower grant than the same
mandate without it.

It carries one risk that must be designed against rather than assumed away.
**A recipient class asserted by the sender is a claim, not a proof.** A
producer that wants the wider grant can simply write `human` and continue.
The value is therefore only as good as what binds it — for a mandate, the
human's own signature over the constraint; for an envelope, whatever binds
the rest of the channel block. Any concrete proposal must state plainly what
an attacker gains by lying in this field, and must not describe it as a
control it is not. The honest framing is that it constrains an
*honest-but-over-broad* agent, which is the actual threat here — Alice's own
agent doing more than she meant — and does not constrain a hostile one.

## What this deliberately does not do

It does not add a channel kind, and it does not add a field: it proposes a
shape and names the questions that must be settled before any field exists.
It does not decide whether recipient class belongs on the channel block, the
mandate, or both. It does not enumerate the classes — `human` and `agent` are
used above as the two that motivated the report, not as a proposed closed
set, and the question of whether the set should be closed at all is open and
non-obvious given the reasoning in RFC 0004. It does not settle the rollout
rule. And it does not claim to solve consent generally: it addresses one
distinction a human plainly intends and currently cannot write down.
