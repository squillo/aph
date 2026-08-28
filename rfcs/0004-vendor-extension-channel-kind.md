# RFC 0004 — A vendor-extension arm for `ChannelKind`

- **Status:** Rejected
- **Issue:** raised by three independent implementations on 2026-08-28, in
  implementer reports rather than the issue form; recorded here because the
  same question arrived three times in one day and deserves one findable
  answer instead of three private ones.
- **Spec sections touched:** none — rejected; §7.1.5 and Appendix A stand as
  written.

## The problem

The problem is real, and it was reported precisely: **the closed set had no
member for a channel a shipping implementation actually emits.**

An implementation was emitting a channel kind that §7.1.5 does not define. It
had been doing so at many call sites, and every delegation mandate it minted
listed that value in `allowedChannels`. Under §7.1's strict-parse rule the
value was always non-conforming, but until the reference implementation made
the closed sets into types, nothing said so out loud: the field was a
`String`, so an unrecognized value round-tripped in silence.

Making the sets into types turned that silence into a refusal. Three
implementers asked the same question in response, and one framed it as the
spec question it really is:

> the vocabulary was published as closed while a conforming implementation
> needed a word that wasn't in it. Worth deciding deliberately whether §7.1.5
> is closed-and-complete or closed-and-extensible.

They asked to rule on one of:

- **(a)** `ChannelKind` gains a first-party arm — a named variant, or an open
  `Other(String)` / `Vendor(String)` with a documented wire form; or
- **(b)** the value is permanently off-spec, and the implementation maps to a
  named existing kind or stops claiming a channel kind on that path.

## The design (as proposed, and rejected)

The proposal was an open arm on the closed enum: a variant carrying an
arbitrary string, so that any vendor could name a channel the spec had not yet
registered without waiting for a spec revision.

**This is rejected, and the rejection is permanent rather than "not yet."**

An open arm in a closed set is not a compromise between closed and open. It is
a repeal. The property §7.1.5's closure exists to create is that *a verifier
refuses a value it does not recognize*; an `Other(String)` arm restores, in
one line, exactly the "any string round-trips" behaviour that closing the set
removed. Worse, it hands the decision to the wrong party: a producer could
disable a recipient's channel check by writing a word that recipient has never
seen. The spec already states this reasoning for the sibling vocabulary at
§6.3.3 — an unrecognized `statusPurpose` is a failure precisely because
treating it as "no claim was made" would turn the closed set into an opt-out.
The argument does not change when the field is `kind` instead of
`statusPurpose`.

### The ruling: (b), and the reason is sharper than "off-spec"

The reported value does not name a delivery medium. It names an **internal
membership scope** in the emitting system — the constant sits beside that
system's channel-membership join path, which grants a scope, not a route to a
recipient. It was placed in `kind`, which §7.1.5 defines as the end-delivery
medium.

So this is not a missing word. It is **two different axes wearing one string**:
a scope name in a medium field. That diagnosis is confirmed by the reporters'
own evidence — their mandate check was already refusing their own peers,
because a mandate granting the scope name could not authorize an envelope
whose medium was `email`. That refusal was not a bug to work around. It was
the verifier correctly detecting the axis error, and it had been reporting the
answer for as long as it had been failing.

**The mapping is therefore `email`** wherever the end delivery is SMTP mail to
a real mailbox — which the affected path is. §7.1.5's `kind` describes where
the message lands, not which subsystem emitted it, and §1.1.1 already
fixes this reading: the `channel` block "always describes the end-delivery
medium — never the agent-to-agent rail." An agent-to-agent transport is not
promoted to a channel kind by being the thing that carried the bytes, and
neither is an internal scope by being the thing that authorized them.

**This mapping disposes of the SCOPE-NAME case, and only that case.** An
earlier draft of this document stated the `email` mapping flatly, which read
as settling every question anyone might raise about mail-shaped channels. It
does not. A separate request — argued on CONSENT GRANULARITY rather than on
vocabulary, and asking whether unattended agent-to-agent mail should be
distinguishable from mail a human reads — was already open when this was
written, and nothing here answers it. That question is taken up on its own
terms in `rfcs/0005-recipient-class.md`; the reasoning in this document
neither grants nor refuses it, because the two are not the same question. A
scope name in a medium field is an error. Asking whether one medium serves
two materially different recipients is a design question with a real answer
on either side.

### What IS admissible

A named first-party variant is **categorically admissible**, and pretending
otherwise would be a lie: six of the seven registered kinds are vendor names,
so the set is already a vendor registry. If a vendor's in-product channel — a
human reading a message inside an application — needs a wire kind, that is an
ordinary RFC, and it will be processed like any other.

What it does not get is minting by fiat. A guessed variant name becomes a
signed wire value, permanently, in artifacts that outlive the guess. And a
request from the authoring organization gets *more* scrutiny than an outside
one, not less, for the obvious reason: the party that owns the registry must
not be able to grant itself entries more cheaply than it grants them to
others.

## Alternatives considered

**`Other(String)` / `Vendor(String)`.** Rejected permanently, above: it is a
repeal of the closure rather than an extension of the set, and it relocates
the decision from the verifier to the producer.

**A `Squillo` variant, minted now to unblock the build.** Rejected as
sequencing, not as substance. The break is a compile error in a downstream
bridge; the fix for a compile error must not be a permanent wire-vocabulary
entry chosen under time pressure. The variant remains available through the
normal process, on its merits, once someone states the channel it names.

**Reverting the closed types.** Rejected, and all three reporters independently
agreed. An unrecognized value becoming a parse failure is what §8.3 step 1
always required; the change converted a silent non-conformance into a loud
one, which is the outcome the strict-parse rule was written to produce.

**A local spelling in the consumer's own vocabulary.** Not available to them
and correctly so — their domain vocabulary re-exports this crate's types
rather than redefining them, which is the property that made this a single
findable question instead of a slow divergence between two enums with the same
name.

## Compatibility

**Nothing in this document changes the wire.** An envelope minted yesterday
with a conforming `kind` is unaffected; a verifier that has not updated is
unaffected.

Artifacts carrying the non-conforming value were never conforming, and no
version bump can retroactively make them so. They must be re-minted with a
registered kind. Mandates listing the value in `allowedChannels` must be
re-issued the same way — and that is the load-bearing half, because a mandate
outlives the envelope it authorizes.

**One sequencing warning, contributed by the third reporter and worth more
than the ruling it accompanied.** Where a downstream conversion is being made
fallible to accommodate the closed types, the emitted value must be corrected
**before or in the same change**, never after. A conversion that merely becomes
fallible will compile and then fail at runtime on every artifact carrying the
old value — turning a build error into a signed-envelope refusal of the
implementation's own traffic, which is strictly worse than the break it fixed.
Fix the emitted value first; the type change is the second half, not the
first.

## Security considerations

This interacts with the channel-confusion threat: the reason `kind` is closed
at all is that a recipient's policy may differ by medium, and a producer that
can name its own medium can select the policy it prefers. An open arm defeats
that directly, which is the whole of the rejection.

The axis error carries a smaller, quieter risk worth naming: a scope name in a
medium field reads to a human auditor as a medium, so an envelope can look
channel-bound while binding nothing a recipient can act on. Closure surfaces
that as a refusal instead of leaving it to review.

## Closed-and-complete, or closed-and-extensible?

**Extensible.** The spec already says so in the row that defines the field —
§7.1.5: "New channel kinds are additive in 0.x minor versions" — and
Appendix A repeats it for post-1.0 minors. The seven kinds have never been
claimed as the final enumeration of every delivery medium.

The two properties are not in tension, because they answer different
questions. **Closed** governs what a *verifier* does with a value it does not
recognize: refuse, with no opt-out, so that a producer cannot disable a check
by inventing a word. **Extensible** governs how the *set* changes over time:
by request-for-change, with the addition visible to implementers before it
appears on the wire. RFC 0002 is exercising exactly that mechanism for a
proposed `service` kind.

So a word missing from the set is not a defect in closure. It is closure's
cost, and it is the correct cost — the alternative is a vocabulary against
which no verifier can refuse anything.

**A finding against this project, recorded because the reporters earned it.**
If an implementation needed a word the set lacked and shipped many call sites
using an invented one rather than asking for it, that is evidence the
request path was not visible or cheap enough to reach for. The remedy is not
to loosen the vocabulary; it is to make the request path obvious from the
place where the need is felt. §7.1.5 now says where to ask, and the same
pointer belongs anywhere a closed vocabulary is defined.

## What this deliberately does not do

It does not add, rename, or remove any channel kind. It does not rule on
whether a vendor in-product channel should eventually be registered — that
question is open, and this document declines to prejudge it in either
direction. It does not touch `ContentClass`, whose closure rests on the same
reasoning and is untested by this report. And it does not prescribe the
downstream repair beyond the sequencing warning above; where the parse belongs
in another project's layering is that project's decision, not this one's.

**And it does not make the axis rule mechanically enforceable, because it
cannot be.** The closed type refuses an unrecognized STRING, which is what
caught this case. It cannot catch the same error committed with a recognized
one: a sender that coined `email` to name an internal scope would parse
cleanly, satisfy every check in §8.3, and bind nothing a recipient can act
on. The axis is a claim about what the sender MEANT, and no verifier can
check intent — it can only check the value. So the rule in §7.1.5 is
addressed to implementers rather than to verifiers, and it is stated as
guidance for the same reason it is not stated as a MUST: there is no
conforming behaviour a verifier could adopt that would enforce it.

This is recorded rather than left silent because a reader who finds the rule
in the specification is entitled to know whether anything checks it. Nothing
does. What the closed set buys is that the *unrecognized* case — the one that
actually occurred, three times in one day — becomes loud instead of silent,
and `spec/aph-0.1.md`'s enumerations are now welded to the reference type's
in both directions, so the two cannot drift apart while each looks correct
on its own.
