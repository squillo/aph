# RFC 0003 — Audience binding and single-use envelopes

- **Status:** Accepted
- **Issue:** ruled directly (see Decision)
- **Spec sections touched:** §7.1 (envelope shape — new `audience`), §8.3
  (verification steps — new audience and single-use checks), §11 (error
  taxonomy — two new codes), §6.3 (validity windows — guidance),
  `security-considerations.md` §3 (replay, currently unlisted)

## The problem

An APH envelope names the human who authorized an act, the agent that may
perform it, and the act itself. It does not name **who may accept it**, and
nothing says it may be accepted **only once**. Both omissions are load-bearing,
and both were found by attacking the published corpus rather than by reading.

**Nothing binds an envelope to a recipient.** §8.3's normative verification
list has a verifier check the signature, the window, revocation, and the body
hash. No step asks *"was this addressed to me?"* — because no field could
answer. Under the A2A carriage the extension defines, an envelope handed to
recipient A is a complete, valid, signed credential in the hands of anyone who
later holds those bytes. A relay, a log, an archive, or the recipient itself
can present it to recipient B, and B's verifier — following §8.3 exactly —
admits it.

**Nothing spends an envelope.** `id` is `urn:uuid:` and MUST be globally unique
(§7.1), but uniqueness is a property of minting, not of use. No step records
that an id was seen, so a verifier that follows §8.3 to the letter accepts the
same envelope an unbounded number of times inside its validity window. We
measured this against our own reference integration: 100 presentations of one
golden envelope, 100 admissions.

The two compose into the attack that matters. Capture one envelope — from a
message archive, a relay hop, a debug log — and you hold a reusable
authorization to perform that act, against any recipient, until the window
closes. Every published example ships a **24-hour** window, while this
project's own threat model says windows "should be on the order of minutes,
not hours" (`security-considerations.md:53`). The corpus contradicts the
threat model, and the spec gives a verifier no tool to close the gap.

`security-considerations.md` §3 does not list replay as a considered threat.
That is the omission this RFC exists to correct.

**And the spec currently claims the property it does not provide.** §1 lists,
among the protocol's stated guarantees:

> **Replay-resistant.** Each envelope binds to a specific outbound payload via
> a body hash, a time window, and a unique envelope identifier.

All three facts are true and the conclusion does not follow. A body hash binds
an envelope to a *payload*, not to a single *use* of that payload. A time
window bounds replay, it does not prevent it — the DKIM `x=` lesson exactly. A
unique identifier prevents two envelopes from colliding; it prevents nothing at
all unless some verifier is obliged to **remember** it, and no step in §8.3
obliges anyone. Three ingredients of replay resistance are on the table and the
dish is never cooked.

This RFC treats that sentence as the specification's own bug report. Either the
claim comes out, or the mechanism goes in. It proposes the mechanism.

**A second, smaller defect in the same area.** §8.3 makes validating the
envelope's time window a MUST, but the closed §11 code set has no code for
failing it. `APH_E003` is `MandateExpired`, defined as "a Communication Mandate
or Delegation Mandate was consulted past its `expiresAt` / `validUntil`" —
scoped to mandates, not to the envelope's own window against the current
clock. An implementer refusing an expired envelope today must either invent a
refusal or miscite `APH_E003`. We caught ourselves about to miscite it, which
is how it was found. This RFC adds the missing code.

## What email already knows

Email solved a strictly harder version of this in public, over twenty years,
and its scars are the argument for doing it now rather than later.

**SMTP has a precise moment where responsibility transfers.** [RFC 5321
§6.1](https://datatracker.ietf.org/doc/html/rfc5321#section-6.1): when the
receiver returns `250 OK` to the end of `DATA`, it accepts responsibility for
the message and the sender may forget it. Acceptance is a state change, not a
read. APH has no such moment: a verifier that admits an envelope leaves no
trace that it did.

**DKIM's replay problem is the same shape as ours, and it is not theoretical.**
A validly signed message is captured and re-sent to thousands of recipients;
every signature verifies, because the signature was never bound to a
recipient. It has its own IETF working-group document —
[draft-ietf-dkim-replay-problem](https://datatracker.ietf.org/doc/draft-ietf-dkim-replay-problem/)
— and the mitigation the IETF converged on is exactly the field we are missing:
[draft-kucherawy-dkim-anti-replay](https://www.ietf.org/archive/id/draft-kucherawy-dkim-anti-replay-03.html)
proposes **binding a signature to specific recipients**.

**DKIM's expiry tag is the accidental defense.** [RFC
6376](https://www.rfc-editor.org/rfc/rfc6376.html) defines `x=`, a signature
expiration, and says plainly it is *not* intended as a replay defense — yet it
became the practical one, and large senders now issue lifetimes of hours or
minutes. Our 24-hour examples are on the wrong side of that lesson.

So: email needed recipient binding and short expiry, discovered both the
expensive way, and is still retrofitting the first into a deployed base of
billions of verifiers. APH has twelve example files and one reference
implementation. **If email can do it, we can do it while it is still cheap.**

## The design

Three changes. The first two are wire; the third is guidance.

### 1. `audience` — who may accept this

A new OPTIONAL member of `credentialSubject`, omitted when absent (the §7.5
byte-identity rule: an envelope without it is byte-identical to a pre-RFC-0003
envelope, so existing fixtures and their signatures stay valid).

```json
"credentialSubject": {
  "audience": {
    "id": "did:web:ssot.example.com",
    "channelBinding": { "kind": "slack", "teamId": "T01234567", "channelId": "C01234567" }
  }
}
```

`audience.id` is the DID of the endpoint entitled to accept. `channelBinding`
is OPTIONAL and, when present, restates the delivery coordinates the envelope
authorizes, so an envelope for one channel cannot be spent on another.

**§8.3 gains a step, after signature verification and before the body hash:**

> **Audience check.** When `credentialSubject.audience` is present, the
> verifier MUST compare `audience.id` against its own identity and MUST reject
> with `APH_E017` when they differ. When `audience.channelBinding` is present,
> the verifier MUST additionally compare each member against the delivery
> coordinates of the act it is being asked to perform, and MUST reject on any
> mismatch. A verifier that cannot determine its own identity MUST reject
> rather than skip the step.

That last sentence is the one that matters: a check a verifier may skip when
inconvenient is not a check. Absence of the field is a producer's decision to
issue a bearer credential; absence of the *ability to check* is not the
verifier's decision to make.

### 2. Single use — the envelope is spent on acceptance

`id` becomes a nonce as well as an identifier. §8.3 gains a final step, after
every other check has passed:

> **Single-use.** A verifier MUST record `id` upon acceptance and MUST reject
> (`APH_E018`) any later presentation of the same `id`. The record MUST be
> retained at least until `validUntil` has passed; it MAY be discarded
> thereafter, because the window check already refuses the envelope. Recording
> MUST occur at the moment the verifier commits to the act — acceptance, in
> the [RFC 5321 §6.1](https://datatracker.ietf.org/doc/html/rfc5321#section-6.1)
> sense — so that a crash between check and act cannot spend the envelope
> twice, and so that a verifier which rejects for any other reason has not
> consumed it.

The retention bound is what makes this implementable: a verifier stores ids for
the length of the longest window it will accept, not forever. Shorten windows
(below) and the store shrinks with them.

Deliberately NOT specified: where the record lives. A single process may use a
set; a cluster needs shared state; a notary MAY offer a burn endpoint. The
protocol states the obligation, not the storage.

### 3. Windows measured in minutes

§6.3 gains guidance matching the threat model already in the repository: an
envelope authorizing a single act SHOULD carry a window on the order of
minutes. The published corpus is regenerated to match — twelve 24-hour windows
today, each of them an argument the spec loses to its own security document.

### New error codes

| Code | Meaning |
|---|---|
| `APH_E017` | Audience mismatch — the envelope names an endpoint that is not this verifier, or channel coordinates that are not this act's. |
| `APH_E018` | Envelope already spent — this `id` was accepted before. |
| `APH_E019` | Envelope window expired or not yet valid — the envelope's own `validFrom`/`validUntil` judged against the verifier's clock. Distinct from `APH_E003`, which is a *mandate* consulted past its expiry. |

### 4. The §1 claim is corrected either way

If this RFC is accepted, §1's "Replay-resistant" bullet becomes true and gains
a pointer to the single-use step. If it is rejected, the bullet MUST still
change — to state that envelopes are replay-*bounded* by their validity window
and that single-use enforcement is left to recipients. The one outcome this RFC
rules out is the sentence surviving unchanged, because it currently promises a
property no conformant implementation provides.

## Alternatives considered

**Do nothing; treat replay as the integration's problem.** Rejected: this is
what DKIM did, and the result is an IETF working group two decades later
retrofitting recipient binding into a deployed base. The cost of the omission
is paid by every implementer, forever, and paid again by every implementer who
does not realize they are paying it.

**Bind to the transport instead (TLS channel binding, A2A session).** Rejected:
APH's central claim is that a credential is verifiable by a stranger with no
relationship to the issuer and no shared session. Binding to a transport makes
the envelope unverifiable off that transport, which is the property we are
selling.

**Make `audience` REQUIRED.** Rejected for v0.x: broadcast and
multi-recipient acts are real, and a required field forces a producer to
either lie or mint N envelopes. Making it optional keeps bearer semantics
available *as an explicit choice* rather than as the silent default — which is
the actual defect. A future version may flip the default once the field is
deployed.

**Nonce field separate from `id`.** Rejected: `id` is already REQUIRED,
already `urn:uuid:`, already MUST-globally-unique. A second field would add a
way for the two to disagree.

**Shorter windows alone.** Rejected as insufficient — it narrows the replay
window without closing it, and DKIM's `x=` is the proof: helpful, widely
adopted, and explicitly not a replay defense.

## Compatibility

**Envelopes minted yesterday** stay valid. `audience` is omitted-when-absent,
so their bytes and signatures are unchanged, and the audience step is a no-op
for them. They gain single-use semantics at verifiers that implement this RFC,
which is a tightening a replayer cannot exploit.

**A verifier that has not updated** ignores `audience` — it parses strictly and
would reject an unknown field, so this RFC's spec change must land before any
producer emits one. That ordering is the real compatibility cost and it is
stated plainly: **producers MUST NOT emit `audience` until the version
declaring it is published.**

Under CONTRIBUTING.md's rules this is an **additive minor** for the wire and a
**tightening** for verification. The single-use step changes verifier
behavior for existing envelopes, so it is called out as behavior-affecting
rather than purely additive.

## Security considerations

Interacts directly with `security-considerations.md` §3, which does not
currently list replay. This RFC adds it as a considered threat and moves it
from unlisted to mitigated-with-conditions.

Two honest limits:

1. **Single-use is per-verifier.** Two independent verifiers each accept once,
   because no shared state exists between strangers — which is the same
   property that makes APH verifiable by strangers. Audience binding is what
   narrows that to one intended verifier; the two mechanisms are load-bearing
   together and neither is sufficient alone.
2. **An envelope with no `audience` remains a bearer credential.** This RFC
   makes that a producer's explicit choice rather than the protocol's silent
   default. It does not eliminate the shape.

This RFC does **not** address the embedded Delegation Mandate's own bearer
problem — a mandate is reusable by any party who receives one, independent of
the envelope carrying it. That is a separate and arguably larger finding and
deserves its own RFC rather than a subsection here.

## What this deliberately does not do

- Does not specify storage, clustering, or a burn endpoint for the single-use
  record. The obligation is normative; the mechanism is an implementation's.
- Does not make `audience` required, or define multi-recipient audiences.
- Does not touch the Delegation Mandate's fields, its bearer semantics, or its
  revocation wiring.
- Does not add cryptography. Both new checks are comparisons; every
  implementation already has the values they compare.

## Decision

**Accepted 2026-08-29**, by the sole maintainer, and implemented the same
day. The solo-ratification limitation recorded in RFC 0006 and 0007's
Decision blocks applies verbatim: the second-maintainer requirement is open
and unfilled, and this was decided anyway, deliberately and on the record —
the demonstrated bearer-replay attack was judged worse than the process gap,
and the ecosystem was already half-implemented (`APH_E017` registered ahead
of this document under the additive-codes rule, §8.3 step 8's conditional
MUST, a consumed-envelope ledger live in one verifier).

What landed with ratification, so a reader need not diff the spec:
`audience` is §7.1.13; the audience check is §8.3 step 5a; single-use is
§8.3 step 8b; the window code split is `APH_E019` (this document's proposal
named the pair E017/E018 for audience and single-use and E019 for the
window, and that is how they landed); §6.3 carries the minutes-order window
guidance and the ENTIRE published corpus was regenerated to match — the
twelve 24-hour windows this document indicts are gone, the signed vectors
re-minted through their committed seams. The §1 "Replay-resistant" bullet
was rewritten to be TRUE, with the per-verifier limit stated in it.

One deferral, recorded rather than hidden: the language bindings expose no
dedicated audience-check operation yet. The check is a comparison a consumer
can write in any host language; a binding operation is minted when the first
consumer asks, and the parity contract's census will count it when it
arrives.
