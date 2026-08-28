# RFC 0006 — Published guardrail vocabularies

*Meaning as a resolvable third party.*

- **Status:** Draft
- **Author:** Scott Wyatt
- **Issue:** [#3](https://github.com/squillo/aph/issues/3) — the first RFC in
  this directory with one, per the lifecycle in `rfcs/README.md`.
- **Spec sections touched:** none yet — design only. It would touch §7.1
  (a reference field), §8.3 (a recipient step), and reuse §8.4 wholesale.

## The problem

Two agents can already prove *who authorized an act*. They cannot agree on
*what the act was*.

APH binds a payload, a channel, an agent, and a policy decision to a human's
authority. Everything in that sentence is structural. Nothing in it says
whether the message asked to **grant access**, **move money**, or **schedule a
meeting** — and those are the distinctions a recipient's policy actually turns
on. Today a recipient re-derives the meaning from the payload, with its own
classifier, against its own vocabulary. Two recipients can read the same
signed bytes and reach different conclusions about what was asked, and both
can be conformant.

The guardrail vocabulary shipped alongside this protocol closes half of that.
It defines families of acts and labels within them, versioned independently of
the wire, precisely so meaning can move at its own pace. It already states why
it is a separate artifact:

> A vocabulary that ships inside one party's protocol implementation is that
> party's vocabulary. A vocabulary that resolves independently is a **third
> party** both sides can point at — which is the same move APH already makes
> for notary keys, applied to meaning instead of identity. Neither
> counterparty defines the term; both resolve it.

**But it does not resolve.** It is a file in this repository. Its own README
says so plainly — *"No wire binding exists yet. Nothing in the APH envelope
carries these labels today."* So the third party both sides point at is, at
present, us. That is the gap this RFC is about, and it has two halves:

1. **Anyone should be able to author a vocabulary**, not just this project.
   An industry, a company, a regulator, or two counterparties with a private
   arrangement all have act distinctions that matter to them and to nobody
   else. A single central vocabulary either grows to hold everyone's
   specialized terms — which makes it unreviewable — or refuses them, which
   makes it useless for the cases where meaning matters most.
2. **A vocabulary must be resolvable and pinned.** A reference to meaning that
   cannot be dereferenced is a comment. A reference that can be dereferenced
   but not verified is worse than a comment, because it looks like a
   guarantee.

## The design

**Reuse the extension model that already exists. Add publication, and only
publication.**

### 1. The extension model is already the right one, and it already ships

A third party does not fork the vocabulary. It publishes an **overlay** against
the base, and the base's own lattice rules constrain what an overlay may do:

> The first entry for a namespace is the base; every later entry is a
> tighten-only overlay. A contributor may add a label, raise a confidence
> floor, remove a rung, restrict privacy locality, or harden a fail posture —
> and may never do the reverse. Violations are loud load refusals, never
> silent clamps.

**That tighten-only rule is the whole safety argument for accepting a
stranger's vocabulary**, and it is why this RFC proposes almost no new
mechanism. A third party cannot loosen what the base requires. It cannot lower
an accuracy floor, widen a privacy locality, or soften a fail posture. The
worst a hostile publisher can do is be *stricter* than the base — which
degrades their own traffic and nobody else's.

Six families are **sealed** and refuse overlays entirely: authority, consent,
safety, injection, disclosure, and human-loop. Those are exactly the families
where a redefinition would be dangerous rather than merely wrong, and the only
change path for them is a new base version a verifier can see and choose. A
published-vocabulary mechanism must not create a back door around that, and
this one does not: an overlay that touches a sealed family is refused at load,
wherever it was fetched from.

### 2. Publication reuses §8.4, because it is the same problem

APH already solves *"resolve a third party you have no prior relationship
with"* — that is what §8.4 does for notary keys, across three mechanisms
(`did:key` self-description, DNS TXT, and `did:web` over HTTPS), with a
defined resolution order and the rule that **absence advances while corruption
refuses**.

A vocabulary is the same shape of problem with a different payload. So the
proposal is to publish a vocabulary the way a notary key is published, rather
than to invent a second discovery story with its own failure modes. Concretely,
a publisher serves the compiled bundle at an HTTPS origin it controls, and the
identity that vouches for it is a DID resolvable by the mechanisms §8.4
already defines.

### 2a. Signed, immutable, and temporal are three different properties

They are routinely conflated, and a design that gets one and believes it has
all three is the common failure. Naming them separately is most of the work:

| Property | What it answers | What provides it |
|---|---|---|
| **Signed** | Who says this is their vocabulary? | A signature over the bundle, by an identity §8.4 resolves |
| **Immutable** | Am I reading the same bytes the reference meant? | The content digest — the bundle already carries `integrity: sha256-…` |
| **Temporal** | What did this publisher say, and when, and have they shown everyone the same thing? | An append-only log with inclusion proofs |

**A signature is not immutability.** It proves who authored the bytes in front
of you. It does nothing to stop the publisher signing a different vocabulary
tomorrow and serving that at the same URL under the same version. A consumer
holding only a signature cannot tell the two apart.

**A digest is not a history.** Pinning by digest makes *your* reference stable
— you either get the bytes you cited or a refusal — but it says nothing about
what the publisher showed anyone else, or what they showed you last week.

**The property worth the most here is the one with no common name:
non-equivocation.** A publisher must not be able to show one vocabulary to you
and a different one to your counterparty under the same name and version. That
is precisely the guarantee an exchange between two parties needs, because the
whole point is that both resolve the same third party. A signature does not
provide it. A digest provides it only if both parties independently obtained
the same digest — which is the thing an append-only log makes checkable.

### 2b. The three layers, and only the first is required

**Layer 1 — sign the bundle and pin the digest. Required.** Both compiled
bundles already carry `integrity: sha256-…`. A publisher signs a small
manifest binding `{name, version, integrity}` with a key §8.4 already
discovers; consumers cite the digest. The bytes may then be served, mirrored,
or cached anywhere, because any copy is verifiable. **Buys:** authenticity and
integrity. **Does not buy:** any history.

**Layer 2 — record the signed digest in an append-only transparency log.
Recommended, and this is the answer to "immutable temporal".** A public log
with inclusion proofs gives a timestamped, non-retractable record that a
vocabulary existed under an identity at a time, and makes equivocation
detectable rather than merely unlikely. This is a solved problem with running
public infrastructure; a project should use one rather than build one, and the
reasoning is the same reasoning that runs through this document. **A log we
operate is a log we could rewrite, and the entire premise here is a third
party neither counterparty controls.** Publishing to a log we own would
reproduce, one layer down, exactly the problem publishing was meant to solve.

**Layer 3 — content-addressed distribution. Optional.** Where the address IS
the digest, immutability is structural rather than checked. Useful if
distribution becomes a problem; it adds availability dependencies and no
integrity the digest does not already give.

### 2c. The DNS record, concretely

§8.4.5 already publishes key material at `_aph._notary.<domain>` as a
DKIM-style tag list. A vocabulary digest is the same shape of fact — small,
public, and useful to someone with no prior relationship — so it takes the
same shape rather than a new one:

```
_aph._vocab.example.com.  IN  TXT  "v=APHv1; n=aph_guardrails; ver=0.1.0-alpha.1; h=sha256-y6E/EGldCz2ogpVB7wlnS5orbnAjcCpoUBaDietJmXA="
```

Required tags: `v` (version, `APHv1`, as §8.4.5), `n` (vocabulary name), `ver`
(vocabulary version), `h` (the bundle's `integrity` value, verbatim — the same
SRI-shaped string the compiled Snapp already carries, not a re-encoding of
it). A publisher serving several vocabularies publishes several TXT records at
the one name; a resolver selects on `n` and `ver` and MUST refuse rather than
guess when two records claim the same pair with different digests.

It fits comfortably: the example above is well inside a single 255-byte
character-string, which matters because a digest split across strings is a
concatenation rule nobody will implement identically.

`_aph._vocab` would need adding to the underscored names §13 reserves
alongside `_aph` and `_aph._notary` — one line in the same registration,
not a second registration.

**What this buys.** A second, independent path to the digest, which is the
shape §8.4.6's multi-mechanism resolution already assumes; DNSSEC where the
zone is signed; and no new infrastructure, since a publisher operating a
`did:web` identity already controls the zone.

**What it does not buy, and the distinction matters more than the mechanism.**
DNS is not append-only. A publisher can change the record, and a resolver
sees only what it is served — so this is a *discovery* path for the current
digest, **not** the temporal layer and **not** non-equivocation. Layer 2
remains necessary for those, and a design that ships this record and calls the
temporal question answered has confused a cheap win for the expensive one.

**The failure mode is benign, which is why it is worth having anyway.** A
spoofed or stale record yields a digest that does not match the bytes, and the
bytes are then refused. The worst outcome is denial, never substitution — an
attacker who controls DNS can stop you resolving a vocabulary and cannot make
you accept a different one. That asymmetry is what makes an unauthenticated
lookup acceptable here, and it holds only because the digest is doing the
integrity work.

**What none of it buys, stated because it is the tempting inference:** none of
this makes a vocabulary correct, or its accuracy claims measured, or its
labels well-chosen. It establishes that you are reading the bytes a named
publisher published at a known time. That is necessary and it is not
sufficient, and the distinction belongs anywhere this is described.

### 3. The reference is a logical identifier plus a digest — never a path

An envelope references a vocabulary by **name, version, and content digest**,
and names the term within it by family and label:

```
vocabulary:  aph_guardrails@0.1.0-alpha.1
             sha256-<the bundle's integrity digest>
term:        APH_ACT_ACCESS / ACCESS_GRANT
```

**Not a path into the serialization.** That distinction is load-bearing and
was learned the expensive way: re-exporting an unchanged bundle under a newer
toolchain moved its blocks from one nesting to another. Every reference
written as a path into the old shape would have dangled, and a signature
cannot be re-pointed. A reference must name the thing, not one serialization
of the thing.

The digest is what turns "we agree on this term" from a shared assumption into
a checkable fact. Without it, a reference points at whatever the publisher is
serving today, and a publisher — or anyone who compromises their origin — can
change what a signed envelope meant after it was signed.

### 4. What a recipient does with it

Deliberately understated, because the strong version is the tempting one and
it is wrong. A recipient that recognizes the vocabulary and the term MAY apply
policy to it. A recipient that does not recognize it MUST treat the envelope
exactly as it would today — the reference is additional information, never a
precondition, and never something whose absence changes a verdict.

This is the same posture §8.4.6 takes toward discovery: **absence advances,
corruption refuses.** A vocabulary that cannot be fetched is an unrecognized
term. A vocabulary that is fetched and fails its digest is a refusal, because
absent and corrupt are not the same event.

## Alternatives considered

**A single central vocabulary; extensions by pull request here.** This is the
status quo and it does not scale past the cases we happen to think of. It also
puts this project in the position of ruling on whether another industry's act
distinctions are legitimate — which we are not qualified to do and should not
want to.

**Free-form labels: any string, no vocabulary.** Rejected for the reason RFC
0004 rejects an open arm in a closed set. A label nobody can resolve is a
label whose meaning each party supplies for itself, which is precisely the
ambiguity this is meant to remove, dressed as interoperability.

**A path into the published JSON (`$.classifiers.FAMILY.labels.LABEL`).**
Rejected, per §3 above: the serialization shape has already changed once under
a toolchain bump, and the exporter encodes type information into key names, so
the clean-looking path does not even exist today. Naming the term is stable;
naming its location is not.

**Fetch the vocabulary at verification time, by default.** Rejected as a
default, and this is the most important rejection here. See below.

## Security considerations

This is the section that decides whether the idea is any good, so it is longer
than the design.

**Resolving a stranger's vocabulary is a request to a stranger's server, made
by a verifier, while it verifies.** Every hazard that attaches to outbound
fetches in a verification path attaches here: server-side request forgery
against internal addresses, a slow or hanging origin becoming a denial of
service on the verify path, and an origin learning that you are verifying
something and roughly what. Any implementation MUST reuse the same outbound
controls the protocol already requires for status-list fetches rather than
opening a second, laxer path — and SHOULD prefer resolution out of band, on a
cadence, over a fetch triggered by an inbound envelope. A cached, digest-pinned
vocabulary has none of these problems; a lazy fetch has all of them.

**The privacy shape mirrors §6.3.3's.** Fetching a vocabulary on receipt tells
its publisher when traffic classified against it arrives. Where the publisher
is also a counterparty, that is a side channel about your traffic. The digest
pin is what makes caching safe, and caching is what makes the side channel go
away.

**A vocabulary is not a proof of classification.** The honest limit, stated
plainly: a reference proves *which vocabulary the sender cited*, not that the
sender classified the act correctly. A sender can label a fund transfer
`TIME_PROPOSED` and sign it. What this buys is that a *disagreement* becomes
visible instead of a *misunderstanding* staying invisible — two parties now
mean the same thing by a word, and can detect when the label and the payload
disagree. That is genuinely valuable and it is not integrity of
classification. No implementation should describe it as the latter.

**Unmeasured accuracy claims travel with the vocabulary.** Every family names
a `min_accuracy` gate, and the base vocabulary states that its corpora do not
ship, so the gates "assert what a conforming evaluation must clear — they are
not yet evidence that anything clears it." A third-party vocabulary can assert
the same numbers with the same absence of evidence, and publishing makes those
claims look more official than they are. A published vocabulary SHOULD carry
its evaluation corpus or say explicitly that it does not.

**The tighten-only lattice is the containment, and it must be enforced by the
consumer.** The base vocabulary is already honest that seals are authored
intent: *"Whether `sealed = true` is enforced is a property of the consuming
runtime's fold, not of these bytes."* Publication raises the stakes on that
sentence considerably — a runtime that does not enforce tighten-only will
happily load a hostile overlay that widens a sealed family. **Verify your
engine refuses overlays against sealed specs before resolving any vocabulary
you did not write.**

## What this deliberately does not do

It does not define the wire field, its name, or where it sits in the envelope
— that is the open wire-binding question, and this RFC deliberately does not
settle it by implication. It does not define the publication path, media type,
or cache policy. It does not decide whether a vocabulary reference belongs on
the envelope, the mandate, or both — a mandate-side reference would let a
human's grant be scoped in terms both parties resolve, which is a strictly
larger idea and deserves its own argument.

It does not create a registry, a directory, or any central list of published
vocabularies. Discovery of *which* vocabulary to use is a human and commercial
question, and a protocol that answers it acquires a gatekeeper.

And it does not claim to make agents interoperable. It makes one specific
thing shareable — the meaning of an act — which is a precondition for
interoperation and not a substitute for it.
