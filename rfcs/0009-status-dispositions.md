# RFC 0009 — Named status dispositions for the two passing outcomes

- **Status:** Accepted 2026-08-31 — first entry of the v0.3 delta
  (`spec/aph-0.3-draft.md` §1).
- **Origin:** filed as [issue #2](https://github.com/squillo/aph/issues/2)
  by the r14n/RLPS maintainer, after this project raised the gap in the
  r14n exchange (2026-08-24b) and deliberately declined to file it. The
  issue's problem statement is adopted here nearly verbatim, because it
  is correct and better argued than a restatement would be.
- **Spec sections touched:** the v0.3 delta §1; §6.3.3.4 is unchanged in
  v0.1.0 and v0.2.0.

## The problem, in one sentence

§6.3.3.4's two PASSING outcomes — no status claim offered, and status
affirmatively live — are radically different facts about authority that
produce the same verification result, and an audit record downstream
cannot distinguish them.

## Why the passing side needs names and the rejecting side does not

The trichotomy's two rejections already name themselves: `APH_E008`
(present and unresolvable) and `APH_E015` (revoked) are codes an audit
record can carry today, and §11's rationale for one code covering all of
case 2 is unchanged. The passes carry nothing:

1. **Case 1, absent.** No `credentialStatus` was offered. The verifier
   checks nothing and conformantly advances.
2. **Case 3, bit clear.** Status was resolved, proof verified, issuer and
   purpose confirmed, freshness satisfied — the mandate is affirmatively
   live as of an instant. §6.3.3.4 gives this one clause and no name.

Both are conformant passes, §6.3.3.4 case 1 explicitly makes requiring a
status reference LOCAL POLICY, and §6.3.3.3's freshness bound makes
"live" decay — so a record without the instant can only be re-trusted,
never re-evaluated. The divergence this invites is not hypothetical: the
first downstream repository (r14n, `docs/aph-integration.md`) already had
to specify enforcement-side evidence vocabulary in its own repo to define
its two APH-backed control keys. One repository is the cheapest moment
this will ever be reconcilable.

## The rule (normative at v0.3, delta §1)

- The two passing dispositions form a CLOSED SET of two terms, in
  §6.3.3.5's idiom: **`StatusAbsent`** (case 1) and **`StatusLive`**
  (case 3 with the bit clear).
- A verifier that records evidence that verification occurred MUST use
  these terms for the status disposition, and for `StatusLive` MUST
  additionally carry (a) the instant the status was established and
  (b) an identifier for the status list credential consulted.
- Emission stays OPTIONAL. APH gains no obligation to produce evidence;
  it gains the vocabulary for those who do. A verifier that emits nothing
  is unaffected and remains conformant.
- Rejections gain nothing: `APH_E008` and `APH_E015` already name
  themselves.

## What this deliberately does NOT define

The shape of the evidence record — serialization, whether it is a
credential, how it binds to the envelope, where it lives. No gate exists
to constrain it; that design waits for one, exactly as the issue itself
argued. Putting the evidence in the envelope is structurally impossible
(the notary mints before verification; §2.6's conflation, one layer up)
and defining the terms in RLPS is backwards (a second protocol restating
the first is the drift failure mode this RFC exists to close).

## Decision

**Accepted 2026-08-31**, by the sole maintainer — the standing
arrangement recorded in CONTRIBUTING.md and `rfcs/README.md`
(deliberately solo within the Squillo organization). Decided on a
decision card the same day, opening the v0.3 delta: naming now costs one
subsection; naming after more gates exist costs a vocabulary migration,
and the first local vocabulary has already shipped.
