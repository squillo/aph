# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Report privately via **[GitHub private vulnerability reporting](https://github.com/squillo/aph/security/advisories/new)** —
the *Report a vulnerability* button under this repository's Security tab. That
channel reaches the maintainers without disclosing anything publicly, supports
collaboration on a fix inside a draft advisory, and credits you when the
advisory is published.

If you cannot use GitHub, email the maintainer: **scott@squillo.com** with
`[APH SECURITY]` in the subject line.

You can expect an acknowledgment within **72 hours**. APH is pre-1.0 and
pre-adoption, which cuts in your favor: a confirmed protocol defect is
corrected **in place** in the current specification (see
[CONTRIBUTING.md](CONTRIBUTING.md), the pre-production exception) rather than
queued behind a release train, and the fix lands as a dated revision entry the
same way every other correction has.

## Scope

In scope:

- The **protocol specification** (`spec/aph-0.1.md` and its companion
  documents) — anything that lets a conformant verifier accept what it should
  refuse, or refuse what it should accept: signature or canonicalization
  confusion, replay, downgrade, revocation bypass, discovery-order abuse,
  same-origin escapes.
- The **reference implementation and bindings** (`interpreters/`) — including
  divergence between implementations, since two conformant-claiming verifiers
  reaching opposite verdicts on the same bytes is itself a vulnerability.
- The **published examples and test vectors** — a vector that teaches an
  unsafe practice is a defect in the place implementers actually look.

Before reporting, read the threat model in
[`spec/security-considerations.md`](spec/security-considerations.md): **§2**
lists what APH defends against, **§3** what it deliberately does not. A report
that a §3 exclusion is excluded is working as designed — though a case that an
exclusion is *wrongly drawn* is absolutely in scope, and is the kind of report
we most want.

## Disclosure

We ask for coordinated disclosure: give us the 72-hour acknowledgment window
and a good-faith interval to ship a fix before publishing. We will not pursue
or support legal action against good-faith security research conducted within
this policy, and we credit reporters in the published advisory unless you ask
otherwise.
