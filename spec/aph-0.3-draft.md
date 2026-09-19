# APH v0.3-draft — the delta over v0.2.0

**Status:** DRAFT. v0.2.0 (`aph-0.2.md`) is FINAL and nothing here amends
it, exactly as v0.2.0 amends nothing in v0.1.0 (`aph-0.1.md`). This
document is where accepted post-0.2-cut RFCs accumulate as a versioned
DELTA until v0.3 is cut. Nothing in this delta adds or changes an
ENVELOPE MEMBER: both sections below govern verifier behavior and
citation semantics only, so no wire-version rule is introduced and no
existing envelope's bytes are affected. A v0.1-only or v0.2-only
implementation that has never read this file remains fully conformant.

Opened 2026-08-31 with two entries: RFC 0009 (§1) and RFC 0010 (§2).

---

## 1. Named status dispositions (RFC 0009, Accepted 2026-08-31)

§6.3.3.4's two PASSING outcomes gain names, as a CLOSED SET in
§6.3.3.5's idiom:

| Disposition | §6.3.3.4 case | Meaning |
|---|---|---|
| `StatusAbsent` | case 1 | No `credentialStatus` was offered. Nothing was checked; nobody asserted the mandate was live. |
| `StatusLive` | case 3, bit `0` | Status was resolved, its proof verified, issuer and purpose confirmed, freshness satisfied — the mandate was affirmatively live at an instant. |

**The evidence rule.** A verifier that records evidence that verification
occurred MUST use these terms for the status disposition. For
`StatusLive` the record MUST additionally carry (a) the instant the
status was established and (b) an identifier for the status list
credential consulted — the two facts that make the record re-evaluable
after §6.3.3.3's freshness bound has decayed it.

**Emission stays OPTIONAL.** APH gains no obligation to produce evidence;
it gains the vocabulary for those who do. A verifier that emits nothing
is unaffected and remains conformant. The rejecting outcomes gain
nothing: `APH_E008` and `APH_E015` already name themselves.

**Deliberately undefined:** the evidence record's shape — serialization,
credential-or-not, binding to the envelope, storage. That design waits
for an enforcement gate to constrain it (RFC 0009 §"What this
deliberately does NOT define").

## 2. Vocabulary digest semantics (RFC 0010, Accepted 2026-08-31)

A vocabulary citation's digest — §8.5.1's `h` tag and
`actClassification.vocabularies[].digest` — is **SHA-256 over the fetched
artifact bytes**, spelled `sha256-<base64>` (SRI-style). It lives in the
CITATION and is never required inside the artifact; internal integrity
metadata an artifact happens to carry has no protocol meaning.

This supersedes one clause of v0.1.0 §7.1.12 ("the same `sha256-…`
string the bundle carries"): a file cannot contain its own hash, so a
carried string is computed over something other than the fetched bytes
and §8.5.3's mandatory byte-check cannot be performed against it by a
stranger. "VERBATIM" continues to mean the citation copies the
publisher's declared string exactly — and that string MUST equal the
SHA-256 of the artifact bytes, which makes §8.5.3 performable by anyone
holding nothing but the artifact and the citation. §8.5.2's failure
asymmetry (denial, never substitution) is unchanged.

Citations minted before this rule against carried-integrity strings
remain resolvable only by parties who pin those exact artifacts; a
publisher SHOULD re-declare them SRI-style.
