# RFC 0010 — Vocabulary digest semantics: the citation hashes the bytes

- **Status:** Accepted 2026-08-31 — v0.3 delta §2
  (`spec/aph-0.3-draft.md`).
- **Spec sections touched:** the v0.3 delta §2; §7.1.12 and §8.5 are
  unchanged in v0.1.0 and v0.2.0, and the delta supersedes one clause of
  each at v0.3.

## The defect, found by executing against it

v0.1.0 states two rules about a vocabulary citation's `digest` that
cannot both work:

- §7.1.12: the digest is *"the bundle's integrity digest, VERBATIM — the
  same `sha256-…` string the bundle carries, never a re-encoding of it."*
- §8.5.3: a verifier that resolves a vocabulary *"whose bytes do not
  match the cited digest MUST refuse the classification."*

A file cannot contain its own hash. A digest the bundle CARRIES is
necessarily computed over something other than the fetched bytes — a
source merkle, a manifest-less content form — so a stranger holding only
the fetched artifact and the citation cannot perform §8.5.3's check
without the producing toolchain's private algorithm, which is exactly the
dependency §8.5 was designed to avoid. The contradiction stayed invisible
until the first re-mint against it: the 2026-09-19 `nlang` dev drop
stopped minting the `@snapp` manifest into emitted bundles at all, at
which point there was no carried string to cite and no way to check one.

## The rule (normative at v0.3, delta §2)

- A vocabulary citation's digest is **SHA-256 over the fetched artifact
  bytes**, spelled `sha256-<base64>` — SRI-style, computable by publisher
  and resolver alike from nothing but the artifact.
- The digest lives in the CITATION — the §8.5.1 TXT record's `h` tag and
  `actClassification.vocabularies[].digest` — and is never required to
  appear inside the artifact. An artifact MAY carry internal integrity
  metadata; it has no protocol meaning.
- "VERBATIM" now means: cite the publisher's declared digest string
  exactly, and that string MUST equal the SHA-256 of the artifact bytes.
  §8.5.3's byte-check is unchanged — this RFC makes it performable.
- Citations minted before this rule against carried-integrity strings
  remain resolvable only by parties who pin those exact artifacts; a
  publisher SHOULD re-declare such citations SRI-style.

## Why not the alternative

Keeping carried integrity and specifying its algorithm would put the
producing toolchain's canonical-content definition inside every APH
resolver, for no security gain: the SRI hash already binds the citation
to the exact bytes a resolver fetches, which is the only thing §8.5.3
ever checks. The failure asymmetry §8.5.2 documents (denial, never
substitution) is preserved unchanged.

## Decision

**Accepted 2026-08-31**, by the sole maintainer (standing solo
arrangement, recorded). Decided on a decision card the same day the
contradiction was found, because the first blessed citation
(`aph_guardrails`) was minted the same day and every citation minted
under the ambiguity inherits it. The blessed `aph_guardrails@0.1.0`
citation is SRI-style from birth.
