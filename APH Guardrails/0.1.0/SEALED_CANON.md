# SEALED_CANON — the families that refuse all overlays, and why

This file is the REGISTRY half of a weld. The classifier sources under
`APH_GUARDRAILS/` carry the flags (`sealed = true`, inside each family's
`classifiers` block); this file states the intended sealed SET in one place,
with one line of reason per family; and a conformance walker in the reference
repository compares the two in both directions on every test run. A seal
dropped in an edit — or added without a stated reason — fails a gate instead
of vanishing silently.

The reasons below are the README's extension-model rationale, applied per
family: the tighten-only lattice makes a third-party overlay safe wherever
"stricter" is well-defined, and these six are the families where even a
STRICTER redefinition changes what a verdict means. For them, the only change
path is a new base version a verifier can see and choose.

## The sealed six

| Family | Why sealed |
|---|---|
| `APH_ACT_AUTHORITY` | Classifies changes to the delegation chain itself; an overlay here would let a contribution redefine what counts as granting authority, which is the one act class the lattice must never let anyone refine. |
| `APH_GUARD_CONSENT` | A fail-closed gate on whether a human agreed; "tighter consent" and "different consent" are indistinguishable from outside, so no overlay is admissible. |
| `APH_GUARD_SAFETY` | A fail-closed gate whose labels route to refusal; narrowing a safety label's reach IS widening what passes, so the tighten-only direction is undefined here. |
| `APH_GUARD_INJECTION` | Detects attempts to subvert the classifier stack itself; an overlay surface on the anti-subversion family would be the subversion surface. |
| `APH_GUARD_DISCLOSURE` | A fail-closed gate on revealing protected information; as with safety, "narrower" labels widen what escapes, so the lattice's safe direction does not exist. |
| `APH_HUMAN_LOOP` | The routing output the other fifteen feed; its labels answer "so what do we do", and an overlay would let a contribution reroute verdicts it did not produce. |

## What this file is not

It is not enforcement — the README is already honest that whether
`sealed = true` is honoured is the consuming runtime's property, not these
bytes'. It is not a second source of the flags — the sources are canonical,
and when this file and a source disagree, the walker fails and a person
decides which one is wrong. And it is not append-only: sealing a seventh
family, or unsealing one of these, is done by changing BOTH halves in one
commit, with the reason column carrying the argument.
