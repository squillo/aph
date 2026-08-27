---
section: "APH Guardrails"
name: "APH Guardrails Module Index"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Module Index

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

Deterministic declaration index for the APH Guardrails Snapp root.
By the language's determinism invariant, declaration order IS the file
load order. A sibling file that is not declared here never loads, so this
index replaces glob-based discovery for this Snapp.

## Why this is a separate Snapp

The APH protocol Snapp (`aph`) defines the **wire**: what an envelope looks
like, which fields are signed, how a key is discovered. This Snapp defines
the **meaning**: when an agent says "accept the proposed time" or "update the
customer record", what has it actually claimed?

They are separated because they change on different clocks and for different
reasons. A wire format is stable by obligation — every change risks stranding
credentials already in the field. A vocabulary grows continuously, because new
kinds of act keep being invented. Binding them to one version number would
force the wire to churn at the vocabulary's rate, or the vocabulary to freeze
at the wire's. Independent versions let each move at its own pace, and let a
verifier state exactly which vocabulary version it read.

The separation is also the point of the design. A vocabulary that ships inside
one party's protocol implementation is that party's vocabulary. A vocabulary
that resolves independently is a **third party** both sides can point at — which
is the same move APH already makes for notary keys, applied to meaning instead
of identity. Neither counterparty defines the term; both resolve it.

## Honest scope: the accuracy gates are declarations of intent

Every classifier below names a `golden_set` path under `eval/` and a
`min_accuracy` gate. The corpora do not ship in this version. The gates state
what a conforming evaluation MUST clear before trusting a family's verdicts —
they are not yet evidence that anything clears it, and a consumer must not
read the presence of a gate as the presence of a measurement. Shipping the
corpora, or a per-family measurement in their place, is the open obligation
this paragraph exists to keep visible.

## Module Declarations

```nlang
mod APH_GUARDRAILS {};
```
