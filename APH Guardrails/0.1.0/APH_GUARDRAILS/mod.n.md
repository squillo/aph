---
section: "APH Guardrails"
name: "APH Guardrails Module Index"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Classifier Module Index

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

Deterministic declaration index for the `APH_GUARDRAILS` directory.
By the language's determinism invariant, declaration order IS load order.

## Why the order is what it is

Ledger position is not decoration here — it is the extension mechanism. The
**first** entry for a classifier namespace is the base, which establishes the
floor; **every later entry for that namespace is a tighten-only overlay**. So
the order below is what makes a third party's contribution a refinement rather
than a redefinition.

The families are grouped so that reading them in load order walks the same path
a verifier walks:

1. **Acts** — what is the agent actually asking for? Seven families, from
   scheduling through the delegation chain itself.
2. **Guards** — sealed, fail-closed gates. Consent, safety, injection, and
   disclosure. These load after the acts because they answer a question *about*
   an act.
3. **Risk** — how bad is it if this act is wrong, on two axes that are
   deliberately independent: how recoverable, and how many parties are hit.
4. **Routing** — `APH_HUMAN_LOOP` loads **last** because it is the output the
   other fifteen feed into. Its labels answer "so what do we do", and that
   answer is only meaningful once everything upstream has a verdict.

A file not declared here never loads. Adding a family means adding a line.

## Module Declarations

```nlang
mod APH_ACT_SCHEDULING {};
mod APH_ACT_COMMITMENT {};
mod APH_ACT_DATA_MUTATION {};
mod APH_ACT_ACCESS {};
mod APH_ACT_FINANCIAL {};
mod APH_ACT_LEGAL {};
mod APH_ACT_AUTHORITY {};
mod APH_GUARD_CONSENT {};
mod APH_GUARD_SAFETY {};
mod APH_GUARD_INJECTION {};
mod APH_GUARD_DISCLOSURE {};
mod APH_JURISDICTION {};
mod APH_RISK_IRREVERSIBILITY {};
mod APH_RISK_BLAST_RADIUS {};
mod APH_URGENCY {};
mod APH_HUMAN_LOOP {};
```
