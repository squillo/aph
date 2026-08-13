---
section: "APH Specification"
name: "APH Spec Module Index"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Specification — Module Index

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.


Deterministic declaration index for the `APH_SPEC` directory.
Per N_BOOK 1.1 "The Determinism Invariant": declaration order IS load order.

Load order is dependency order. `APH` declares the Snapp itself and the
protocol constants. `APH_PROTOCOL` declares the closed vocabularies and
enumerations that later blocks reference by name. `APH_MANDATES` declares the
two documents that carry authority, and `APH_ENVELOPE` the credential that
consumes them.

Mandates load **before** the envelope because the envelope now embeds one:
`PolicyDescriptor.delegation_mandate` is a `DelegationMandate`, so the
mandate type must exist by the time the envelope is read. That ordering is
the load order made visible — the dependency is real, not stylistic.

## Module Declarations

```nlang
mod APH {};
mod APH_PROTOCOL {};
mod APH_MANDATES {};
mod APH_ENVELOPE {};
mod APH_TESTS {};
```
