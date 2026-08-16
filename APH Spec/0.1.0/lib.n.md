---
section: "APH Specification"
name: "APH Module Index"
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


Deterministic declaration index for the APH Specification Snapp root.
By the language's determinism invariant, declaration order IS the file
load order. A sibling file that is not declared here never loads, so this
index replaces glob-based discovery for the APH Snapp.

## Module Declarations

```nlang
mod APH_SPEC {};
```
