---
section: "APH Specification"
name: "APH Spec Module Index"
version: "0_1_0"
---
# APH Specification — Module Index

Deterministic declaration index for the `APH_SPEC` directory.
Per N_BOOK 1.1 "The Determinism Invariant": declaration order IS load order.

Load order is dependency order. `APH` declares the Snapp itself and the
protocol constants. `APH_PROTOCOL` declares the closed vocabularies and
enumerations that later blocks reference by name. `APH_ENVELOPE` defines the
credential, and `APH_MANDATES` the two documents that carry authority into
it.

## Module Declarations

```nlang
mod APH {};
mod APH_PROTOCOL {};
mod APH_ENVELOPE {};
mod APH_MANDATES {};
```
