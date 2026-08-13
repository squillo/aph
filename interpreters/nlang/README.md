# APH — N Lang types

N Lang type definitions for the APH protocol's JSON documents: the
`NotarizationEnvelope` and everything inside it, both mandate types, the
closed vocabularies, the flow states, the error taxonomy, and the key
discovery records.

## What N Lang is

**N Lang is a programming language by [Squillo](https://squillo.com).** Its
unit of distribution is a *Snapp* — a versioned, compiled bundle of nodes
and types that other Snapps can depend on. To learn the language, start at
**<https://squillo.com/nlang>**.

If you have the CLI, `nlang how <topic>` is the fastest way in — it returns
worked examples with citations into the language book:

```sh
nlang how define a block struct
nlang how define an enum
```

## What this Snapp is, and is not

This is a **library Snapp**. It defines types and exports nothing
executable — there is no `main.n` and no binary. APH does not ship an N Lang
runtime; the protocol's executable reference implementation is the Rust
workspace in [`../rust`](../rust).

What it is *for* is qualification: a Snapp gives N Lang consumers the APH
types directly, so they read the same shapes the Rust implementation
enforces instead of re-deriving them from specification prose.

The specification is normative. Where this Snapp and
[`spec/aph-0.1.md`](../../spec/aph-0.1.md) disagree, the specification wins.

## Layout

| File | Contents |
|---|---|
| `src/lib.n` | Library root. Declaration order is load order, and an undeclared sibling file never loads. |
| `src/envelope.n` | `NotarizationEnvelope` and its subject objects (spec §7). |
| `src/mandates.n` | `DelegationMandate` and `CommunicationMandate` (spec §6). |
| `src/protocol.n` | Roles, closed vocabularies, flow states, error taxonomy, key discovery (spec §5, §8.4, §9, §11). |

## Building

```sh
nlang export          # compile and write dist/aph@<version>.json
nlang ast src/lib.n   # parse a single file
```

`nlang export` is the real gate: `ast` only parses, while `export` resolves
types across files.

`emit_types` is set to `true` in `.n/nlang.config.n`, unlike the scaffold
default. A types-only Snapp needs it — with it off, every enum is dropped
from the bundle and only the prop-bearing blocks survive.

## Reading the types

Two N Lang rules shape how these files are written, and both differ from the
Rust side:

**A type definition carries either props or enums, never both.** So
`VaultMutationMandate` holds the props while its variants live beside it in
`VaultMutation`, and the prop references them by qualified path
(`$::*::VaultMutation::VaultMutationKind`) — the only path form props accept.

**Wire names are camelCase; props are snake_case.** The mapping is
mechanical (`aphVersion` → `aph_version`). Two wire keys have no identifier
form at all and are called out where they appear: `@context`, and the
`type` array — the latter *is* a legal prop name in N Lang, unlike in Rust,
so it is spelled exactly as it appears on the wire.

One asymmetry is deliberate rather than an oversight: the interior keys of
`vaultMutation` are snake_case while the envelope around them is camelCase.
That is the deployed wire shape, pinned by the reference implementation, so
it is reproduced faithfully here.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
