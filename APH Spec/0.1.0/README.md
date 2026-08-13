# APH Specification Snapp

The APH protocol's JSON documents, defined as N Lang types: the
`NotarizationEnvelope` and everything inside it, both mandate types, the
closed vocabularies, the two flow state machines, the error taxonomy, and
the key discovery records.

## N Lang

**N Lang is a programming language by [Squillo](https://squillo.com).** Its
unit of distribution is a *Snapp* — a versioned, compiled bundle of nodes
and types that other Snapps depend on. To learn the language, start here:

> **<https://squillo.com/nlang>**

With the CLI installed, `nlang how <topic>` is the fastest way in. It
returns worked examples with citations into the language book:

```sh
nlang how define a block struct
nlang how define an enum
nlang how library snapp lib entry point
```

## What this Snapp is

A **literate specification**. The `.n.md` files are markdown documents whose
fenced `nlang` blocks are the actual declarations — the prose explaining a
type and the type itself live in one place and cannot drift apart.

It is also a **library**: no `main`, nothing executable. APH does not ship
an N Lang runtime. The protocol's executable reference implementation is the
Rust workspace at [`interpreters/rust`](../../interpreters/rust); this Snapp
exists so N Lang consumers read the same shapes that implementation
enforces, rather than re-deriving them from prose.

The specification text is normative. Where this Snapp and
[`spec/aph-0.1.md`](../../spec/aph-0.1.md) disagree, the specification wins.

## Layout

| Path | Contents |
|---|---|
| `lib.n.md` | Snapp root. Declares `APH_SPEC`. |
| `APH_SPEC/mod.n.md` | Module index. Declaration order IS load order. |
| `APH_SPEC/APH.n.md` | Snapp definition, protocol constants, contexts, the A2A extension URI. |
| `APH_SPEC/APH_PROTOCOL.n.md` | Roles, closed vocabularies, both flow state machines, the error taxonomy, key discovery (§5, §8.4, §9, §11). |
| `APH_SPEC/APH_ENVELOPE.n.md` | The notarization envelope and its subject objects (§7). |
| `APH_SPEC/APH_MANDATES.n.md` | Delegation and Communication Mandates (§6). |
| `how/` | Worked examples served by `nlang how`, one JSON file per example. |

Declaration order is load order, and a sibling file that is not declared in
a `mod` index never loads (N_BOOK 1.1, "The Determinism Invariant"). A
module declared as `mod X {};` must be backed by a file named exactly
`X.n.md`; prose-only companions carry no `.n` and are not modules.

## Building

```sh
nlang export     # compile and write ../../snapp/aph@<version>.json
```

`nlang export` is the gate that matters. `nlang ast` only tokenizes a single
file and does not understand literate `.n.md` at all — it fails on ordinary
markdown prose, including on the gold-standard Snapps. Only `export`
resolves types across files.

The exported bundle under [`snapp/`](../../snapp) is committed; the
intermediate `build/` directory is not.

## Learning APH from the CLI

This Snapp registers as an `nlang how` plugin, so once it is installed the
protocol is searchable from the terminal alongside the language's own
examples:

```sh
nlang how --plugin aph --list        # all 15 examples, by category
nlang how notarization envelope      # search across every plugin
nlang how delegation mandate scope
nlang how did:key offline discovery
```

Each example carries the declaration, a note explaining the reasoning
behind it, and a citation into the specification.

### Installing locally

Discovery is by symlink into the Snapp directory, the same as the other
Spec Snapps on a Squillo workstation:

```sh
ln -sfn "$PWD" ~/.n/snapps/aph
nlang plugin refresh
```

`nlang plugin refresh` reports the Snapps it discovered; `aph` appearing in
that list is the confirmation that registration worked.

### Adding an example

Drop a JSON file into the matching `how/<category>/` directory with exactly
five keys — `title`, `tags`, `nlang_code`, `note`, `book_ref` — then run
`nlang plugin refresh`. A new *category* additionally needs an entry under
`cli_plugin.how.categories` in `.n/nlang.config.n` pointing at its
directory; without that entry the files are simply never read.

Keep `nlang_code` copied from the `.n.md` sources rather than paraphrased,
so an example cannot drift from the type it documents.

## Round-trip verification

The published example envelopes are checked against these blocks by
`interpreters/rust/aph-conformance/tests/nlang_snapp_test.rs`, which runs
under `cargo test` in CI. It reads the committed bundle rather than
invoking the N Lang compiler, so it needs no toolchain beyond Rust.

It checks both directions. Every key of every published example must map to
a declared prop, walking nested objects and validating internally tagged
enum variants against their declared items; and every required prop must be
exercised by at least one example, so the types cannot declare surface the
protocol never sends.

The check is mutation-tested — renaming a prop, adding an unexercised
required prop, and adding an undeclared enum item were each confirmed to
fail it before it was trusted.

One caveat worth knowing: a **typed ledger binding is not structurally
validated** by the compiler today. Unknown props, missing required props,
and wrong-typed values are all accepted in a `x: <Block> = { ... }`
construction. That is why this round-trip lives outside N Lang rather than
as an in-Snapp test — an in-Snapp version would pass unconditionally and
prove nothing.

## Notes for editors

Three N Lang rules shape these files, each learned from a compiler error
rather than assumed:

**A type definition carries either props or enums, never both.** So
`VaultMutationMandate` holds the props while its variants live beside it in
`VaultMutation`, and `AphTxtKeyRecord` sits beside the `Discovery` enums
rather than inside them.

**A prop referencing a namespaced enum accepts only the fully qualified
path**, `$::*::Container::Enum`. The shorter `Container::Enum` and
`Container.Enum` forms are rejected by the parser.

**`emit_types` must be `true`** in `.n/nlang.config.n`, against the scaffold
default. With it off, the bundle keeps the prop-bearing blocks and silently
drops every enum — the error codes and vocabularies simply vanish.

On naming: wire names are camelCase and props are snake_case, mapped
mechanically (`aphVersion` → `aph_version`). `@context` has no identifier
form and is noted where it appears. `type` is spelled exactly as it appears
on the wire, since N Lang permits it as a prop name where Rust needs
`r#type`. The snake_case interior of `vaultMutation` inside the camelCase
envelope is the deployed wire shape, not an inconsistency to tidy.

## License

Apache-2.0 — see [LICENSE](../../LICENSE).
