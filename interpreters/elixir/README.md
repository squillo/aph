# aph-ex

**Gate every agent-sent message in your BEAM pipeline on a verifiable human
authorization — strict-parse it, check its window, bind it to its mandate —
with the Rust reference doing the judging and Elixir doing the routing.**

Elixir bindings for the APH (Agent per Human) v0.1 protocol types. The OTP
application and the public module are both named `aph` / `APH`.

This is a **binding** of the Rust reference implementation — a rustler NIF over
`aph-core` — and not a second implementation of the protocol. There is no
cryptography on the Elixir side: not a `:crypto` call, not a canonicalizer, not
a signature check. Anything that touches a signature crosses into Rust.

## The boundary is JSON text, in both directions

Every function takes a JSON string and returns a JSON string. Envelopes never
cross as maps or lists, and that is a structural safety property rather than a
convenience — it is the same rule the wasm and Python bindings follow.

The envelope's `proof` field is an untagged union: a single object
(`NotaryAttested`) or a two-element chain (`PrincipalSigned`, principal first).
Untagged matching is exactly where a value that changed shape can silently
change which arm deserializes, and a term route hands that decision to a
*second* deserializer reading whatever the caller's terms happen to hold.

The BEAM makes that hazard easy to underestimate, which is why it is spelled
out: Erlang integers are arbitrary precision, so the integer-widening trap that
motivates the rule in JS and Python does not bite here. The trap that does bite
is the encoder — a map/list encoder must pick one arm of the union with no
schema to consult, and a caller who decoded an envelope, edited it and handed
the terms back can produce a one-element proof list or a float `bodySize`
without noticing. Text in, text out: the only union and number parser that runs
is `serde_json`'s.

## Parity with the other three bindings, and what none of them is

`aph-ex`, the wasm binding, the Python binding and the Go binding are four
**bindings of one reference implementation**. They export the same six
operations, with the same semantics and the same error identity, each in its
language's idiom (the Go column lives in
[aph-py's README](../rust/aph-py/README.md), which carries the full
four-column table):

| wasm/TS                  | Python                     | Elixir                           |
|--------------------------|----------------------------|----------------------------------|
| `parseEnvelopeJson`      | `parse_envelope_json`      | `APH.parse_envelope_json/1`      |
| `serializeEnvelope`      | `serialize_envelope`       | `APH.serialize_envelope/1`       |
| `verifyProofStructure`   | `verify_proof_structure`   | `APH.verify_proof_structure/1`   |
| `requireAttestationMode` | `require_attestation_mode` | `APH.require_attestation_mode/2` |
| `mandateIsValidAt`       | `mandate_is_valid_at`      | `APH.mandate_is_valid_at/2`      |
| `verifyEmbeddedMandateBinding` | `verify_embedded_mandate_binding` | `APH.verify_embedded_mandate_binding/1` |

None may grow an operation the others lack. Bindings that teach different
things about one protocol are how a protocol acquires several meanings — so a
change to this surface is not finished until the same change lands in the other
two, and the reverse.

What none of them is: independent evidence. A binding that agrees with the
reference agrees with itself. The question "can a stranger build this from the
specification alone?" is answered by an implementation that shares no code with
the reference — see `interpreters/typescript/`.

## ⛔ Why the NIF glue is trivially thin

This is a testability rule, not a style preference, and it is forced by the
hosting relationship. A pyo3 extension embeds CPython *inside* Rust, so
`cargo test` can start an interpreter and drive that whole boundary. A rustler
NIF is the inverse — Rust embedded *in* the BEAM — and there is no supported
way to embed the BEAM in a Rust test binary. `mix test` is therefore the only
thing that ever exercises the term boundary.

The mitigation is architectural. Every NIF function is
`decode binary -> call aph-core -> encode result` and nothing else, so the
entire behavioural surface already lives in `aph-core` under `cargo test`, and
what only `mix test` can reach shrinks to term glue. A wrapper that grows a
branch, a default, or a coercion is a **defect**, precisely because no Rust
test can reach it. The NIF crate is built `cdylib`-only and carries no
`#[cfg(test)]` module for the same reason: such a test binary could not link,
because the `enif_*` symbols it would need are supplied by the BEAM at load
time.

## Build and test

Requires a Rust toolchain (mix compiles the NIF through cargo) and a BEAM
toolchain. From this directory:

```sh
mix deps.get
mix test
```

The declared floor is Elixir 1.13 / OTP 24 — the oldest pair this has been run
and passed on. CI runs a current pair instead; both matter, and the workflow
comment says why the floor cannot run there.

The rustler version is pinned tight on purpose. The installed BEAM toolchain,
not the newest release number, decides it: rustler 0.37 and later actually
require Elixir 1.15 even where the package metadata says otherwise, and 0.37.0
was retired over a bug in how it discovers a crate's workspace shape — not a
thing to be adventurous about when the crate under `native/` has an unusual
one. See the comment in `mix.exs`.

### Layout, and why the NIF crate is not a workspace member

```
mix.exs                     the OTP app `aph`
lib/aph.ex                  APH — the documented surface (pure delegation)
lib/aph/native.ex           APH.Native — the NIF module
native/aph_nif/             the rustler crate: a path dependency on aph-core
test/                       ExUnit: the only gate that sees the term boundary
```

`native/aph_nif` is excluded from the Rust workspace rather than merely kept
out of its default members. Mix is the build driver for a NIF, and two build
drivers pointed at one workspace member is a reliability defect — they disagree
about target directory, profile and feature unification, and cargo would
produce an artifact mix then rebuilds anyway. Keeping it out of the default set
(the shape the wasm and Python bindings use) only half-solves that, because an
explicit `-p` or a `--workspace` flag still reaches a member.

## Usage

```elixir
# Both directions are JSON strings.
{:ok, normalized} = APH.parse_envelope_json(received)
envelope = Jason.decode!(normalized)
{:ok, ^normalized} = APH.serialize_envelope(Jason.encode!(envelope))

# Structure verification: which attestation mode do these bytes prove?
{:ok, mode} = APH.verify_proof_structure(received)

# Policy gate: refuses an envelope weaker than required.
:ok = APH.require_attestation_mode(received, "PrincipalSigned")
```

`Jason` above is the caller's choice, not this package's requirement — nothing
under `lib/` decodes JSON. It appears in `mix.exs` because the test suite uses
it, and because the NIF library already requires it.

### Errors

Every refusal is `{:error, message}` — a plain string, never an exception,
because a refused envelope is an ordinary outcome on this boundary. Protocol
refusals carry the reference implementation's own message, which **leads with**
the `APH_E*` code, so a BEAM caller matches a code exactly as a TypeScript
caller matches it on the thrown message:

```elixir
case APH.verify_proof_structure(received) do
  {:ok, mode} -> mode
  {:error, "APH_E013" <> _} -> :forged_label
  {:error, other} -> {:refused, other}
end
```

`APH_E013` is a forged `PrincipalSigned` label; `APH_E012` is a refused mode
downgrade. Shape refusals — a field APH never defined, a malformed document —
carry the parser's message and no code, because no protocol rule was reached.

## Status, and what has NOT been done

The surface covers JSON round-trip plus proof-structure verification, so a BEAM
consumer can detect a forged `PrincipalSigned` label instead of trusting the
self-asserted string. Cryptographic signature verification stays on the Rust
side. Any addition here is an addition to the other three bindings as well; see
the parity contract above.

**Not published to hex.pm.** This package has never been pushed, and `mix.exs`
carries no package metadata precisely so it cannot be mistaken for something
that has. The `aph` name on hex.pm was not registered when this was written,
but *unclaimed is not reserved* — the same lesson the crates.io registration
taught, where a name that looked obvious already belonged to someone else.
Claiming the name and publishing are owner actions, not build steps, and
nothing here should be read as either having happened.
