# aph-py

Python bindings for the APH (Agent per Human) v0.1 protocol types. The Python
module is named `aph`.

This crate validates envelopes against the canonical Rust
`NotarizationEnvelope` shape from `aph-core`, crossing the FFI boundary as
**JSON text in both directions** — the Python side hands in and receives
`str`, never `dict` or `list`. That routing is deliberate, and it is the same
rule the wasm binding follows: the envelope's `proof` union is an untagged
object-or-array shape, so which arm deserializes is decided by what the bytes
look like. Routing envelopes through Python objects hands that decision to a
second deserializer reading whatever the caller's objects hold, and a Python
`float` is an IEEE-754 double exactly like a JS `number` — a caller who edits
a parsed envelope can hand `bodySize` back as a float, or as an integer past
2^53 that a double cannot hold, without noticing either. Text in, text out:
the only number parser that runs is `serde_json`'s.

## Parity with the other two bindings, and what this crate is not

`aph-py`, `aph-ts` and the Elixir binding under `interpreters/elixir` are three
**bindings of one reference implementation**, not three implementations. They
export the same operations, with the same semantics and the same error text, in
each language's idiom:

| `aph-ts` (JS)            | `aph` (Python)             | `aph` (Elixir)                   |
|--------------------------|----------------------------|----------------------------------|
| `parseEnvelopeJson`      | `parse_envelope_json`      | `APH.parse_envelope_json/1`      |
| `serializeEnvelope`      | `serialize_envelope`       | `APH.serialize_envelope/1`       |
| `verifyProofStructure`   | `verify_proof_structure`   | `APH.verify_proof_structure/1`   |
| `requireAttestationMode` | `require_attestation_mode` | `APH.require_attestation_mode/2` |

None may grow an operation the others lack. Bindings that teach different
things about one protocol are how a protocol acquires several meanings — so a
change to this surface is not finished until the same change lands in the other
two, and the reverse. The Elixir member answers `{:ok, result} | {:error,
code}` instead of raising, because that is the BEAM's spelling for a refusal
that is an ordinary outcome; the `APH_E*` code still travels as the wire string.

What none of the three is: independent evidence. A binding that agrees with the
reference agrees with itself. The question "can a stranger build this from the
specification alone?" is answered by an implementation that shares no code
with this workspace — not by any of these bindings.

## Test

`aph-py` sits **outside** `default-members`, so plain `cargo test` never
reaches it: a Python toolchain is not a prerequisite for testing the protocol
crates. Name it explicitly:

```sh
cargo test -p aph-py
```

The tests run under a real interpreter (`Python::attach` with pyo3's
`auto-initialize`), which needs a Python distribution shipping a **shared**
libpython — a framework build on macOS, `python3-dev` or an equivalent on
Linux. pyo3's build script says so plainly if the one it finds is static-only.

## Build a wheel

Wheel builds are documented, not gated — CI's job is `cargo test -p aph-py`.

```sh
# One-time:
pip install maturin

# From interpreters/rust/aph-py/:
maturin build --release      # wheel in ../target/wheels/
maturin develop              # or: install into the active virtualenv
```

`abi3-py39` means one wheel serves CPython 3.9 and every later version rather
than one wheel per minor release.

## Usage

```python
import json
import aph

# Both directions are JSON strings.
normalized = aph.parse_envelope_json(received)      # raises on invalid shape
envelope = json.loads(normalized)                   # plain dict
round_tripped = aph.serialize_envelope(json.dumps(envelope))

# Structure verification: which attestation mode do these bytes prove?
mode = aph.verify_proof_structure(received)         # "PrincipalSigned" | "NotaryAttested"

# Policy gate: refuses an envelope weaker than required.
aph.require_attestation_mode(received, "PrincipalSigned")
```

### Errors

Every refusal raises `aph.AphError`. Protocol refusals carry the reference
implementation's own message, which leads with the `APH_E*` code — so a Python
caller matches a code exactly as a TypeScript caller matches it on the thrown
message:

```python
try:
    aph.verify_proof_structure(received)
except aph.AphError as e:
    if str(e).startswith("APH_E013"):
        ...  # a PrincipalSigned label above a structure that cannot bear it
```

`APH_E013` is a forged `PrincipalSigned` label; `APH_E012` is a refused mode
downgrade. Shape refusals — a field APH never defined, a malformed document —
raise the same exception carrying the parser's message instead of a code,
because no protocol rule has been reached yet.

## Status

The surface covers JSON round-trip plus proof-structure verification, so a
Python consumer can detect a forged `PrincipalSigned` label instead of
trusting the self-asserted string. Cryptographic signature verification stays
on the Rust side. Any addition here is an addition to the other two bindings as
well; see the parity contract above.
