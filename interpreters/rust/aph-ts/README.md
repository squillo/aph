# aph-ts

WebAssembly bindings for the APH (Agent per Human) v0.1 protocol types.

This crate validates envelopes against the canonical Rust
`NotarizationEnvelope` shape from `aph-core`, crossing the wasm boundary
as **JSON text in both directions** — the JS side hands in and receives
strings, never structured `JsValue`s. That routing is deliberate: the
envelope's `proof` union is an untagged object-or-array shape, and a
`JsValue` path widens integers through JavaScript's f64 on the way in,
which can reject a valid chain-form envelope. Text in, text out — the
only number parser that runs is `serde_json`'s.

This crate targets `wasm32` and is excluded from default host builds and
tests (see `default-members` in the workspace `Cargo.toml`); build it
explicitly with `wasm-pack` as shown below. Its native tests run with
`cargo test -p aph-ts`; the wasm32 smoke suite runs under Node with
`wasm-pack test --node aph-ts`. CI runs both on every push.

## Build

```sh
# Install wasm-pack (one-time):
cargo install wasm-pack

# Build the wasm bundle (web target), from interpreters/rust/:
wasm-pack build aph-ts --target web

# Output lives in aph-ts/pkg/ as an npm-compatible package.
```

## Usage (TypeScript)

```ts
import init, {
  parseEnvelopeJson,
  serializeEnvelope,
  verifyProofStructure,
  requireAttestationMode,
} from 'aph-ts';

await init();

// Both directions are JSON strings.
const normalized: string = parseEnvelopeJson(jsonString);
const roundTripped: string = serializeEnvelope(normalized);

// Structure verification: which attestation mode do these bytes prove?
// A forged `PrincipalSigned` label above a single proof throws APH_E013.
const mode: string = verifyProofStructure(jsonString);

// Policy gate: throws APH_E012 if the envelope is weaker than required.
requireAttestationMode(jsonString, 'PrincipalSigned');
```

## Status

The API surface covers JSON round-trip plus proof-structure verification
(`verifyProofStructure` / `requireAttestationMode`), so a TS consumer can
detect a forged `PrincipalSigned` label instead of trusting the
self-asserted string. Cryptographic signature verification stays on the
Rust side; ergonomic per-field accessors may land in a follow-up.
