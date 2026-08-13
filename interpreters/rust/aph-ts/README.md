# aph-ts

WebAssembly bindings for the APH (Agent per Human) v0.1 protocol types.

This crate re-exports the canonical Rust `NotarizationEnvelope` shape from
`aph-core` via `wasm-bindgen`, providing a single source-of-truth for
TypeScript / JavaScript consumers.

This crate targets `wasm32` and is excluded from default host builds and
tests (see `default-members` in the workspace `Cargo.toml`); build it
explicitly with `wasm-pack` as shown below.

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
import init, { parseEnvelopeJson, serializeEnvelope } from 'aph-ts';

await init();

const env = parseEnvelopeJson(jsonString);
const roundTripped = serializeEnvelope(env);
```

## Status

The current API surface covers JSON round-trip only; ergonomic per-field
accessors / typed constructors may land in a follow-up.
