# aph — the Go binding

**Check "did a human authorize this agent's message?" from Go — one
`go get`, no cgo, no C toolchain, one artifact everywhere.**

A Go binding of the APH reference implementation. The reference crate is
compiled to a plain WebAssembly module and executed in-process by
[wazero](https://wazero.io), a pure-Go WebAssembly runtime — so `go get`
works with **no cgo, no C toolchain, and one artifact for every platform**.
The wasm ABI shim lives at `interpreters/rust/aph-wasm-abi`; its ABI is
documented in that crate well enough to target from any language.

This is a **binding, not an implementation**: zero cryptography and zero
canonicalization happen in Go. Envelopes cross the boundary as **JSON text in
both directions** — and in Go the reason is the original one, not an
inherited formality: `encoding/json` widens numbers to `float64`, and the
envelope's untagged, position-sensitive `proof` union must never be decided
by a second deserializer. An integer no double can hold (2⁵³+1) survives this
boundary byte-exact *because* it is never decoded into a Go number; there is
a test whose whole job is that sentence.

## Use

```go
ctx := context.Background()
rt, err := aph.New(ctx)      // instantiates the embedded wasm module
defer rt.Close(ctx)

parsed, err := rt.ParseEnvelopeJSON(ctx, envelopeText)
mode,   err := rt.VerifyProofStructure(ctx, envelopeText)
err          = rt.RequireAttestationMode(ctx, envelopeText, "PrincipalSigned")
inWindow, err := rt.MandateIsValidAt(ctx, mandateText, "2026-05-21T00:05:00Z")
err          = rt.VerifyEmbeddedMandateBinding(ctx, envelopeText)
```

Errors carry the APH protocol code as a matchable string: `errors.As` into
`*aph.Error` and compare `.Code` against `"APH_E013"` exactly as a TypeScript
caller matches a thrown message. The operations are methods on a `*Runtime`
handle rather than package-level functions — the one idiom divergence from
the sibling bindings, and a deliberate one: the wasm instance has a lifecycle
(`New`/`Close`) the other three runtimes manage implicitly, and Go's
convention is to make such a lifecycle explicit.

## Parity

`aph-ts` (wasm/JS), `aph-py` (Python), the Elixir binding, and this package
are FOUR bindings of one reference at a stated export-parity contract: the
same four envelope-facing operations, the same semantics, the same error
identity. An operation added to any one is unfinished until it lands in the
other three. None of the four is a second implementation — that is
`interpreters/typescript/`, which shares nothing with the reference but the
specification and the published vectors.

## The committed artifact, and how to regenerate it

`internal/wasm/aph.wasm` is this repository's one deliberate binary, and it
is **verified rather than trusted**: CI rebuilds it from the pinned Rust
toolchain and byte-diffs the result against the committed copy on every push
that could affect it. Reproducibility rests on two legs — the pinned
compiler version (see `.github/workflows/go.yml`, and move the artifact in
the same commit that moves the pin) and canonicalized source paths, because
rustc embeds panic-location and registry paths that would otherwise differ
per machine and leak developer paths into a committed file.

**The reference builder is the CI job, not a developer machine.** The same
rustc version on macOS and on Linux does not produce byte-identical wasm —
the host-shipped standard library differs — so exactly one platform's bytes
can be the committed truth, and the Linux runner is it. To regenerate after
changing the shim or moving the toolchain pin:

1. Push the source change (the byte-diff job fails, by design, and uploads
   the freshly built reference as the `rebuilt-aph-wasm` workflow artifact).
2. Download that artifact, place it at `internal/wasm/aph.wasm`, run
   `go test ./...` locally against it (wasm is platform-independent at
   runtime, so any machine can verify it), and commit.

A local build with the same canonicalized flags is still useful — it proves
the source compiles and the tests pass end to end before pushing — it just
cannot produce the committed bytes:

```sh
cd interpreters/rust
RUSTFLAGS="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=$(pwd)=/build" \
  cargo build --release --target wasm32-unknown-unknown -p aph-wasm-abi
cp target/wasm32-unknown-unknown/release/aph_wasm_abi.wasm ../go/internal/wasm/aph.wasm
cd ../go && go test ./...
```

## Tests

`go test ./...` runs the suite over the published corpus: the signed golden
admitted by every operation, a forged `PrincipalSigned` label refused with
`APH_E013` and a mode downgrade with `APH_E012` (exact codes, not error
substrings), both proof-union arms round-tripped value-lossless against the
published bytes, the 2⁵³+1 widening tripwire, and a pin that the boundary is
string-in/string-out. A missing or truncated embedded artifact fails with a
REGENERATE-FIRST message pointing here, never a runtime panic.
