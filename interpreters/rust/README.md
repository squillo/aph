# APH — Rust reference implementation

The reference implementation of the [APH protocol](../spec/aph-0.1.md), v0.1.

```sh
cargo test                      # 185 tests
cargo clippy --all-targets -- -D warnings
```

## Crates

| Crate | What it is |
|---|---|
| [`aph-core`](aph-core/) | The protocol: envelope wire types, mandates, flow state machines, roles, error taxonomy, and signing helpers. No dependency on anything outside serde/chrono/p256/base64/thiserror. |
| [`aph-conformance`](aph-conformance/) | Golden fixtures, contract tests, the three channel binding specs, and a suite that validates the repo's `examples/` against the implementation. |
| [`aph-cli`](aph-cli/) | The `aph` binary — `validate`, `inspect`, `golden`. |
| [`aph-ts`](aph-ts/) | WebAssembly binding: `parseEnvelopeJson`, `serializeEnvelope`, `verifyProofStructure`, `requireAttestationMode`. |
| [`aph-py`](aph-py/) | Python binding (pyo3, module `aph`): the same four operations in snake_case — `parse_envelope_json`, `serialize_envelope`, `verify_proof_structure`, `require_attestation_mode`. |
| [`aph-resolver`](aph-resolver/) | Ready-made §8.4.5 DNS TXT + §8.4.4 `did:web` fetch adapters over `aph-core`'s discovery ports, for adopters with no adapter layer of their own. The ONLY crate carrying HTTP/DNS/runtime dependencies. |

`aph-ts` and `aph-py` are two **bindings of this one implementation**, held at
export parity — same operations, same semantics, same error text, each in its
language's case convention. Neither is a second implementation. Adding an
operation to one is unfinished until it lands in the other.

Both are workspace members and both sit OUTSIDE `default-members` (6 members,
4 default), each because building it needs a toolchain the protocol crates do
not: `aph-ts` targets `wasm32-unknown-unknown`, and `aph-py` links a Python
interpreter. So `cargo test` at the workspace root attempts neither — name
them:

```sh
cargo check -p aph-ts --target wasm32-unknown-unknown
wasm-pack build aph-ts --target web

cargo test -p aph-py     # needs a Python distribution with a shared libpython
```

## Runnable examples

Each prints its own explanation as it goes — read the source alongside the
output.

```sh
cargo run -p aph-core --example parse_and_inspect    # strict parsing, reading a claim
cargo run -p aph-core --example sign_and_verify      # JCS -> detached JWS -> verify -> tamper
cargo run -p aph-core --example mandates_and_flows   # scope + validity + both state machines
```

## Command line

```sh
cargo run -p aph-cli -- validate ../../examples/slack_reply_envelope.json
cargo run -p aph-cli -- inspect  ../../examples/slack_reply_envelope.json
cargo run -p aph-cli -- golden            # list conformance fixtures
cargo run -p aph-cli -- golden 3          # print fixture 3 as raw JSON
```

`validate` performs a **strict structural parse only**. It does not check
signatures, time windows, or body hashes — those are spec §8.3 steps 2–8, and
the CLI implements step 1. Exit codes: `0` valid, `1` invalid, `2` usage error.

## Conformance

Two fixture corpora are exercised:

- **In-source goldens** (`aph-conformance/src/lib.rs`) — seven envelopes
  covering a foreign `did:web` issuer on ES256, a populated `linkedMandate`,
  a multi-hop `actChain`, and three awkward `recipientAddressing` shapes.
- **Published examples** (`../../examples/*.json`) — the documents handed to
  third-party implementers. `repo_examples_test.rs` asserts they strict-parse
  AND that what this implementation emits is value-identical to them, which is
  what catches serializer-side drift.

## Wire compatibility

Every serde attribute here is load-bearing. Verification re-canonicalizes a
received envelope and checks the signature over those bytes, so a field
rename, a changed `null`-vs-omitted decision, or a different key ordering
invalidates credentials that were already issued.

Two divergences from the referenced RFCs are deliberate, documented in-source,
and pinned by tests:

1. Canonicalization sorts keys in UTF-8 byte order (RFC 8785 specifies UTF-16
   code-unit order) and formats floats via Rust `Display` rather than the
   ECMAScript number algorithm.
2. Detached JWS carries DER-encoded ES256 signatures rather than RFC 7518's
   raw R‖S, and declares `b64:false` while encoding the payload into the
   signing input.

Both are the deployed wire behavior. Changing either is a version-bump
decision, not a bug fix — the tests that pin them say so explicitly.
