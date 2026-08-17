# APH in TypeScript — the second implementation

A complete APH v0.1 implementation — **mint and verify** — written from
`spec/aph-0.1.md` and the published `examples/`. It shares no code with the
Rust reference: its own RFC 8785 canonicalizer, its own strict parser, its own
§7.2.1 signing bases, its own base58btc and `did:key` codecs. Signatures go
through the runtime's WebCrypto.

## The scope, honestly

Read this before the rest, because the value of a second implementation is
exactly as large as the claim it can honestly make.

- **Independence of CODE, not of TEAM.** The same authors wrote both. What
  this proves is that the specification is implementable twice from its own
  text — not that it survives a stranger. The invitation to outside
  implementers in the repository README is the missing half and still stands.
- **No wasm, no binding, no translation.** `aph-ts` and `aph-py` are bindings
  of the reference and prove the boundary; this is a different implementation
  and proves the document. Nothing here imports either, and no Rust logic
  informed this TypeScript — the algorithms, the error mapping, and the
  canonicalizer were derived from the specification text and the published
  vectors. The one place the reference was consulted is the Rust-side
  cross-verify test, `ts_minted_cross_verify.rs`, which had to call real
  `aph-core` APIs and so was written against that crate's public declarations.
  That is a checkable claim rather than a promise about process: nothing under
  `src/` imports the reference, and the cross-verify test is the only Rust in
  this deliverable.
- **It parses bytes and NEVER fetches.** §8.4 key discovery and §6.3.3's
  status fetch are network acts. Keys arrive as parameters, `now` arrives as a
  parameter. That is the same boundary the reference draws around its core, and
  it is why a browser runtime is a legitimate host.
- **Every hash and every signature runs through SubtleCrypto.** Nothing here
  implements a curve or a digest. RFC 8785 canonicalization *is* implemented
  here, because deciding which bytes a signature covers is protocol logic.
- **Dependencies: the TypeScript compiler, at dev time, and nothing else.**
  No runtime package, and no `@types/node` — the small Node surface the tests
  and the mint script use is declared in `types/node-builtins.d.ts`, and
  `src/` imports none of it.

## Cross-verification, in both directions

One implementation reading another's output is half of interop. Both are
committed artifacts, and neither stack invokes the other — they exchange
files.

| Direction | Artifact | Checked by |
|---|---|---|
| → TS verifies Rust | `examples/principal_signed_envelope.json` | `test/verify_golden.test.ts` — all four Ed25519 signatures, individually and through the whole §8.3 procedure |
| → TS verifies Rust | the `ecdsa-jcs-2019` and `JsonWebSignature2020` vectors | `test/corpus.test.ts`, narrowed to the proofs whose `did:key` carries its own key |
| ← Rust verifies TS | `examples/ts_minted_envelope.json` | `interpreters/rust/aph-conformance/tests/ts_minted_cross_verify.rs` — strict parse, structure, issuance order, mandate bindings, and all four signatures |

**Why the committed artifact is Ed25519 only.** Ed25519 is deterministic in
both stacks (RFC 8032 derives the nonce from the key and the message), so the
bytes can be pinned and committed. WebCrypto's ECDSA is **randomized** — it
exposes no RFC 6979 deterministic mode — so an ES256 envelope minted here has
different bytes on every run and there is nothing to commit. ES256 is
therefore covered in one direction as a verify (against the reference's
deterministic vector) plus a mint-then-verify self-test inside one run, in
`test/es256_selftest.test.ts`. Both facts are asserted by tests rather than
asserted here: see `test/known_answer.test.ts`.

## Running it

Node 20 or newer — that is the first release where SubtleCrypto exposes
Ed25519.

```sh
cd interpreters/typescript
npm install          # the compiler, and nothing else
npm run build        # tsc -> dist/
npm test             # node --test dist/test/
npm run mint         # regenerates examples/ts_minted_envelope.json
```

`npm run mint` is idempotent: the fixture is entirely constants and Ed25519 is
deterministic, so a second run writes the same bytes. It refuses to publish
anything its own verifier rejects.

## What the tests are for

Each file opens with why it exists and what it pins; the short version:

- `jcs.test.ts` — RFC 8785, before any signature is involved, so a
  canonicalization bug is reported as one.
- `baseenc_didkey.test.ts` — base58btc and `did:key` checked against the
  PUBLISHED corpus, because a broken encoder that is also a broken decoder
  round-trips perfectly.
- `known_answer.test.ts` — the RFC 8032 §7.1 vectors, signed and compared
  against the RFC's own signatures.
- `verify_golden.test.ts` — the (→) direction.
- `mandate_base_ambiguity.test.ts` — a specification contradiction this
  implementation had to resolve; see below.
- `refusals.test.ts` — the §11 codes, one per attack.
- `mint_roundtrip.test.ts` — the mint and verify halves meeting, plus the
  §7.1.7.1 rules that need a freshly signed mandate to reach.
- `es256_selftest.test.ts` — the paths that cannot be committed.
- `corpus.test.ts` — the comparison harness: a verdict per example file, and a
  failure for any example nobody classified.
- `ts_minted_artifact.test.ts` — byte identity of the (←) artifact.

**A second ECMAScript engine runs the same code, from cargo.** RFC 8785
§3.2.2.3 does not define number serialization — it *defers* to ECMAScript
`Number::toString`, so the bytes a signature covers are decided by whatever
engine this canonicalizer runs on, and a suite that exercises one engine cannot
tell a correct canonicalizer from one that quietly inherited a host assumption.
So `interpreters/rust/aph-js-harness` loads this package's **compiled output**
into Boa — an ECMAScript engine written from scratch in Rust — and drives it
from the same expectation table the Node suite reads,
`testkit/jcs_vectors.json`: one table, two engines, including the
float-formatting edge set that exists for this purpose (integer-valued doubles,
both zeroes, both exponent boundaries, the 2^53 neighbourhood). A row that
disagrees between the engines fails with both outputs printed, as a conformance
finding about this code rather than something to branch around. What it
deliberately does **not** cover is cryptography: a language engine has no
WebCrypto, every hash and signature here goes through SubtleCrypto by design,
and so the second-engine scope is the crypto-free core — canonicalization,
strict parse, proof structure and mode, and the §11 codes reachable without a
signature. A Rust-backed SubtleCrypto shim would extend it to the full verifier
and is named as future work, not smuggled in; until then the signature paths are
proven under Node alone, and this paragraph is the honest boundary. Build first
(`npm run build`), then `cd ../rust && cargo test -p aph-js-harness` — the
harness sits outside the workspace's default members precisely so that testing
the protocol crates never requires a Node toolchain to have run.

## What writing this found

A second implementation earns its keep by disagreeing. One disagreement was
real and is recorded in `src/bases.ts` and pinned in
`test/mandate_base_ambiguity.test.ts`:

**§6.1 and §7.2.1 contradict each other on the mandate signing bases.** §6.1's
field table says a mandate signature covers the canonical form "MINUS" the
signature members; §7.2.1 closes with "In every case the signer sets the field
to the **empty string** rather than removing the member". Removing a member and
emptying it produce different JCS bytes, so the two readings can never verify
each other. The published bytes settle it — the REMOVAL reading is what
`examples/principal_signed_envelope.json` was signed under, and the test proves
the emptying reading does not verify. §7.2.1's closing sentence is correct for
`proofValue` and overreaches into the mandate bullet three lines above it.

Two smaller notes, filed rather than accommodated:

- §6.1 describes `notarySignature` as "Multibase- **or** base64url-encoded".
  This decoder accepts multibase only. Two spellings of one signature make a
  mandate's bytes non-unique, which is the failure §7.2 spends a section
  arguing against, and every published artifact uses multibase.
- §8.4.3 prints "0xed01 indicates Ed25519; 0x1200 indicates P-256", which are
  two different conventions: `ed01` is already the unsigned-varint form, while
  `1200` is the multicodec code whose varint form is `0x80 0x24`. This
  implementation follows the multicodec registry and the W3C `did:key`
  registration, which is why its P-256 identifiers read `zDn…`.

If your own implementation disagrees with a published artifact, file it — see
the repository `CONTRIBUTING.md`. Where the specification and a fixture
conflict, the fixture is the defect.
