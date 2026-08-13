# aph-core

Reference Rust implementation of the [APH (Agent per Human)](https://github.com/squillo/aph)
notarization protocol, v0.1.

APH binds an agent's outbound action to a verifiable human authorization: a
W3C Verifiable Credential 2.0-shaped `NotarizationEnvelope`, signed by a
Notary Service whose public key any recipient can resolve from public
infrastructure (`did:key`, `did:web`, or a DNS TXT record) with no prior
trust relationship.

This crate is the wire layer and is deliberately squillo-free — it depends
only on `serde`, `serde_json`, `thiserror`, `chrono`, `p256`, and `base64`.

## What's here

- **Envelope wire types** — `NotarizationEnvelope` and its subject objects,
  with strict (`deny_unknown_fields`) parsing per spec §7.1.
- **Mandates** — `DelegationMandate` (standing authority) and
  `CommunicationMandate` (single-use, per-message).
- **Flow state machines** — human-present (7 states) and human-not-present
  (5 states); illegal transitions return `APH_E002`.
- **Roles and operations** — the §5 permission matrix.
- **Error taxonomy** — the closed `APH_E001`–`APH_E010` set.
- **Signing helpers** (`crypto`) — JCS-style canonicalization, detached
  JWS, and ES256 sign/verify.
- **Registered extensions** (spec §7.5) — `appleAurAcceptance`,
  `linkedMandate.ap2SignedPayloadB64`, `linkedMandate.vaultMutation`.

## Usage

```rust
let envelope: aph_core::NotarizationEnvelope = serde_json::from_str(json)?;
let canonical = aph_core::canonicalize_rfc8785(&serde_json::to_value(&envelope)?);
```

## Wire compatibility

Every serde attribute in this crate is load-bearing. Envelopes already
signed by deployed notaries must keep parsing and re-canonicalizing to
identical bytes, because verification recomputes the canonical form and
compares signatures over it. The golden fixtures under `tests/golden/` and
the `aph-conformance` crate are the regression gate.

Two interop notes are deliberate and documented in-source: canonicalization
sorts keys in UTF-8 byte order (not RFC 8785's UTF-16 order) and formats
floats via Rust `Display`; detached JWS carries DER-encoded ES256
signatures rather than RFC 7518's raw R||S. Both are the deployed wire
behavior and must not be "corrected" without a version bump.

## License

Apache-2.0
