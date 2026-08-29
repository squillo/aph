# aph-sealed

**Seal a payload so an agent can carry it, prove it, forward it — and never
read it.** The draft implementation of
[RFC 0008](../../../rfcs/0008-sealed-payloads.md): verification and
readership as independent capabilities.

⚠ **EXPERIMENTAL AND OFF-WIRE.** RFC 0008 is a Draft targeting the v0.2
line. v0.1.0 is final and its strict parse refuses any envelope carrying a
`sealedPayload` member — correctly — so this crate is `publish = false` and
touches nothing in `aph-core`. It exists so design review reads working
code with tests instead of prose. It sits INSIDE the workspace's default
gate set on purpose: an experimental crate whose suite the bare `cargo
test` never runs would be drift with no alarm on it.

## The two scenarios, one mechanism

- **Sealed to the receiver:** an envelope forwards through a chain of
  agents; every hop runs the full §8.3 verification — signatures, mandate,
  audience, single-use, body hash over the CIPHERTEXT — and none can read
  what it carries.
- **Sealed to the sender** (or any designated third key): the counterparty
  holds, forwards, and proves receipt of bytes only the designated reader
  opens.

```rust
use aph_sealed::{seal, unseal, SealedReader};

let sealed = seal(
    &mut rand::rngs::OsRng,               // production: OS CSPRNG, always
    SealedReader { id: "did:web:receiver.example.com".into(), kid: "enc-1".into() },
    &reader_x25519_public_key,            // a keyAgreement key from §8.4 discovery
    envelope_id,                          // the envelope staging this seal
    b"only the reader sees this",
)?;
// … place into the (v0.2) envelope, sign, forward through any hops …
let plaintext = unseal(&sealed, &reader_private_key, envelope_id)?;
```

## What the AAD authenticates, and why

The HPKE additional authenticated data is the full seal context — `suite`,
`reader.id`, `reader.kid`, envelope id — canonically serialized. The opener
rebuilds it from the payload's OWN claimed fields, so a ciphertext lifted
into a different envelope refuses, and so does a payload relabeled about
its own reader or suite. The audit probe that forced the context widening
is kept in the suite as a permanent test.

## What this is not

One pinned RFC 9180 suite (X25519-HKDF-SHA256 / HKDF-SHA256 /
ChaCha20-Poly1305) via the pure-Rust [`hpke`](https://crates.io/crates/hpke)
crate — this repository writes no cryptography. No multi-recipient sealing,
no sealed headers, no sender authentication from the seal itself (that is
the envelope's job), no padding scheme (ciphertext length is visible), and
no `APH_E` error codes until a spec version exists that can declare them.
RFC 0008's Security considerations section carries the full honest list.
