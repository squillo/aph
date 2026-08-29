# v0.2 vectors

Vectors for members the **v0.2 delta** (`spec/aph-0.2.md`)
declares and v0.1.0 does not. They sit in this subdirectory — outside the
`examples/*.json` conformance corpus — because every v0.1 gate MUST refuse
them at strict parse, and a vector that correctly fails every gate does not
belong in the list those gates admit.

- `sealed_envelope.json` — RFC 0008's `sealedPayload` on an
  `aphVersion: "0.2"` envelope: a body sealed to
  `did:web:receiver.example.com` (a TEST key derived from fixed IKM in the
  `aph-sealed` suite), `bodySha256` computed over the raw decoded
  ciphertext octets so a blind hop verifies §8.3 step 8 without plaintext.
  Byte-welded: the `aph-sealed` suite regenerates it deterministically and
  fails on any drift, and a second test opens the committed bytes with the
  derived reader key — pinning the wire format's stability, not just this
  build's.

- `sealed_signed_envelope.json` — the strongest artifact here: a v0.2
  envelope carrying an audience binding AND a sealed payload, SIGNED by a
  did:key notary. The independent TypeScript implementation verifies it
  end-to-end with no supplied keys — audience satisfied as the named
  verifier, seal ridden as opaque bytes, signature verified over the
  ciphertext it covers. Two implementations, one verdict, no plaintext.
- `rotation_attestation.json` — RFC 0001's statement (`spec/aph-0.2.md`
  §5), signed with the RFC 8032 test-vector key, verifying under
  `aph_core::rotation::verify_rotation_attestation`.

`sealed_envelope.json`'s proof is illustrative (shape-only), like the
corpus's unsigned nine — it exercises the non-reader parse path. The
other two are signed and verify. All three are drift-printed and
byte-welded by the `aph-sealed` suite, and all three validate against
the schema family in CI.
