# v0.2-draft vectors

Vectors for members the **v0.2-draft delta** (`spec/aph-0.2-draft.md`)
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

The proof is illustrative (shape-only), like the corpus's unsigned nine:
these vectors exercise the DELTA members, and signing paths already have
their own signed vectors.
