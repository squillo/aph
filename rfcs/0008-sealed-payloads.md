# RFC 0008 — Sealed payloads: carriage without readership

- **Status:** Accepted
- **Author:** Scott Wyatt
- **Issue:** requested by the maintainer from two recurring integration
  scenarios; this document is the proposal and the experimental
  implementation's design of record, not a ruling
- **Target:** the **v0.2 line**. v0.1.0 is final and its parse is strict, so
  nothing here may appear on a 0.1 wire; the draft implementation ships as a
  crate deliberately OFF the envelope (see §6)
- **Spec sections touched (at v0.2, none yet):** §7.1 (envelope shape — new
  `sealedPayload`), §8.3 (one verification note), §8.4 (key discovery — the
  `keyAgreement` surface), §11 (error codes, assigned then, not now)

## The problem

An APH envelope proves WHO authorized an act and binds WHAT was sent by
hash. Today it assumes one more thing it never states: that every agent
holding the envelope may also READ the payload it authorizes. Two recurring
scenarios break that assumption, in opposite directions:

**Scenario 1 — the carrier must not read.** An agent forwards an act through
one or more intermediate APH agents to a final recipient. Every hop must
verify the envelope — the signatures, the mandate, the audience, the window
— but only the final recipient may read the payload. Today the payload
either travels in the clear (every hop reads it) or out of band (no hop can
verify what it is carrying). A chain of verifiable carriers who cannot read
what they carry is the missing shape.

**Scenario 2 — the counterparty must not read.** The sending side holds
material the receiving agent must carry, prove receipt of, or act on
later — a credential, a guardrail configuration, an instruction that
becomes readable only under conditions the sender controls — without the
receiving agent being able to open it. The seal points at the SENDER's own
key (or any third key the sender designates): the envelope travels, the
verifier verifies, and the content stays sealed to everyone but the
designated reader.

Both are the same mechanism with a different reader. The property they
share: **verification and readership become independent capabilities.** A
verifier needs no plaintext; a reader needs no trust in the hops between.

**What this buys against treacherous relays — the honest framing.** In the
Byzantine generals' terms the request invoked: a lieutenant relaying this
envelope can neither read the order, alter it undetectably (the signature
covers the ciphertext; the AEAD tag covers the plaintext), nor replay or
redirect it (RFC 0003's audience + single-use steps apply unchanged,
because they never needed the plaintext). What it does NOT buy is
agreement: this is authenticated, confidential, integrity-protected relay
through untrusted intermediaries — the *messenger* half of the generals'
problem — not consensus among them. No availability property is claimed: a
traitorous hop can still drop the envelope, and only delivery receipts (out
of scope) would reveal that.

## Prior art, and what it decides

- **JWE (RFC 7516)** is the JOSE answer and would rhyme with the spec's
  existing JWS profile — but the mature JWE implementations in this
  ecosystem bind to OpenSSL, and this repository's bindings run the same
  reference everywhere from wasm to wazero. A C dependency in the sealing
  path would fork the "one reference, many carriages" property the bindings
  exist for.
- **HPKE (RFC 9180)** is the modern, formally analyzed public-key sealing
  construction — single-shot seal to a recipient public key, with
  authenticated additional data — with a pure-Rust implementation and
  published test vectors. It is the primitive TLS ECH and MLS settled on
  after the ecosystem's decade of ad-hoc hybrid encryption.
- **NaCl sealed boxes** are simpler but carry no standard AAD binding — and
  the AAD is load-bearing here (§3).
- **Onion routing** solves the harder multi-hop-privacy problem; this RFC
  deliberately does not. Hops here are visible to each other; only CONTENT
  is sealed.

HPKE, single suite, no negotiation — the same alg-minimalism §8.1 already
practices for signatures.

## The design

### 1. One suite

`X25519-HKDF-SHA256` KEM, `HKDF-SHA256` KDF, `ChaCha20-Poly1305` AEAD
(RFC 9180 §7; the combination its test vectors cover). One suite, pinned,
no negotiation: a `suite` member exists on the wire so a future version CAN
move, and a verifier refuses a value it does not know — closed-set
discipline, applied to ciphersuites from birth.

### 2. The wire member (v0.2 shape, stated for review)

```json
"sealedPayload": {
  "suite": "APH-SEAL-1",
  "reader": { "id": "did:web:receiver.example.com", "kid": "enc-1" },
  "enc": "<base64url: HPKE encapsulated key>",
  "ciphertext": "<base64url: AEAD ciphertext, tag included>"
}
```

- `reader.id` is the DID whose key can open the seal — the final recipient
  (scenario 1), the sender itself (scenario 2), or any designated third
  party. `reader.kid` names which of that DID's keys.
- The reader's key is a **`keyAgreement` X25519 key**, discovered through
  the same §8.4 surfaces that publish signing keys. Signing keys are NEVER
  converted to encryption keys: the cross-protocol-use hazards of reusing
  an Ed25519 key as X25519 are exactly the kind of cleverness a protocol
  regrets, so an encrypting reader publishes a distinct `keyAgreement`
  entry. This is the one new operational obligation the RFC creates, and
  §8.4's DID-document path already has a standard slot for it.

### 3. The two bindings that make it safe

- **AAD = the seal context.** Sealing happens BEFORE signing, and the
  HPKE additional authenticated data is the canonical serialization of
  everything the sealed payload CLAIMS about itself plus the envelope
  staging it: `{suite, reader.id, reader.kid, envelope id}`, as a JSON
  object with exactly that field order. The opener rebuilds the context
  from the payload's OWN claimed fields, so a ciphertext lifted into a
  different envelope refuses AEAD open — and so does a payload relabeled
  about its own reader or suite, which the envelope signature would catch
  only AFTER signing and which the seal must therefore catch itself. (An
  earlier draft bound only the envelope id; the implementation's audit
  probe demonstrated the relabeling gap and the widened context is the
  fix, with the probe kept as a test.)
- **`bodySha256` binds the ciphertext.** When the sealed payload IS the
  act's body, `communication.bodySha256` is computed over the RAW
  ciphertext octets — the base64url-DECODED `ciphertext` value, tag
  included, never the JSON serialization around it — so §8.3 step 8
  verifies body binding WITHOUT plaintext and two implementations cannot
  disagree about which bytes were hashed. Verification and readership
  stay independent, which is the whole point.

### 4. Verification (the one new sentence §8.3 needs at v0.2)

A verifier that is not the reader treats `sealedPayload` as opaque bytes
under everything it already checks. A verifier that IS the reader MAY open
the seal after the envelope verifies, and MUST treat an AEAD failure as a
refusal of the envelope, not of the seal alone — an unopenable seal
addressed to you is evidence of tampering or mis-staging, never a shrug.

### 5. Error codes: deliberately NOT minted here

The §11 set is closed and v0.1.0 is final. This RFC does not invent
`APH_E`-prefixed names ahead of a version that can declare them; the draft
implementation carries its own error type, and the codes (seal-unopenable,
unknown-suite, reader-key-undiscoverable) are assigned when v0.2 opens.
Registering ahead served RFC 0003 because the spec could still move; it
cannot, and a name minted outside the closed set is the exact defect the
closure exists to refuse.

### 6. The draft implementation (in this repository now)

`interpreters/rust/aph-sealed` — an EXPERIMENTAL, `publish = false` crate:
the `SealedPayload` type exactly as §2 shapes it, `seal` / `unseal` over
RFC 9180 single-shot HPKE (pure-Rust `hpke` crate; this repository writes
no cryptography), context-AAD binding per §3 (probe-hardened), and tests deriving keys from RFC 9180
test-vector IKM. It is deliberately NOT wired into `NotarizationEnvelope`:
the 0.1 parse is strict and final, so an envelope carrying `sealedPayload`
today is refused at strict parse by every conformant verifier — which is
correct, and which the version-gated emission rule (§10.1 reasoning) will
govern at v0.2 exactly as it governed `audience` and `recipientClass`.

## Security considerations

- **Length leaks.** ChaCha20-Poly1305 hides content, not size: the
  ciphertext is plaintext length + 16, visible to every hop. A sender for
  whom length is itself the secret pads BEFORE sealing; this RFC defines
  no padding scheme and says so rather than gesturing at one.
- **The RNG is load-bearing.** The seal's ephemeral key comes from the
  caller-supplied CSPRNG; in production that argument MUST be an
  operating-system CSPRNG. The implementation's API makes the RNG a
  parameter for testability, and its documentation carries this MUST.
- **A `keyAgreement` key compromise reads everything ever sealed to it.**
  There is no forward secrecy across envelopes in single-shot HPKE base
  mode. The mitigation is the one the protocol already practices for
  signing keys: rotation through the §8.4 surfaces, short key lifetimes,
  and — at v0.2 — the same retirement visibility rules. Readers SHOULD
  treat sealing keys as more rotation-worthy than signing keys, not less.
- **Metadata stays visible by design.** Who sealed, to whom, under which
  envelope, on which channel: all readable, because hops verify and route
  on it. This RFC seals CONTENT; senders needing recipient privacy need a
  different protocol (see the onion-routing note above).
- **The seal does not authenticate the SENDER to the reader.** HPKE base
  mode proves nothing about who sealed; sender authenticity comes from
  the ENVELOPE — the principal's signature and mandate — which is why §4
  ties seal-opening to envelope verification rather than replacing it.

## What this deliberately does not do

- No multi-recipient sealing (CEK-wrapping per reader). Both motivating
  scenarios have exactly one reader; the `recipients[]` generalization is
  real, JWE-shaped, and deferred until a scenario needs it.
- No sealed HEADERS: `channel`, `audience`, `recipientClass`, windows and
  mandates stay readable, because hops route and verify on them. Sealing
  what verification needs would trade the verifiable-carrier property for
  onion routing, which is a different protocol.
- No key escrow, no receipt protocol, no consensus. See the honest framing
  in §"The problem".
- No new discovery mechanism: `keyAgreement` rides the §8.4 surfaces that
  exist.

## Decision

**Accepted 2026-08-29**, by the sole maintainer — a standing arrangement
ruled the same day and recorded in CONTRIBUTING.md and `rfcs/README.md`
(deliberately solo within the Squillo organization), which Decision blocks
now cite instead of re-litigating.

Implemented the same day, with the post-cut discipline the RFC itself
demanded: v0.1.0 is untouched. What exists now:

- **`spec/aph-0.2-draft.md`** — the versioned DELTA where post-cut
  accepted RFCs accumulate. It declares the wire member, the authenticated
  context (as audited: suite + reader + envelope id, not envelope id
  alone), the wire-version rule (`aphVersion: "0.2"` declares the member;
  anything earlier carrying it is strict-parse-class malformed), the seal
  verification step, and the three codes — `APH_E021 SealUnopenable`,
  `APH_E022 SealSuiteUnknown`, `APH_E023 SealReaderKeyUnpublished` —
  growing the taxonomy twenty → twenty-three at v0.2.
- **The reference**: wire types in `aph-core` (so the envelope carries
  them; the crate's dependency discipline holds — no cryptography moved),
  the declaration rule as `sealed_payload_is_declared`, the three codes in
  the error enum with the census at twenty-three, and the envelope-level
  operations `seal_into_envelope` / `unseal_from_envelope` in `aph-sealed`
  with the code mapping §2's step specifies. Twelve tests, including both
  scenarios on a published golden lifted to `aphVersion 0.2`, both
  directions of the wire-version rule, the code mapping, and the
  blind-hop `bodySha256` reproduction.

Deliberately still deferred, and the same list §"What this deliberately
does not do" opened with: multi-recipient sealing, sealed headers, the
independent TypeScript implementation and the bindings (they follow when
the 0.2 delta stabilizes — a draft wire taught to five surfaces at once
is five surfaces to re-teach on every draft revision), and any corpus
golden (a 0.2 vector would refuse in every 0.1 gate, correctly; vectors
arrive with the v0.2 cut).

**Deferrals discharged (2026-08-29, later the same day).** The three
deferred surfaces landed once the shape stopped moving:

- **One strict-parse entry, everywhere.** The four bindings each carried an
  identical local serde parse; the hoist (`aph_core::parse_envelope_json`)
  folds the wire-version rule into the ONE parse path every text boundary
  delegates to, so the rule holds at every binding by construction. Each
  boundary carries the proof: the committed vector parses, its downgrade
  refuses naming the rule.
- **The committed vector.** `examples/v0.2-draft/sealed_envelope.json` —
  deterministic (derived test keys, seeded RNG, a committed golden as
  base), byte-welded by the same drift-print discipline as the signed
  v0.1 vectors, and opened by the derived reader key in a second test that
  pins the FORMAT's stability, not just the build's. Excluded from the
  v0.1 conformance corpus with its reason in the manifest, per the
  established subdirectory precedent.
- **The independent TypeScript implementation, in the NON-READER role.**
  It admits aphVersion `0.2`, strict-parses the member, enforces the
  wire-version rule, and verifies around the seal as opaque bytes — the
  exact role §2's verification step defines for every verifier that is
  not the reader. It deliberately does not OPEN seals: WebCrypto has no
  ChaCha20-Poly1305, and a userland cipher would cost the
  platform-crypto-only claim. That boundary is stated in its README
  rather than discovered.
