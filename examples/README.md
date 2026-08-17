# APH Envelope Examples

This directory contains 12 example APH `NotarizationEnvelope` JSON files:
one per supported channel kind (7), one exercising the §7.5 registered
optional extensions, **three signed vectors — one for each of the signing
paths §8.1/§8.2 make MUST-support** — and `ts_minted_envelope.json`, which
the TypeScript implementation mints and the Rust reference verifies. They
illustrate the wire shape of v0.1 envelopes and are suitable for round-trip
parsing by any APH implementation; the four signed ones are additionally
suitable for verification.

## Files

- `slack_reply_envelope.json` — Slack thread reply
- `email_reply_envelope.json` — Email reply (with `In-Reply-To`)
- `discord_dm_envelope.json` — Discord direct message
- `teams_channel_envelope.json` — Microsoft Teams channel post
- `whatsapp_envelope.json` — WhatsApp message
- `google_chat_envelope.json` — Google Chat space message
- `imessage_envelope.json` — Apple iMessage
- `slack_new_with_extensions_envelope.json` — Slack post carrying all three
  spec §7.5 registered optional extensions (`appleAurAcceptance`,
  `linkedMandate.ap2SignedPayloadB64`, `linkedMandate.vaultMutation`)
- `principal_signed_envelope.json` — the spec §7.3.1 worked example,
  **signed for real** with Ed25519 / `eddsa-jcs-2022` (see below)
- `es256_signed_envelope.json` — the same `PrincipalSigned` shape,
  **signed for real** with ES256 / `ecdsa-jcs-2019` (see below)
- `detached_jws_envelope.json` — a `NotaryAttested` envelope whose proof is a
  compact detached JWS, **signed for real** (`JsonWebSignature2020`, see below)
- `ts_minted_envelope.json` — the same `PrincipalSigned` Ed25519 shape,
  **minted by the TypeScript implementation** rather than by the Rust one, and
  the only file here whose body binding is real (see below)

## What's the same across all files

- `aphVersion`: `"0.1"`
- `@context`: W3C VC 2.0 + APH v1
- `type`: `["VerifiableCredential", "AgentSendAuthorizationCredential"]`
- `validFrom` / `validUntil`: 24-hour window
- `agent`: a sample agent DID
- `communication.bodySha256`: a fixed 64-char lowercase hex in **eleven of the
  twelve** files (the SHA-256 of an empty string, used as an anchor for
  deterministic round-trip testing — DOES NOT represent a real message body).
  `ts_minted_envelope.json` is the exception and carries a real digest of a
  real body.

`proof` is the one block that varies by design, because §8.1 and §8.2 define
more than one way to make one. Eleven of the twelve files use the Data
Integrity form, `"type": "DataIntegrityProof"`: ten declare `eddsa-jcs-2022`
(the seven channel files, the extensions file,
`principal_signed_envelope.json` and `ts_minted_envelope.json`) and
`es256_signed_envelope.json` declares `ecdsa-jcs-2019`. The twelfth,
`detached_jws_envelope.json`, uses the other §8.2 format —
`"type": "JsonWebSignature2020"`, no `cryptosuite` member at all (§7.1.11
omits it there, and omitted means ABSENT: the member sits inside the §7.2.1
signing base, so a `null` would change the bytes every verifier has to
rebuild), and a compact detached JWS in `proofValue` instead of multibase
signature bytes.

## The nine `NotaryAttested` files

Nine files carry no `policy.attestationMode`, and an absent field means
`NotaryAttested` (spec §7.1.7). Read them as *a notary asserts this human
authorized this* — the notary's key is the one that signs them.

**Eight of the nine exercise shape only.** The seven channel files and the
extensions file carry opaque illustrative multibase strings in
`proof.proofValue`, NOT real signatures, and their `issuer` is a sample
notary service DID. Their `id`s are unique per file
(`urn:uuid:00000000-0000-4000-8000-00000000000{1..8}`). Signature
verification on those eight is *expected* to fail.

`detached_jws_envelope.json` is the ninth and it verifies — see below.

## The three `PrincipalSigned` goldens

All three carry the §7.3.1 chain: `policy.attestationMode` is
`"PrincipalSigned"`, `proof` is the two-element array (principal proof, then
notary countersignature linked by `previousProof`), and `issuer` is the
**human principal's** DID, because in `PrincipalSigned` mode the human is the
issuing authority and the notary a witness (§7.3.1).

Each differs from the others in exactly one dimension, which is what makes
diffing them informative. `principal_signed` and `es256_signed` differ only by
CRYPTOSUITE, so a diff shows precisely what §8.1's second algorithm changes and
what it does not. `ts_minted` differs only by AUTHORSHIP — a different
implementation in a different language produced it.

### `principal_signed_envelope.json` — Ed25519, `eddsa-jcs-2022`

The spec §7.3.1 worked example with every placeholder replaced by a REAL
Ed25519 signature — the first `PrincipalSigned` envelope published anywhere in
the APH ecosystem:

- `policy.delegationMandate` embeds the parent grant with both of its §6.1
  signatures computed for real, so this file is also the vector for §7.1.7.1's
  embedded-mandate binding.
- Every key derives from a **fixed public test seed** — RFC 8032 §7.1
  TEST 2 (the principal) and TEST 3 (the notary). These are the RFC's own
  published vectors: they authorize nothing, and anyone can re-derive
  every byte with no secret material.
- The `id`s and timestamps are the §7.3.1 worked example's own values, so
  the spec's prose and this file describe the same credential. Its
  envelope `id` (`...00f3`) sits in the tail range worked examples now
  reserve — distinct from the `{1..8}` channel-example sequence above,
  ending the id collision the earlier `...0002` reuse carried.
- The conformance suite regenerates this file from constants through the
  reference implementation's own signing path and byte-compares the
  result, verifies both envelope proofs, the issuance order, the
  embedded-mandate binding, and both mandate signatures from the published
  bytes — and proves the negative: strip the countersignature and the
  remainder verifies under NO key (§7.2.1 array-form domain separation).

### `es256_signed_envelope.json` — ES256, `ecdsa-jcs-2019`

§8.1's second MUST-support algorithm, with a published byte string for the
first time. Envelope `id` `...00e3`; proof ids `...00e1` / `...00e2`.

- Both keys are **published P-256 test scalars**: the principal's is the
  RFC 6979 Appendix A.2.5 sample key, the notary's is the `d` of the ES256
  example JWK in RFC 7515 Appendix A.3.1. A P-256 scalar cannot be a
  repeated-byte placeholder the way an Ed25519 seed can — it has to be a valid
  scalar — so each cites the document that publishes it, and the conformance
  suite checks each against something that document prints.
- `proofValue` is **P1363 `r‖s`** (64 bytes, multibase base58btc), per the
  `ecdsa-jcs-2019` suite definition — never DER. The same repository signs
  Delegation Mandates and the detached JWS below with DER: the encoding
  follows the carriage, not the algorithm.
- **Why byte comparison works on an ECDSA signature.** Most ECDSA is
  randomized and would produce a different signature on every run. The
  reference implementation uses RFC 6979 *deterministic* ECDSA, where the
  nonce is derived from the key and the message, so this file is
  byte-reproducible. If your ES256 signer is randomized, your envelope is
  still valid — it just will not equal this one byte for byte, and you should
  compare by *verifying* rather than by diffing.
- It embeds no Delegation Mandate: the Ed25519 golden already publishes those
  signatures, and repeating them on a second curve would add signatures to
  check without adding a rule to learn.

### `ts_minted_envelope.json` — the same shape, a different implementation

Ed25519 / `eddsa-jcs-2022` again, but minted by `interpreters/typescript/` and
verified by the Rust conformance suite, so it is a document two independent
codebases already agree on. Envelope `id` `...00c3`; proof ids `...00c1` /
`...00c2`. Two properties make it the easiest first target for a stranger's
verifier:

- **BOTH parties are `did:key`** — the notary too, unlike the Ed25519 golden's
  `did:web` notary whose key must be supplied out of band. Every key travels
  inside the file, so it verifies with no configuration and no network.
- **Its body binding is REAL.** The complete body is short enough to travel in
  `preview` verbatim, `bodySize` is that text's UTF-8 length and `bodySha256`
  its digest. It is the only file here against which §8.3 step 8 can be checked
  at all — the other eleven pair the empty-string hash with a non-zero
  `bodySize` and publish no body to hash.

It also embeds its parent Delegation Mandate with both §6.1 signatures, from
the same RFC 8032 §7.1 TEST 2 / TEST 3 public seeds the Ed25519 golden uses.

## The detached-JWS vector

`detached_jws_envelope.json` is the §8.2 alternative proof format: a compact
detached JWS in `proofValue`, over the **same** §7.2.1 canonicalization base a
Data Integrity proof would cover. Envelope `id` `...0009`.

- `issuer` is the notary's own `did:key` (a P-256 identifier, `did:key:zDn…`),
  so the file verifies **offline from itself** — decode the compressed point
  out of the identifier and check the signature, no network and no prior trust
  relationship (§8.4.6 mechanism 1).
- The protected header carries the six members §8.2 requires — `alg` (`ES256`),
  `typ` (`aph+jws`), `cty` (`vc+ld+json`), `b64` (`false`), `crit`
  (`["b64"]`), and `kid` (the proof's own `verificationMethod`) — and a
  verifier MUST check them (§8.3 step 7); that is what rejects `alg: none`.
- ⛔ **Two deployed quirks are preserved on purpose.** The header declares
  `"b64":false` with `"crit":["b64"]` (RFC 7797 unencoded payload) while the
  payload is nevertheless base64url-encoded into the signing input; and the
  ES256 signature inside the token is **DER**, not the raw `r‖s` RFC 7518
  specifies. A standards-pure RFC 7518 signer will therefore produce a token
  this vector's verifier rejects. Both are the deployed interoperability wire,
  changing either would fork it, and both are stated here rather than
  discovered.
- `alg: EdDSA` inside a JWS is MUST-support in §8.1 and is **not** implemented
  by the reference; it is refused by name (`APH_E010`). There is no vector for
  it because there is no implementation of it.

## What varies

- `credentialSubject.channel.kind`: one of `slack`, `email`, `discord`, `teams`, `whatsapp`, `google_chat`, `imessage`
- `credentialSubject.channel.recipientAddressing`: channel-shaped opaque blob (see each file)
- `credentialSubject.policy.matchedScope`: `per-channel` for channel-broadcast media (Slack, Email, Teams, Google Chat); `per-recipient` for direct-addressed media (Discord, WhatsApp, iMessage)
- `credentialSubject.communication.bodySize` and `preview`: small variations for realism

## Usage

Any APH implementation should be able to parse each file into its
`NotarizationEnvelope` data type with strict schema validation
(`deny_unknown_fields` or equivalent). The eight placeholder files exercise
shape only — their proof values are illustrative. The four signed files
additionally exercise real signing and verification, three of them one per
MUST-support path: `principal_signed_envelope.json` (four Ed25519 signatures —
two envelope proofs and two mandate signatures — under the RFC 8032 §7.1
TEST 2 / TEST 3 public keys), `es256_signed_envelope.json` (two
`ecdsa-jcs-2019` proofs under the RFC 6979 A.2.5 and RFC 7515 A.3.1 public
keys), `detached_jws_envelope.json` (one `JsonWebSignature2020` proof, its key
resolvable from the file's own `issuer`), and `ts_minted_envelope.json` (four
Ed25519 signatures again, but minted by the TypeScript implementation, every
key resolvable from the file, and the one file whose `bodySha256` can be
recomputed from what it publishes).

## These files are generated, never text-edited

Each signed file is rebuilt from constants and re-signed, then byte-compared
against what is committed here — so a change to canonicalization, field order,
or a signing base fails loudly instead of leaving a published example nothing
can verify. Byte comparison is only possible because both algorithms are
deterministic: Ed25519 by construction (RFC 8032), and ES256 because the
reference uses RFC 6979.

Three of the four are generated by the Rust reference. To change one, edit its
generator under `interpreters/rust/aph-conformance/tests/`
(`principal_signed_example_test.rs`, `es256_signed_example_test.rs`,
`detached_jws_example_test.rs` — the last two share
`tests/generator_support/mod.rs`) and paste the block its byte-identity test
prints between the `----8<----` cut lines.

`ts_minted_envelope.json` is the exception, because its generator is not Rust:
edit `interpreters/typescript/testkit/ts_minted.ts` and run `npm run build &&
npm run mint`, which rewrites the file in place. Its Rust-side tripwire is
`ts_minted_cross_verify.rs`, which must stay green afterwards — a file the two
implementations no longer agree on is the one thing this artifact exists to
catch.
