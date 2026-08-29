# APH v0.2 — the delta over v0.1.0

**Version:** 0.2.0
**Status:** Final for v0.2 (cut 2026-08-29)
**Repository:** `github.com/squillo/aph`
**License:** Apache-2.0

v0.1.0 (`aph-0.1.md`) remains FINAL and nothing here amends it: this
document is the v0.2 line, published as a versioned DELTA over it rather
than a restatement, cut 2026-08-29 with everything below implemented in
the reference and welded to committed vectors. A v0.1-only implementation
that has never read this file remains fully conformant, and its strict
parse refuses every member below — which is the compatibility story, not
a defect. Producers MUST NOT emit anything defined here to a recipient
not known to implement it (the v0.1 §10.1 rule, unchanged). From this cut
the same discipline recurses: normative additions land in the NEXT
versioned delta through the RFC process, never in place here.

An envelope using this delta declares `"aphVersion": "0.2"`. The delta is
additive over v0.1.0: everything v0.1.0 defines holds unchanged unless a
section below says otherwise, and none below does.

The delta carries everything the 0.1 cut deferred to it: RFC 0008
(sealed payloads, §1-§4), RFC 0001 (rotation attestation, §5), the JSON
Schema family (§6), and published, signed test vectors (§7).

---

## 1. `sealedPayload` (RFC 0008, Accepted 2026-08-29)

A new OPTIONAL member of `credentialSubject`: a payload the envelope
authorizes but only a named reader can open — verification and readership
as independent capabilities.

| Field | Type | Required | Description |
|---|---|---|---|
| `suite` | string | yes | The seal ciphersuite. This draft defines exactly one: `APH-SEAL-1` = RFC 9180 HPKE, X25519-HKDF-SHA256 KEM, HKDF-SHA256 KDF, ChaCha20-Poly1305 AEAD, base mode, single-shot. An opener MUST refuse a value it does not implement (`APH_E022`). |
| `reader` | object | yes | `{ "id": <DID>, "kid": <string> }` — whose `keyAgreement` key opens the seal. Signing keys are never converted to encryption keys; the reader publishes a distinct X25519 `keyAgreement` entry through the v0.1 §8.4 surfaces. |
| `enc` | string | yes | Unpadded base64url of the HPKE encapsulated key. |
| `ciphertext` | string | yes | Unpadded base64url of the AEAD ciphertext, tag included. |

**The authenticated context.** The HPKE `info` is the fixed string
`aph sealed payload v1`. The AAD is the JSON serialization of
`{"suite": …, "reader_id": …, "reader_kid": …, "envelope_id": …}` with
exactly that member order — everything the payload claims about itself
plus the envelope staging it. The opener rebuilds the context from the
payload's OWN claimed members, so a ciphertext lifted into a different
envelope refuses AEAD open, and so does a payload relabeled about its own
reader or suite.

**The wire-version rule.** `sealedPayload` is declared from
`aphVersion: "0.2"` and nothing earlier. An envelope claiming an earlier
version while carrying the member is malformed for the version it claims
— a strict-parse-class refusal (plain message, below the §11 code
vocabulary), which is also exactly what a v0.1-only parser produces via
its unknown-member rule. Two implementations, two mechanisms, one
verdict.

**Body binding.** When the sealed payload is the act's body,
`communication.bodySha256` is computed over the RAW ciphertext octets —
the base64url-decoded `ciphertext` value, tag included, never the JSON
serialization around it — so v0.1 §8.3 step 8 verifies blind at every
hop.

## 2. Verification (the v0.1 §8.3 list gains one step at v0.2)

> **Seal opening (readers only).** A verifier that is not the seal's
> reader treats `sealedPayload` as opaque bytes under every check it
> already runs. A verifier that IS the reader MAY open the seal after the
> envelope verifies, and MUST treat a failure to open as a refusal of the
> ENVELOPE (`APH_E021`), never of the seal alone.

## 3. Error codes (the §11 taxonomy grows twenty → twenty-four at v0.2)

| Code | Name | Meaning | Suggested resolution |
|---|---|---|---|
| `APH_E021` | `SealUnopenable` | A sealed payload addressed to THIS verifier did not open: wrong key, tampered ciphertext, or a seal staged under a different context — indistinguishable by AEAD design, and a refusal of the envelope per §2 above. | Refuse the envelope and tell the sender: re-seal to the current `keyAgreement` key under this envelope's own context. |
| `APH_E022` | `SealSuiteUnknown` | The payload names a ciphersuite this verifier does not implement; refused by name before touching key material. | Re-seal with the one defined suite; suite agility arrives by amendment, not negotiation. |
| `APH_E023` | `SealReaderKeyUnpublished` | The reader's DID document publishes no `keyAgreement` entry matching the named `kid`. Distinct from `APH_E014` exactly as E014 is distinct from E008: which surface came up empty is the repair. | Publish a `keyAgreement` entry under that kid, or seal to a key the reader actually publishes. |
| `APH_E024` | `RotationAttestationInvalid` | A rotation attestation (§5) failed a structural rule or its signature — the carried reason names the specific rule, because "invalid" with no reason teaches an operator nothing. | Re-mint the attestation with the predecessor key it names, over the lone-proof base, with an ordered window. |

## 4. Security considerations

RFC 0008's Security considerations section is normative for this delta:
length is visible (no padding scheme is defined and none is implied), the
sealer's RNG MUST be an operating-system CSPRNG, a `keyAgreement` key
compromise reads everything ever sealed to it (rotate sealing keys at
least as aggressively as signing keys), metadata stays visible by design,
and the seal authenticates no sender — the envelope does.

## 5. Rotation attestation (RFC 0001, Accepted 2026-08-29)

A signed statement by a notary's CURRENT key that a named successor key is
its own — closing the gap RFC 0001 opens with: domain control alone
publishes notary keys, so a domain hijacker can publish keys the notary
never held. The attestation makes a rotation something the OLD key said,
not merely something the domain now shows.

**The statement.** A JSON object, all members required, camelCase:

| Field | Description |
|---|---|
| `aphVersion` | `"0.2"` — the version that declares this statement. |
| `type` | Exactly `AphRotationAttestation`. |
| `id` | Stable name for THIS statement, so a retraction can refer to exactly one attestation. |
| `subject` | The DID the statement is about. |
| `predecessor` | The SPEAKER, as a DID URL including its `#kid` fragment — never inferred from where the record was found. |
| `successor` | `{ kid, alg, publicKeyMultibase, notBefore, notAfter }` — the key being named: its future fragment, its algorithm in §8.1's JWS spelling (`EdDSA`/`ES256` — NOT §8.4.5's TXT spelling `ed25519`/`p256`), the key bytes themselves in multibase (naming a kid without bytes would let whoever controls publication bind it to any key — the attack this exists to stop), and an ordered RFC 3339 activation window. |
| `created` | RFC 3339; orders two attestations naming the same predecessor. |
| `proof` | §8.2's proof block, unchanged. Signing base is the statement with `proof.proofValue` present and EMPTIED (§7.2.1's lone-proof rule), canonicalized by JCS, `eddsa-jcs-2022`. |

**Verification, in order, every refusal `APH_E024` with the failed rule
named:** `type` is the constant; `aphVersion` is `"0.2"`; `predecessor`
is a key OF `subject` (prefix `subject#`); `proof.verificationMethod` IS
the named predecessor — the chain value and the signing key are one
claim, not two; `successor.alg` is in §8.1's set; `successor.publicKeyMultibase`
decodes as a supported multikey; the activation window parses and is
ordered; and finally the signature verifies against the PREDECESSOR's
key — the key the verifier already trusts.

**Publication.** In the subject's DID document under the property
`https://w3id.org/aph/v1#rotationAttestation`, riding the v0.1 §8.4
surfaces that already exist. No new discovery mechanism, no custodian, no
service the protocol then depends on — RFC 0001 §8's constraint check
carries over unchanged.

**What it cannot add** (normative honesty, from RFC 0001): an attacker
holding the CURRENT key can attest their own successor; the mechanism
narrows the domain-hijack window, it does not close key compromise.

## 6. The JSON Schema family (`spec/schemas/`)

Machine-readable renderings of the envelope family for adopters who
implement from JSON Schema rather than from a reference interpreter:
`notarization-envelope.schema.json` (the full family, v0.1.0 members plus
this delta's) and `rotation-attestation.schema.json` (§5's statement).
The prose specs are normative; where a schema disagrees, the schema is
the defect. The reference repository welds the claim shut: every
committed vector validates against the schemas in CI, and a member
smuggled into a golden must FAIL validation. Cross-member rules no schema
can express — including the wire-version rule above — are listed in
`spec/schemas/README.md`.

## 7. Published test vectors (`examples/v0.2/`)

Committed, byte-pinned, drift-printed like every v0.1 golden:

- `sealed_envelope.json` — a v0.2 envelope carrying `sealedPayload`,
  illustrative proof; exercises the non-reader path.
- `sealed_signed_envelope.json` — audience-bound AND sealed, signed by a
  did:key notary; verifies end-to-end, keyless, in the independent
  TypeScript implementation — two implementations, one verdict, no
  plaintext.
- `rotation_attestation.json` — §5's statement, signed by the RFC 8032
  test-vector key, verifying under `verify_rotation_attestation`.
