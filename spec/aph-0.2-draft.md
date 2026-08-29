# APH v0.2-draft — the delta over v0.1.0

**Status:** DRAFT. v0.1.0 (`aph-0.1.md`) is the current FINAL specification
and nothing here amends it. This document is where accepted post-cut RFCs
accumulate as a versioned DELTA until v0.2 is cut; a v0.1-only
implementation that has never read this file remains fully conformant, and
its strict parse refuses every member below — which is the compatibility
story, not a defect. Producers MUST NOT emit anything defined here to a
recipient not known to implement it (the v0.1 §10.1 rule, unchanged).

An envelope using this delta declares `"aphVersion": "0.2"`. The delta is
additive over v0.1.0: everything v0.1.0 defines holds unchanged unless a
section below says otherwise, and none below does.

Planned but not yet drafted into this delta: RFC 0001 (rotation
attestation), the JSON Schema family, published test vectors.

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

## 3. Error codes (the §11 taxonomy grows twenty → twenty-three at v0.2)

| Code | Name | Meaning | Suggested resolution |
|---|---|---|---|
| `APH_E021` | `SealUnopenable` | A sealed payload addressed to THIS verifier did not open: wrong key, tampered ciphertext, or a seal staged under a different context — indistinguishable by AEAD design, and a refusal of the envelope per §2 above. | Refuse the envelope and tell the sender: re-seal to the current `keyAgreement` key under this envelope's own context. |
| `APH_E022` | `SealSuiteUnknown` | The payload names a ciphersuite this verifier does not implement; refused by name before touching key material. | Re-seal with the one defined suite; suite agility arrives by amendment, not negotiation. |
| `APH_E023` | `SealReaderKeyUnpublished` | The reader's DID document publishes no `keyAgreement` entry matching the named `kid`. Distinct from `APH_E014` exactly as E014 is distinct from E008: which surface came up empty is the repair. | Publish a `keyAgreement` entry under that kid, or seal to a key the reader actually publishes. |

## 4. Security considerations

RFC 0008's Security considerations section is normative for this delta:
length is visible (no padding scheme is defined and none is implied), the
sealer's RNG MUST be an operating-system CSPRNG, a `keyAgreement` key
compromise reads everything ever sealed to it (rotate sealing keys at
least as aggressively as signing keys), metadata stays visible by design,
and the seal authenticates no sender — the envelope does.
