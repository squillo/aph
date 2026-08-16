# JSON Schemas

Machine-readable renderings of wire shapes defined in `../aph-0.1.md`.

**The prose spec is normative; these files are not.** Where a schema and
`aph-0.1.md` disagree, the spec wins and the schema is a defect. They exist
because a mechanism specified only in prose is not implementable by a
non-Rust adopter without reverse-engineering the reference implementation —
the schema and the conformance vectors are the two artifacts that make it
implementable, and shipping either one late means shipping it never.

## Files

| File | Spec section | What it constrains |
|---|---|---|
| `credential-status-entry.schema.json` | §6.3.3.1, §7.1.1 | The OPTIONAL top-level `credentialStatus` member of a `NotarizationEnvelope`. Closed (`additionalProperties: false`), because the envelope parses strictly. |
| `bitstring-status-list-credential.schema.json` | §6.3.3.3 | The status list credential a notary serves at the derived endpoint. Deliberately OPEN — it is a general W3C artifact carrying members APH does not read. |

## What a schema pass does NOT prove

Necessary, never sufficient. Three of the mechanism's rules are relational
or cryptographic and no JSON Schema can state them:

1. **Same-origin binding (§6.3.3.2).** `statusListCredential` must share
   scheme, host and port with the endpoint DERIVED from
   `credentialSubject.notarization.notaryService.id`. That is a relation
   between two places in two different documents.
2. **Issuer binding (§6.3.3.3).** The list's `issuer` must be the notary the
   endpoint was derived from — not merely *a* DID.
3. **Proof and freshness (§6.3.3.3).** A signature check and a comparison
   against `now`.

An implementation that validates against these files and stops has built the
shape of the mechanism without its security.

## `$id` values are URNs on purpose

They are `urn:aph:schema:0.1:<name>`, not `https://` URLs. APH already
carries one unpublished identifier (`https://w3id.org/aph/v1`, §7.1.1), and
minting a second HTTP `$id` that resolves to nothing would invite tooling to
fetch it and fail. A URN names the schema without promising to serve it.
