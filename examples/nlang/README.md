# N Lang examples of the APH Spec surface

Each directory here is one N Lang package that depends on the published APH
Spec bundle and exercises one corner of its surface: a notarized envelope on
one channel kind, a delegation or communication mandate, a policy decision,
a flow, a refusal, a discovery record, an act classification, a proof form,
or a vault mutation. Every package compiles and its tests pass against the
Spec bundle committed at `snapp/aph@0.1.0.nbin`.

## Layout

```
examples/nlang/<name>/
  .n/nlang.config.n   the package manifest (framework "n")
  src/lib.n           the example: a header comment, the @deps block, tests
```

The `@deps` block in every `src/lib.n` pins the Spec bundle by relative path
and by SHA-256 of the artifact bytes. The path form is for development inside
this repository; when the bundle is published to a registry the `from` field
becomes the registry coordinate `@com::squillo/aph@0.1.0` and the integrity
digest stays the same.

## Running one package

From the repository root:

```
nlang check -r examples/nlang/slack_reply_bound_to_its_body
nlang test  -r examples/nlang/slack_reply_bound_to_its_body
```

The compiler writes its resolved dependency copy and build cache under the
package's `.n/` directory; both are ignored by git.

## What the examples hold to

- Every identifier is fictional or a published test vector. People,
  organizations, and hosts use names under `example.com`, `example.org`, and
  `example.net`; phone numbers are in the 555-0100 block reserved for fiction;
  `did:key` identifiers are the RFC 8032 and RFC 6979 test-vector keys that
  the signed wire fixtures in `examples/` also use.
- Body digests are real: each `body_sha256` is SHA-256 over the body text
  shown, and `body_size` is its byte length.
- Proof values and mandate signatures are well formed but illustrative. The
  really signed envelopes are the JSON fixtures one directory up.
- Field values follow the wire vocabulary the signed fixtures use: channel
  kinds in lower case, `DM` in capitals, decisions `AlwaysAllow`,
  `AskEveryTime`, and `NeverAllow`, scopes `per-channel` and `per-recipient`.
- One assertion per test. The test idiom is the one the Spec's own test
  module uses.

## Families

| Family | Packages | What they cover |
|---|---|---|
| Envelopes by channel | 10 | one full `NotarizationEnvelope` per channel kind |
| Content classes | 10 | every `ContentClass`, preview lines, the empty body |
| Delegation mandates | 10 | channels, recipient classes, rate limits, windows, signatures |
| Communication mandates | 10 | per-message authority, with and without a delegation |
| Policy and attestation | 10 | the three decisions, two scopes, both attestation modes, downgrades |
| Flows | 10 | human-present and human-not-present states, roles, operations |
| Refusals | 10 | every `AphErrorCode`, each with the state that triggers it |
| Discovery | 11 | `did:key`, DNS TXT key records, rotation, attestation, the order |
| Act classification and audience | 10 | vocabulary pins, digests, labels, audiences, channel binding |
| Proofs and linked mandates | 11 | both cryptosuites, detached JWS, every vault mutation kind, AP2, acceptance claims |
