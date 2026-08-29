```nlang
@name: "aph"
@description: "APH (Agent per Human) Protocol Specification"
@author: "Scott Wyatt <scott@squillo.com>, APH Protocol Contributors"
@copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
@license: "Apache-2.0 (SEE LICENSE). N Lang is proprietary to Squillo Inc.; commercial licensing of the language only through Squillo Inc."
```

# APH — Snapp Definition

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.


APH is an open protocol for cryptographically notarizing the actions an
autonomous agent takes on behalf of a specific human. It produces a W3C
Verifiable Credential 2.0-shaped envelope that any recipient can verify
independently — across vendors and across organizations — without trusting
the sending agent's runtime or its identity provider.

Think of the credential as an **agent's driver's license**. A human is the
issuing authority, a Notary Service is the DMV, the license carries a scope
(which channels, which content classes, for how long), and it is revocable
by the human who issued it.

This Snapp defines the shapes of the protocol's JSON documents so N Lang
consumers read the same types the reference implementation enforces rather
than re-deriving them from prose.

## Normative source

The specification text is normative; this Snapp is a faithful transcription
of it. Where the two disagree, the specification wins. Section references
throughout these files (for example §7.1.5) point into it.

- Specification: `spec/aph-0.1.md`
- A2A extension descriptor: `spec/a2a-extension.md`
- Security considerations: `spec/security-considerations.md`
- Rust reference implementation: `interpreters/rust`

## Status

`0.1.0`, FINAL for the 0.1 line (cut 2026-08-29). The wire shape, signing
profiles, and state machines are frozen for this version; changes are
versioned from here, and the v0.2 line is named in `rfcs/README.md`.

## Protocol constants

The version literal carried by every envelope in `aphVersion`. A verifier
MUST reject an envelope whose version it does not support, so this value is
part of the compatibility contract rather than a cosmetic label.

```nlang
mod blocks AphVersion {
  props {
    // Always "0.1" for this revision of the protocol.
    aph_version: str,
  }
}
```

## JSON-LD contexts

Every envelope's `@context` array begins with the W3C Verifiable Credentials
2.0 context, followed by the APH context. Verifiers compare these URIs
literally, so both the values and their order are fixed.

- `https://www.w3.org/ns/credentials/v2`
- `https://w3id.org/aph/v1`

## Credential type

The `type` array MUST contain both `VerifiableCredential` and
`AgentSendAuthorizationCredential`. The first makes the document a
Verifiable Credential to generic VC tooling; the second identifies it as an
APH send authorization specifically.

## A2A extension

An agent advertises APH support by declaring an extension on its A2A Agent
Card. The URI is compared byte-for-byte and is never dereferenced, so it is
declared once as a single constant and never assembled from parts.

```
aph://extensions/notarization/v1
```
