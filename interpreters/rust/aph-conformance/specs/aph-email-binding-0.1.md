# APH Email Channel Binding — v0.1

Status: Draft
Scope: SMTP send / IMAP receive pipelines.

## Overview

This document specifies how the APH (Authenticated Provenance Header) envelope
is bound to an Email channel. The binding is transport-agnostic with respect
to the underlying mail relay; it concerns itself only with the on-the-wire
representation of the APH envelope inside a standard RFC-5322 message and
the canonicalization rules that govern body hashing.

Wire form: the APH envelope is serialized to **compact JSON** (no insignificant
whitespace), then **base64-encoded** (standard alphabet, padding retained),
then embedded as the last line of the message body in the form:

```
[aph: <base64>]
```

The footer line MUST be preceded by exactly one blank line (`\r\n\r\n`) to
disambiguate it from preceding body content. The footer MUST be the last
non-empty line of the body.

## Header conventions

The following MIME headers are OPTIONAL but RECOMMENDED for verifier discovery
and fast-path triage:

| Header              | Value                              | Notes                                       |
|---------------------|------------------------------------|---------------------------------------------|
| `X-APH-Version`     | `0.1`                              | Indicates the binding version in use.       |
| `X-APH-Envelope-Id` | `urn:uuid:<uuid-v4>`               | Stable correlation handle for audit logs.   |
| `X-APH-Algorithm`   | `EdDSA` \| `ES256`                 | Hint for signature pre-validation.          |

When `X-APH-Version` is absent, verifiers MUST still attempt to locate an
`[aph: ...]` footer; the headers are purely advisory.

## Recipient addressing

Recipient lists from the SMTP envelope and the RFC-5322 headers MUST be
mirrored into the APH `ChannelDescriptor.recipient_addressing` block:

```jsonc
{
  "recipient_addressing": {
    "to":  ["alice@example.com"],
    "cc":  ["bob@example.com"],
    "bcc": ["carol@example.com"]
  }
}
```

When a `Bcc:` header is stripped at relay time (per RFC-5322 §3.6.3), the
APH envelope STILL carries the original `bcc` list to preserve provenance for
the sender's records. Receivers reconstruct only `to` and `cc` from the
visible headers; the `bcc` entry is opaque to them.

## Attachments

> **v0.1 status note:** the `CommunicationDescriptor.attachments` array
> described below is a **v0.2 candidate** — the v0.1 envelope's
> `CommunicationDescriptor` (spec §7.1.6) does not define it, and v0.1's
> strict envelope-level parsing rejects unknown fields. Until the field is
> registered (spec §7.5 extension or v0.2 core field), producers MUST NOT
> emit it at the envelope level; the hashing rules below fix the intended
> semantics in advance.

Every MIME part marked as an attachment (`Content-Disposition: attachment`)
MUST have its **decoded** payload hashed with SHA-256 and recorded in the
APH `CommunicationDescriptor.attachments` array:

```jsonc
{
  "attachments": [
    {
      "filename": "report.pdf",
      "mime_type": "application/pdf",
      "size_bytes": 38421,
      "sha256": "9f1c0a..."
    }
  ]
}
```

The SHA-256 is taken over the post-MIME-decode bytes (i.e. after
`base64` or `quoted-printable` decoding). Inline parts that are not
attachments (e.g. `multipart/related` cid-referenced images embedded
in HTML) are NOT included.

## Body canonicalization

The `CommunicationDescriptor.body_sha256` field MUST equal the SHA-256
of the canonical body bytes. The canonicalization procedure:

1. Select the `text/plain` body part. If only `text/html` is present, use
   that part. If both are present, the `text/plain` part is authoritative.
2. Apply MIME content-transfer-encoding decode (`quoted-printable` or
   `base64` as indicated by `Content-Transfer-Encoding`). The output is
   UTF-8 (assuming a UTF-8 charset; senders SHOULD declare `charset=utf-8`).
3. Normalize line endings to `\n` (LF). CRLF and CR are folded to LF.
4. Remove the trailing `[aph: ...]` footer, including the blank-line
   separator immediately preceding it.
5. Hash the resulting bytes with SHA-256. Hex-encode lowercase.

This ordering guarantees that the body hash is stable across the footer
attach/detach round-trip.

## Verification flow

A receiver verifies an inbound email as follows:

1. Parse the MIME message.
2. Locate the `[aph: ...]` footer in the canonical body part. If absent →
   classify the message as **unsigned** and stop.
3. Base64-decode the footer payload. On failure → classify **tampered**.
4. JSON-parse the decoded payload into an `AphEnvelope`. On failure →
   classify **tampered**.
5. Compute `body_sha256` over the canonical body (see above) AFTER the
   footer has been stripped.
6. Invoke `verify_inbound(envelope, body_sha256)`:
   - resolve the sender's issuer key (DidWeb → DNS TXT fallback);
   - verify the envelope signature;
   - check that `envelope.communication.body_sha256` matches the computed
     hash;
   - check that all `envelope.communication.attachments[].sha256` entries
     match the actual attachment hashes.
7. On any mismatch → classify **tampered**. On success → classify **verified**.

## Failure modes

| Symptom                                  | Classification |
|------------------------------------------|----------------|
| `[aph: ...]` footer missing               | `unsigned`     |
| Base64 decode of footer fails             | `tampered`     |
| JSON parse of footer fails                | `tampered`     |
| Signature verification fails              | `tampered`     |
| `body_sha256` mismatch                    | `tampered`     |
| Any attachment `sha256` mismatch          | `tampered`     |
| Issuer key resolution fails (offline)     | `indeterminate`|

`indeterminate` is a soft-fail bucket: the message MAY be re-verified later
when the issuer key resolver succeeds (e.g. after DNS connectivity returns).

## Forward-compatibility notes

Future binding versions MAY:

- Extend the footer with a content-encoding hint (`[aph+gz: ...]`).
- Add structured `multipart/signed` alternatives carrying a detached
  signature, for clients that cannot tolerate footer text in the body.

Such extensions MUST bump the `X-APH-Version` minor version.
