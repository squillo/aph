# APH Envelope Examples

This directory contains 7 example APH `NotarizationEnvelope` JSON files,
one per supported channel kind. They illustrate the wire shape of v0.1
envelopes and are suitable for round-trip parsing by any APH
implementation.

## Files

- `slack_reply_envelope.json` — Slack thread reply
- `email_reply_envelope.json` — Email reply (with `In-Reply-To`)
- `discord_dm_envelope.json` — Discord direct message
- `teams_channel_envelope.json` — Microsoft Teams channel post
- `whatsapp_envelope.json` — WhatsApp message
- `google_chat_envelope.json` — Google Chat space message
- `imessage_envelope.json` — Apple iMessage

## What's the same across all 7

- `aphVersion`: `"0.1"`
- `@context`: W3C VC 2.0 + APH v1
- `type`: `["VerifiableCredential", "AgentSendAuthorizationCredential"]`
- `issuer`: a sample notary service DID
- `validFrom` / `validUntil`: 24-hour window
- `humanPrincipal`: a sample human principal DID
- `agent`: a sample agent DID
- `communication.bodySha256`: a fixed 64-char lowercase hex (the SHA-256 of an empty string, used as an anchor for deterministic round-trip testing — DOES NOT represent a real message body)
- `proof.type`: `"DataIntegrityProof"`
- `proof.cryptosuite`: `"eddsa-jcs-2022"`
- `proof.proofValue`: an opaque illustrative multibase string (NOT a real signature)

## What varies

- `id`: unique per file (`urn:uuid:00000000-0000-4000-8000-00000000000{1..7}`)
- `credentialSubject.channel.kind`: one of `slack`, `email`, `discord`, `teams`, `whatsapp`, `google_chat`, `imessage`
- `credentialSubject.channel.recipientAddressing`: channel-shaped opaque blob (see each file)
- `credentialSubject.policy.matchedScope`: `per-channel` for channel-broadcast media (Slack, Email, Teams, Google Chat); `per-recipient` for direct-addressed media (Discord, WhatsApp, iMessage)
- `credentialSubject.communication.bodySize` and `preview`: small variations for realism

## Usage

Any APH implementation should be able to parse each file into its
`NotarizationEnvelope` data type with strict schema validation
(`deny_unknown_fields` or equivalent). The `proof.proofValue` strings
are NOT cryptographically valid signatures — they are illustrative
placeholders. Real signing + verification is a separate concern from
shape validation.
