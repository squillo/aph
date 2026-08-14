# APH Envelope Examples

This directory contains 9 example APH `NotarizationEnvelope` JSON files:
one per supported channel kind, one exercising the §7.5 registered
optional extensions, and one signed `PrincipalSigned` golden. They
illustrate the wire shape of v0.1 envelopes and are suitable for
round-trip parsing by any APH implementation.

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
  **signed for real** (see below)

## What's the same across all files

- `aphVersion`: `"0.1"`
- `@context`: W3C VC 2.0 + APH v1
- `type`: `["VerifiableCredential", "AgentSendAuthorizationCredential"]`
- `validFrom` / `validUntil`: 24-hour window
- `agent`: a sample agent DID
- `communication.bodySha256`: a fixed 64-char lowercase hex (the SHA-256 of an empty string, used as an anchor for deterministic round-trip testing — DOES NOT represent a real message body)
- `proof.type`: `"DataIntegrityProof"`
- `proof.cryptosuite`: `"eddsa-jcs-2022"`

## The eight `NotaryAttested` files

None of the eight channel/extension files carry `policy.attestationMode`,
and an absent field means `NotaryAttested` (spec §7.1.7). Read them as *a
notary asserts this human authorized this* — the notary's key is the one
that would sign them. Their `proof.proofValue` strings are opaque
illustrative multibase strings, NOT real signatures, and their `issuer` is
a sample notary service DID. Their `id`s are unique per file
(`urn:uuid:00000000-0000-4000-8000-00000000000{1..8}`).

## The `PrincipalSigned` golden

`principal_signed_envelope.json` is the spec §7.3.1 worked example with
every placeholder replaced by a REAL Ed25519 signature — the first
`PrincipalSigned` envelope published anywhere in the APH ecosystem:

- `policy.attestationMode` is `"PrincipalSigned"`, `proof` is the
  two-element chain (principal proof, then notary countersignature linked
  by `previousProof`), and `policy.delegationMandate` embeds the parent
  grant with both of its §6.1 signatures computed for real.
- `issuer` is the **human principal's** DID: in `PrincipalSigned` mode the
  human is the issuing authority, the notary a witness (§7.3.1).
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

## What varies

- `credentialSubject.channel.kind`: one of `slack`, `email`, `discord`, `teams`, `whatsapp`, `google_chat`, `imessage`
- `credentialSubject.channel.recipientAddressing`: channel-shaped opaque blob (see each file)
- `credentialSubject.policy.matchedScope`: `per-channel` for channel-broadcast media (Slack, Email, Teams, Google Chat); `per-recipient` for direct-addressed media (Discord, WhatsApp, iMessage)
- `credentialSubject.communication.bodySize` and `preview`: small variations for realism

## Usage

Any APH implementation should be able to parse each file into its
`NotarizationEnvelope` data type with strict schema validation
(`deny_unknown_fields` or equivalent). The eight `NotaryAttested` files
exercise shape only — their proof values are illustrative placeholders.
`principal_signed_envelope.json` additionally exercises real signing and
verification: its four signatures (two envelope proofs, two mandate
signatures) verify under the RFC 8032 §7.1 TEST 2/TEST 3 public keys.
