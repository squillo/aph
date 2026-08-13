# APH Media (Chat Platform) Channel Binding — v0.1

Status: Draft
Scope: Slack, Discord, Microsoft Teams, WhatsApp Business, Google Chat.

## Overview

This document specifies how the APH (Authenticated Provenance Header) envelope
is bound to **chat-platform** channels. The wire form mirrors the email
binding (see `aph-email-binding-0.1.md`): the envelope is serialized to
compact JSON, base64-encoded, and appended as a footer line to the visible
message text:

```
\n\n[aph: <base64>]
```

The double-newline separator ensures the footer renders as its own block on
platforms that auto-format whitespace, and provides a stable parsing anchor
for receivers.

Unlike email, chat platforms do not expose MIME headers, so APH-specific
metadata (version, envelope id) is carried INSIDE the JSON envelope rather
than out-of-band. Discovery is purely by footer presence.

## Per-platform notes

> **v0.1 status note:** the unified `recipient_addressing` keys used in this
> section (`workspace_id`, `channel_id`, `thread_id`) are this binding's
> **v0.2 proposal** for cross-platform normalization. The v0.1 normative
> per-channel addressing shapes are those of main-spec §7.4 (e.g. Slack:
> `teamId` / `channelId` / `parentTs`), which every published example and
> golden fixture uses. `recipientAddressing` is opaque to verifiers either
> way (§7.4), so both shapes parse — but v0.1 producers SHOULD emit the §7.4
> forms. An iMessage binding is deferred (no chat-platform binding covers
> `imessage` in v0.1).

### Slack

- **API**: `chat.postMessage` (Web API).
- **Footer placement**: appended to the `text` field of the message payload.
- **Required bot scope**: `chat:write`. For private channels add `groups:write`.
- **Workspace ID**: carried as `ChannelDescriptor.recipient_addressing.workspace_id`.
- **Channel ID**: carried as `ChannelDescriptor.recipient_addressing.channel_id`
  (Slack `C…` / `G…` / `D…` identifier).
- **Threading**: if `thread_ts` is set on the post, it MUST also appear at
  `ChannelDescriptor.recipient_addressing.thread_id` so the verifier can
  reconstruct the parent thread context.

### Discord

- **API**: `POST /channels/{channel.id}/messages` (`messages.create`).
- **Footer placement**: appended to the `content` field.
- **Required permission**: `SEND_MESSAGES` on the target channel. Bot token
  via the standard Bot User Auth flow.
- **Guild ID**: carried as `ChannelDescriptor.recipient_addressing.workspace_id`.
- **Channel ID**: carried as `ChannelDescriptor.recipient_addressing.channel_id`.
- **DMs**: for direct messages, `workspace_id` is the literal string `"@me"`.

### Microsoft Teams

- **API**: Microsoft Graph `POST /chats/{chat-id}/messages`
  (`chatMessages.create`).
- **Footer placement**: appended to the `body.content` field. If
  `body.contentType` is `html`, the footer MUST be wrapped in a
  `<pre>` block so verifier extraction can match the literal text.
- **Required app permission**: `Chat.ReadWrite` (delegated) or
  `ChatMessage.Send` (application).
- **Tenant ID**: carried as `ChannelDescriptor.recipient_addressing.workspace_id`.
- **Chat ID**: carried as `ChannelDescriptor.recipient_addressing.channel_id`
  (the Teams chat thread, e.g. `19:...@thread.v2`).

### WhatsApp Business Cloud

- **API**: `POST /{phone-number-id}/messages` (Cloud API).
- **Footer placement**: appended to `text.body` for `type: text` messages.
- **Authorization**: the sender phone-number-id MUST be registered against
  the configured Meta Business Account, and the System User access token
  MUST carry `whatsapp_business_messaging`.
- **Sender phone**: carried as `ChannelDescriptor.recipient_addressing.workspace_id`
  (the E.164 sender number).
- **Recipient phone**: carried as `ChannelDescriptor.recipient_addressing.channel_id`
  (the E.164 recipient number).
- **Template messages**: APH footers MUST NOT be appended to pre-approved
  template messages — template body text is fixed by Meta review. For
  template messages, the binding is **not supported** in v0.1.

### Google Chat

- **API**: `POST /v1/{parent=spaces/*}/messages` (`spaces.messages.create`).
- **Footer placement**: appended to the `text` field.
- **Authorization**: Chat app or service-account credential with the
  `chat.bot` scope.
- **Space ID**: carried as `ChannelDescriptor.recipient_addressing.workspace_id`
  (the `spaces/...` resource name).
- **Thread**: optional; if `thread.name` is set, carried at
  `ChannelDescriptor.recipient_addressing.thread_id`.

## Recipient addressing summary

All five platforms collapse into a unified shape:

```jsonc
{
  "recipient_addressing": {
    "platform":     "slack" | "discord" | "teams" | "whatsapp" | "google_chat",
    "workspace_id": "<platform-native workspace/guild/tenant/sender>",
    "channel_id":   "<platform-native channel/chat/recipient>",
    "thread_id":    "<optional thread anchor>"
  }
}
```

The `platform` discriminator MUST be present so verifiers route to the
correct platform-specific footer-extraction rule.

## Body canonicalization

The `CommunicationDescriptor.body_sha256` field MUST equal the SHA-256
of the message text **BEFORE** the `\n\n[aph: ...]` footer is appended.

Canonicalization procedure:

1. Take the message text as it would have been sent without the footer.
2. Normalize line endings to `\n` (LF).
3. Strip trailing whitespace from the final line.
4. Hash with SHA-256. Hex-encode lowercase.

Note that this is the **pre-footer** body, not the post-footer body — this
differs from email where the footer is stripped during canonicalization.
The motivation is symmetry with how chat senders compose messages: the
sender hashes what they typed, then appends the footer.

## Verification flow

A receiver verifies an inbound chat message as follows:

1. Acquire the raw message text from the platform's webhook / events API.
2. Search for `\n\n[aph: <base64>]` anchored at the end of the text. If
   absent → classify **unsigned**.
3. Base64-decode the captured payload. On failure → classify **tampered**.
4. JSON-parse to `AphEnvelope`. On failure → classify **tampered**.
5. Strip the `\n\n[aph: ...]` suffix from the text. Compute the SHA-256
   of the stripped text.
6. Invoke `verify_inbound(envelope, body_sha256)` (see email binding for
   the issuer-key resolution / signature-check pipeline).

## Common failure modes

| Symptom                                  | Classification |
|------------------------------------------|----------------|
| `[aph: ...]` footer missing               | `unsigned`     |
| Base64 decode of footer fails             | `tampered`     |
| JSON parse of footer fails                | `tampered`     |
| Signature verification fails              | `tampered`     |
| `body_sha256` mismatch                    | `tampered`     |
| `recipient_addressing.platform` missing   | `tampered`     |
| Issuer key resolution offline             | `indeterminate`|

## Platform-specific edge cases

- **Slack thread-broadcast posts**: a reply with `reply_broadcast: true`
  produces TWO visible posts; the APH footer is attached only to the
  thread reply. The broadcast copy is treated as a derivative and is
  NOT independently verifiable.
- **Discord message edits**: editing a message changes the body but does
  NOT re-sign. Verifiers MUST treat `edited_timestamp != null` as a hint
  to re-fetch the canonical body; if the footer's `body_sha256` no longer
  matches, classify **tampered**.
- **Teams card content**: adaptive cards (`attachments[].contentType`)
  are not covered by v0.1. Only the textual `body.content` is bound.
- **WhatsApp media messages**: `type: image` / `type: document` etc. are
  not covered by v0.1; the binding applies only to `type: text`.
- **Google Chat formatted text**: simple markdown is preserved by the
  platform. The `body_sha256` is taken over the markdown source as sent,
  not the rendered output.

## Forward-compatibility notes

Future binding versions MAY:

- Define platform-specific extension blocks (`extensions.slack.blocks_hash`,
  `extensions.teams.adaptive_card_hash`) to bind rich content.
- Adopt an out-of-band sidecar channel (e.g. Slack `metadata` field on
  `chat.postMessage`) so the footer does not need to appear in the
  visible body.

Such extensions MUST be additive and gated on a `version` discriminator
inside the envelope.
