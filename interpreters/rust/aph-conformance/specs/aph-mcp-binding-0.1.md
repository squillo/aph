# APH MCP Server Channel Binding — v0.1

Status: Draft
Scope: Model Context Protocol (MCP) tool surface for APH operations.

## Overview

This document specifies the binding between APH operations and an
**MCP (Model Context Protocol)** server. The MCP server exposes APH
notarization, verification, and delegation lookup as MCP **tools** so
LLM-driven agents can produce signed communications and verify inbound
ones without invoking the host implementation directly.

The transport dialect is **JSON-RPC 2.0** over stdio, conforming to
the standard MCP framing rules. The server is single-tenant: one MCP
server process serves one host identity, configured at spawn time.

## Tools exposed

The server registers three tools. All three are synchronous from the
MCP caller's perspective; internally they are routed to the host's
local notary service.

### `aph.notarize`

Produces a signed APH envelope for an outbound communication.

**Input schema** (abbreviated JSON Schema):

```jsonc
{
  "type": "object",
  "required": ["channel", "communication"],
  "properties": {
    "channel": {
      "type": "object",
      "description": "ChannelDescriptor — platform, recipient_addressing"
    },
    "communication": {
      "type": "object",
      "required": ["body_sha256"],
      "description": "CommunicationDescriptor — body_sha256, attachments[]"
    },
    "delegation_id": {
      "type": "string",
      "description": "Optional delegation handle authorizing this notarization"
    }
  }
}
```

**Output schema**:

```jsonc
{
  "type": "object",
  "required": ["envelope_b64"],
  "properties": {
    "envelope_b64": { "type": "string" },
    "envelope_id":  { "type": "string", "format": "uri" }
  }
}
```

### `aph.verify_inbound`

Verifies an APH envelope against a computed body hash.

**Input schema**:

```jsonc
{
  "type": "object",
  "required": ["envelope_b64", "body_sha256"],
  "properties": {
    "envelope_b64": { "type": "string" },
    "body_sha256":  { "type": "string", "pattern": "^[0-9a-f]{64}$" }
  }
}
```

**Output schema**:

```jsonc
{
  "type": "object",
  "required": ["classification"],
  "properties": {
    "classification": {
      "type": "string",
      "enum": ["verified", "unsigned", "tampered", "indeterminate"]
    },
    "issuer": { "type": "string", "description": "DID of the verified issuer" },
    "reason": { "type": "string", "description": "Diagnostic for non-verified outcomes" }
  }
}
```

### `aph.lookup_delegation`

Returns the delegation chain associated with a delegation handle.

**Input schema**:

```jsonc
{
  "type": "object",
  "required": ["delegation_id"],
  "properties": {
    "delegation_id": { "type": "string" }
  }
}
```

**Output schema**:

```jsonc
{
  "type": "object",
  "properties": {
    "chain":      { "type": "array", "items": { "type": "object" } },
    "expires_at": { "type": "string", "format": "date-time" },
    "scopes":     { "type": "array", "items": { "type": "string" } }
  }
}
```

## Authorization

The caller MUST possess an appropriate delegation prior to invoking
`aph.notarize`. The recommended flow:

1. Call `aph.lookup_delegation` with a candidate `delegation_id`.
2. Inspect the returned `scopes` and `expires_at`.
3. If the delegation covers the intended channel and is not expired,
   invoke `aph.notarize` passing the same `delegation_id`.

The server MAY reject `aph.notarize` calls that omit `delegation_id`
when its configured policy requires explicit delegation.

`aph.verify_inbound` does NOT require a delegation — verification is
a read-only operation against the issuer's public key.

## Transport

- **Default**: stdio. The MCP server reads JSON-RPC frames from stdin
  and writes responses to stdout. stderr is reserved for logging.
- **Framing**: MCP standard — each frame is a `Content-Length:`-prefixed
  JSON-RPC 2.0 message.
- **Future**: a Server-Sent Events (SSE) and an HTTP-streaming transport
  are reserved for v0.2. The wire dialect (JSON-RPC 2.0 with the same
  three tools) does not change across transports.

## Server discovery

Clients spawn the host binary in a dedicated MCP-server mode (typically a
command-line flag such as `--mcp-server`). In this mode the host binary
suppresses any interactive UI it would normally present and enters the MCP
event loop bound to stdin/stdout.

The MCP server SHOULD be opt-in: hosts are expected to launch it only when
an explicit configuration setting enables it, OR when the binary is
explicitly invoked in MCP-server mode. A host application MAY auto-spawn
one MCP server alongside its main process for in-app agent integrations
when the setting is enabled.

## Error handling

JSON-RPC error codes used by the APH MCP server:

| Code     | Meaning                                            |
|----------|----------------------------------------------------|
| `-32600` | Invalid request (malformed JSON-RPC).              |
| `-32601` | Method not found (unknown tool name).              |
| `-32602` | Invalid params (schema validation failure).        |
| `-32000` | APH notary service unavailable.                    |
| `-32001` | Delegation lookup failed.                          |
| `-32002` | Signing key unavailable (no identity configured).  |

## Forward-compatibility notes

Future binding versions MAY:

- Add streaming tool variants (`aph.notarize_stream`) for very large
  attachment lists.
- Expose a `aph.list_pending_verifications` resource for inbound queues.
- Add a `tools/list` schema discriminator so clients can detect the
  binding version they are talking to.

Such extensions MUST be additive and discoverable via MCP `tools/list`.
