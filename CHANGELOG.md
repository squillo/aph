# Changelog

All notable changes to APH (Agent per Human Notarization Protocol) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-draft] — 2026-05-21

### Added

- Initial public draft of the APH protocol specification.
- Canonical envelope shape (W3C Verifiable Credential 2.0).
- Two mandate types: `DelegationMandate` (ongoing) and `CommunicationMandate` (per-message).
- Five protocol roles: `HumanPrincipal`, `AgentSender`, `NotaryService`, `ChannelAdapter`, `RecipientEndpoint`.
- Two flow state machines: human-present (7 states) and human-not-present (5 states).
- A2A Agent Card extension descriptor (URI `aph://extensions/notarization/v1`).
- SD-JWT-VC profile pinning (draft-ietf-oauth-sd-jwt-vc-16, draft-ietf-oauth-selective-disclosure-jwt-22).
- 7 example envelope JSON files covering Slack, Email, Discord, Teams, WhatsApp, Google Chat, and iMessage channels.

### Notes

- This is a draft for community review. Wire shape may change before v0.1.0 final.
- JSON Schema files are deferred to v0.2.
- Conformance test vectors are deferred to v0.2.
