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

### Added (revision 2026-05-21 — additive clarification within 0.1.0-draft)

- New §8.4 **Notary Key Material + Public-Key Discovery**. Defines the public/private keypair model for Notary Service operators and THREE publication mechanisms a verifier can use to resolve a notary's public key with NO prior trust relationship: (1) `did:key` self-describing decode, (2) `did:web` `.well-known/did.json` HTTPS resolution, (3) DNS TXT records at `_aph._notary.<domain>` (DKIM-style tag-list).
- §8.4.5 specifies the DNS TXT record name `_aph._notary.<domain>`, required tags (`v=APHv1`, `alg`, `k`), optional tags (`did`, `kid`, `notBefore`, `notAfter`), worked record examples, and verifier resolution flow.
- §8.4.6 defines verifier resolution order across mechanisms.
- §8.4.7 defines key rotation + overlap windows.
- §8.4.8 defines optional pinning + trust-on-first-use behavior for high-stakes verifiers.
- §13 IANA Considerations extended to reserve the underscore-prefixed DNS labels `_aph` and `_aph._notary` by convention (formal IANA registration deferred to v0.2).
- §14.1 normative references extended with `did:key`, `did:web`, RFC 1035, RFC 4034.
- §14.2 informative references extended with multicodec + multibase pointers.
- §8.3 step 2 cross-references §8.4 for resolution detail.

### Notes

- This is a draft for community review. Wire shape may change before v0.1.0 final.
- JSON Schema files are deferred to v0.2.
- Conformance test vectors are deferred to v0.2.
