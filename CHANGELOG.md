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

### Added (revision 2026-05-21b — driver's-license framing + revocation conceptual model within 0.1.0-draft)

- New §1.1 **Mental model — the agent's driver's license**. Frames APH credentials as drivers' licenses for agents, with the human as the issuing authority, the notary as the DMV, and bounded scope (channels, rate, time window, policy decision) directly analogous to license endorsements + restrictions + expiration. Establishes cross-jurisdiction portability (interstate-license framing) as a first-class property.
- New §1.1.1 **Concrete example** — two agents from different organizations negotiating a meeting across an A2A channel under APH, including notary-key resolution via `did:web` and DNS TXT (§8.4), revocation, and the recipient-side verification flow.
- §6.3 **Mandate lifecycle** rewritten. NEW §6.3.1 makes mandate revocation NORMATIVE in v0.1 at the conceptual layer (issuer-side `revoked` state, downstream issuance cutoff, recipient policy guidance, short-validity-window posture for v0.1). On-wire revocation transport (W3C Verifiable Credential Status List 2021 or equivalent) remains deferred to v0.2. NEW §6.3.2 makes expiration semantics explicit (no re-activation; new mandate required).
- §10.1 **A2A composition** expanded with explicit positioning ("A2A defines transport; APH defines the human authorization that rides on top") + back-reference to §1.1.1 worked example.
- §10.2 **AP2 composition** expanded with explicit positioning ("AP2 authorizes payment; APH authorizes the broader category of human-on-behalf-of actions, including the communication that surrounds a payment"). Adds the toll-booth / driver's-license / road-network framing of the A2A + AP2 + APH triad.
- §1 Abstract reworded to scope "outbound actions" more broadly than "outbound communications" — APH covers any human-authorized agent action, including messaging, scheduling, content authorship, and the communications surrounding payments.

### Notes

- This is a draft for community review. Wire shape may change before v0.1.0 final.
- JSON Schema files are deferred to v0.2.
- Conformance test vectors are deferred to v0.2.
