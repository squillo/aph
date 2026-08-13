//! NotarizationEnvelope — the W3C VC 2.0-shaped credential carrying an
//! APH notarization. This is the canonical on-wire shape.
//!
//! The envelope is a JSON-LD compatible W3C Verifiable Credential 2.0
//! payload. The `@context` field carries the JSON-LD contexts; the `type`
//! field MUST include `"VerifiableCredential"` plus
//! `"AgentSendAuthorizationCredential"`. All struct field names use
//! snake_case in Rust and camelCase on the wire (via
//! `#[serde(rename_all = "camelCase")]`), except `@context` (JSON-LD
//! convention) and `type` (Rust reserved keyword routed through `r#type`
//! + explicit `#[serde(rename = "type")]` for defense in depth).
//!
//! This module is shape-only — `proof.proof_value` is a String; no
//! cryptographic validation occurs in this module.

/// Top-level APH envelope. JSON-LD compatible W3C VC 2.0 credential.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotarizationEnvelope {
  /// APH version pin (`"0.1"`).
  pub aph_version: String,
  /// JSON-LD `@context` array. Always begins with W3C VC 2.0 context.
  #[serde(rename = "@context")]
  pub context: Vec<String>,
  /// JSON-LD `type` array; MUST include `"VerifiableCredential"` and
  /// `"AgentSendAuthorizationCredential"`.
  #[serde(rename = "type")]
  pub r#type: Vec<String>,
  /// `urn:uuid:...` envelope identifier.
  pub id: String,
  /// DID of the notary service.
  pub issuer: String,
  /// RFC 3339 issuance timestamp.
  pub valid_from: String,
  /// RFC 3339 expiry timestamp.
  pub valid_until: String,
  /// Inner credential subject (the notarized claim).
  pub credential_subject: CredentialSubject,
  /// Optional link to an AP2 IntentMandate (for cross-protocol mandates).
  #[serde(default)]
  pub linked_mandate: std::option::Option<LinkedMandate>,
  /// Cryptographic proof block (Data Integrity Proof or JWS detached).
  pub proof: EnvelopeProof,
}

/// The notarized claim: who authorized what, on which channel, under
/// which policy, attested by which notary.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSubject {
  /// The human on whose behalf the agent acted.
  pub human_principal: HumanPrincipalRef,
  /// The agent that produced the communication.
  pub agent: AgentRef,
  /// Delivery channel and recipient addressing.
  pub channel: ChannelDescriptor,
  /// What was sent: content class, body hash, size, preview.
  pub communication: CommunicationDescriptor,
  /// The authorization decision and the scope it matched.
  pub policy: PolicyDescriptor,
  /// Which notary decided, when, and how long it took.
  pub notarization: NotarizationMetadata,
  /// Last-position additive field. Optional Apple Foundation Models AUR
  /// acceptance claim per `(user_id, device_id, aur_version_hash)`.
  /// `#[serde(default, skip_serializing_if = "Option::is_none")]` preserves
  /// wire back-compat (legacy envelopes omit the field and continue to
  /// deserialize cleanly).
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub apple_aur_acceptance: std::option::Option<AppleAurAcceptanceClaim>,
}

/// Reference to the human on whose behalf the agent acted.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanPrincipalRef {
  /// DID of the human principal.
  pub id: String,
  /// Human-readable name, for display in consent UIs and audit logs.
  pub display_name: String,
}

/// Reference to the agent that produced the communication.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentRef {
  /// DID of the agent (typically `did:web:...`).
  pub id: String,
  /// Optional URI of the agent's A2A Agent Card.
  #[serde(default)]
  pub agent_card_uri: std::option::Option<String>,
  /// Human-readable agent name.
  pub display_name: String,
  /// Agent version string, so a recipient can tell releases apart.
  pub version: String,
}

/// Delivery channel and its channel-shaped recipient addressing.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelDescriptor {
  /// Channel kind: `"slack" | "email" | "discord" | ...`.
  pub kind: String,
  /// Channel-shaped opaque blob (opaque to APH core).
  pub recipient_addressing: serde_json::Value,
}

/// What was sent: classification plus the hash that binds this credential
/// to a specific message body.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommunicationDescriptor {
  /// Content classification (`"Reply"`, `"New"`, `"DM"`, ...).
  pub content_class: String,
  /// SHA-256 of the message body, 64 lowercase hex characters.
  pub body_sha256: String,
  /// Body length in bytes.
  pub body_size: u64,
  /// Number of body lines included in `preview`.
  pub preview_lines: u32,
  /// Truncated body excerpt for human review at decision time.
  pub preview: String,
}

/// The authorization decision and the scope that produced it.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyDescriptor {
  /// `"AlwaysAllow" | "AskEveryTime" | "NeverAllow"`.
  pub decision: String,
  /// e.g., `"per-channel" | "per-recipient" | "global"`.
  pub matched_scope: String,
  /// Parent delegation mandate, absent for one-shot AskEveryTime grants.
  #[serde(default)]
  pub delegation_mandate_id: std::option::Option<String>,
  /// OAuth 2.0 Token Exchange `act` chain (RFC 8693) — optional cross-system
  /// principal chain. Each element is a DID string.
  #[serde(default)]
  pub act_chain: Vec<String>,
}

/// Which notary made the decision, when, and how long it took.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotarizationMetadata {
  /// The notary service that decided.
  pub notary_service: NotaryServiceRef,
  /// RFC 3339 decision timestamp.
  pub decision_timestamp: String,
  /// Decision latency in milliseconds — audit evidence for whether a human
  /// was plausibly in the loop.
  pub decision_latency_ms: u64,
}

/// Identity of the notary service, used for key discovery (spec §8.4).
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotaryServiceRef {
  /// DID of the notary.
  pub id: String,
  /// Human-readable notary service name.
  pub name: String,
  /// Notary implementation version.
  pub version: String,
}

/// Cross-protocol links carried alongside the send authorization.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedMandate {
  /// URI of an AP2 IntentMandate cross-linking payment authorization.
  #[serde(default)]
  pub ap2_intent_mandate_uri: std::option::Option<String>,
  /// Optional base64-encoded AP2 SignedPayload for self-contained
  /// verification when the verifier cannot dereference
  /// `ap2_intent_mandate_uri`. `#[serde(default)]` preserves wire
  /// back-compat for envelopes written before this field was added.
  #[serde(default)]
  pub ap2_signed_payload_b64: std::option::Option<String>,
  /// Optional cross-vault mutation mandate for LinkedMandates issued by a
  /// cross-vault federation engine.
  /// `#[serde(default, skip_serializing_if = "...")]` preserves
  /// wire back-compat (legacy envelopes omit the field).
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub vault_mutation: std::option::Option<
    crate::vault_mutation::VaultMutationMandate,
  >,
}

#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
/// The cryptographic proof block: either a W3C Data Integrity Proof or a
/// detached JWS, per spec §8.2.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeProof {
  /// Always `"DataIntegrityProof"` for the JCS-canonicalized cryptosuites,
  /// or `"JsonWebSignature2020"` for compact JWS detached.
  #[serde(rename = "type")]
  pub r#type: String,
  /// Required for DataIntegrityProof. e.g., `"eddsa-jcs-2022"` or
  /// `"ecdsa-jcs-2019"`.
  #[serde(default)]
  pub cryptosuite: std::option::Option<String>,
  /// DID URL referencing the verifying key
  /// (e.g., `did:key:z6Mk...#z6Mk...`).
  pub verification_method: String,
  /// RFC 3339.
  pub created: String,
  /// Always `"assertionMethod"` for APH.
  pub proof_purpose: String,
  /// Multibase or base64url-encoded signature bytes.
  pub proof_value: String,
}

/// Last-position sibling struct. Carries Apple Foundation Models AUR
/// acceptance per `(user_id, device_id, aur_version_hash)` tuple.
/// Embedded as `Option<AppleAurAcceptanceClaim>` on
/// `CredentialSubject.apple_aur_acceptance`. The field is
/// `#[serde(default, skip_serializing_if = "...")]` so legacy envelopes that
/// predate this claim continue to deserialize cleanly.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppleAurAcceptanceClaim {
  /// User-scoped DID for whom acceptance was recorded.
  pub user_id: String,
  /// Device-scoped opaque identifier (acceptance is recorded per
  /// `(user_id, device_id)` pair).
  pub device_id: String,
  /// SHA-256 hex of the Apple AUR snapshot text accepted.
  pub aur_version_hash: String,
  /// RFC 3339 acceptance timestamp.
  pub accepted_at: String,
  /// `"foundation_models_framework_aur"` for forward-compat with future Apple legal documents.
  pub document_kind: String,
}

#[cfg(test)]
mod tests {
  // -------- helpers --------

  fn sample_human_principal() -> super::HumanPrincipalRef {
    super::HumanPrincipalRef {
      id: "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy".to_string(),
      display_name: "Scott Wyatt".to_string(),
    }
  }

  fn sample_agent() -> super::AgentRef {
    super::AgentRef {
      id: "did:web:agent.squillo.io".to_string(),
      agent_card_uri: std::option::Option::Some(
        "https://agent.squillo.io/.well-known/agent-card.json".to_string(),
      ),
      display_name: "Squillo Concierge".to_string(),
      version: "1.0".to_string(),
    }
  }

  fn sample_channel() -> super::ChannelDescriptor {
    super::ChannelDescriptor {
      kind: "slack".to_string(),
      recipient_addressing: serde_json::json!({
        "teamId": "T01234567",
        "channelId": "C01234567",
        "parentTs": "1716249600.000100"
      }),
    }
  }

  fn sample_communication() -> super::CommunicationDescriptor {
    super::CommunicationDescriptor {
      content_class: "Reply".to_string(),
      body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
      body_size: 1842,
      preview_lines: 3,
      preview: "hello world".to_string(),
    }
  }

  fn sample_policy() -> super::PolicyDescriptor {
    super::PolicyDescriptor {
      decision: "AskEveryTime".to_string(),
      matched_scope: "per-channel".to_string(),
      delegation_mandate_id: std::option::Option::None,
      act_chain: std::vec::Vec::new(),
    }
  }

  fn sample_notary_service() -> super::NotaryServiceRef {
    super::NotaryServiceRef {
      id: "did:web:notary.squillo.io".to_string(),
      name: "Squillo Notary Service".to_string(),
      version: "0.1.0".to_string(),
    }
  }

  fn sample_notarization_metadata() -> super::NotarizationMetadata {
    super::NotarizationMetadata {
      notary_service: sample_notary_service(),
      decision_timestamp: "2026-05-21T00:00:01Z".to_string(),
      decision_latency_ms: 1834,
    }
  }

  fn sample_credential_subject() -> super::CredentialSubject {
    super::CredentialSubject {
      human_principal: sample_human_principal(),
      agent: sample_agent(),
      channel: sample_channel(),
      communication: sample_communication(),
      policy: sample_policy(),
      notarization: sample_notarization_metadata(),
      apple_aur_acceptance: std::option::Option::None,
    }
  }

  fn sample_linked_mandate() -> super::LinkedMandate {
    super::LinkedMandate {
      ap2_intent_mandate_uri: std::option::Option::Some(
        "urn:uuid:11111111-1111-4111-8111-111111111111".to_string(),
      ),
      ap2_signed_payload_b64: std::option::Option::None,
      vault_mutation: std::option::Option::None,
    }
  }

  fn sample_proof() -> super::EnvelopeProof {
    super::EnvelopeProof {
      r#type: "DataIntegrityProof".to_string(),
      cryptosuite: std::option::Option::Some("eddsa-jcs-2022".to_string()),
      verification_method:
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"
          .to_string(),
      created: "2026-05-21T00:00:01Z".to_string(),
      proof_purpose: "assertionMethod".to_string(),
      proof_value:
        "z3WgvA9JHkbV3qLZHcM4FxBp4xHfQVnVnPKKDdyazQwQGdGzxsRdmZWBxXwQvN6P2sLZbLP4HnRy9LcZdpFLLM6h"
          .to_string(),
    }
  }

  fn sample_envelope() -> super::NotarizationEnvelope {
    super::NotarizationEnvelope {
      aph_version: "0.1".to_string(),
      context: std::vec![
        "https://www.w3.org/ns/credentials/v2".to_string(),
        "https://w3id.org/aph/v1".to_string(),
      ],
      r#type: std::vec![
        "VerifiableCredential".to_string(),
        "AgentSendAuthorizationCredential".to_string(),
      ],
      id: "urn:uuid:00000000-0000-4000-8000-000000000001".to_string(),
      issuer: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV".to_string(),
      valid_from: "2026-05-21T00:00:00Z".to_string(),
      valid_until: "2026-05-22T00:00:00Z".to_string(),
      credential_subject: sample_credential_subject(),
      linked_mandate: std::option::Option::None,
      proof: sample_proof(),
    }
  }

  // -------- Test 1: per-struct round-trip --------

  #[test]
  fn round_trip_human_principal_ref() {
    // Per-struct round-trips exist because deny_unknown_fields makes every
    // sub-struct independently strict: a field lost or renamed here would
    // fail only when that specific object is parsed. This one carries the
    // human's DID — the identity the whole credential attests.
    let v = sample_human_principal();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::HumanPrincipalRef = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_agent_ref() {
    // The agent identity a recipient checks against the delegation; its
    // optional agentCardUri must survive round-tripping alongside the
    // required fields.
    let v = sample_agent();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::AgentRef = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_channel_descriptor() {
    // Holds the opaque recipientAddressing blob (§7.4), the one place
    // arbitrary JSON is preserved verbatim — this pins that it survives
    // untouched rather than being normalized or dropped.
    let v = sample_channel();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::ChannelDescriptor = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_communication_descriptor() {
    // Carries bodySha256 and bodySize — the binding between the credential
    // and the actual message. Any loss here breaks the APH_E009 body-hash
    // check that stops a signature being reused for a different body.
    let v = sample_communication();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::CommunicationDescriptor = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_policy_descriptor() {
    // The authorization record itself (decision, matched scope, delegation
    // id, act chain). Dropping actChain or delegationMandateId would erase
    // the evidence a verifier uses to trace authority back to the human.
    let v = sample_policy();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::PolicyDescriptor = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_notary_service_ref() {
    // Identifies which notary made the decision — needed for key discovery
    // (§8.4) and for auditing which service to hold accountable.
    let v = sample_notary_service();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::NotaryServiceRef = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_notarization_metadata() {
    // Decision timestamp and latency: audit evidence for whether a human
    // was plausibly in the loop, so it must survive intact.
    let v = sample_notarization_metadata();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::NotarizationMetadata = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_credential_subject() {
    // Composition test: the six sub-objects must nest correctly together.
    // Per-struct round-trips above cannot catch a broken assembly (e.g. a
    // field attached at the wrong level).
    let v = sample_credential_subject();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::CredentialSubject = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_linked_mandate() {
    // Cross-protocol link (AP2 payment authorization, vault mutation). It
    // holds three independently-optional fields, so round-tripping proves
    // none of them is lost when the others are absent.
    let v = sample_linked_mandate();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::LinkedMandate = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_envelope_proof() {
    // The signature block itself. If any proof field failed to round-trip,
    // a re-serialized envelope would carry an unverifiable proof.
    let v = sample_proof();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::EnvelopeProof = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_notarization_envelope() {
    // The whole credential end to end — the exact operation a relaying
    // verifier performs. This is the last line of defense against any
    // field being silently dropped in transit.
    let v = sample_envelope();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::NotarizationEnvelope = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  // -------- Test 2: wire-key shape for reserved/JSON-LD names --------

  #[test]
  fn envelope_serializes_type_as_type_and_context_as_at_context() {
    // Two JSON-LD keys Rust cannot name directly: "@context" (illegal
    // identifier) and "type" (keyword, written r#type). Both depend on
    // explicit #[serde(rename)] attributes — drop one and the envelope
    // stops being a valid W3C Verifiable Credential.
    let v = sample_envelope();
    let s = serde_json::to_string(&v).unwrap();
    std::assert!(
      s.contains("\"type\":"),
      "envelope must serialize r#type as \"type\": {}",
      s
    );
    std::assert!(
      s.contains("\"@context\":"),
      "envelope must serialize context as \"@context\": {}",
      s
    );
    std::assert!(
      !s.contains("\"rType\""),
      "envelope must NOT serialize as \"rType\": {}",
      s
    );
    std::assert!(
      !s.contains("\"r#type\""),
      "envelope must NOT serialize as \"r#type\": {}",
      s
    );
  }

  #[test]
  fn proof_serializes_type_as_type() {
    // Same r#type rename, applied on the nested proof block — pinned
    // separately because the attribute must be repeated per struct and is
    // easy to omit on a newly added one.
    let v = sample_proof();
    let s = serde_json::to_string(&v).unwrap();
    std::assert!(
      s.contains("\"type\":"),
      "proof must serialize r#type as \"type\": {}",
      s
    );
    std::assert!(
      !s.contains("\"rType\""),
      "proof must NOT serialize as \"rType\": {}",
      s
    );
  }

  // -------- Test 3: deny_unknown_fields rejection --------

  #[test]
  fn envelope_rejects_unknown_field() {
    // Strict parsing (§7.1, §8.3 step 1) is normative: an unknown envelope
    // field must be a hard error. Accepting-and-ignoring would let a
    // producer smuggle a claim the verifier never evaluates.
    let s = serde_json::json!({
      "aphVersion": "0.1",
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/aph/v1"
      ],
      "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
      "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
      "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
      "validFrom": "2026-05-21T00:00:00Z",
      "validUntil": "2026-05-22T00:00:00Z",
      "credentialSubject": {
        "humanPrincipal": {
          "id": "did:key:abc",
          "displayName": "X"
        },
        "agent": {
          "id": "did:web:agent.squillo.io",
          "displayName": "X",
          "version": "1.0"
        },
        "channel": {
          "kind": "slack",
          "recipientAddressing": {}
        },
        "communication": {
          "contentClass": "Reply",
          "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "bodySize": 0,
          "previewLines": 0,
          "preview": ""
        },
        "policy": {
          "decision": "AskEveryTime",
          "matchedScope": "per-channel"
        },
        "notarization": {
          "notaryService": {
            "id": "did:web:notary.squillo.io",
            "name": "Squillo Notary Service",
            "version": "0.1.0"
          },
          "decisionTimestamp": "2026-05-21T00:00:01Z",
          "decisionLatencyMs": 0
        }
      },
      "proof": {
        "type": "DataIntegrityProof",
        "verificationMethod": "did:key:abc#abc",
        "created": "2026-05-21T00:00:01Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z..."
      },
      "extraKey": "x"
    })
    .to_string();
    let r: std::result::Result<super::NotarizationEnvelope, _> = serde_json::from_str(&s);
    std::assert!(
      r.is_err(),
      "deny_unknown_fields must reject extraKey: {:?}",
      r
    );
  }

  #[test]
  fn human_principal_ref_rejects_unknown_field() {
    // deny_unknown_fields does NOT cascade to nested structs — each one
    // needs its own attribute. This pins that the nested case is covered,
    // not merely the top level.
    let s = serde_json::json!({
      "id": "did:key:abc",
      "displayName": "X",
      "rogue": true
    })
    .to_string();
    let r: std::result::Result<super::HumanPrincipalRef, _> = serde_json::from_str(&s);
    std::assert!(
      r.is_err(),
      "deny_unknown_fields must reject rogue field: {:?}",
      r
    );
  }

  // -------- Test 4: defaults on optional fields --------

  #[test]
  fn envelope_deserializes_without_linked_mandate() {
    // Most envelopes carry no cross-protocol link, so the common case must
    // parse with the key absent — under deny_unknown_fields this works
    // only while #[serde(default)] is present.
    let s = serde_json::json!({
      "aphVersion": "0.1",
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/aph/v1"
      ],
      "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
      "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
      "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
      "validFrom": "2026-05-21T00:00:00Z",
      "validUntil": "2026-05-22T00:00:00Z",
      "credentialSubject": {
        "humanPrincipal": {
          "id": "did:key:abc",
          "displayName": "X"
        },
        "agent": {
          "id": "did:web:agent.squillo.io",
          "displayName": "X",
          "version": "1.0"
        },
        "channel": {
          "kind": "slack",
          "recipientAddressing": {}
        },
        "communication": {
          "contentClass": "Reply",
          "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "bodySize": 0,
          "previewLines": 0,
          "preview": ""
        },
        "policy": {
          "decision": "AskEveryTime",
          "matchedScope": "per-channel"
        },
        "notarization": {
          "notaryService": {
            "id": "did:web:notary.squillo.io",
            "name": "Squillo Notary Service",
            "version": "0.1.0"
          },
          "decisionTimestamp": "2026-05-21T00:00:01Z",
          "decisionLatencyMs": 0
        }
      },
      "proof": {
        "type": "DataIntegrityProof",
        "verificationMethod": "did:key:abc#abc",
        "created": "2026-05-21T00:00:01Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z..."
      }
    })
    .to_string();
    let v: super::NotarizationEnvelope =
      serde_json::from_str(&s).expect("must deserialize with linkedMandate omitted");
    std::assert!(v.linked_mandate.is_none());
  }

  #[test]
  fn agent_ref_deserializes_without_agent_card_uri() {
    // Not every agent publishes an A2A AgentCard; omitting the URI must
    // stay legal rather than making those agents unable to be notarized.
    let s = serde_json::json!({
      "id": "did:web:agent.squillo.io",
      "displayName": "X",
      "version": "1.0"
    })
    .to_string();
    let v: super::AgentRef =
      serde_json::from_str(&s).expect("must deserialize with agentCardUri omitted");
    std::assert!(v.agent_card_uri.is_none());
  }

  #[test]
  fn policy_descriptor_deserializes_without_optionals() {
    // The one-shot AskEveryTime shape has no delegation and no act chain,
    // so both optional fields must be omissible together — the defaults
    // that make a human-present decision representable at all.
    let s = serde_json::json!({
      "decision": "AskEveryTime",
      "matchedScope": "per-channel"
    })
    .to_string();
    let v: super::PolicyDescriptor =
      serde_json::from_str(&s).expect("must deserialize with optionals omitted");
    std::assert!(v.delegation_mandate_id.is_none());
    std::assert!(v.act_chain.is_empty());
  }

  #[test]
  fn linked_mandate_deserializes_without_ap2_uri() {
    // A linkedMandate may carry a vault mutation with no payment link, so
    // its fields must be independently optional rather than all-or-nothing.
    let s = serde_json::json!({}).to_string();
    let v: super::LinkedMandate =
      serde_json::from_str(&s).expect("must deserialize with ap2IntentMandateUri omitted");
    std::assert!(v.ap2_intent_mandate_uri.is_none());
  }

  #[test]
  fn envelope_proof_deserializes_without_cryptosuite() {
    // cryptosuite applies to DataIntegrityProof but not to the
    // JsonWebSignature2020 form (§8.2), so a JWS-style proof must parse
    // without it instead of being rejected as malformed.
    let s = serde_json::json!({
      "type": "JsonWebSignature2020",
      "verificationMethod": "did:key:abc#abc",
      "created": "2026-05-21T00:00:01Z",
      "proofPurpose": "assertionMethod",
      "proofValue": "z..."
    })
    .to_string();
    let v: super::EnvelopeProof =
      serde_json::from_str(&s).expect("must deserialize with cryptosuite omitted");
    std::assert!(v.cryptosuite.is_none());
  }

  // -------- Test 5: camelCase wire form --------

  #[test]
  fn human_principal_ref_serializes_camel_case() {
    // Rust field names are snake_case; the wire is camelCase. This pins
    // that the rename_all attribute is actually applied — without it every
    // key would silently change and no other implementation could parse it.
    let v = super::HumanPrincipalRef {
      id: "did:key:abc".to_string(),
      display_name: "Scott".to_string(),
    };
    let s = serde_json::to_string(&v).unwrap();
    std::assert!(
      s.contains("\"displayName\""),
      "must serialize display_name as displayName: {}",
      s
    );
    std::assert!(
      !s.contains("\"display_name\""),
      "must NOT serialize as display_name: {}",
      s
    );
  }

  // -------- Test 6: AppleAurAcceptanceClaim round-trip --------

  #[test]
  fn apple_aur_acceptance_claim_round_trip() {
    // Registered optional extension (spec §7.5.1). It must round-trip
    // fully when present while staying absent-by-default, so that
    // extension-free envelopes keep their exact pre-extension bytes.
    let claim = super::AppleAurAcceptanceClaim {
      user_id: "did:key:z6MkUserAbc123".to_string(),
      device_id: "device-opaque-id-001".to_string(),
      aur_version_hash:
        "a3b4c5d6e7f8091011121314151617181920212223242526272829303132333435".to_string(),
      accepted_at: "2026-06-09T00:00:00Z".to_string(),
      document_kind: "foundation_models_framework_aur".to_string(),
    };
    let subject = super::CredentialSubject {
      human_principal: sample_human_principal(),
      agent: sample_agent(),
      channel: sample_channel(),
      communication: sample_communication(),
      policy: sample_policy(),
      notarization: sample_notarization_metadata(),
      apple_aur_acceptance: std::option::Option::Some(claim.clone()),
    };
    let s = serde_json::to_string(&subject).unwrap();
    // wire form must use camelCase key
    std::assert!(
      s.contains("\"appleAurAcceptance\""),
      "must serialize apple_aur_acceptance as appleAurAcceptance: {}",
      s
    );
    let v2: super::CredentialSubject = serde_json::from_str(&s).unwrap();
    std::assert_eq!(subject, v2);
    let recovered = v2.apple_aur_acceptance.expect("must be Some after round-trip");
    std::assert_eq!(recovered.document_kind, "foundation_models_framework_aur");
    std::assert_eq!(recovered.user_id, claim.user_id);
    std::assert_eq!(recovered.device_id, claim.device_id);
    std::assert_eq!(recovered.aur_version_hash, claim.aur_version_hash);
    std::assert_eq!(recovered.accepted_at, claim.accepted_at);
  }

  // -------- Test 7: legacy wire back-compat (field absent) --------

  #[test]
  fn credential_subject_legacy_omit_apple_aur_acceptance() {
    // A legacy CredentialSubject JSON payload that does NOT contain
    // `appleAurAcceptance` must still deserialize cleanly with
    // `apple_aur_acceptance == None` (wire back-compat).
    let s = serde_json::json!({
      "humanPrincipal": {
        "id": "did:key:z6MkLegacyUser",
        "displayName": "Legacy User"
      },
      "agent": {
        "id": "did:web:agent.squillo.io",
        "displayName": "Squillo Concierge",
        "version": "1.0"
      },
      "channel": {
        "kind": "slack",
        "recipientAddressing": {}
      },
      "communication": {
        "contentClass": "Reply",
        "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "bodySize": 0,
        "previewLines": 0,
        "preview": ""
      },
      "policy": {
        "decision": "AskEveryTime",
        "matchedScope": "per-channel"
      },
      "notarization": {
        "notaryService": {
          "id": "did:web:notary.squillo.io",
          "name": "Squillo Notary Service",
          "version": "0.1.0"
        },
        "decisionTimestamp": "2026-05-21T00:00:01Z",
        "decisionLatencyMs": 0
      }
    })
    .to_string();
    let v: super::CredentialSubject = serde_json::from_str(&s)
      .expect("legacy payload without appleAurAcceptance must deserialize cleanly");
    std::assert!(
      v.apple_aur_acceptance.is_none(),
      "apple_aur_acceptance must be None when absent from legacy wire payload"
    );
  }
}
