//! Property-based tests + golden vector parse tests for APH domain types.
//!
//! The single `use` statement is permitted (and required) by the
//! `proptest!` macro, which relies on identifiers from `proptest::prelude`
//! being in scope. Outside the proptest macro bodies, every other path is
//! fully qualified per house style.
//!
//! Coverage:
//! - serde round-trip on `NotarizationEnvelope`, `DelegationMandate`,
//!   `CommunicationMandate` (proptest-driven).
//! - serde round-trip on `AphPartyRole` + `AphOperation` (table-driven).
//! - golden-vector parse for the 7 channel-specific envelopes shipped in
//!   `tests/golden/`.
//! - state-machine walks for `HumanPresentNotarizationFlow` (approved
//!   path) and `HumanNotPresentNotarizationFlow` (delivered path), plus
//!   one negative-transition assertion against `AphError::APH_E002`.

use proptest::prelude::*;

// ============================================================
// Shared constants for the proptest-built minimal envelopes.
// ============================================================

/// Fixed 64-char lowercase hex SHA-256 of empty input (RFC 6234 anchor).
/// Reused across every proptest envelope so the proptest only varies the
/// surrounding string fields.
const FIXED_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const FIXED_VALID_FROM: &str = "2026-05-21T00:00:00Z";
const FIXED_VALID_UNTIL: &str = "2026-05-22T00:00:00Z";

// ============================================================
// Proptest round-trip tests.
// ============================================================

proptest! {
  /// Serialize -> parse -> serialize cycle preserves a `NotarizationEnvelope`.
  /// The strategy generates short alpha strings for every text field; channel
  /// addressing is fixed to a Slack-shaped opaque JSON blob (the addressing
  /// field is `serde_json::Value`, so shape is irrelevant to the type).
  #[test]
  // Property test over generated DIDs and ids: round-tripping must hold
  // for arbitrary identifier content, not just the hand-written fixtures.
  // Guards against escaping or length assumptions that happen to work for
  // the sample values but fail on real-world identifiers.
  fn envelope_serde_roundtrip(
    id_tail in "[a-z]{1,20}",
    issuer_tail in "[a-z]{1,20}",
    human_did_tail in "[a-z]{1,20}",
    agent_did_tail in "[a-z]{1,20}",
    display_name in "[a-z]{1,20}",
    agent_display_name in "[a-z]{1,20}",
    agent_version in "[a-z]{1,20}",
    channel_kind in "[a-z]{1,20}",
    content_class in "[a-z]{1,20}",
    preview in "[a-z]{1,20}",
    decision in "[a-z]{1,20}",
    matched_scope in "[a-z]{1,20}",
    notary_name in "[a-z]{1,20}",
    notary_version in "[a-z]{1,20}",
  ) {
    let envelope = crate::envelope::NotarizationEnvelope {
      aph_version: std::string::String::from("0.1"),
      context: std::vec![
        std::string::String::from("https://www.w3.org/ns/credentials/v2"),
        std::string::String::from("https://w3id.org/aph/v1"),
      ],
      r#type: std::vec![
        std::string::String::from("VerifiableCredential"),
        std::string::String::from("AgentSendAuthorizationCredential"),
      ],
      id: std::format!("urn:uuid:{}", id_tail),
      issuer: std::format!("did:key:{}", issuer_tail),
      valid_from: std::string::String::from(FIXED_VALID_FROM),
      valid_until: std::string::String::from(FIXED_VALID_UNTIL),
      credential_subject: crate::envelope::CredentialSubject {
        human_principal: crate::envelope::HumanPrincipalRef {
          id: std::format!("did:key:{}", human_did_tail),
          display_name: display_name.clone(),
        },
        agent: crate::envelope::AgentRef {
          id: std::format!("did:web:{}", agent_did_tail),
          agent_card_uri: std::option::Option::None,
          display_name: agent_display_name.clone(),
          version: agent_version.clone(),
        },
        channel: crate::envelope::ChannelDescriptor {
          kind: channel_kind.clone(),
          recipient_addressing: serde_json::json!({"opaque": "addressing"}),
        },
        communication: crate::envelope::CommunicationDescriptor {
          content_class: content_class.clone(),
          body_sha256: std::string::String::from(FIXED_BODY_SHA256),
          body_size: 1842,
          preview_lines: 3,
          preview: preview.clone(),
        },
        policy: crate::envelope::PolicyDescriptor {
          decision: decision.clone(),
          matched_scope: matched_scope.clone(),
          delegation_mandate_id: std::option::Option::None,
          act_chain: std::vec::Vec::new(),
        },
        notarization: crate::envelope::NotarizationMetadata {
          notary_service: crate::envelope::NotaryServiceRef {
            id: std::string::String::from("did:web:notary.squillo.io"),
            name: notary_name.clone(),
            version: notary_version.clone(),
          },
          decision_timestamp: std::string::String::from("2026-05-21T00:00:01Z"),
          decision_latency_ms: 1834,
        },
        apple_aur_acceptance: std::option::Option::None,
      },
      linked_mandate: std::option::Option::None,
      proof: crate::envelope::EnvelopeProof {
        r#type: std::string::String::from("DataIntegrityProof"),
        cryptosuite: std::option::Option::Some(std::string::String::from("eddsa-jcs-2022")),
        verification_method: std::string::String::from(
          "did:key:zVerify#zVerify",
        ),
        created: std::string::String::from("2026-05-21T00:00:01Z"),
        proof_purpose: std::string::String::from("assertionMethod"),
        proof_value: std::string::String::from("zProofValueOpaque"),
      },
    };

    let json = serde_json::to_string(&envelope).expect("serialize");
    let parsed: crate::envelope::NotarizationEnvelope =
      serde_json::from_str(&json).expect("deserialize");
    prop_assert_eq!(&envelope, &parsed);
  }

  /// `DelegationMandate` round-trips through serde_json with proptest-generated
  /// principal/agent DIDs, allowed channel kinds, and signature string.
  #[test]
  // Same generated-input sweep for the standing mandate: its fields are
  // signature-covered, so serialization must be stable across arbitrary
  // identifier content rather than only the sample() shape.
  fn delegation_mandate_serde_roundtrip(
    id_tail in "[a-z]{1,20}",
    human_did_tail in "[a-z]{1,20}",
    agent_did_tail in "[a-z]{1,20}",
    channels in proptest::collection::vec("[a-z]{1,15}", 1..=3),
    signature in "[a-z]{1,40}",
  ) {
    let mandate = crate::delegation_mandate::DelegationMandate {
      id: std::format!("urn:uuid:{}", id_tail),
      human_principal_did: std::format!("did:key:{}", human_did_tail),
      agent_did: std::format!("did:web:{}", agent_did_tail),
      allowed_channels: channels.clone(),
      rate_limit_per_hour: std::option::Option::None,
      valid_from: std::string::String::from(FIXED_VALID_FROM),
      valid_until: std::string::String::from(FIXED_VALID_UNTIL),
      notary_signature: signature.clone(),
    };
    let json = serde_json::to_string(&mandate).expect("serialize");
    let parsed: crate::delegation_mandate::DelegationMandate =
      serde_json::from_str(&json).expect("deserialize");
    prop_assert_eq!(&mandate, &parsed);
  }

  /// `CommunicationMandate` round-trips through serde_json with proptest-generated
  /// channel + content_class + signature fields. `body_sha256` is fixed to the
  /// canonical 64-char lowercase hex SHA-256 of empty input.
  #[test]
  // Same for the per-message mandate, completing property coverage of all
  // three signed wire objects (envelope, delegation, communication).
  fn communication_mandate_serde_roundtrip(
    id_tail in "[a-z]{1,20}",
    human_did_tail in "[a-z]{1,20}",
    agent_did_tail in "[a-z]{1,20}",
    channel_kind in "[a-z]{1,15}",
    content_class in "[a-z]{1,15}",
    policy_decision in "[a-z]{1,15}",
    signature in "[a-z]{1,40}",
  ) {
    let mandate = crate::communication_mandate::CommunicationMandate {
      id: std::format!("urn:uuid:{}", id_tail),
      delegation_mandate_id: std::option::Option::None,
      human_principal_did: std::format!("did:key:{}", human_did_tail),
      agent_did: std::format!("did:web:{}", agent_did_tail),
      channel_kind: channel_kind.clone(),
      recipient_addressing: serde_json::json!({"opaque": "addressing"}),
      content_class: content_class.clone(),
      body_sha256: std::string::String::from(FIXED_BODY_SHA256),
      body_size: 1842,
      policy_decision: policy_decision.clone(),
      issued_at: std::string::String::from(FIXED_VALID_FROM),
      expires_at: std::string::String::from(FIXED_VALID_UNTIL),
      notary_signature: signature.clone(),
    };
    let json = serde_json::to_string(&mandate).expect("serialize");
    let parsed: crate::communication_mandate::CommunicationMandate =
      serde_json::from_str(&json).expect("deserialize");
    prop_assert_eq!(&mandate, &parsed);
  }
}

// ============================================================
// Table-driven role + operation serde round-trip.
// ============================================================

#[test]
fn role_serde_roundtrip() {
  // Cross-module check from outside roles.rs: confirms the enum is
  // round-trippable through the crate's public path, not just via the
  // in-module tests that can see private details.
  for role in crate::roles::AphPartyRole::all() {
    let json = serde_json::to_string(role).expect("role serialize");
    let parsed: crate::roles::AphPartyRole =
      serde_json::from_str(&json).expect("role deserialize");
    std::assert_eq!(*role, parsed);
  }
  for op in crate::roles::AphOperation::all() {
    let json = serde_json::to_string(op).expect("op serialize");
    let parsed: crate::roles::AphOperation =
      serde_json::from_str(&json).expect("op deserialize");
    std::assert_eq!(*op, parsed);
  }
}

// ============================================================
// Golden vector parse tests.
//
// Each test reads a checked-in JSON file via `include_str!` and asserts that
// it deserializes cleanly into `NotarizationEnvelope`. The strict
// `deny_unknown_fields` on every wire struct means a field-name drift
// between golden corpus and Rust types fails these tests.
//
// Path from this file:
//   src/prop_tests.rs -> ../tests/golden/<file>.json
// ============================================================

#[test]
fn golden_slack_reply_parses() {
  // Golden vectors are frozen wire samples: they must keep parsing under
  // deny_unknown_fields forever. This is the regression gate that catches
  // any field rename or removal that would orphan already-signed
  // envelopes. Slack exercises thread addressing (parentTs).
  let raw = std::include_str!("../tests/golden/slack_reply_envelope.json");
  let env: crate::envelope::NotarizationEnvelope =
    serde_json::from_str(raw).expect("slack golden parses");
  std::assert_eq!(env.credential_subject.channel.kind, "slack");
}

#[test]
fn golden_email_reply_parses() {
  // Email golden: array-valued addressing (to/cc/bcc) plus inReplyTo —
  // the shape most unlike the chat channels, so it guards against an
  // addressing model that only fits single-recipient platforms.
  let raw = std::include_str!("../tests/golden/email_reply_envelope.json");
  let env: crate::envelope::NotarizationEnvelope =
    serde_json::from_str(raw).expect("email golden parses");
  std::assert_eq!(env.credential_subject.channel.kind, "email");
}

#[test]
fn golden_discord_dm_parses() {
  // Discord golden: direct-message addressing, where matchedScope is
  // per-recipient rather than per-channel.
  let raw = std::include_str!("../tests/golden/discord_dm_envelope.json");
  let env: crate::envelope::NotarizationEnvelope =
    serde_json::from_str(raw).expect("discord golden parses");
  std::assert_eq!(env.credential_subject.channel.kind, "discord");
}

#[test]
fn golden_teams_channel_parses() {
  // Teams golden: three-part tenant/team/channel addressing, the deepest
  // addressing nesting in the corpus.
  let raw = std::include_str!("../tests/golden/teams_channel_envelope.json");
  let env: crate::envelope::NotarizationEnvelope =
    serde_json::from_str(raw).expect("teams golden parses");
  std::assert_eq!(env.credential_subject.channel.kind, "teams");
}

#[test]
fn golden_whatsapp_parses() {
  // WhatsApp golden: E.164 phone addressing — a bare identifier string
  // rather than a workspace/channel pair.
  let raw = std::include_str!("../tests/golden/whatsapp_envelope.json");
  let env: crate::envelope::NotarizationEnvelope =
    serde_json::from_str(raw).expect("whatsapp golden parses");
  std::assert_eq!(env.credential_subject.channel.kind, "whatsapp");
}

#[test]
fn golden_google_chat_parses() {
  // Google Chat golden: also pins the snake_case `google_chat` channel
  // kind fixed by the §7.1.5 erratum (early drafts said `googleChat`).
  let raw = std::include_str!("../tests/golden/google_chat_envelope.json");
  let env: crate::envelope::NotarizationEnvelope =
    serde_json::from_str(raw).expect("google_chat golden parses");
  std::assert_eq!(env.credential_subject.channel.kind, "google_chat");
}

#[test]
fn golden_imessage_parses() {
  // iMessage golden: alternative addressing (appleId or phone), the one
  // channel whose recipient key is not fixed.
  let raw = std::include_str!("../tests/golden/imessage_envelope.json");
  let env: crate::envelope::NotarizationEnvelope =
    serde_json::from_str(raw).expect("imessage golden parses");
  std::assert_eq!(env.credential_subject.channel.kind, "imessage");
}

// ============================================================
// Flow state machine walk tests.
// ============================================================

#[test]
fn human_present_flow_walks_approved_path() {
  // Cross-module smoke: the flow is driven through its public API from
  // outside its own module, proving the machine is usable as exported
  // rather than only through module-internal helpers.
  let mut flow =
    crate::human_present_flow::HumanPresentNotarizationFlow::new("cm-test");
  std::assert_eq!(
    flow.state(),
    crate::human_present_flow::HumanPresentNotarizationState::Drafted,
  );
  flow
    .transition_to(
      crate::human_present_flow::HumanPresentNotarizationState::PendingDecision,
    )
    .expect("Drafted -> PendingDecision");
  flow
    .transition_to(crate::human_present_flow::HumanPresentNotarizationState::Approved)
    .expect("PendingDecision -> Approved");
  flow
    .transition_to(
      crate::human_present_flow::HumanPresentNotarizationState::MandateIssued,
    )
    .expect("Approved -> MandateIssued");
  flow
    .transition_to(
      crate::human_present_flow::HumanPresentNotarizationState::EnvelopeIssued,
    )
    .expect("MandateIssued -> EnvelopeIssued");
  flow
    .transition_to(crate::human_present_flow::HumanPresentNotarizationState::Delivered)
    .expect("EnvelopeIssued -> Delivered");
  std::assert!(flow.state().is_terminal());
}

#[test]
fn human_not_present_flow_walks_delivered_path() {
  // Same cross-module exercise for the standing-delegation machine, so
  // both flows are proven reachable through the crate's public surface.
  let mut flow =
    crate::human_not_present_flow::HumanNotPresentNotarizationFlow::new("dm-test");
  std::assert_eq!(
    flow.state(),
    crate::human_not_present_flow::HumanNotPresentNotarizationState::Drafted,
  );
  flow
    .transition_to(
      crate::human_not_present_flow::HumanNotPresentNotarizationState::MandateIssued,
    )
    .expect("Drafted -> MandateIssued");
  flow
    .transition_to(
      crate::human_not_present_flow::HumanNotPresentNotarizationState::EnvelopeIssued,
    )
    .expect("MandateIssued -> EnvelopeIssued");
  flow
    .transition_to(
      crate::human_not_present_flow::HumanNotPresentNotarizationState::Delivered,
    )
    .expect("EnvelopeIssued -> Delivered");
  std::assert!(flow.state().is_terminal());
}

#[test]
fn human_present_flow_rejects_skip() {
  // Re-pins the consent-bypass guard from outside the module: skipping
  // PendingDecision must fail through the public API too, since that is
  // the path a real caller would use to try it.
  let mut flow =
    crate::human_present_flow::HumanPresentNotarizationFlow::new("cm-test");
  let result = flow.transition_to(
    crate::human_present_flow::HumanPresentNotarizationState::MandateIssued,
  );
  let err = result.expect_err("Drafted -> MandateIssued must be rejected");
  std::assert_eq!(err.code(), "APH_E002");
}
