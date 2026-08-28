//! CommunicationMandate — per-message authorization. References a parent
//! `DelegationMandate` and binds to a specific outbound payload by hash.

/// Single-use, per-message authorization derived from a standing
/// `DelegationMandate` (or issued directly for a one-shot AskEveryTime
/// decision). Signed by the notary.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommunicationMandate {
  /// `urn:uuid:...` mandate identifier.
  pub id: String,
  /// Parent `DelegationMandate.id` (or `None` for one-shot AskEveryTime flow).
  #[serde(default)]
  pub delegation_mandate_id: std::option::Option<String>,
  /// DID of the human principal (re-stated for tamper-detect).
  pub human_principal_did: String,
  /// DID of the agent sender (re-stated).
  pub agent_did: String,
  /// Channel kind, drawn from the closed set (§7.1.5).
  ///
  /// Typed to match the envelope's field for the same reason as
  /// `content_class` below: §6.2 requires this value EQUAL the value
  /// the resulting envelope carries, and that equality is only
  /// checkable by the compiler if both sides are the same type.
  pub channel_kind: crate::envelope::ChannelKind,
  /// Recipient addressing (channel-shaped JSON; opaque to APH core).
  pub recipient_addressing: serde_json::Value,
  /// Content classification, drawn from the closed set (§7.1.6).
  ///
  /// Typed to match the envelope's field: §6.2 requires the mandate value
  /// EQUAL the value the resulting envelope carries, and an equality between
  /// two `String`s that are meant to be the same closed vocabulary is an
  /// equality the compiler cannot help with.
  pub content_class: crate::envelope::ContentClass,
  /// SHA-256 hex of the outbound message body bytes (lowercase, no `0x`).
  pub body_sha256: String,
  /// Body size in bytes.
  pub body_size: u64,
  /// Policy decision the human made (`AlwaysAllow`, `AskEveryTime`, `NeverAllow`).
  pub policy_decision: String,
  /// RFC 3339 issuance timestamp.
  pub issued_at: String,
  /// RFC 3339 expiry timestamp.
  pub expires_at: String,
  /// Notary service signature over the canonical JCS form MINUS `notary_signature`.
  pub notary_signature: String,
}

#[cfg(test)]
mod tests {
  fn sample() -> super::CommunicationMandate {
    super::CommunicationMandate {
      id: String::from("urn:uuid:00000000-0000-4000-8000-000000000002"),
      delegation_mandate_id: std::option::Option::Some(String::from(
        "urn:uuid:00000000-0000-4000-8000-000000000001",
      )),
      human_principal_did: String::from("did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy"),
      agent_did: String::from("did:web:agent.squillo.com"),
      channel_kind: crate::envelope::ChannelKind::Slack,
      recipient_addressing: serde_json::json!({
        "teamId": "T01234567",
        "channelId": "C01234567",
        "parentTs": "1716249600.000100"
      }),
      content_class: crate::envelope::ContentClass::Reply,
      // 64-char lowercase hex SHA-256 (the empty-string SHA-256).
      body_sha256: String::from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
      body_size: 1842,
      policy_decision: String::from("AskEveryTime"),
      issued_at: String::from("2026-05-21T00:00:00Z"),
      expires_at: String::from("2026-05-21T01:00:00Z"),
      notary_signature: String::from("z3WgvA9JHkbV3qLZHcM4FxBp4xHfQVnVnPKKDdyazQwQGdGzxsRdmZW"),
    }
  }

  #[test]
  fn serde_round_trip_preserves_equality() {
    // A CommunicationMandate is single-use and signed; losing a field on
    // reload would mean authorizing a send whose terms differ from the
    // ones the notary actually certified.
    let m = sample();
    let json = serde_json::to_string(&m).unwrap();
    let back: super::CommunicationMandate = serde_json::from_str(&json).unwrap();
    std::assert_eq!(m, back);
  }

  #[test]
  fn serde_uses_camel_case_field_names() {
    // Spec §6.2 fixes these key names, and notarySignature covers the
    // canonical form built from them — renaming one both breaks interop
    // and invalidates existing signatures.
    let m = sample();
    let json = serde_json::to_string(&m).unwrap();
    std::assert!(json.contains("\"delegationMandateId\""));
    std::assert!(json.contains("\"humanPrincipalDid\""));
    std::assert!(json.contains("\"agentDid\""));
    std::assert!(json.contains("\"channelKind\""));
    std::assert!(json.contains("\"recipientAddressing\""));
    std::assert!(json.contains("\"contentClass\""));
    std::assert!(json.contains("\"bodySha256\""));
    std::assert!(json.contains("\"bodySize\""));
    std::assert!(json.contains("\"policyDecision\""));
    std::assert!(json.contains("\"issuedAt\""));
    std::assert!(json.contains("\"expiresAt\""));
    std::assert!(json.contains("\"notarySignature\""));
  }

  #[test]
  fn delegation_mandate_id_defaults_to_none_when_omitted() {
    // One-shot AskEveryTime mandates have no parent delegation, so the id
    // must be omissible — otherwise the human-present flow could not
    // produce a parseable mandate at all.
    let json = r#"{
      "id": "urn:uuid:2",
      "humanPrincipalDid": "did:key:h",
      "agentDid": "did:web:a",
      "channelKind": "slack",
      "recipientAddressing": {"userId": "U1"},
      "contentClass": "DM",
      "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "bodySize": 12,
      "policyDecision": "AskEveryTime",
      "issuedAt": "2026-05-21T00:00:00Z",
      "expiresAt": "2026-05-21T01:00:00Z",
      "notarySignature": "zsig"
    }"#;
    let m: super::CommunicationMandate = serde_json::from_str(json).unwrap();
    std::assert_eq!(m.delegation_mandate_id, std::option::Option::None);
  }

  #[test]
  fn body_sha256_is_64_hex_chars() {
    // Pins the hash encoding the spec requires (64 lowercase hex, §7.1.6).
    // A different encoding — uppercase, base64, or a "sha256:" prefix —
    // would silently fail every recipient's body-hash comparison.
    let m = sample();
    std::assert_eq!(
      m.body_sha256.len(),
      64,
      "SHA-256 hex must be exactly 64 chars"
    );
    std::assert!(
      m.body_sha256.chars().all(|c| c.is_ascii_hexdigit()),
      "body_sha256 must be lowercase hex"
    );
    std::assert!(
      m.body_sha256.chars().all(|c| !c.is_ascii_uppercase()),
      "body_sha256 must be lowercase"
    );
  }

  #[test]
  fn deny_unknown_fields_rejects_extra_key() {
    // Strict parsing must reject unknown keys rather than dropping them,
    // so a mandate cannot carry a restriction the verifier never sees.
    let json = r#"{
      "id": "urn:uuid:2",
      "humanPrincipalDid": "did:key:h",
      "agentDid": "did:web:a",
      "channelKind": "slack",
      "recipientAddressing": {"userId": "U1"},
      "contentClass": "DM",
      "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "bodySize": 12,
      "policyDecision": "AskEveryTime",
      "issuedAt": "2026-05-21T00:00:00Z",
      "expiresAt": "2026-05-21T01:00:00Z",
      "notarySignature": "zsig",
      "extraneousField": "should-fail"
    }"#;
    let result: std::result::Result<super::CommunicationMandate, _> = serde_json::from_str(json);
    std::assert!(
      result.is_err(),
      "deny_unknown_fields must reject unknown keys"
    );
  }

  #[test]
  fn recipient_addressing_carries_channel_shaped_json() {
    // recipientAddressing is deliberately opaque (§7.4) so new channels
    // need no type changes; this pins that arbitrary channel-shaped JSON
    // survives intact and stays reachable, rather than being flattened.
    let m = sample();
    let team_id = m
      .recipient_addressing
      .get("teamId")
      .and_then(|v| v.as_str())
      .unwrap_or("");
    std::assert_eq!(team_id, "T01234567");
  }
}
