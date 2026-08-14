//! DelegationMandate — human → agent ongoing authorization to send on
//! specific channels under bounded scope. Issued ONCE; referenced by N
//! `CommunicationMandate`s.

/// Standing authority a human grants an agent: which channels, for how
/// long, at what rate.
///
/// Carries TWO signatures (spec §6.1). `principalSignature` is the human's
/// own — the actual grant of authority, and the root of every credential
/// issued under this mandate. `notarySignature` is the notary's
/// countersignature over what the principal signed. The order matters when
/// verifying: a countersignature over an unverifiable grant proves nothing,
/// so `principalSignature` is checked FIRST.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationMandate {
  /// `urn:uuid:...` mandate identifier.
  pub id: String,
  /// DID of the human principal granting authority.
  pub human_principal_did: String,
  /// DID of the agent receiving authority.
  pub agent_did: String,
  /// Channel kinds permitted under this mandate (e.g., `["slack", "email"]`).
  pub allowed_channels: Vec<String>,
  /// Per-channel max-send rate (per hour). `None` = unlimited.
  #[serde(default)]
  pub rate_limit_per_hour: std::option::Option<u32>,
  /// RFC 3339 "valid from" timestamp.
  pub valid_from: String,
  /// RFC 3339 "valid until" timestamp.
  pub valid_until: String,
  /// Multibase signature by the PRINCIPAL's OWN key over the canonical JCS
  /// form of this struct MINUS BOTH signature fields (§6.1, §7.2.1).
  ///
  /// REQUIRED, not optional: this is the human's actual grant of authority.
  /// Were it omissible, a notary could mint a standing delegation the human
  /// never signed and every envelope issued under it would trace back to
  /// nothing but the notary's own assertion.
  pub principal_signature: String,
  /// Notary service signature over the canonical JCS form of this struct
  /// MINUS the `notary_signature` field, with `principal_signature` PRESENT
  /// (deterministic dehydration). The notary countersigns what the principal
  /// signed.
  pub notary_signature: String,
}

impl DelegationMandate {
  /// Returns `true` if `now` falls within `[valid_from, valid_until]`.
  /// Caller passes RFC 3339 string; parsing failure returns `false`.
  pub fn is_valid_at(&self, now_rfc3339: &str) -> bool {
    let now = chrono::DateTime::parse_from_rfc3339(now_rfc3339);
    let from = chrono::DateTime::parse_from_rfc3339(&self.valid_from);
    let until = chrono::DateTime::parse_from_rfc3339(&self.valid_until);
    match (now, from, until) {
      (std::result::Result::Ok(n), std::result::Result::Ok(f), std::result::Result::Ok(u)) => {
        n >= f && n <= u
      }
      _ => false,
    }
  }

  /// Returns `true` if `channel_kind` is in `allowed_channels`.
  pub fn allows_channel(&self, channel_kind: &str) -> bool {
    self.allowed_channels.iter().any(|c| c == channel_kind)
  }
}

#[cfg(test)]
mod tests {
  fn sample() -> super::DelegationMandate {
    super::DelegationMandate {
      id: String::from("urn:uuid:00000000-0000-4000-8000-000000000001"),
      human_principal_did: String::from("did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy"),
      agent_did: String::from("did:web:agent.squillo.com"),
      allowed_channels: std::vec![String::from("slack"), String::from("email")],
      rate_limit_per_hour: std::option::Option::Some(60),
      valid_from: String::from("2026-05-21T00:00:00Z"),
      valid_until: String::from("2026-05-22T00:00:00Z"),
      principal_signature: String::from("z-illustrative-principal-signature"),
      notary_signature: String::from("z3WgvA9JHkbV3qLZHcM4FxBp4xHfQVnVnPKKDdyazQwQGdGzxsRdmZW"),
    }
  }

  #[test]
  fn serde_round_trip_preserves_equality() {
    // A DelegationMandate is signed and persisted, then reloaded to
    // authorize later sends; if a field were lost in the round trip the
    // reloaded mandate would authorize a different scope than the human
    // approved.
    let m = sample();
    let json = serde_json::to_string(&m).unwrap();
    let back: super::DelegationMandate = serde_json::from_str(&json).unwrap();
    std::assert_eq!(m, back);
  }

  #[test]
  fn serde_uses_camel_case_field_names() {
    // The spec (§6.1) fixes these camelCase names, and notarySignature
    // covers the canonical form built from them — a rename would both
    // break cross-implementation parsing and invalidate signatures.
    let m = sample();
    let json = serde_json::to_string(&m).unwrap();
    std::assert!(json.contains("\"humanPrincipalDid\""));
    std::assert!(json.contains("\"agentDid\""));
    std::assert!(json.contains("\"allowedChannels\""));
    std::assert!(json.contains("\"rateLimitPerHour\""));
    std::assert!(json.contains("\"validFrom\""));
    std::assert!(json.contains("\"validUntil\""));
    std::assert!(json.contains("\"principalSignature\""));
    std::assert!(json.contains("\"notarySignature\""));
  }

  #[test]
  fn principal_signature_is_required_on_the_wire() {
    // §6.1 makes principalSignature REQUIRED — it is the human's grant of
    // authority. A mandate that parsed without it would be a standing
    // delegation resting on the notary's word alone, which is exactly the
    // trust gap the 2026-08-13 revision closes. Optionality here would make
    // the strong shape unenforceable, because every producer could skip it.
    let json = r#"{
      "id": "urn:uuid:1",
      "humanPrincipalDid": "did:key:h",
      "agentDid": "did:web:a",
      "allowedChannels": ["slack"],
      "validFrom": "2026-05-21T00:00:00Z",
      "validUntil": "2026-05-22T00:00:00Z",
      "notarySignature": "zsig"
    }"#;
    let result: std::result::Result<super::DelegationMandate, _> = serde_json::from_str(json);
    std::assert!(
      result.is_err(),
      "a mandate missing principalSignature must be rejected"
    );
  }

  #[test]
  fn rate_limit_per_hour_defaults_to_none_when_omitted() {
    // rateLimitPerHour is optional in §6.1, so an issuer that never sets a
    // rate limit must still produce a parseable mandate — under
    // deny_unknown_fields a missing #[serde(default)] would reject it.
    let json = r#"{
      "id": "urn:uuid:1",
      "humanPrincipalDid": "did:key:h",
      "agentDid": "did:web:a",
      "allowedChannels": ["slack"],
      "validFrom": "2026-05-21T00:00:00Z",
      "validUntil": "2026-05-22T00:00:00Z",
      "principalSignature": "zprincipal",
      "notarySignature": "zsig"
    }"#;
    let m: super::DelegationMandate = serde_json::from_str(json).unwrap();
    std::assert_eq!(m.rate_limit_per_hour, std::option::Option::None);
  }

  #[test]
  fn is_valid_at_returns_true_inside_window() {
    // Positive control for the validity gate: if this failed closed, every
    // legitimately delegated send would be refused.
    let m = sample();
    std::assert!(m.is_valid_at("2026-05-21T12:00:00Z"));
  }

  #[test]
  fn is_valid_at_returns_false_before_window() {
    // A mandate must not authorize sends before it starts — the guard
    // against post-dating a delegation to cover earlier activity.
    let m = sample();
    std::assert!(!m.is_valid_at("2026-05-20T23:59:59Z"));
  }

  #[test]
  fn is_valid_at_returns_false_after_window() {
    // Expiry is the primary revocation mechanism in v0.1 (on-wire
    // revocation is deferred to v0.2), so an expired mandate that still
    // validated would leave a human with no way to withdraw authority.
    let m = sample();
    std::assert!(!m.is_valid_at("2026-05-22T00:00:01Z"));
  }

  #[test]
  fn is_valid_at_returns_false_on_unparseable_input() {
    // Fail closed on garbage timestamps: an unparseable "now" must deny,
    // never default to valid, and must not panic on hostile input.
    let m = sample();
    std::assert!(!m.is_valid_at("not-a-timestamp"));
  }

  #[test]
  fn allows_channel_positive() {
    // Every listed channel must be honored, including entries after the
    // first — a scope check that only ever matched allowed_channels[0]
    // would silently narrow what the human authorized.
    let m = sample();
    std::assert!(m.allows_channel("slack"));
    std::assert!(m.allows_channel("email"));
  }

  #[test]
  fn allows_channel_negative() {
    // The containment check that produces APH_E005: an unlisted channel —
    // and the empty string, the classic accidental-match case — must be
    // refused, or an agent could send anywhere under a narrow delegation.
    let m = sample();
    std::assert!(!m.allows_channel("discord"));
    std::assert!(!m.allows_channel(""));
  }

  #[test]
  fn deny_unknown_fields_rejects_extra_key() {
    // Strict parsing is a security property here: an unknown key must be a
    // hard error, not silently dropped, so a mandate cannot carry a
    // condition the verifier ignores while the signer believed it applied.
    let json = r#"{
      "id": "urn:uuid:1",
      "humanPrincipalDid": "did:key:h",
      "agentDid": "did:web:a",
      "allowedChannels": ["slack"],
      "validFrom": "2026-05-21T00:00:00Z",
      "validUntil": "2026-05-22T00:00:00Z",
      "principalSignature": "zprincipal",
      "notarySignature": "zsig",
      "extraneousField": "should-fail"
    }"#;
    let result: std::result::Result<super::DelegationMandate, _> = serde_json::from_str(json);
    std::assert!(
      result.is_err(),
      "deny_unknown_fields must reject unknown keys"
    );
  }
}
