//! APH party roles + permitted operations.
//!
//! 5 roles: HumanPrincipal, AgentSender, NotaryService, ChannelAdapter,
//! RecipientEndpoint.

/// One of the five APH protocol roles.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::marker::Copy,
  std::cmp::PartialEq,
  std::cmp::Eq,
  std::hash::Hash,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum AphPartyRole {
  /// The natural person on whose behalf an outbound communication is sent.
  HumanPrincipal,
  /// The agent (LLM-backed software) drafting the message.
  AgentSender,
  /// The notary service issuing the verifiable credential.
  NotaryService,
  /// The channel adapter (Slack/Email/Discord/...) transporting the message.
  ChannelAdapter,
  /// The far-end recipient endpoint verifying the credential.
  RecipientEndpoint,
}

/// An APH operation that a role may perform.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::marker::Copy,
  std::cmp::PartialEq,
  std::cmp::Eq,
  std::hash::Hash,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum AphOperation {
  /// Issue a `DelegationMandate` granting an agent ongoing authority.
  IssueDelegationMandate,
  /// Issue a `CommunicationMandate` for a single outbound message.
  IssueCommunicationMandate,
  /// Sign + emit a `NotarizationEnvelope`.
  Notarize,
  /// Carry an envelope across a transport channel.
  Transport,
  /// Verify an inbound envelope's signature + policy.
  Verify,
  /// Reject an envelope per local policy.
  Reject,
}

impl AphPartyRole {
  /// Returns the operations this role is allowed to perform.
  pub fn allowed_operations(&self) -> &'static [AphOperation] {
    match self {
      Self::HumanPrincipal => &[
        AphOperation::IssueDelegationMandate,
        AphOperation::IssueCommunicationMandate,
      ],
      Self::AgentSender => &[AphOperation::IssueCommunicationMandate],
      Self::NotaryService => &[AphOperation::Notarize, AphOperation::Reject],
      Self::ChannelAdapter => &[AphOperation::Transport],
      Self::RecipientEndpoint => &[AphOperation::Verify],
    }
  }

  /// Returns `true` if this role is permitted to perform `op`.
  pub fn can_perform(&self, op: AphOperation) -> bool {
    self.allowed_operations().contains(&op)
  }

  /// All role variants for iteration.
  pub fn all() -> &'static [AphPartyRole] {
    &[
      Self::HumanPrincipal,
      Self::AgentSender,
      Self::NotaryService,
      Self::ChannelAdapter,
      Self::RecipientEndpoint,
    ]
  }

  /// Human-readable label for this role.
  pub fn label(&self) -> &'static str {
    match self {
      Self::HumanPrincipal => "Human Principal",
      Self::AgentSender => "Agent Sender",
      Self::NotaryService => "Notary Service",
      Self::ChannelAdapter => "Channel Adapter",
      Self::RecipientEndpoint => "Recipient Endpoint",
    }
  }
}

impl AphOperation {
  /// All operation variants for iteration.
  pub fn all() -> &'static [AphOperation] {
    &[
      Self::IssueDelegationMandate,
      Self::IssueCommunicationMandate,
      Self::Notarize,
      Self::Transport,
      Self::Verify,
      Self::Reject,
    ]
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn role_serde_roundtrip_all_variants() {
    // Iterates all() rather than a fixed list so a newly added role is
    // covered automatically — a variant that serialized but failed to
    // deserialize would break any persisted or transmitted role.
    for role in super::AphPartyRole::all() {
      let json = serde_json::to_string(role).unwrap();
      let back: super::AphPartyRole = serde_json::from_str(&json).unwrap();
      std::assert_eq!(*role, back);
    }
  }

  #[test]
  fn operation_serde_roundtrip_all_variants() {
    // Same exhaustive sweep for operations: these name the actions a role
    // is permitted to take, so an unparseable variant would strand an
    // audit record no one can interpret.
    for op in super::AphOperation::all() {
      let json = serde_json::to_string(op).unwrap();
      let back: super::AphOperation = serde_json::from_str(&json).unwrap();
      std::assert_eq!(*op, back);
    }
  }

  #[test]
  fn role_serde_uses_camel_case() {
    // Pins the exact wire spelling (spec §5.1), checking both a two-word
    // and a longest-name variant since rename_all is where casing bugs
    // show up first. Other implementations match on these strings.
    let json = serde_json::to_string(&super::AphPartyRole::HumanPrincipal).unwrap();
    std::assert_eq!(json, "\"humanPrincipal\"");
    let json = serde_json::to_string(&super::AphPartyRole::RecipientEndpoint).unwrap();
    std::assert_eq!(json, "\"recipientEndpoint\"");
  }

  #[test]
  fn operation_serde_uses_camel_case() {
    // Same casing pin for operations (spec §5.2), covering both a
    // multi-word and a single-word variant.
    let json = serde_json::to_string(&super::AphOperation::IssueDelegationMandate).unwrap();
    std::assert_eq!(json, "\"issueDelegationMandate\"");
    let json = serde_json::to_string(&super::AphOperation::Notarize).unwrap();
    std::assert_eq!(json, "\"notarize\"");
  }

  #[test]
  fn every_operation_assigned_to_at_least_one_role() {
    // Completeness guard on the permission matrix: an operation no role
    // can perform is dead protocol surface — either the matrix has a gap
    // or the operation should not exist.
    for op in super::AphOperation::all() {
      let assigned = super::AphPartyRole::all()
        .iter()
        .any(|r| r.can_perform(*op));
      std::assert!(assigned, "{:?} is not assigned to any role", op);
    }
  }

  #[test]
  fn human_principal_can_issue_mandates() {
    // Separation of duties: the human issues authority but must NOT be
    // able to notarize. Collapsing those would let the authorizing party
    // also vouch for itself, destroying third-party verifiability.
    let role = super::AphPartyRole::HumanPrincipal;
    std::assert!(role.can_perform(super::AphOperation::IssueDelegationMandate));
    std::assert!(role.can_perform(super::AphOperation::IssueCommunicationMandate));
    std::assert!(!role.can_perform(super::AphOperation::Notarize));
    std::assert!(!role.can_perform(super::AphOperation::Transport));
  }

  #[test]
  fn notary_service_can_notarize_and_reject_only() {
    // The other half of separation of duties: a notary attests decisions
    // but must not issue mandates, or it could manufacture the very
    // authority it then certifies.
    let role = super::AphPartyRole::NotaryService;
    std::assert!(role.can_perform(super::AphOperation::Notarize));
    std::assert!(role.can_perform(super::AphOperation::Reject));
    std::assert!(!role.can_perform(super::AphOperation::IssueDelegationMandate));
    std::assert!(!role.can_perform(super::AphOperation::Transport));
    std::assert!(!role.can_perform(super::AphOperation::Verify));
  }

  #[test]
  fn channel_adapter_can_only_transport() {
    // The adapter is deliberately the least-privileged role: it moves
    // bytes and nothing else. Granting it Notarize or Verify would let the
    // delivery layer certify or accept its own traffic.
    let role = super::AphPartyRole::ChannelAdapter;
    std::assert!(role.can_perform(super::AphOperation::Transport));
    std::assert!(!role.can_perform(super::AphOperation::Notarize));
    std::assert!(!role.can_perform(super::AphOperation::Verify));
    std::assert!(!role.can_perform(super::AphOperation::IssueCommunicationMandate));
  }

  #[test]
  fn label_non_empty_for_all_roles() {
    // Labels surface in consent prompts and audit logs; an empty one would
    // render a blank role in a UI where the human is deciding whether to
    // authorize an action.
    for role in super::AphPartyRole::all() {
      std::assert!(!role.label().is_empty(), "{:?} has empty label", role);
    }
  }

  #[test]
  fn all_returns_expected_counts() {
    // all() is hand-maintained, so a variant added to either enum without
    // being appended here would silently vanish from every exhaustive
    // sweep above. The counts (5 roles, 6 operations) are spec-fixed.
    std::assert_eq!(super::AphPartyRole::all().len(), 5);
    std::assert_eq!(super::AphOperation::all().len(), 6);
  }
}
