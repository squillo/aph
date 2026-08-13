//! Human-not-present notarization flow state machine.
//!
//! Models the path when the human has issued a standing
//! `DelegationMandate` and is NOT at the device. 5 states. The notary
//! auto-decides against the standing mandate's scope.
//!
//! State diagram:
//! ```text
//! Drafted -> MandateIssued -> EnvelopeIssued -> Delivered (terminal)
//!         -> Denied (terminal)
//! ```

/// State in the APH human-not-present notarization flow.
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
pub enum HumanNotPresentNotarizationState {
  /// Agent drafted; notary will auto-decide against the standing mandate.
  Drafted,
  /// Notary issued the `CommunicationMandate` against `DelegationMandate`.
  MandateIssued,
  /// Notary signed and emitted the envelope.
  EnvelopeIssued,
  /// Terminal: delivered to channel.
  Delivered,
  /// Terminal: standing mandate denied (scope mismatch, expired, NeverAllow).
  Denied,
}

impl HumanNotPresentNotarizationState {
  /// Returns `true` if this state is terminal (no further transitions).
  pub fn is_terminal(&self) -> bool {
    matches!(self, Self::Delivered | Self::Denied)
  }

  /// Returns the set of states this state may transition to.
  pub fn valid_transitions(&self) -> &'static [Self] {
    match self {
      Self::Drafted => &[Self::MandateIssued, Self::Denied],
      Self::MandateIssued => &[Self::EnvelopeIssued],
      Self::EnvelopeIssued => &[Self::Delivered],
      Self::Delivered => &[],
      Self::Denied => &[],
    }
  }

  /// Returns `true` if `next` is a legal successor of `self`.
  pub fn can_transition_to(&self, next: Self) -> bool {
    self.valid_transitions().contains(&next)
  }
}

/// A human-not-present APH notarization flow wrapping state + mandate
/// references.
#[derive(std::fmt::Debug, std::clone::Clone, std::cmp::PartialEq, std::cmp::Eq, serde::Serialize, serde::Deserialize)]
pub struct HumanNotPresentNotarizationFlow {
  state: HumanNotPresentNotarizationState,
  delegation_mandate_id: String,
  communication_mandate_id: std::option::Option<String>,
  envelope_id: std::option::Option<String>,
}

impl HumanNotPresentNotarizationFlow {
  /// Constructs a new flow in the `Drafted` state bound to the given
  /// `DelegationMandate.id`.
  pub fn new(delegation_mandate_id: impl std::convert::Into<String>) -> Self {
    Self {
      state: HumanNotPresentNotarizationState::Drafted,
      delegation_mandate_id: delegation_mandate_id.into(),
      communication_mandate_id: std::option::Option::None,
      envelope_id: std::option::Option::None,
    }
  }

  /// Current state of the flow.
  pub fn state(&self) -> HumanNotPresentNotarizationState {
    self.state
  }

  /// Bound `DelegationMandate.id`.
  pub fn delegation_mandate_id(&self) -> &str {
    &self.delegation_mandate_id
  }

  /// Optionally-bound `CommunicationMandate.id` (set after `MandateIssued`).
  pub fn communication_mandate_id(&self) -> std::option::Option<&str> {
    self.communication_mandate_id.as_deref()
  }

  /// Optionally-bound `NotarizationEnvelope.id` (set after `EnvelopeIssued`).
  pub fn envelope_id(&self) -> std::option::Option<&str> {
    self.envelope_id.as_deref()
  }

  /// Binds the per-message communication-mandate identifier.
  pub fn set_communication_mandate_id(&mut self, id: impl std::convert::Into<String>) {
    self.communication_mandate_id = std::option::Option::Some(id.into());
  }

  /// Binds the envelope identifier.
  pub fn set_envelope_id(&mut self, id: impl std::convert::Into<String>) {
    self.envelope_id = std::option::Option::Some(id.into());
  }

  /// Attempts to transition to `next`. Returns `APH_E002` on illegal
  /// transitions; leaves `self.state` unchanged on error.
  pub fn transition_to(
    &mut self,
    next: HumanNotPresentNotarizationState,
  ) -> std::result::Result<(), super::errors::AphError> {
    if self.state.can_transition_to(next) {
      self.state = next;
      std::result::Result::Ok(())
    } else {
      std::result::Result::Err(super::errors::AphError::invalid_flow_transition(
        format!("{:?}", self.state),
        format!("{:?}", next),
      ))
    }
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn terminal_states() {
    // Same absorbing-state rule as the human-present flow (spec §9.2),
    // pinned separately because this machine has its own 5-state table
    // that could drift from its sibling.
    std::assert!(super::HumanNotPresentNotarizationState::Delivered.is_terminal());
    std::assert!(super::HumanNotPresentNotarizationState::Denied.is_terminal());
    std::assert!(!super::HumanNotPresentNotarizationState::Drafted.is_terminal());
    std::assert!(!super::HumanNotPresentNotarizationState::MandateIssued.is_terminal());
    std::assert!(!super::HumanNotPresentNotarizationState::EnvelopeIssued.is_terminal());
  }

  #[test]
  fn full_transition_walk_delivered_path() {
    // The standing-delegation path: no PendingDecision state, because
    // authority was granted in advance. Walking it end to end pins that
    // the shorter machine still reaches Delivered.
    let mut flow = super::HumanNotPresentNotarizationFlow::new("dm-1");
    std::assert_eq!(
      flow.state(),
      super::HumanNotPresentNotarizationState::Drafted
    );
    std::assert_eq!(flow.delegation_mandate_id(), "dm-1");

    flow
      .transition_to(super::HumanNotPresentNotarizationState::MandateIssued)
      .unwrap();
    flow
      .transition_to(super::HumanNotPresentNotarizationState::EnvelopeIssued)
      .unwrap();
    flow
      .transition_to(super::HumanNotPresentNotarizationState::Delivered)
      .unwrap();

    std::assert_eq!(
      flow.state(),
      super::HumanNotPresentNotarizationState::Delivered
    );
    std::assert!(flow.state().is_terminal());
  }

  #[test]
  fn denial_path() {
    // Even with the human absent, the notary must be able to refuse
    // (expired or out-of-scope delegation) — so Drafted → Denied has to
    // exist without any human interaction.
    let mut flow = super::HumanNotPresentNotarizationFlow::new("dm-deny");
    flow
      .transition_to(super::HumanNotPresentNotarizationState::Denied)
      .unwrap();
    std::assert_eq!(
      flow.state(),
      super::HumanNotPresentNotarizationState::Denied
    );
    std::assert!(flow.state().is_terminal());
  }

  #[test]
  fn terminal_no_transitions() {
    // Terminality enforced by the table, not merely reported by the flag.
    std::assert!(
      super::HumanNotPresentNotarizationState::Delivered
        .valid_transitions()
        .is_empty()
    );
    std::assert!(
      super::HumanNotPresentNotarizationState::Denied
        .valid_transitions()
        .is_empty()
    );
  }

  #[test]
  fn invalid_transition_returns_error() {
    // Illegal moves must fail with APH_E002 and leave state untouched.
    // With no human in the loop, this table IS the only gate on how an
    // unattended notarization may proceed.
    let mut flow = super::HumanNotPresentNotarizationFlow::new("dm-bad");
    let err = flow
      .transition_to(super::HumanNotPresentNotarizationState::EnvelopeIssued)
      .unwrap_err();
    std::assert_eq!(err.code(), "APH_E002");
    std::assert_eq!(
      flow.state(),
      super::HumanNotPresentNotarizationState::Drafted
    );
  }

  #[test]
  fn set_communication_mandate_id_works() {
    // Binds the per-message mandate to the flow once issued; without it an
    // audit could not tie the delivered message to the authority used.
    let mut flow = super::HumanNotPresentNotarizationFlow::new("dm-cm");
    std::assert!(flow.communication_mandate_id().is_none());
    flow.set_communication_mandate_id("cm-7");
    std::assert_eq!(
      flow.communication_mandate_id(),
      std::option::Option::Some("cm-7")
    );
  }

  #[test]
  fn set_envelope_id_works() {
    // Completes the audit chain delegation → mandate → envelope; the id
    // starts unset and must be bindable exactly once the envelope exists.
    let mut flow = super::HumanNotPresentNotarizationFlow::new("dm-env");
    std::assert!(flow.envelope_id().is_none());
    flow.set_envelope_id("env-9");
    std::assert_eq!(flow.envelope_id(), std::option::Option::Some("env-9"));
  }

  #[test]
  fn state_serde_roundtrip() {
    // Unattended flows are persisted and resumed by background workers, so
    // a state that failed to round-trip would lose in-flight sends.
    let variants = [
      super::HumanNotPresentNotarizationState::Drafted,
      super::HumanNotPresentNotarizationState::MandateIssued,
      super::HumanNotPresentNotarizationState::EnvelopeIssued,
      super::HumanNotPresentNotarizationState::Delivered,
      super::HumanNotPresentNotarizationState::Denied,
    ];
    for v in &variants {
      let json = serde_json::to_string(v).unwrap();
      let back: super::HumanNotPresentNotarizationState = serde_json::from_str(&json).unwrap();
      std::assert_eq!(*v, back, "round-trip mismatch for {:?}", v);
    }
  }
}
