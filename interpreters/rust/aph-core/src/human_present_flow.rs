//! Human-present notarization flow state machine.
//!
//! Models the path when a human is present at the device to make an
//! AskEveryTime decision. 7 states.
//!
//! State diagram:
//! ```text
//! Drafted -> PendingDecision -> Approved -> MandateIssued
//!                            -> Denied (terminal)
//! Approved -> MandateIssued -> EnvelopeIssued -> Delivered (terminal)
//! ```

/// State in the APH human-present notarization flow.
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
pub enum HumanPresentNotarizationState {
  /// Agent has drafted a message and requested notarization.
  Drafted,
  /// Notary has shown the approval modal to the human.
  PendingDecision,
  /// Human approved (AlwaysAllow scope match OR AskEveryTime accept).
  Approved,
  /// Notary issued the `CommunicationMandate`.
  MandateIssued,
  /// Notary signed and emitted the `NotarizationEnvelope`.
  EnvelopeIssued,
  /// Terminal: envelope delivered to channel adapter.
  Delivered,
  /// Terminal: human denied or NeverAllow scope match.
  Denied,
}

impl HumanPresentNotarizationState {
  /// Returns `true` if this state is terminal (no further transitions).
  pub fn is_terminal(&self) -> bool {
    matches!(self, Self::Delivered | Self::Denied)
  }

  /// Returns the set of states this state may transition to.
  pub fn valid_transitions(&self) -> &'static [Self] {
    match self {
      Self::Drafted => &[Self::PendingDecision],
      Self::PendingDecision => &[Self::Approved, Self::Denied],
      Self::Approved => &[Self::MandateIssued],
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

/// A human-present APH notarization flow wrapping state + mandate references.
#[derive(std::fmt::Debug, std::clone::Clone, std::cmp::PartialEq, std::cmp::Eq, serde::Serialize, serde::Deserialize)]
pub struct HumanPresentNotarizationFlow {
  state: HumanPresentNotarizationState,
  communication_mandate_id: String,
  envelope_id: std::option::Option<String>,
}

impl HumanPresentNotarizationFlow {
  /// Constructs a new flow in the `Drafted` state bound to the given
  /// `CommunicationMandate.id`.
  pub fn new(communication_mandate_id: impl std::convert::Into<String>) -> Self {
    Self {
      state: HumanPresentNotarizationState::Drafted,
      communication_mandate_id: communication_mandate_id.into(),
      envelope_id: std::option::Option::None,
    }
  }

  /// Current state of the flow.
  pub fn state(&self) -> HumanPresentNotarizationState {
    self.state
  }

  /// Bound `CommunicationMandate.id`.
  pub fn communication_mandate_id(&self) -> &str {
    &self.communication_mandate_id
  }

  /// Optionally-bound `NotarizationEnvelope.id` (set after `MandateIssued`).
  pub fn envelope_id(&self) -> std::option::Option<&str> {
    self.envelope_id.as_deref()
  }

  /// Binds the envelope identifier to this flow.
  pub fn set_envelope_id(&mut self, id: impl std::convert::Into<String>) {
    self.envelope_id = std::option::Option::Some(id.into());
  }

  /// Attempts to transition to `next`. Returns `APH_E002` on illegal
  /// transitions; leaves `self.state` unchanged on error.
  pub fn transition_to(
    &mut self,
    next: HumanPresentNotarizationState,
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
    // Delivered and Denied are the only absorbing states (spec §9.1). A
    // non-terminal Denied would let a refused request be resurrected into
    // an approval; a terminal Drafted would strand every new request.
    std::assert!(super::HumanPresentNotarizationState::Delivered.is_terminal());
    std::assert!(super::HumanPresentNotarizationState::Denied.is_terminal());
    std::assert!(!super::HumanPresentNotarizationState::Drafted.is_terminal());
    std::assert!(!super::HumanPresentNotarizationState::PendingDecision.is_terminal());
    std::assert!(!super::HumanPresentNotarizationState::Approved.is_terminal());
    std::assert!(!super::HumanPresentNotarizationState::MandateIssued.is_terminal());
    std::assert!(!super::HumanPresentNotarizationState::EnvelopeIssued.is_terminal());
  }

  #[test]
  fn full_transition_walk_approved_path() {
    // Walks the entire happy path Drafted → … → Delivered in one test, so
    // the states are proven reachable IN ORDER — pairwise checks could all
    // pass while the end-to-end path is broken.
    let mut flow = super::HumanPresentNotarizationFlow::new("cm-1");
    std::assert_eq!(flow.state(), super::HumanPresentNotarizationState::Drafted);

    flow
      .transition_to(super::HumanPresentNotarizationState::PendingDecision)
      .unwrap();
    flow
      .transition_to(super::HumanPresentNotarizationState::Approved)
      .unwrap();
    flow
      .transition_to(super::HumanPresentNotarizationState::MandateIssued)
      .unwrap();
    flow
      .transition_to(super::HumanPresentNotarizationState::EnvelopeIssued)
      .unwrap();
    flow
      .transition_to(super::HumanPresentNotarizationState::Delivered)
      .unwrap();

    std::assert_eq!(
      flow.state(),
      super::HumanPresentNotarizationState::Delivered
    );
    std::assert!(flow.state().is_terminal());
    std::assert_eq!(flow.communication_mandate_id(), "cm-1");
  }

  #[test]
  fn denial_path() {
    // The branch that encodes a human saying no. If PendingDecision could
    // not reach Denied, a refusal would have nowhere to land — the single
    // most important outcome for a consent protocol to represent.
    let mut flow = super::HumanPresentNotarizationFlow::new("cm-deny");
    flow
      .transition_to(super::HumanPresentNotarizationState::PendingDecision)
      .unwrap();
    flow
      .transition_to(super::HumanPresentNotarizationState::Denied)
      .unwrap();

    std::assert_eq!(flow.state(), super::HumanPresentNotarizationState::Denied);
    std::assert!(flow.state().is_terminal());
  }

  #[test]
  fn terminal_no_transitions() {
    // Terminality must be enforced by the transition table itself, not
    // just reported by is_terminal() — an outgoing edge from a terminal
    // state would make the flag a lie.
    std::assert!(
      super::HumanPresentNotarizationState::Delivered
        .valid_transitions()
        .is_empty()
    );
    std::assert!(
      super::HumanPresentNotarizationState::Denied
        .valid_transitions()
        .is_empty()
    );
  }

  #[test]
  fn invalid_transition_returns_error() {
    // An illegal move must return APH_E002 and leave the flow unchanged,
    // never panic or half-apply — the state machine is fed by remote input.
    let mut flow = super::HumanPresentNotarizationFlow::new("cm-bad");
    let err = flow
      .transition_to(super::HumanPresentNotarizationState::Delivered)
      .unwrap_err();
    std::assert_eq!(err.code(), "APH_E002");
  }

  #[test]
  fn skip_state_rejected() {
    // The security core of the human-present flow: jumping Drafted →
    // MandateIssued would mint authority WITHOUT passing through
    // PendingDecision — i.e. without the human ever approving.
    let mut flow = super::HumanPresentNotarizationFlow::new("cm-skip");
    let err = flow
      .transition_to(super::HumanPresentNotarizationState::MandateIssued)
      .unwrap_err();
    std::assert_eq!(err.code(), "APH_E002");
    std::assert_eq!(flow.state(), super::HumanPresentNotarizationState::Drafted);
  }

  #[test]
  fn backward_transition_rejected() {
    // The flow is one-way. Rewinding would allow re-deciding an already
    // decided request — a replay path around the human's answer.
    let mut flow = super::HumanPresentNotarizationFlow::new("cm-back");
    flow
      .transition_to(super::HumanPresentNotarizationState::PendingDecision)
      .unwrap();
    flow
      .transition_to(super::HumanPresentNotarizationState::Approved)
      .unwrap();
    flow
      .transition_to(super::HumanPresentNotarizationState::MandateIssued)
      .unwrap();
    let err = flow
      .transition_to(super::HumanPresentNotarizationState::Drafted)
      .unwrap_err();
    std::assert_eq!(err.code(), "APH_E002");
    std::assert_eq!(
      flow.state(),
      super::HumanPresentNotarizationState::MandateIssued
    );
  }

  #[test]
  fn set_envelope_id_works() {
    // The envelope id starts unset and is bound once the envelope is
    // issued; this link is what ties a completed flow to the credential it
    // produced for later audit.
    let mut flow = super::HumanPresentNotarizationFlow::new("cm-env");
    std::assert!(flow.envelope_id().is_none());
    flow.set_envelope_id("env-42");
    std::assert_eq!(flow.envelope_id(), std::option::Option::Some("env-42"));
  }

  #[test]
  fn state_serde_roundtrip() {
    // Flow state is persisted across process restarts (a human may take
    // minutes to answer), so a state that failed to round-trip would
    // orphan an in-flight consent request.
    let variants = [
      super::HumanPresentNotarizationState::Drafted,
      super::HumanPresentNotarizationState::PendingDecision,
      super::HumanPresentNotarizationState::Approved,
      super::HumanPresentNotarizationState::MandateIssued,
      super::HumanPresentNotarizationState::EnvelopeIssued,
      super::HumanPresentNotarizationState::Delivered,
      super::HumanPresentNotarizationState::Denied,
    ];
    for v in &variants {
      let json = serde_json::to_string(v).unwrap();
      let back: super::HumanPresentNotarizationState = serde_json::from_str(&json).unwrap();
      std::assert_eq!(*v, back, "round-trip mismatch for {:?}", v);
    }
  }
}
