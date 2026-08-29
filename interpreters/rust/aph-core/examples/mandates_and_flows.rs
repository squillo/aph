//! Mandates and the two notarization flows.
//!
//! Run with: `cargo run -p aph-core --example mandates_and_flows`
//!
//! A mandate is the authority; a flow is how a single notarization moves
//! from draft to delivered. Which flow applies depends on whether the human
//! is present to decide, or whether they granted standing authority earlier.

fn main() {
  // ── Standing authority ────────────────────────────────────────────────
  // Alice grants her agent 24 hours to send on Slack and email, capped at
  // 12 sends per hour.
  let mandate = aph_core::DelegationMandate {
    id: String::from("urn:uuid:00000000-0000-4000-8000-0000000000a1"),
    human_principal_did: String::from("did:key:zAlice"),
    agent_did: String::from("did:web:agent.example"),
    allowed_channels: vec![aph_core::ChannelKind::Slack, aph_core::ChannelKind::Email],
    allowed_recipient_classes: std::option::Option::None,
    rate_limit_per_hour: Some(12),
    valid_from: String::from("2026-05-21T00:00:00Z"),
    valid_until: String::from("2026-05-22T00:00:00Z"),
    // Two signatures, and the order matters (spec §6.1). The PRINCIPAL's is
    // the actual grant of authority — the human's own key, the root of every
    // credential issued under this mandate. The notary only countersigns it,
    // and a countersignature over an unverifiable grant proves nothing, so a
    // verifier checks the principal's first.
    principal_signature: String::from("z-illustrative-principal-signature"),
    notary_signature: String::from("z-illustrative-not-a-real-signature"),
  };

  println!("scope checks:");
  for channel in [
    aph_core::ChannelKind::Slack,
    aph_core::ChannelKind::Email,
    aph_core::ChannelKind::Discord,
  ] {
    println!("  {:<8} allowed: {}", channel.label(), mandate.allows_channel(channel));
  }

  println!("\nvalidity window:");
  for now in [
    "2026-05-21T12:00:00Z", // inside
    "2026-05-23T00:00:00Z", // expired
    "not-a-timestamp",      // garbage: must fail closed
  ] {
    println!("  {:<22} valid: {}", now, mandate.is_valid_at(now));
  }

  // ── Human present: the agent asks, the human answers ──────────────────
  // The decisive property is that MandateIssued is unreachable without
  // passing through PendingDecision — authority cannot be minted without
  // the human having been asked.
  println!("\nhuman-present flow:");
  let mut flow = aph_core::HumanPresentNotarizationFlow::new("urn:uuid:cm-1");
  println!("  start: {:?}", flow.state());

  let skipped = flow.transition_to(aph_core::HumanPresentNotarizationState::MandateIssued);
  match skipped {
    Err(e) => println!("  skipping the human is refused: {} [{}]", e, e.code()),
    Ok(()) => println!("  BUG: consent was bypassed"),
  }

  for next in [
    aph_core::HumanPresentNotarizationState::PendingDecision,
    aph_core::HumanPresentNotarizationState::Approved,
    aph_core::HumanPresentNotarizationState::MandateIssued,
    aph_core::HumanPresentNotarizationState::EnvelopeIssued,
    aph_core::HumanPresentNotarizationState::Delivered,
  ] {
    flow.transition_to(next).expect("legal transition");
    println!("  -> {:?}{}", flow.state(), if flow.state().is_terminal() { " (terminal)" } else { "" });
  }

  // ── Human not present: standing delegation, no prompt ─────────────────
  // Shorter machine, no PendingDecision state — the human decided in
  // advance by issuing the DelegationMandate above.
  println!("\nhuman-not-present flow:");
  let mut auto = aph_core::HumanNotPresentNotarizationFlow::new("urn:uuid:dm-1");
  for next in [
    aph_core::HumanNotPresentNotarizationState::MandateIssued,
    aph_core::HumanNotPresentNotarizationState::EnvelopeIssued,
    aph_core::HumanNotPresentNotarizationState::Delivered,
  ] {
    auto.transition_to(next).expect("legal transition");
    println!("  -> {:?}{}", auto.state(), if auto.state().is_terminal() { " (terminal)" } else { "" });
  }

  // ── Who may do what ───────────────────────────────────────────────────
  // Separation of duties: the human issues authority, the notary attests
  // it, and neither can do the other's job.
  println!("\npermission matrix:");
  for role in aph_core::AphPartyRole::all() {
    let allowed: Vec<String> = aph_core::AphOperation::all()
      .iter()
      .filter(|op| role.can_perform(**op))
      .map(|op| format!("{:?}", op))
      .collect();
    println!("  {:<18} {}", role.label(), allowed.join(", "));
  }
}
