//! Parse an APH envelope and read the claim it carries.
//!
//! Run with: `cargo run -p aph-core --example parse_and_inspect`
//!
//! Shows the two things a recipient does first: strict-parse the credential,
//! then read who authorized what. Strict parsing is normative (spec §7.1) —
//! an unknown field is a hard error, never silently ignored, so a producer
//! cannot smuggle a claim past a verifier that does not understand it.

fn main() {
  // A frozen wire sample. In a real verifier this arrives off the channel.
  let raw = include_str!("../tests/golden/slack_reply_envelope.json");

  let envelope: aph_core::NotarizationEnvelope =
    serde_json::from_str(raw).expect("golden fixture parses");

  let subject = &envelope.credential_subject;
  println!("envelope    {}", envelope.id);
  println!("issuer      {}", envelope.issuer);
  println!("valid       {} .. {}", envelope.valid_from, envelope.valid_until);
  println!();
  println!("human       {} ({})", subject.human_principal.display_name, subject.human_principal.id);
  println!("agent       {} ({})", subject.agent.display_name, subject.agent.id);
  println!("channel     {}", subject.channel.kind);
  println!("content     {}", subject.communication.content_class);
  println!("body sha256 {}", subject.communication.body_sha256);
  println!("decision    {} (scope: {})", subject.policy.decision, subject.policy.matched_scope);
  println!("notary      {}", subject.notarization.notary_service.name);
  println!("proof       {} / {}",
    envelope.proof.r#type,
    envelope.proof.cryptosuite.as_deref().unwrap_or("(none)"));

  // The addressing blob is deliberately opaque (spec §7.4): APH does not
  // model per-channel shapes, so new channels need no changes here.
  println!("addressing  {}", subject.channel.recipient_addressing);

  // Strict parsing, demonstrated: inject a field the type does not model.
  let mut tampered: serde_json::Value = serde_json::from_str(raw).unwrap();
  tampered["surpriseField"] = serde_json::json!("unexpected");
  let result: Result<aph_core::NotarizationEnvelope, _> =
    serde_json::from_value(tampered);
  println!();
  match result {
    Ok(_) => println!("BUG: unknown field was accepted"),
    Err(e) => println!("unknown field correctly rejected: {}", e),
  }
}
