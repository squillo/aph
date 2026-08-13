//! Canonicalize, sign, and verify — the cryptographic core of APH.
//!
//! Run with: `cargo run -p aph-core --example sign_and_verify`
//!
//! A signature covers the CANONICAL form of the envelope, not the JSON text
//! it arrived as. That is what lets an envelope survive re-serialization by
//! intermediaries: both sides derive the same bytes from equal data.

fn main() {
  // Deterministic key so this example prints the same thing every run. A
  // real notary's key is device-held and published for discovery (spec §8.4).
  let signing_key = p256::ecdsa::SigningKey::from_bytes(&[42u8; 32].into())
    .expect("valid P-256 scalar");
  let verifying_key = *signing_key.verifying_key();

  let raw = include_str!("../tests/golden/slack_reply_envelope.json");
  let envelope: aph_core::NotarizationEnvelope = serde_json::from_str(raw).unwrap();

  // Step 1: empty the signature slot, because the signature cannot cover
  // itself (spec §7.2). "Empty" is not "remove": §7.2.1 settles this
  // normatively, because JCS over an object with the member absent and JCS
  // over the same object with the member empty produce different bytes.
  //
  // This fixture carries a LONE notary proof, so `proof` is an object and
  // this one line is the whole canonicalization base. A two-element chain
  // has two different bases (§7.2.1): the principal's is the envelope with
  // `proof` a ONE-ELEMENT ARRAY holding its proof alone, and the notary's
  // keeps both proofs with the principal's `proofValue` complete.
  let mut unsigned = serde_json::to_value(&envelope).unwrap();
  unsigned["proof"]["proofValue"] = serde_json::json!("");

  // Step 2: canonicalize. Key order and number formatting are fixed here,
  // so two implementations reach byte-identical input.
  let canonical = aph_core::canonicalize_rfc8785(&unsigned);
  println!("canonical bytes: {} bytes", canonical.len());
  println!("first 120:       {}", &canonical[..120.min(canonical.len())]);

  // Step 3: sign the canonical bytes as a detached JWS — "detached" because
  // the payload travels beside the signature rather than inside it.
  let jws = aph_core::create_detached_jws(canonical.as_bytes(), &signing_key);
  println!("\ndetached jws:    {}", jws);

  let ok = aph_core::verify_detached_jws(&jws, canonical.as_bytes(), &verifying_key);
  println!("verifies:        {}", ok);
  assert!(ok, "a freshly produced signature must verify");

  // Tamper with the body hash and re-canonicalize: the signature no longer
  // matches, which is the property that stops a credential being reused to
  // authorize a different message.
  let mut altered = unsigned.clone();
  altered["credentialSubject"]["communication"]["bodySha256"] =
    serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000");
  let altered_canonical = aph_core::canonicalize_rfc8785(&altered);
  let still_ok =
    aph_core::verify_detached_jws(&jws, altered_canonical.as_bytes(), &verifying_key);
  println!("after tampering: {}", still_ok);
  assert!(!still_ok, "a tampered body must not verify");

  // Mandates use the same primitive over their own canonical form.
  let signature = aph_core::sign_mandate(canonical.as_bytes(), &signing_key);
  println!(
    "\nmandate sig:     {} bytes (DER), verifies: {}",
    signature.as_bytes().len(),
    aph_core::verify_mandate(canonical.as_bytes(), &signature, &verifying_key)
  );
}
