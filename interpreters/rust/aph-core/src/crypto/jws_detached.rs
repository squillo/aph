//! JWS Detached Signature (RFC 7515 Appendix F).
//!
//! The payload is not embedded in the JWS — it's transmitted separately
//! and the signature covers the original payload bytes.
//!
//! Interop note: the protected header declares `"b64":false` with
//! `"crit":["b64"]` (RFC 7797 unencoded payload), yet the payload is
//! base64url-encoded into the signing input — behaviorally `b64:true`.
//! Existing signers and verifiers agree on this construction, so it must
//! be preserved exactly.
//!
//! Interop note: ES256 signatures are DER-encoded inside the JWS rather
//! than the raw 64-byte R||S concatenation RFC 7518 specifies. This is
//! the deployed wire behavior and must not be changed.

/// Creates a JWS detached signature (header..signature, payload omitted).
///
/// Returns the compact serialization with an empty payload section.
pub fn create_detached_jws(payload: &[u8], signing_key: &p256::ecdsa::SigningKey) -> String {
  use p256::ecdsa::signature::Signer;

  let header = r#"{"alg":"ES256","b64":false,"crit":["b64"]}"#;
  let header_b64 = crate::crypto::base64url::encode(header.as_bytes());
  let payload_b64 = crate::crypto::base64url::encode(payload);

  let signing_input = format!("{header_b64}.{payload_b64}");
  let sig: p256::ecdsa::DerSignature = signing_key.sign(signing_input.as_bytes());
  let sig_b64 = crate::crypto::base64url::encode(sig.to_bytes().as_ref());

  // Detached: header..signature (empty payload section)
  format!("{header_b64}..{sig_b64}")
}

/// Verifies a JWS detached signature against the separate payload.
pub fn verify_detached_jws(
  jws: &str,
  payload: &[u8],
  verifying_key: &p256::ecdsa::VerifyingKey,
) -> bool {
  use p256::ecdsa::signature::Verifier;

  let parts: Vec<&str> = jws.splitn(3, '.').collect();
  if parts.len() != 3 || !parts[1].is_empty() {
    return false;
  }

  let payload_b64 = crate::crypto::base64url::encode(payload);
  let signing_input = format!("{}.{}", parts[0], payload_b64);

  let sig_bytes = match super::base64url::decode(parts[2]) {
    Ok(b) => b,
    Err(_) => return false,
  };

  let signature = match p256::ecdsa::DerSignature::from_bytes(sig_bytes.as_slice()) {
    Ok(s) => s,
    Err(_) => return false,
  };

  verifying_key
    .verify(signing_input.as_bytes(), &signature)
    .is_ok()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn test_keypair() -> (p256::ecdsa::SigningKey, p256::ecdsa::VerifyingKey) {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
    let vk = *sk.verifying_key();
    (sk, vk)
  }

  #[test]
  fn test_create_and_verify_roundtrip() {
    // The load-bearing happy path: a signature this crate produces must
    // verify in this crate. If signer and verifier ever disagree on the
    // signing-input construction, every APH envelope stops verifying.
    let (sk, vk) = test_keypair();
    let payload = b"mandate payload bytes";
    let jws = create_detached_jws(payload, &sk);
    assert!(verify_detached_jws(&jws, payload, &vk));
  }

  #[test]
  fn test_detached_format_has_empty_payload() {
    // "Detached" is the whole point: the payload travels beside the JWS,
    // never inside it. A regression that embedded the payload would leak
    // message bodies into channel metadata that only carries the signature.
    let (sk, _) = test_keypair();
    let jws = create_detached_jws(b"data", &sk);
    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    assert_eq!(parts.len(), 3);
    assert!(
      parts[1].is_empty(),
      "payload section must be empty in detached JWS"
    );
  }

  #[test]
  fn test_tampered_payload_rejected() {
    // The core security property: a signature must not authorize a body it
    // did not cover. Without this, an attacker could swap the message under
    // a valid notarization.
    let (sk, vk) = test_keypair();
    let jws = create_detached_jws(b"original", &sk);
    assert!(!verify_detached_jws(&jws, b"tampered", &vk));
  }

  #[test]
  fn test_wrong_key_rejected() {
    // Verification must actually bind to the notary's key, not merely check
    // that the signature is well-formed — otherwise anyone could mint
    // envelopes that pass as another notary's.
    let (sk, _) = test_keypair();
    let wrong_sk = p256::ecdsa::SigningKey::from_bytes(&[99u8; 32].into()).unwrap();
    let wrong_vk = *wrong_sk.verifying_key();
    let jws = create_detached_jws(b"data", &sk);
    assert!(!verify_detached_jws(&jws, b"data", &wrong_vk));
  }

  #[test]
  fn test_invalid_format_rejected() {
    // Malformed input from the wire must fail closed (return false), never
    // panic — this function parses attacker-controlled strings.
    let (_, vk) = test_keypair();
    assert!(!verify_detached_jws("invalid", b"data", &vk));
    assert!(!verify_detached_jws("a.b.c", b"data", &vk));
  }

  /// Split a valid detached JWS into its header and signature sections.
  fn header_and_sig(sk: &p256::ecdsa::SigningKey, payload: &[u8]) -> (String, String) {
    let jws = create_detached_jws(payload, sk);
    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    (parts[0].to_string(), parts[2].to_string())
  }

  #[test]
  fn test_wrong_dot_count_and_empty_forms_rejected() {
    // Structural fuzzing of the compact serialization: every arity other
    // than exactly three sections must fail closed. Indexing parts[2] on a
    // short split would panic, so this pins the guard that prevents it.
    let (sk, vk) = test_keypair();
    let (h, sig) = header_and_sig(&sk, b"data");
    for malformed in ["", "abc", &format!("{}.{}", h, sig), ".."] {
      assert!(
        !verify_detached_jws(malformed, b"data", &vk),
        "must reject {:?}",
        malformed
      );
    }
  }

  #[test]
  fn test_empty_signature_section_rejected_without_panic() {
    // An empty signature section is the one malformed input that decodes
    // SUCCESSFULLY (base64url of "" is Ok(vec![])), so rejection depends on
    // the DER parse taking its Err arm rather than on the decoder. Pinned
    // because a fail-open here would accept unsigned envelopes.
    let (sk, vk) = test_keypair();
    let (h, _) = header_and_sig(&sk, b"data");
    assert!(!verify_detached_jws(&format!("{}..", h), b"data", &vk));
  }

  #[test]
  fn test_non_b64_and_tampered_header_rejected() {
    // This crate never decodes or inspects the protected header, so header
    // integrity rests entirely on the header text participating verbatim in
    // the signing input. Pinned to prove that indirect protection is real:
    // swapping the header still fails verification.
    let (sk, vk) = test_keypair();
    let (h, sig) = header_and_sig(&sk, b"data");
    assert!(!verify_detached_jws(&format!("!!!..{}", sig), b"data", &vk));
    let flipped: String = h.chars().rev().collect();
    assert!(!verify_detached_jws(&format!("{}..{}", flipped, sig), b"data", &vk));
  }

  #[test]
  fn test_padded_der_signature_rejected() {
    // Signature malleability guard: URL_SAFE_NO_PAD gives every signature
    // exactly one accepted text form, so an attacker cannot produce a
    // second, differently-encoded token that verifies for the same message
    // (which would defeat replay caches keyed on the token text).
    let (sk, vk) = test_keypair();
    let (h, sig) = header_and_sig(&sk, b"data");
    assert!(!verify_detached_jws(&format!("{}..{}==", h, sig), b"data", &vk));
  }

  #[test]
  fn test_raw_rs_signature_rejected_der_required() {
    // Pins the documented deliberate divergence from RFC 7518: this dialect
    // carries DER-encoded ES256 signatures, not raw R||S. A standards-
    // conformant signer's token must therefore NOT verify here — surprising,
    // but it is the deployed behavior, and silently accepting both encodings
    // would create two valid forms per signature.
    let (sk, vk) = test_keypair();
    let (h, _) = header_and_sig(&sk, b"data");
    let signing_input = format!("{}.{}", h, crate::crypto::base64url::encode(b"data"));
    let sig: p256::ecdsa::Signature =
      p256::ecdsa::signature::Signer::sign(&sk, signing_input.as_bytes());
    let raw = crate::crypto::base64url::encode(&sig.to_bytes());
    assert!(!verify_detached_jws(&format!("{}..{}", h, raw), b"data", &vk));
  }

  #[test]
  fn test_payload_length_change_rejected() {
    // Extends same-length tampering to length changes (truncation and
    // extension, including the empty payload) — the shapes an attacker
    // reaches for when trying to reuse a notarization on a shorter body.
    let (sk, vk) = test_keypair();
    let jws = create_detached_jws(b"short", &sk);
    assert!(!verify_detached_jws(&jws, b"short plus more bytes", &vk));
    assert!(!verify_detached_jws(&jws, b"", &vk));
  }
}
