//! ECDSA ES256 signing and verification.
//!
//! Uses the `p256` crate for NIST P-256 ECDSA (ES256). Signing keys
//! are `p256::ecdsa::SigningKey`, verification uses `VerifyingKey`.

/// Signs arbitrary bytes with ECDSA ES256 and returns the DER-encoded signature.
pub fn sign_mandate(
  data: &[u8],
  signing_key: &p256::ecdsa::SigningKey,
) -> p256::ecdsa::DerSignature {
  use p256::ecdsa::signature::Signer;
  signing_key.sign(data)
}

/// Verifies an ECDSA ES256 signature against the given data and public key.
pub fn verify_mandate(
  data: &[u8],
  signature: &p256::ecdsa::DerSignature,
  verifying_key: &p256::ecdsa::VerifyingKey,
) -> bool {
  use p256::ecdsa::signature::Verifier;
  verifying_key.verify(data, signature).is_ok()
}

#[cfg(test)]
mod tests {
  use super::*;

  fn test_keypair() -> (p256::ecdsa::SigningKey, p256::ecdsa::VerifyingKey) {
    let signing = p256::ecdsa::SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
    let verifying = *signing.verifying_key();
    (signing, verifying)
  }

  #[test]
  fn test_sign_verify_roundtrip() {
    // Baseline agreement between the two halves of the mandate-signing
    // seam. Mandates (§6.1/§6.2) carry a notarySignature produced here; if
    // sign and verify diverge, no delegation chain can be validated.
    let (sk, vk) = test_keypair();
    let data = b"intent mandate payload";
    let sig = sign_mandate(data, &sk);
    assert!(verify_mandate(data, &sig, &vk));
  }

  #[test]
  fn test_tampered_data_rejected() {
    // A mandate signature must bind to its exact bytes: otherwise an agent
    // could edit an allowedChannels list or expiry under a real signature.
    let (sk, vk) = test_keypair();
    let sig = sign_mandate(b"original", &sk);
    assert!(!verify_mandate(b"tampered", &sig, &vk));
  }

  #[test]
  fn test_wrong_key_rejected() {
    // Verification must bind to the issuing notary's key — a signature that
    // merely parses must not pass under a different notary's identity.
    let (sk, _) = test_keypair();
    let wrong_sk = p256::ecdsa::SigningKey::from_bytes(&[99u8; 32].into()).unwrap();
    let wrong_vk = *wrong_sk.verifying_key();
    let sig = sign_mandate(b"data", &sk);
    assert!(!verify_mandate(b"data", &sig, &wrong_vk));
  }

  #[test]
  fn test_empty_data_sign_verify() {
    // Degenerate-input guard: zero-length messages must sign and verify
    // like any other, not hit a special-case path or panic.
    let (sk, vk) = test_keypair();
    let sig = sign_mandate(b"", &sk);
    assert!(verify_mandate(b"", &sig, &vk));
  }

  #[test]
  fn test_jcs_canonical_then_sign_verify() {
    // Exercises the real production composition — canonicalize first, sign
    // the canonical bytes — because that pairing, not either half alone, is
    // what every APH proof and notarySignature actually depends on.
    let (sk, vk) = test_keypair();
    let payload = serde_json::json!({"z": 1, "a": 2, "amount": 999});
    let canonical = crate::crypto::jcs::canonicalize_rfc8785(&payload);
    let sig = sign_mandate(canonical.as_bytes(), &sk);
    assert!(verify_mandate(canonical.as_bytes(), &sig, &vk));
  }

  #[test]
  fn test_sign_verify_large_payload() {
    // Envelopes carry previews and addressing blobs, so the signing path
    // must impose no practical size ceiling.
    let (sk, vk) = test_keypair();
    let large_data = vec![0xABu8; 10240]; // 10KB
    let sig = sign_mandate(&large_data, &sk);
    assert!(verify_mandate(&large_data, &sig, &vk));
  }

  #[test]
  fn test_sign_verify_1mb_payload() {
    // No size ceiling on the signing path.
    let (sk, vk) = test_keypair();
    let data = vec![0xA5u8; 1 << 20];
    let sig = sign_mandate(&data, &sk);
    assert!(verify_mandate(&data, &sig, &vk));
  }

  #[test]
  fn test_signing_is_deterministic() {
    // RustCrypto ECDSA is RFC 6979 deterministic: the same key + message
    // yields byte-identical signatures. Pinned so a future switch to a
    // randomized signer (which would make signatures unreproducible and
    // break golden-vector expectations) is caught here.
    let (sk, vk) = test_keypair();
    let data = b"mandate to verify";
    let a = sign_mandate(data, &sk);
    let b = sign_mandate(data, &sk);
    assert_eq!(a.as_bytes(), b.as_bytes());
    assert!(verify_mandate(data, &a, &vk));
  }
}
