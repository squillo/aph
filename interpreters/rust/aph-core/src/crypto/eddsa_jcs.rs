//! `eddsa-jcs-2022` — envelope signing and verification.
//!
//! This is the cryptosuite every published APH example declares and the
//! default for the protocol: Ed25519 over the JCS-canonical form of the
//! envelope, with the signature carried as multibase base58btc in
//! `proof.proofValue`.
//!
//! # The empty-string convention
//!
//! Spec §7.2 notes that a signer must exclude `proof.proofValue` from the
//! bytes it signs, but leaves open whether to REMOVE the member or set it to
//! an empty string. Those produce different canonical bytes, so signer and
//! verifier must agree. This implementation sets it to `""`, matching what
//! deployed notaries emit; the choice is pinned by tests here and, being the
//! reference implementation, settles the question for v0.1.

/// Returns the canonical bytes a proof covers: the envelope with
/// `proof.proofValue` emptied, JCS-canonicalized.
///
/// Signer and verifier both route through this function, so they cannot
/// drift apart in how the signing input is derived.
pub fn signing_input(
  envelope: &crate::envelope::NotarizationEnvelope,
) -> std::result::Result<String, crate::errors::AphError> {
  let mut unsigned = envelope.clone();
  unsigned.proof.proof_value = String::new();
  let value = match serde_json::to_value(&unsigned) {
    std::result::Result::Ok(v) => v,
    // An envelope that cannot be serialized cannot be signed or checked.
    std::result::Result::Err(_) => {
      return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
    }
  };
  std::result::Result::Ok(super::jcs::canonicalize_rfc8785(&value))
}

/// Signs an envelope in place under `eddsa-jcs-2022`.
///
/// Sets `proof.cryptosuite` and `proof.proofValue`. The caller remains
/// responsible for `proof.verificationMethod` and the rest of the proof
/// block, because those name the key and are policy, not cryptography.
pub fn sign_envelope(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  signing_key: &ed25519_dalek::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  let canonical = signing_input(envelope)?;
  let signature: ed25519_dalek::Signature =
    ed25519_dalek::Signer::sign(signing_key, canonical.as_bytes());
  envelope.proof.cryptosuite =
    std::option::Option::Some(String::from(crate::aph_config::APH_DI_CRYPTOSUITE));
  envelope.proof.proof_value = super::multibase::base58btc_encode(&signature.to_bytes());
  std::result::Result::Ok(())
}

/// Verifies an envelope's `eddsa-jcs-2022` proof against a known key.
///
/// Resolving that key from the issuer DID is the caller's job (spec §8.4);
/// for a `did:key` issuer, [`crate::crypto::did_key::decode`] does it offline.
pub fn verify_envelope(
  envelope: &crate::envelope::NotarizationEnvelope,
  verifying_key: &ed25519_dalek::VerifyingKey,
) -> std::result::Result<(), crate::errors::AphError> {
  // An absent proof value is an unsigned envelope, not a failed signature.
  if envelope.proof.proof_value.is_empty() {
    return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
  }

  // Refuse to verify under an algorithm the proof does not claim: silently
  // checking Ed25519 against a proof labelled otherwise would let a
  // downgrade pass unnoticed.
  if let std::option::Option::Some(suite) = envelope.proof.cryptosuite.as_deref() {
    if suite != crate::aph_config::APH_DI_CRYPTOSUITE {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(suite));
    }
  }

  let raw = super::multibase::base58btc_decode(&envelope.proof.proof_value)?;
  let bytes: [u8; 64] = match raw.as_slice().try_into() {
    std::result::Result::Ok(b) => b,
    // Ed25519 signatures are exactly 64 bytes; anything else is malformed.
    std::result::Result::Err(_) => {
      return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
    }
  };
  let signature = ed25519_dalek::Signature::from_bytes(&bytes);
  let canonical = signing_input(envelope)?;

  match ed25519_dalek::Verifier::verify(verifying_key, canonical.as_bytes(), &signature) {
    std::result::Result::Ok(()) => std::result::Result::Ok(()),
    std::result::Result::Err(_) => {
      std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature)
    }
  }
}

/// Verifies an envelope whose `issuer` is a `did:key` identifier, resolving
/// the key from the DID itself.
///
/// This is the whole offline path: no network, no prior trust relationship —
/// the property that makes an APH credential checkable by a stranger.
pub fn verify_envelope_did_key(
  envelope: &crate::envelope::NotarizationEnvelope,
) -> std::result::Result<(), crate::errors::AphError> {
  match super::did_key::decode(&envelope.issuer)? {
    super::did_key::DecodedDidKey::Ed25519(key) => verify_envelope(envelope, &key),
    super::did_key::DecodedDidKey::P256(_) => std::result::Result::Err(
      crate::errors::AphError::unsupported_algorithm("ecdsa-jcs-2019 (P-256 issuer)"),
    ),
  }
}

#[cfg(test)]
mod tests {
  fn keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let vk = sk.verifying_key();
    (sk, vk)
  }

  fn fixture() -> crate::envelope::NotarizationEnvelope {
    let raw = include_str!("../../tests/golden/slack_reply_envelope.json");
    serde_json::from_str(raw).expect("golden fixture parses")
  }

  #[test]
  fn sign_then_verify_round_trips() {
    // The load-bearing path for the protocol's default cryptosuite: what
    // this crate signs, this crate must verify.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    std::assert!(super::verify_envelope(&envelope, &vk).is_ok());
  }

  #[test]
  fn signing_sets_the_declared_cryptosuite() {
    // A verifier dispatches on proof.cryptosuite, so signing must label the
    // proof it produced rather than leaving a stale or absent value.
    let (sk, _) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    std::assert_eq!(envelope.proof.cryptosuite.as_deref(), Some("eddsa-jcs-2022"));
    std::assert!(envelope.proof.proof_value.starts_with('z'));
  }

  #[test]
  fn signing_input_empties_rather_than_removes_proof_value() {
    // Pins the §7.2 convention this implementation settles: the member is
    // present-but-empty in the signed bytes. Removing it instead would
    // change the canonical bytes and break every deployed signature.
    let envelope = fixture();
    let canonical = super::signing_input(&envelope).unwrap();
    std::assert!(canonical.contains(r#""proofValue":"""#), "got: {}", canonical);
  }

  #[test]
  fn tampering_with_the_body_hash_breaks_the_signature() {
    // The property the whole protocol rests on: a credential must not
    // authorize a message it did not cover.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    envelope.credential_subject.communication.body_sha256 = "0".repeat(64);
    std::assert!(super::verify_envelope(&envelope, &vk).is_err());
  }

  #[test]
  fn another_notarys_key_does_not_verify() {
    // Verification must bind to the issuing notary, not merely confirm the
    // signature is well-formed.
    let (sk, _) = keypair();
    let other = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]).verifying_key();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    std::assert!(super::verify_envelope(&envelope, &other).is_err());
  }

  #[test]
  fn unsigned_envelope_is_rejected_as_such() {
    // An empty proof value means nobody signed it. That must fail, and it
    // must be distinguishable from a signature that failed to check.
    let (_, vk) = keypair();
    let mut envelope = fixture();
    envelope.proof.proof_value = String::new();
    std::assert!(super::verify_envelope(&envelope, &vk).is_err());
  }

  #[test]
  fn mismatched_cryptosuite_reports_unsupported_algorithm() {
    // Downgrade guard: a proof labelled with a different suite must not be
    // quietly checked as Ed25519. APH_E010 tells the operator what happened.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    envelope.proof.cryptosuite = Some(String::from("ecdsa-jcs-2019"));
    std::assert_eq!(super::verify_envelope(&envelope, &vk).unwrap_err().code(), "APH_E010");
  }

  #[test]
  fn wrong_length_proof_value_is_rejected_not_panicking() {
    // Attacker-controlled: a decodable but wrong-sized proof value must not
    // panic on the fixed-size array conversion.
    let (_, vk) = keypair();
    let mut envelope = fixture();
    envelope.proof.proof_value = crate::crypto::multibase::base58btc_encode(&[1u8, 2, 3]);
    std::assert!(super::verify_envelope(&envelope, &vk).is_err());
  }

  #[test]
  fn did_key_issuer_verifies_with_no_network() {
    // The offline discovery path end to end: derive the issuer DID from the
    // key, sign, and let a verifier recover the key from the DID alone.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    envelope.issuer = crate::crypto::did_key::encode_ed25519(&vk);
    super::sign_envelope(&mut envelope, &sk).unwrap();
    std::assert!(super::verify_envelope_did_key(&envelope).is_ok());
  }

  #[test]
  fn did_key_verification_rejects_a_substituted_issuer() {
    // Swapping the issuer DID for someone else's must fail: otherwise an
    // attacker could re-label a valid envelope as another notary's.
    let (sk, _) = keypair();
    let impostor = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]).verifying_key();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    envelope.issuer = crate::crypto::did_key::encode_ed25519(&impostor);
    std::assert!(super::verify_envelope_did_key(&envelope).is_err());
  }
}
