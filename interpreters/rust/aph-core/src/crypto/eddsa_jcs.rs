//! `eddsa-jcs-2022` — envelope signing and verification.
//!
//! This is the cryptosuite every published APH example declares and the
//! default for the protocol: Ed25519 over the JCS-canonical form of the
//! envelope, with the signature carried as multibase base58btc in
//! `proof.proofValue`.
//!
//! # One proof or two
//!
//! An envelope carries either a lone notary proof or a two-element proof
//! chain — the principal's own proof, then the notary's countersignature
//! (§7.1.11). Three functions cover the three signatures:
//!
//! - [`sign_envelope`] — the notary signature, lone or countersigning.
//! - [`sign_as_principal`] — the human's proof, the head of a chain.
//! - [`countersign_as_notary`] — the notary's proof over a chain whose
//!   principal proof is already complete.
//!
//! Order is normative and forced (§7.2.1): the principal signs the envelope
//! the notary prepared, then the notary countersigns. A signer cannot sign
//! bytes that do not exist yet.
//!
//! # The empty-string convention
//!
//! Spec §7.2 requires a signer to exclude its own `proofValue` from the bytes
//! it signs, and §7.2.1 settles HOW: set the member to `""` rather than
//! removing it, because JCS over an absent member and JCS over an empty one
//! produce different bytes. That is what this implementation has always done,
//! and what [`crate::crypto::proof_base`] now does for all three bases.

/// Returns the canonical bytes the NOTARY's proof covers: the lone-notary
/// base, or — when the envelope carries a chain — the countersignature base
/// with the principal's `proofValue` complete (§7.2.1).
///
/// Kept as public API under its original name because callers depend on it.
/// It is deliberately NOT the principal's base: for that, ask
/// [`crate::crypto::proof_base::signing_base`] with
/// [`crate::crypto::proof_base::ProofRole::Principal`], which is a different
/// byte string on purpose.
pub fn signing_input(
  envelope: &crate::envelope::NotarizationEnvelope,
) -> std::result::Result<String, crate::errors::AphError> {
  super::proof_base::signing_base(envelope, super::proof_base::ProofRole::Notary)
}

/// Signs an envelope in place as the NOTARY under `eddsa-jcs-2022`.
///
/// Sets the notary proof's `cryptosuite` and `proofValue` — the lone proof of
/// a single-proof envelope, or the second proof of a chain. The caller remains
/// responsible for `verificationMethod` and the rest of the proof block,
/// because those name the key and are policy, not cryptography.
///
/// For a chain, prefer [`countersign_as_notary`]: it additionally refuses to
/// countersign a principal proof that carries no signature.
pub fn sign_envelope(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  signing_key: &ed25519_dalek::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  // Label the proof BEFORE building the base. `cryptosuite` is inside the
  // signed bytes (§7.2.1), so writing it afterwards would emit a proof whose
  // own label was never covered — and which therefore cannot verify.
  {
    let proof = super::proof_base::proof_mut(envelope, super::proof_base::ProofRole::Notary)?;
    proof.cryptosuite = std::option::Option::Some(String::from(
      crate::aph_config::APH_DI_CRYPTOSUITE,
    ));
  }
  let canonical = signing_input(envelope)?;
  let signature: ed25519_dalek::Signature =
    ed25519_dalek::Signer::sign(signing_key, canonical.as_bytes());
  let proof = super::proof_base::proof_mut(envelope, super::proof_base::ProofRole::Notary)?;
  proof.proof_value = super::multibase::base58btc_encode(&signature.to_bytes());
  std::result::Result::Ok(())
}

/// Signs as the PRINCIPAL, producing the head of a proof chain.
///
/// The caller MUST have already placed the principal proof object in the
/// chain, populated with `id`, `created`, `verificationMethod`,
/// `proofPurpose: "assertionMethod"` and an empty `proofValue`; this function
/// fills in `proofValue` and nothing else. In particular it does not invent a
/// `created` timestamp — this crate has no clock and must not acquire one,
/// because a proof timestamp is evidence about when a human acted (§7.2.1
/// pins `created` against `notarization.decisionTimestamp`).
///
/// Errors with `APH_E013` unless `proof` is a two-element chain: a lone proof
/// is a notary proof, and there is nothing for the principal to sign.
pub fn sign_as_principal(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  key: &ed25519_dalek::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  let canonical =
    super::proof_base::signing_base(envelope, super::proof_base::ProofRole::Principal)?;
  let signature: ed25519_dalek::Signature =
    ed25519_dalek::Signer::sign(key, canonical.as_bytes());
  let proof = super::proof_base::proof_mut(envelope, super::proof_base::ProofRole::Principal)?;
  proof.proof_value = super::multibase::base58btc_encode(&signature.to_bytes());
  std::result::Result::Ok(())
}

/// Countersigns as the NOTARY over a chain whose principal proof is already
/// present and complete.
///
/// Refuses (`APH_E013`) when the envelope is not a two-element chain, or when
/// the principal proof carries no `proofValue`. That second check is the point
/// of the countersignature: signing a chain whose principal proof is an empty
/// placeholder would attest to nothing while looking exactly like a valid
/// `PrincipalSigned` envelope.
///
/// Setting the notary proof's own `cryptosuite` here cannot disturb the
/// principal's signature: the principal's base discards the notary proof
/// entirely (§7.2.1).
pub fn countersign_as_notary(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  key: &ed25519_dalek::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  let principal_is_signed = match envelope.proof.principal() {
    std::option::Option::Some(proof) => !proof.proof_value.is_empty(),
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "a notary countersignature requires a two-element proof chain (§7.1.11)",
      ));
    }
  };
  if !principal_is_signed {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      "the principal proof carries no proofValue; a countersignature over an unsigned principal proof attests nothing (§7.1.11)",
    ));
  }
  sign_envelope(envelope, key)
}

/// Verifies one proof of an envelope against a supplied key.
///
/// The two roles fail with DIFFERENT codes, deliberately (§11):
///
/// - `ProofRole::Principal` → `APH_E011` (`PrincipalSignatureInvalid`). Only
///   this one means the authorization itself is forged.
/// - `ProofRole::Notary` → `APH_E001` (`InvalidEnvelopeSignature`).
///
/// Resolving each key from the proof's `verificationMethod`, and checking that
/// the principal proof's method resolves to
/// `credentialSubject.humanPrincipal.id`, are the verifier's duties (§8.3.1
/// steps 1b–1c). This function checks bytes against the key it is handed.
pub fn verify_proof(
  envelope: &crate::envelope::NotarizationEnvelope,
  role: super::proof_base::ProofRole,
  key: &ed25519_dalek::VerifyingKey,
) -> std::result::Result<(), crate::errors::AphError> {
  let proof = match role {
    super::proof_base::ProofRole::Principal => envelope.proof.principal(),
    super::proof_base::ProofRole::Notary => envelope.proof.notary(),
  };
  let proof = match proof {
    std::option::Option::Some(p) => p,
    // No proof in that position: a chain problem, not a bad signature.
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "the envelope carries no proof in the requested chain position (§7.1.11)",
      ));
    }
  };

  // An absent proof value is an unsigned envelope, not a failed signature.
  if proof.proof_value.is_empty() {
    return std::result::Result::Err(failure_for(role));
  }

  // Refuse to verify under an algorithm the proof does not claim: silently
  // checking Ed25519 against a proof labelled otherwise would let a
  // downgrade pass unnoticed.
  if let std::option::Option::Some(suite) = proof.cryptosuite.as_deref() {
    if suite != crate::aph_config::APH_DI_CRYPTOSUITE {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(suite));
    }
  }

  let raw = match super::multibase::base58btc_decode(&proof.proof_value) {
    std::result::Result::Ok(bytes) => bytes,
    // A proofValue that is not decodable is a failure of THIS proof, so it
    // must carry this role's code rather than the notary default.
    std::result::Result::Err(_) => return std::result::Result::Err(failure_for(role)),
  };
  let bytes: [u8; 64] = match raw.as_slice().try_into() {
    std::result::Result::Ok(b) => b,
    // Ed25519 signatures are exactly 64 bytes; anything else is malformed.
    std::result::Result::Err(_) => return std::result::Result::Err(failure_for(role)),
  };
  let signature = ed25519_dalek::Signature::from_bytes(&bytes);
  let canonical = super::proof_base::signing_base(envelope, role)?;

  match ed25519_dalek::Verifier::verify(key, canonical.as_bytes(), &signature) {
    std::result::Result::Ok(()) => std::result::Result::Ok(()),
    std::result::Result::Err(_) => std::result::Result::Err(failure_for(role)),
  }
}

/// Verifies an envelope's NOTARY `eddsa-jcs-2022` proof against a known key.
///
/// Resolving that key from the issuer DID is the caller's job (spec §8.4);
/// for a `did:key` issuer, [`crate::crypto::did_key::decode`] does it offline.
///
/// On a chain this checks the countersignature ONLY. Success therefore means
/// *a notary asserts this human authorized this*, never *this human
/// authorized this* — the principal proof must be verified separately with
/// [`verify_proof`], and §8.3.1 step 1c requires it FIRST.
pub fn verify_envelope(
  envelope: &crate::envelope::NotarizationEnvelope,
  verifying_key: &ed25519_dalek::VerifyingKey,
) -> std::result::Result<(), crate::errors::AphError> {
  verify_proof(envelope, super::proof_base::ProofRole::Notary, verifying_key)
}

/// Verifies an envelope whose `issuer` is a `did:key` identifier, resolving
/// the key from the DID itself.
///
/// This is the whole offline path: no network, no prior trust relationship —
/// the property that makes an APH credential checkable by a stranger.
///
/// Only sound for a lone notary proof. In `PrincipalSigned` mode `issuer` is
/// the PRINCIPAL (§7.1.7), and §7.1.11 forbids inferring a signer from that
/// field at all — so a chain is refused here rather than checked against the
/// wrong key and reported as a bad notary signature.
pub fn verify_envelope_did_key(
  envelope: &crate::envelope::NotarizationEnvelope,
) -> std::result::Result<(), crate::errors::AphError> {
  if envelope.proof.is_chain() {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      "verify_envelope_did_key resolves the key from `issuer`, which does not name a chain's signers; resolve each proof's verificationMethod and call verify_proof (§7.1.11, §8.3.1)",
    ));
  }
  match super::did_key::decode(&envelope.issuer)? {
    super::did_key::DecodedDidKey::Ed25519(key) => verify_envelope(envelope, &key),
    super::did_key::DecodedDidKey::P256(_) => std::result::Result::Err(
      crate::errors::AphError::unsupported_algorithm("ecdsa-jcs-2019 (P-256 issuer)"),
    ),
  }
}

/// The error a failed proof earns, by role.
///
/// `APH_E011` and `APH_E001` are different codes on purpose: only the first
/// means the authorization itself is forged, and an operator reading
/// `APH_E001` would go looking at notary configuration instead.
fn failure_for(role: super::proof_base::ProofRole) -> crate::errors::AphError {
  match role {
    super::proof_base::ProofRole::Principal => {
      crate::errors::AphError::PrincipalSignatureInvalid
    }
    super::proof_base::ProofRole::Notary => crate::errors::AphError::InvalidEnvelopeSignature,
  }
}

#[cfg(test)]
mod tests {
  fn keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let vk = sk.verifying_key();
    (sk, vk)
  }

  /// The human principal's keypair, distinct from the notary's `keypair()`.
  /// Same construction idiom, different seed: the notary must not hold the
  /// principal's key, and a test that used one key for both roles could not
  /// tell a countersignature from an authorization.
  fn principal_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
    let vk = sk.verifying_key();
    (sk, vk)
  }

  fn fixture() -> crate::envelope::NotarizationEnvelope {
    crate::crypto::proof_base::test_support::single_proof_envelope()
  }

  fn chain() -> crate::envelope::NotarizationEnvelope {
    crate::crypto::proof_base::test_support::chain_envelope()
  }

  /// Mutable access to the proof a notary signs — the lone proof, or the tail
  /// of a chain.
  fn notary_mut(
    envelope: &mut crate::envelope::NotarizationEnvelope,
  ) -> &mut crate::envelope::EnvelopeProof {
    crate::crypto::proof_base::proof_mut(envelope, crate::crypto::proof_base::ProofRole::Notary)
      .expect("fixture carries a notary proof")
  }

  /// Mutable access to a chain's principal proof.
  fn principal_mut(
    envelope: &mut crate::envelope::NotarizationEnvelope,
  ) -> &mut crate::envelope::EnvelopeProof {
    crate::crypto::proof_base::proof_mut(
      envelope,
      crate::crypto::proof_base::ProofRole::Principal,
    )
    .expect("chain fixture carries a principal proof")
  }

  /// Signs the chain fixture in the normative order: principal, then notary.
  fn signed_chain() -> (
    crate::envelope::NotarizationEnvelope,
    ed25519_dalek::VerifyingKey,
    ed25519_dalek::VerifyingKey,
  ) {
    let (principal_sk, principal_vk) = principal_keypair();
    let (notary_sk, notary_vk) = keypair();
    let mut envelope = chain();
    super::sign_as_principal(&mut envelope, &principal_sk).expect("principal signs");
    super::countersign_as_notary(&mut envelope, &notary_sk).expect("notary countersigns");
    (envelope, principal_vk, notary_vk)
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
    let proof = envelope.proof.notary().expect("lone proof");
    std::assert_eq!(proof.cryptosuite.as_deref(), Some("eddsa-jcs-2022"));
    std::assert!(proof.proof_value.starts_with('z'));
  }

  #[test]
  fn cryptosuite_is_labelled_inside_the_signed_bytes() {
    // cryptosuite is part of the base (§7.2.1), so it must be written BEFORE
    // the base is built. Written afterwards — as an earlier revision of this
    // file did — signing an envelope whose proof carried no cryptosuite
    // produced bytes that no verifier could reproduce.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    notary_mut(&mut envelope).cryptosuite = std::option::Option::None;
    super::sign_envelope(&mut envelope, &sk).unwrap();
    std::assert!(super::verify_envelope(&envelope, &vk).is_ok());
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
    notary_mut(&mut envelope).proof_value = String::new();
    std::assert!(super::verify_envelope(&envelope, &vk).is_err());
  }

  #[test]
  fn mismatched_cryptosuite_reports_unsupported_algorithm() {
    // Downgrade guard: a proof labelled with a different suite must not be
    // quietly checked as Ed25519. APH_E010 tells the operator what happened.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    notary_mut(&mut envelope).cryptosuite = Some(String::from("ecdsa-jcs-2019"));
    std::assert_eq!(super::verify_envelope(&envelope, &vk).unwrap_err().code(), "APH_E010");
  }

  #[test]
  fn wrong_length_proof_value_is_rejected_not_panicking() {
    // Attacker-controlled: a decodable but wrong-sized proof value must not
    // panic on the fixed-size array conversion.
    let (_, vk) = keypair();
    let mut envelope = fixture();
    notary_mut(&mut envelope).proof_value =
      crate::crypto::multibase::base58btc_encode(&[1u8, 2, 3]);
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

  // -------- proof chains (§7.1.11, §7.2.1) --------

  #[test]
  fn chain_sign_then_verify_round_trips() {
    // The `PrincipalSigned` happy path end to end, in the normative order:
    // the principal signs the envelope the notary prepared, the notary
    // countersigns, and BOTH proofs verify under their own keys. If this
    // fails, no envelope can ever carry a human's own signature.
    let (envelope, principal_vk, notary_vk) = signed_chain();
    std::assert!(
      super::verify_proof(
        &envelope,
        crate::crypto::proof_base::ProofRole::Principal,
        &principal_vk
      )
      .is_ok(),
      "principal proof must verify"
    );
    std::assert!(
      super::verify_proof(
        &envelope,
        crate::crypto::proof_base::ProofRole::Notary,
        &notary_vk
      )
      .is_ok(),
      "notary countersignature must verify"
    );
  }

  #[test]
  fn the_countersignature_covers_the_principals_signature() {
    // This is the property that makes the chain a chain (§7.1.11): because
    // the notary's base includes the principal's completed proofValue, a
    // notary cannot detach a principal's signature and re-attach it to a
    // different envelope. Without this test the countersignature could cover
    // nothing at all and every other test here would still pass.
    let (mut envelope, _, notary_vk) = signed_chain();
    principal_mut(&mut envelope).proof_value.push('9');
    std::assert!(
      super::verify_proof(
        &envelope,
        crate::crypto::proof_base::ProofRole::Notary,
        &notary_vk
      )
      .is_err(),
      "mutating the principal's proofValue must break the countersignature"
    );
  }

  #[test]
  fn stripping_the_notary_proof_does_not_yield_a_valid_single_proof_envelope() {
    // §7.2.1's stated attack: an intermediary strips the notary proof from a
    // PrincipalSigned envelope and re-presents the remainder as a valid
    // single-proof (NotaryAttested) envelope, so a recipient reads the
    // human's own proof as a mere notary attestation. The one-element ARRAY
    // base is what stops it — collapsing to the object form changes the
    // bytes, so the signature no longer verifies.
    let (signed, principal_vk, _) = signed_chain();
    let principal = signed
      .proof
      .principal()
      .expect("a signed chain has a principal proof")
      .clone();
    let mut stripped = signed;
    stripped.proof = crate::envelope::EnvelopeProofs::Single(principal);
    std::assert!(
      super::verify_envelope(&stripped, &principal_vk).is_err(),
      "a stripped chain must not verify as a lone notary proof"
    );
  }

  #[test]
  fn a_forged_principal_proof_reports_aph_e011() {
    // APH_E011 and APH_E001 are different codes on purpose: only APH_E011
    // means the authorization itself is forged. Reporting the notary code
    // here would send an operator to check notary configuration while a
    // fabricated human signature went unmentioned.
    let (envelope, _, _) = signed_chain();
    let impostor = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]).verifying_key();
    let error = super::verify_proof(
      &envelope,
      crate::crypto::proof_base::ProofRole::Principal,
      &impostor,
    )
    .expect_err("a proof made by another key is not the principal's");
    std::assert_eq!(error.code(), "APH_E011");
  }

  #[test]
  fn a_forged_notary_proof_reports_aph_e001() {
    // The other half of the pair: a bad countersignature is APH_E001, not
    // APH_E011, so the two failures stay distinguishable to a remote
    // verifier reading only the code.
    let (envelope, _, _) = signed_chain();
    let impostor = ed25519_dalek::SigningKey::from_bytes(&[33u8; 32]).verifying_key();
    let error = super::verify_proof(
      &envelope,
      crate::crypto::proof_base::ProofRole::Notary,
      &impostor,
    )
    .expect_err("a proof made by another key is not the notary's");
    std::assert_eq!(error.code(), "APH_E001");
  }

  #[test]
  fn the_principal_proof_does_not_verify_as_the_notary_proof() {
    // Domain separation, from the signing side: the principal's signature
    // must not be transplantable into the notary position. If the two bases
    // ever collided, a principal proof moved to the tail of a chain would
    // pass as a countersignature.
    let (envelope, principal_vk, _) = signed_chain();
    std::assert!(
      super::verify_proof(
        &envelope,
        crate::crypto::proof_base::ProofRole::Notary,
        &principal_vk
      )
      .is_err(),
      "the principal's key must not verify the notary position"
    );
  }

  #[test]
  fn sign_as_principal_on_a_single_proof_envelope_is_aph_e013() {
    // A lone proof is a notary proof (§7.1.11), so there is no principal
    // proof to fill in. Attacker-supplied shapes reach this path, so it must
    // be a typed refusal rather than a panic.
    let (sk, _) = principal_keypair();
    let mut envelope = fixture();
    let error = super::sign_as_principal(&mut envelope, &sk)
      .expect_err("a single-proof envelope has no principal proof");
    std::assert_eq!(error.code(), "APH_E013");
  }

  #[test]
  fn countersigning_an_unsigned_principal_proof_is_refused() {
    // A countersignature over an empty principal proofValue attests to
    // nothing while producing an envelope that looks PrincipalSigned. The
    // notary must refuse rather than manufacture that artifact.
    let (notary_sk, _) = keypair();
    let mut envelope = chain();
    let error = super::countersign_as_notary(&mut envelope, &notary_sk)
      .expect_err("the principal proof is still empty");
    std::assert_eq!(error.code(), "APH_E013");
  }

  #[test]
  fn signing_as_principal_leaves_the_notary_proof_untouched() {
    // The principal signs the envelope the notary PREPARED (§7.2.1 issuance
    // order), and must not disturb the notary proof block while doing it —
    // the notary's `created` timestamp is audit evidence about when the
    // decision happened.
    let (sk, _) = principal_keypair();
    let mut envelope = chain();
    let before = envelope.proof.notary().expect("chain tail").clone();
    super::sign_as_principal(&mut envelope, &sk).expect("principal signs");
    std::assert_eq!(envelope.proof.notary().expect("chain tail"), &before);
  }

  #[test]
  fn verify_envelope_did_key_refuses_a_chain() {
    // `issuer` is the PRINCIPAL in PrincipalSigned mode (§7.1.7) and §7.1.11
    // forbids inferring a signer from it. Silently checking the notary proof
    // against the issuer's key would report a key-resolution mistake as a bad
    // notary signature; APH_E013 names the real problem.
    let (envelope, _, _) = signed_chain();
    let error = super::verify_envelope_did_key(&envelope)
      .expect_err("issuer does not name a chain's signers");
    std::assert_eq!(error.code(), "APH_E013");
  }
}
