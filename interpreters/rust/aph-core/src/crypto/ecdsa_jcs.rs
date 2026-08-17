//! `ecdsa-jcs-2019` — ES256 envelope signing and verification.
//!
//! The second of §8.1's two MUST-support algorithms, and — until this module
//! existed — the one the reference implementation could declare but not check.
//!
//! Everything structural is shared with [`crate::crypto::eddsa_jcs`]: the same
//! §7.2.1 canonicalization bases from [`crate::crypto::proof_base`], the same
//! three signing roles, the same present-but-empty `proofValue` convention,
//! the same per-role error codes. Only the curve and the signature encoding
//! differ, which is the point — a suite that changed anything else would be a
//! second protocol wearing the first one's envelope.
//!
//! # The signature encoding, and the one place APH does NOT inherit the
//! deployed dialect
//!
//! A `proofValue` under this suite is the **P1363 `r || s` concatenation** —
//! 64 bytes, multibase base58btc — which is what the `ecdsa-jcs-2019` suite
//! definition specifies and what §8.2 means by "the signature bytes are
//! multibase-encoded".
//!
//! That is deliberately NOT what [`crate::crypto::signing::sign_mandate`]
//! produces. A Delegation Mandate signature is DER, because DER is the
//! deployed AP2-interop wire and re-encoding it would invalidate every mandate
//! signature already made. Envelopes carry no such history — nothing has ever
//! minted an ES256 APH envelope — so the envelope carriage follows the spec
//! rather than inheriting a quirk it was never subject to. The split is
//! pinned by `mandate_and_envelope_encodings_are_deliberately_different`; a
//! later "cleanup" that unified them would fork one wire or the other.
//!
//! # Determinism
//!
//! `p256` implements RFC 6979 deterministic ECDSA, so the same key over the
//! same base yields byte-identical signatures. That is why an ES256 envelope
//! can be published as a byte-comparable golden at all — most ECDSA is
//! randomized, and a randomized signer would make every regenerated vector
//! differ from the committed one for no protocol reason.

/// The `cryptosuite` identifier this module implements (§8.1, §8.2).
pub const CRYPTOSUITE: &str = "ecdsa-jcs-2019";

/// Signs an envelope in place as the NOTARY under `ecdsa-jcs-2019`.
///
/// Sets the notary proof's `type`, `cryptosuite` and `proofValue` — the lone
/// proof of a single-proof envelope, or the second proof of a chain. The
/// caller remains responsible for `verificationMethod` and the rest of the
/// proof block, because those name the key and are policy, not cryptography.
///
/// For a chain, prefer [`countersign_as_notary`]: it additionally refuses to
/// countersign a principal proof that carries no signature.
pub fn sign_envelope(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  signing_key: &p256::ecdsa::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  sign_role(envelope, super::proof_base::ProofRole::Notary, signing_key)
}

/// Signs as the PRINCIPAL, producing the head of a proof chain.
///
/// The caller MUST have already placed the principal proof object in the
/// chain, populated with `id`, `created`, `verificationMethod`,
/// `proofPurpose: "assertionMethod"` and an empty `proofValue`; this function
/// fills in the labels and `proofValue` and nothing else. In particular it
/// does not invent a `created` timestamp — this crate has no clock and must
/// not acquire one, because a proof timestamp is evidence about when a human
/// acted (§7.2.1 pins `created` against `notarization.decisionTimestamp`).
///
/// Errors with `APH_E013` unless `proof` is a two-element chain: a lone proof
/// is a notary proof, and there is nothing for the principal to sign.
pub fn sign_as_principal(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  key: &p256::ecdsa::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  sign_role(envelope, super::proof_base::ProofRole::Principal, key)
}

/// Countersigns as the NOTARY over a chain whose principal proof is already
/// present and complete.
///
/// Refuses (`APH_E013`) when the envelope is not a two-element chain, or when
/// the principal proof carries no `proofValue` — the shared rule in
/// [`crate::crypto::proof_base::require_signed_principal`], which is about the
/// chain rather than about the curve.
///
/// Setting the notary proof's own labels here cannot disturb the principal's
/// signature: the principal's base discards the notary proof entirely
/// (§7.2.1).
pub fn countersign_as_notary(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  key: &p256::ecdsa::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  super::proof_base::require_signed_principal(envelope)?;
  sign_envelope(envelope, key)
}

/// Verifies one `ecdsa-jcs-2019` proof of an envelope against a supplied key.
///
/// The two roles fail with DIFFERENT codes, exactly as the Ed25519 suite does
/// (§11): `ProofRole::Principal` → `APH_E011`, `ProofRole::Notary` →
/// `APH_E001`. Only the first means the authorization itself is forged.
///
/// Resolving each key from the proof's `verificationMethod`, and checking that
/// the principal proof's method resolves to
/// `credentialSubject.humanPrincipal.id`, are the verifier's duties (§8.3.1
/// steps 1b–1c). This function checks bytes against the key it is handed.
pub fn verify_proof(
  envelope: &crate::envelope::NotarizationEnvelope,
  role: super::proof_base::ProofRole,
  key: &p256::ecdsa::VerifyingKey,
) -> std::result::Result<(), crate::errors::AphError> {
  let proof = super::proof_base::proof_of(envelope, role)?;

  // An absent proof value is an unsigned envelope, not a failed signature.
  if proof.proof_value.is_empty() {
    return std::result::Result::Err(super::proof_base::signature_failure(role));
  }

  // Refuse to verify under a suite the proof does not claim: silently checking
  // ES256 against a proof labelled otherwise would let a downgrade pass.
  //
  // An ABSENT `cryptosuite` is refused here where the Ed25519 suite tolerates
  // it, and the asymmetry is deliberate: §7.1.11 requires the member on every
  // `DataIntegrityProof`, and an unlabelled proof is indistinguishable from an
  // Ed25519 one, so guessing ES256 would be inventing the very label a
  // downgrade guard exists to read. Ed25519 keeps its tolerance because
  // envelopes minted before the member was written are already deployed.
  match proof.cryptosuite.as_deref() {
    std::option::Option::Some(CRYPTOSUITE) => {}
    std::option::Option::Some(other) => {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(other));
    }
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
        "a DataIntegrityProof carrying no `cryptosuite` (§7.1.11)",
      ));
    }
  }

  let raw = match super::multibase::base58btc_decode(&proof.proof_value) {
    std::result::Result::Ok(bytes) => bytes,
    // A proofValue that is not decodable is a failure of THIS proof, so it
    // must carry this role's code rather than the notary default.
    std::result::Result::Err(_) => {
      return std::result::Result::Err(super::proof_base::signature_failure(role));
    }
  };
  // P1363, never DER: `from_slice` accepts exactly 64 bytes and rejects a zero
  // or out-of-range scalar, so a DER-encoded signature pasted into an envelope
  // `proofValue` fails here rather than being decoded by a second parser.
  let signature = match p256::ecdsa::Signature::from_slice(raw.as_slice()) {
    std::result::Result::Ok(signature) => signature,
    std::result::Result::Err(_) => {
      return std::result::Result::Err(super::proof_base::signature_failure(role));
    }
  };
  let canonical = super::proof_base::signing_base(envelope, role)?;

  match p256::ecdsa::signature::Verifier::verify(key, canonical.as_bytes(), &signature) {
    std::result::Result::Ok(()) => std::result::Result::Ok(()),
    std::result::Result::Err(_) => {
      std::result::Result::Err(super::proof_base::signature_failure(role))
    }
  }
}

/// Verifies an envelope's NOTARY `ecdsa-jcs-2019` proof against a known key.
///
/// On a chain this checks the countersignature ONLY. Success therefore means
/// *a notary asserts this human authorized this*, never *this human authorized
/// this* — the principal proof must be verified separately with
/// [`verify_proof`], and §8.3.1 step 1c requires it FIRST.
pub fn verify_envelope(
  envelope: &crate::envelope::NotarizationEnvelope,
  verifying_key: &p256::ecdsa::VerifyingKey,
) -> std::result::Result<(), crate::errors::AphError> {
  verify_proof(envelope, super::proof_base::ProofRole::Notary, verifying_key)
}

/// Recovers a P-256 verifying key from the compressed SEC1 point a `did:key`
/// identifier carries (§8.4.3).
///
/// [`crate::crypto::did_key::decode`] checks the LENGTH of that point; this is
/// where it is checked to be a point on the curve at all. The failure code is
/// `APH_E001` for the same reason every `did:key` decode failure is: a
/// verifier that cannot recover the issuer's key must refuse the envelope,
/// never fall through to accepting it.
pub fn verifying_key_from_sec1(
  bytes: &[u8],
) -> std::result::Result<p256::ecdsa::VerifyingKey, crate::errors::AphError> {
  match p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes) {
    std::result::Result::Ok(key) => std::result::Result::Ok(key),
    std::result::Result::Err(_) => {
      std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature)
    }
  }
}

/// Labels a proof for this suite and signs its §7.2.1 base.
///
/// The labels are written BEFORE the base is built, because `type` and
/// `cryptosuite` are both inside the signed bytes (§7.2.1): writing them
/// afterwards would emit a proof whose own labels were never covered, and
/// which therefore cannot verify.
///
/// `type` is set as well as `cryptosuite`, which the Ed25519 suite does not
/// need to do. ES256 is the only algorithm with TWO carriages (§8.2 —
/// Data Integrity here, detached JWS in [`crate::crypto::jws_envelope`]), so a
/// signer that set only `cryptosuite` could emit a proof still labelled
/// `JsonWebSignature2020` while carrying multibase Data Integrity bytes.
fn sign_role(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  role: super::proof_base::ProofRole,
  key: &p256::ecdsa::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  {
    let proof = super::proof_base::proof_mut(envelope, role)?;
    proof.r#type = std::string::String::from(super::proof_base::DATA_INTEGRITY_PROOF_TYPE);
    proof.cryptosuite = std::option::Option::Some(std::string::String::from(CRYPTOSUITE));
  }
  let canonical = super::proof_base::signing_base(envelope, role)?;
  let signature: p256::ecdsa::Signature =
    p256::ecdsa::signature::Signer::sign(key, canonical.as_bytes());
  let proof = super::proof_base::proof_mut(envelope, role)?;
  proof.proof_value = super::multibase::base58btc_encode(&signature.to_bytes());
  std::result::Result::Ok(())
}

#[cfg(test)]
mod tests {
  /// The RFC 6979 Appendix A.2.5 signature over the message `sample`, as the
  /// RFC publishes it: `r || s`. Reproducing it is what proves the shared
  /// `PRINCIPAL_P256_SCALAR` is the RFC's key and not a stray scalar.
  const RFC_6979_SAMPLE_SIGNATURE: [u8; 64] = [
    0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
    0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
    0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
    0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
  ];

  /// The uncompressed SEC1 form of the RFC 7515 Appendix A.3.1 public key —
  /// `0x04 || x || y`, with `x` and `y` the JWK's own base64url members
  /// decoded. Reproducing it proves the shared `NOTARY_P256_SCALAR` is that
  /// JWK's `d`.
  const RFC_7515_PUBLIC_POINT: [u8; 65] = [
    0x04, 0x7f, 0xcd, 0xce, 0x27, 0x70, 0xf6, 0xc4, 0x5d, 0x41, 0x83, 0xcb, 0xee, 0x6f, 0xdb, 0x4b,
    0x7b, 0x58, 0x07, 0x33, 0x35, 0x7b, 0xe9, 0xef, 0x13, 0xba, 0xcf, 0x6e, 0x3c, 0x7b, 0xd1, 0x54,
    0x45, 0xc7, 0xf1, 0x44, 0xcd, 0x1b, 0xbd, 0x9b, 0x7e, 0x87, 0x2c, 0xdf, 0xed, 0xb9, 0xee, 0xb9,
    0xf4, 0xb3, 0x69, 0x5d, 0x6e, 0xa9, 0x0b, 0x24, 0xad, 0x8a, 0x46, 0x23, 0x28, 0x85, 0x88, 0xe5,
    0xad,
  ];

  /// Both published scalars live in `proof_base::test_support` so the three
  /// suites cannot disagree about who the principal is; see the constants
  /// there for the documents they come from.
  fn key(scalar: &[u8; 32]) -> p256::ecdsa::SigningKey {
    crate::crypto::proof_base::test_support::p256_key(scalar)
  }

  fn keypair() -> (p256::ecdsa::SigningKey, p256::ecdsa::VerifyingKey) {
    let signing = key(&crate::crypto::proof_base::test_support::NOTARY_P256_SCALAR);
    let verifying = *signing.verifying_key();
    (signing, verifying)
  }

  fn principal_keypair() -> (p256::ecdsa::SigningKey, p256::ecdsa::VerifyingKey) {
    let signing = key(&crate::crypto::proof_base::test_support::PRINCIPAL_P256_SCALAR);
    let verifying = *signing.verifying_key();
    (signing, verifying)
  }

  fn fixture() -> crate::envelope::NotarizationEnvelope {
    crate::crypto::proof_base::test_support::single_proof_envelope()
  }

  fn chain() -> crate::envelope::NotarizationEnvelope {
    crate::crypto::proof_base::test_support::chain_envelope()
  }

  fn notary_mut(
    envelope: &mut crate::envelope::NotarizationEnvelope,
  ) -> &mut crate::envelope::EnvelopeProof {
    crate::crypto::proof_base::proof_mut(envelope, crate::crypto::proof_base::ProofRole::Notary)
      .expect("fixture carries a notary proof")
  }

  /// Signs the chain fixture in the normative order: principal, then notary.
  fn signed_chain() -> (
    crate::envelope::NotarizationEnvelope,
    p256::ecdsa::VerifyingKey,
    p256::ecdsa::VerifyingKey,
  ) {
    let (principal_sk, principal_vk) = principal_keypair();
    let (notary_sk, notary_vk) = keypair();
    let mut envelope = chain();
    super::sign_as_principal(&mut envelope, &principal_sk).expect("principal signs");
    super::countersign_as_notary(&mut envelope, &notary_sk).expect("notary countersigns");
    (envelope, principal_vk, notary_vk)
  }

  #[test]
  fn the_shared_p256_scalars_reproduce_their_published_documents() {
    // Pins the "published test key" property itself — the same guard the
    // Ed25519 golden puts on its RFC 8032 seeds, and the reason those two
    // constants may sit in a public repository at all. Each is checked
    // against something its own RFC prints: the principal's A.2.5 key by
    // reproducing the RFC's signature over `sample` (which RFC 6979
    // determinism makes exact), the notary's A.3.1 key by deriving the JWK's
    // own public point. A scalar swapped for unpublished key material passes
    // every other test in this crate and fails here.
    //
    // It lives in this module rather than beside the constants because
    // reproducing an ECDSA signature is what proves the first one, and that
    // is this suite's own machinery.
    let (principal_sk, _) = principal_keypair();
    let sample: p256::ecdsa::Signature =
      p256::ecdsa::signature::Signer::sign(&principal_sk, b"sample");
    std::assert_eq!(
      sample.to_bytes().as_slice(),
      RFC_6979_SAMPLE_SIGNATURE.as_slice(),
      "PRINCIPAL_P256_SCALAR must be the RFC 6979 A.2.5 sample key"
    );
    let (_, notary_vk) = keypair();
    std::assert_eq!(
      notary_vk.to_encoded_point(false).as_bytes(),
      RFC_7515_PUBLIC_POINT.as_slice(),
      "NOTARY_P256_SCALAR must be the `d` of the RFC 7515 A.3.1 ES256 JWK"
    );
  }

  #[test]
  fn sign_then_verify_round_trips() {
    // The load-bearing path for §8.1's second MUST-support algorithm: what
    // this crate signs under ES256, this crate must verify. Before this
    // module existed the reference could declare `ecdsa-jcs-2019` and check
    // nothing.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    std::assert!(super::verify_envelope(&envelope, &vk).is_ok());
  }

  #[test]
  fn signing_sets_both_labels_inside_the_signed_bytes() {
    // A verifier dispatches on `type` first and `cryptosuite` second, and
    // both are inside the base (§7.2.1) — so both must be written BEFORE the
    // base is built. Written afterwards, an envelope whose proof arrived
    // labelled for the OTHER carriage would produce bytes no verifier can
    // reproduce.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    notary_mut(&mut envelope).r#type =
      std::string::String::from(crate::crypto::jws_envelope::PROOF_TYPE);
    notary_mut(&mut envelope).cryptosuite = std::option::Option::None;
    super::sign_envelope(&mut envelope, &sk).unwrap();
    let proof = envelope.proof.notary().expect("lone proof");
    std::assert_eq!(proof.r#type, "DataIntegrityProof");
    std::assert_eq!(proof.cryptosuite.as_deref(), std::option::Option::Some("ecdsa-jcs-2019"));
    std::assert!(super::verify_envelope(&envelope, &vk).is_ok());
  }

  #[test]
  fn the_proof_value_is_p1363_not_der() {
    // The §8.2 encoding, asserted as a LENGTH rather than as prose: r||s is
    // exactly 64 bytes, while the DER form this crate uses for mandates is
    // 70-72 bytes and variable. A suite that silently emitted DER would
    // round-trip its own signatures and interoperate with nothing.
    let (sk, _) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    let raw = crate::crypto::multibase::base58btc_decode(
      &envelope.proof.notary().expect("lone proof").proof_value,
    )
    .expect("the proof value is multibase base58btc");
    std::assert_eq!(raw.len(), 64, "an ecdsa-jcs-2019 proofValue is P1363 r||s");
  }

  #[test]
  fn mandate_and_envelope_encodings_are_deliberately_different() {
    // Pins the split the module docs explain: mandates keep the deployed DER
    // wire, envelopes use the spec's P1363. Both are correct, and unifying
    // them "for consistency" would fork one of the two. Only a test that
    // asserts they DIFFER stops that cleanup.
    let (sk, _) = keypair();
    let base = b"the same bytes, signed twice";
    let der = crate::crypto::signing::sign_mandate(base, &sk);
    let p1363: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&sk, base);
    std::assert_ne!(der.as_bytes(), p1363.to_bytes().as_slice());
  }

  #[test]
  fn a_der_proof_value_is_rejected() {
    // The attack the length check above prevents, executed: a DER signature
    // over the correct base, multibase-encoded into `proofValue`. It is a
    // valid signature by the right key over the right bytes, and it must
    // still fail, because accepting two encodings would give every proof two
    // valid wire forms and defeat any cache keyed on the proof value.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    let base = crate::crypto::proof_base::signing_base(
      &envelope,
      crate::crypto::proof_base::ProofRole::Notary,
    )
    .unwrap();
    let der = crate::crypto::signing::sign_mandate(base.as_bytes(), &sk);
    notary_mut(&mut envelope).proof_value =
      crate::crypto::multibase::base58btc_encode(der.as_bytes());
    std::assert!(super::verify_envelope(&envelope, &vk).is_err());
  }

  #[test]
  fn signing_is_deterministic_so_a_vector_can_be_byte_compared() {
    // `p256` is RFC 6979 deterministic, which is the ONLY reason an ES256
    // envelope can ship as a byte-comparable published vector. Pinned here so
    // a future switch to a randomized signer fails in this crate rather than
    // as an unexplained golden-file mismatch in the conformance suite.
    let (sk, _) = keypair();
    let mut once = fixture();
    let mut twice = fixture();
    super::sign_envelope(&mut once, &sk).unwrap();
    super::sign_envelope(&mut twice, &sk).unwrap();
    std::assert_eq!(
      once.proof.notary().expect("lone proof").proof_value,
      twice.proof.notary().expect("lone proof").proof_value
    );
  }

  #[test]
  fn tampering_with_the_body_hash_breaks_the_signature() {
    // The property the whole protocol rests on, on the second curve: a
    // credential must not authorize a message it did not cover.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    envelope.credential_subject.communication.body_sha256 = "0".repeat(64);
    std::assert!(super::verify_envelope(&envelope, &vk).is_err());
  }

  #[test]
  fn another_partys_key_does_not_verify() {
    // Verification must bind to the issuing notary, not merely confirm the
    // signature is well-formed. The stand-in for "somebody else" is the
    // PRINCIPAL's published key rather than an invented one: a P-256 scalar
    // cannot be a repeated-byte fake, and inventing a third would be shipping
    // an unpublished private key to make a negative test read prettier.
    let (sk, _) = keypair();
    let (_, other) = principal_keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    std::assert!(super::verify_envelope(&envelope, &other).is_err());
  }

  #[test]
  fn an_ed25519_labelled_proof_reports_unsupported_algorithm() {
    // Downgrade guard, in the direction this module is responsible for: a
    // proof labelled `eddsa-jcs-2022` must not be quietly checked as ES256.
    // APH_E010 tells the operator what happened.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    notary_mut(&mut envelope).cryptosuite =
      std::option::Option::Some(std::string::String::from("eddsa-jcs-2022"));
    std::assert_eq!(
      super::verify_envelope(&envelope, &vk).unwrap_err().code(),
      "APH_E010"
    );
  }

  #[test]
  fn an_unlabelled_data_integrity_proof_reports_unsupported_algorithm() {
    // §7.1.11 requires `cryptosuite` on every DataIntegrityProof. An absent
    // one is indistinguishable from an Ed25519 proof, so ES256 must refuse
    // rather than guess — the asymmetry with the Ed25519 suite that the
    // `verify_proof` comment explains.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &sk).unwrap();
    notary_mut(&mut envelope).cryptosuite = std::option::Option::None;
    std::assert_eq!(
      super::verify_envelope(&envelope, &vk).unwrap_err().code(),
      "APH_E010"
    );
  }

  #[test]
  fn wrong_length_proof_value_is_rejected_not_panicking() {
    // Attacker-controlled: a decodable but wrong-sized proof value must not
    // panic on the fixed-width signature parse.
    let (_, vk) = keypair();
    let mut envelope = fixture();
    notary_mut(&mut envelope).proof_value =
      crate::crypto::multibase::base58btc_encode(&[1u8, 2, 3]);
    notary_mut(&mut envelope).cryptosuite =
      std::option::Option::Some(std::string::String::from(super::CRYPTOSUITE));
    std::assert!(super::verify_envelope(&envelope, &vk).is_err());
  }

  #[test]
  fn unsigned_envelope_is_rejected_as_such() {
    // An empty proof value means nobody signed it. That must fail, and it
    // must be distinguishable from a signature that failed to check.
    let (_, vk) = keypair();
    let mut envelope = fixture();
    notary_mut(&mut envelope).proof_value = std::string::String::new();
    std::assert!(super::verify_envelope(&envelope, &vk).is_err());
  }

  // -------- proof chains (§7.1.11, §7.2.1) --------

  #[test]
  fn chain_sign_then_verify_round_trips() {
    // The `PrincipalSigned` happy path on the ES256 curve, in the normative
    // order. This is the shape `examples/es256_signed_envelope.json`
    // publishes, so if it fails there is no ES256 vector to publish.
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
    // What makes the chain a chain (§7.1.11): the notary's base includes the
    // principal's completed proofValue, so a notary cannot detach a
    // principal's signature and re-attach it to a different envelope.
    let (mut envelope, _, notary_vk) = signed_chain();
    crate::crypto::proof_base::proof_mut(
      &mut envelope,
      crate::crypto::proof_base::ProofRole::Principal,
    )
    .expect("chain fixture carries a principal proof")
    .proof_value
    .push('9');
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
  fn the_notarys_key_cannot_forge_the_principal_proof_and_reports_aph_e011() {
    // §7.1.11's actual forgery, on the ES256 curve: the notary does not hold
    // the human's key, so a principal proof checked against the notary's key
    // must fail — and must fail as APH_E011, because an operator reading
    // APH_E001 would go and check notary configuration while a fabricated
    // human signature went unmentioned.
    let (envelope, _, notary_vk) = signed_chain();
    let error = super::verify_proof(
      &envelope,
      crate::crypto::proof_base::ProofRole::Principal,
      &notary_vk,
    )
    .expect_err("a proof made by the notary's key is not the principal's");
    std::assert_eq!(error.code(), "APH_E011");
  }

  #[test]
  fn the_principals_key_does_not_verify_the_notary_position_and_reports_aph_e001() {
    // The other half of the pair, and the domain-separation claim in one: if
    // the two §7.2.1 bases ever collided, a principal proof moved to the tail
    // of a chain would pass as a countersignature. It must fail, and as
    // APH_E001, so the two failures stay distinguishable to a remote verifier
    // reading only the code.
    let (envelope, principal_vk, _) = signed_chain();
    let error = super::verify_proof(
      &envelope,
      crate::crypto::proof_base::ProofRole::Notary,
      &principal_vk,
    )
    .expect_err("the principal's key must not verify the notary position");
    std::assert_eq!(error.code(), "APH_E001");
  }

  #[test]
  fn countersigning_an_unsigned_principal_proof_is_refused() {
    // A countersignature over an empty principal proofValue attests to
    // nothing while producing an envelope that looks PrincipalSigned. Shared
    // with the Ed25519 suite through `require_signed_principal`, and pinned
    // on both so the shared helper cannot be bypassed by one of them.
    let (notary_sk, _) = keypair();
    let mut envelope = chain();
    let error = super::countersign_as_notary(&mut envelope, &notary_sk)
      .expect_err("the principal proof is still empty");
    std::assert_eq!(error.code(), "APH_E013");
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
  fn a_did_key_p256_issuer_round_trips_offline() {
    // The whole reason this module exists: a P-256 `did:key` issuer used to
    // be REFUSED outright by `verify_envelope_did_key`, so §8.1's second
    // MUST-support algorithm had no offline path at all. Derived from the
    // key rather than transcribed, so encode and decode are welded together.
    let (sk, vk) = keypair();
    let mut envelope = fixture();
    envelope.issuer = crate::crypto::did_key::encode_p256(&vk);
    super::sign_envelope(&mut envelope, &sk).unwrap();
    crate::crypto::eddsa_jcs::verify_envelope_did_key(&envelope)
      .expect("a P-256 did:key issuer verifies with no network");
  }

  #[test]
  fn verifying_key_from_sec1_rejects_bytes_that_cannot_name_a_point() {
    // `did:key` decoding checks the LENGTH of a compressed point; this is the
    // check that it names a point at all. Attacker-controlled, so it must be
    // a typed refusal rather than a panic inside the curve arithmetic.
    //
    // The fixture is 0x02 || 0xFF*32 — an x-coordinate of 2^256 - 1, which is
    // GREATER THAN THE FIELD PRIME p, so the field-element parse itself must
    // refuse before any curve equation is consulted. Chosen deliberately over
    // "32 arbitrary bytes": for any FIXED x below p, whether a compressed
    // point decodes is a ~50% property of that x (an earlier fixture,
    // 0x02 repeated, turned out to BE on the curve and the expected rejection
    // never fired). A rejection test whose fixture is only probably invalid
    // is a coin standing on edge; x >= p is invalid by the field's
    // definition, every time.
    let mut not_a_point = [0xFFu8; 33];
    not_a_point[0] = 0x02;
    std::assert_eq!(
      super::verifying_key_from_sec1(&not_a_point)
        .expect_err("an x-coordinate at 2^256-1 exceeds the P-256 field prime")
        .code(),
      "APH_E001"
    );
  }
}
