//! `JsonWebSignature2020` — the detached-JWS carriage of an envelope proof
//! (spec §8.2).
//!
//! §8.2 gives APH two proof-block formats. The Data Integrity format puts
//! multibase signature bytes in `proofValue`
//! ([`crate::crypto::eddsa_jcs`], [`crate::crypto::ecdsa_jcs`]); this one puts
//! a COMPACT DETACHED JWS there instead. The bytes signed are the same
//! §7.2.1 base in both cases — §8.2 says so in as many words — which is why
//! [`crate::crypto::proof_base::signing_base`] is used here unchanged rather
//! than re-derived. Two carriages that computed their own base is precisely
//! how one envelope comes to have two answers.
//!
//! # ES256 only, and that is a NAMED gap rather than a silent one
//!
//! §8.1 makes both `ES256` and `EdDSA` MUST-support, and §8.2 lets the JWS
//! protected header declare either. This module implements ES256 alone,
//! because [`crate::crypto::jws_detached`] — the vendored primitive every
//! signature here goes through — takes a P-256 key. An `EdDSA`-in-JWS proof
//! is therefore refused BY NAME (`APH_E010`, from
//! [`crate::crypto::eddsa_jcs::verify_proof`]) rather than mis-reported as a
//! bad signature, and the omission is written down in the repository's
//! coverage-gap lists instead of being discovered by an implementer.
//!
//! # ⛔ Two deployed quirks travel with the primitive
//!
//! [`crate::crypto::jws_detached`] documents both, and neither is fixed here
//! because fixing either would fork the wire it is deployed on:
//!
//! - the protected header declares `"b64":false` with `"crit":["b64"]`
//!   (RFC 7797 unencoded payload) while the payload is nevertheless
//!   base64url-encoded into the signing input;
//! - the ES256 signature inside the JWS is DER, not the raw `r||s` RFC 7518
//!   specifies.
//!
//! The second is worth stating twice, because the SAME crate encodes an
//! `ecdsa-jcs-2019` `proofValue` as `r||s`: the encoding depends on the
//! carriage, not on the algorithm. A vector is whatever
//! [`crate::crypto::jws_detached::verify_detached_jws`] accepts, and
//! `examples/detached_jws_envelope.json` is minted through it for exactly
//! that reason.
//!
//! # The protected header is CHECKED, not merely carried
//!
//! §8.3 step 7 makes algorithm validation a verifier duty, and §8.2 lists six
//! members the header MUST include. [`verify_proof`] decodes the header and
//! requires all six. The header cannot be swapped by an attacker — it is
//! inside the signing input — but a verifier that never read it would still
//! accept a proof claiming `alg: "EdDSA"` over an ES256 signature, and would
//! have no answer at all to "reject `alg: none`".

/// `proof.type` of this carriage (§7.1.11).
pub const PROOF_TYPE: &str = "JsonWebSignature2020";

/// `alg` of the only JWS algorithm this module implements (§8.2).
pub const ALG: &str = "ES256";

/// `typ` §8.2 requires in an APH envelope's JWS protected header.
pub const TYP: &str = "aph+jws";

/// `cty` §8.2 requires in an APH envelope's JWS protected header.
pub const CTY: &str = "vc+ld+json";

/// Builds the §8.2 protected header for a proof made under `verification_method`.
///
/// JCS-canonicalized rather than hand-formatted so the member order is fixed
/// by [`crate::crypto::jcs`] and not by whoever edits this function next: the
/// header text participates VERBATIM in the signing input, so two producers
/// that ordered members differently would sign different bytes for the same
/// header.
///
/// `kid` is the verification method DID URL — the same string the proof block
/// carries — so a reader of the bare JWS can find the key without the
/// envelope, and a verifier can refuse a token whose header names a different
/// one.
pub fn protected_header(verification_method: &str) -> std::string::String {
  super::jcs::canonicalize_rfc8785(&serde_json::json!({
    "alg": ALG,
    "b64": false,
    "crit": ["b64"],
    "cty": CTY,
    "kid": verification_method,
    "typ": TYP,
  }))
}

/// Signs one proof of an envelope as a compact detached JWS (§8.2).
///
/// The labels are written BEFORE the base is built, because both are inside
/// the signed bytes (§7.2.1). `cryptosuite` is CLEARED rather than left alone:
/// §7.1.11 says the member is "omitted for `JsonWebSignature2020`", and a
/// stale value would both contradict the type and change the base.
///
/// The caller remains responsible for `verificationMethod`, `created`,
/// `proofPurpose` and the chain members — those name the key and the moment,
/// which are policy and evidence rather than cryptography.
pub fn sign_proof(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  role: super::proof_base::ProofRole,
  key: &p256::ecdsa::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  let header = {
    let proof = super::proof_base::proof_mut(envelope, role)?;
    proof.r#type = std::string::String::from(PROOF_TYPE);
    proof.cryptosuite = std::option::Option::None;
    protected_header(&proof.verification_method)
  };
  let canonical = super::proof_base::signing_base(envelope, role)?;
  let jws = super::jws_detached::create_detached_jws_with_protected_header(
    &header,
    canonical.as_bytes(),
    key,
  );
  let proof = super::proof_base::proof_mut(envelope, role)?;
  proof.proof_value = jws;
  std::result::Result::Ok(())
}

/// Signs an envelope's lone notary proof as a detached JWS.
///
/// The single-proof convenience the two Data Integrity suites also offer, so a
/// `NotaryAttested` producer does not have to name a role.
pub fn sign_envelope(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  key: &p256::ecdsa::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  sign_proof(envelope, super::proof_base::ProofRole::Notary, key)
}

/// Countersigns as the NOTARY over a chain whose principal proof is complete.
///
/// Same refusal as every other suite's, from the same shared rule
/// ([`crate::crypto::proof_base::require_signed_principal`]): a
/// countersignature over an empty principal `proofValue` attests to nothing
/// while producing something that looks `PrincipalSigned`.
pub fn countersign_as_notary(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  key: &p256::ecdsa::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  super::proof_base::require_signed_principal(envelope)?;
  sign_envelope(envelope, key)
}

/// Verifies one `JsonWebSignature2020` proof against a supplied P-256 key.
///
/// Per-role codes are the shared ones (§11): `Principal` → `APH_E011`,
/// `Notary` → `APH_E001`. A header that does not conform to §8.2 is
/// `APH_E013` — the proof BLOCK is malformed — except for `alg`, which §8.3
/// step 7 and §11's `APH_E010` name specifically.
pub fn verify_proof(
  envelope: &crate::envelope::NotarizationEnvelope,
  role: super::proof_base::ProofRole,
  key: &p256::ecdsa::VerifyingKey,
) -> std::result::Result<(), crate::errors::AphError> {
  let proof = super::proof_base::proof_of(envelope, role)?;

  // Refuse to check a proof that claims the other carriage: a Data Integrity
  // `proofValue` is multibase bytes, not a JWS, and reporting "bad signature"
  // for something this function never parsed would send an operator hunting a
  // key problem that does not exist.
  if proof.r#type != PROOF_TYPE {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      std::format!(
        "proof type `{}` is not `{}`; a Data Integrity proof is checked by its cryptosuite (§8.2)",
        proof.r#type, PROOF_TYPE
      ),
    ));
  }

  // An absent proof value is an unsigned envelope, not a failed signature.
  if proof.proof_value.is_empty() {
    return std::result::Result::Err(super::proof_base::signature_failure(role));
  }

  check_protected_header(&proof.proof_value, &proof.verification_method)?;

  let canonical = super::proof_base::signing_base(envelope, role)?;
  if super::jws_detached::verify_detached_jws(&proof.proof_value, canonical.as_bytes(), key) {
    std::result::Result::Ok(())
  } else {
    std::result::Result::Err(super::proof_base::signature_failure(role))
  }
}

/// Verifies an envelope's NOTARY detached-JWS proof against a known key.
///
/// On a chain this checks the countersignature ONLY — the same warning the
/// other suites carry: success means *a notary asserts this human authorized
/// this*, never *this human authorized this*.
pub fn verify_envelope(
  envelope: &crate::envelope::NotarizationEnvelope,
  key: &p256::ecdsa::VerifyingKey,
) -> std::result::Result<(), crate::errors::AphError> {
  verify_proof(envelope, super::proof_base::ProofRole::Notary, key)
}

/// Enforces §8.2's six required protected-header members (§8.3 step 7).
///
/// Extra members are TOLERATED: §8.2 says the header "MUST include" these, not
/// that it may carry nothing else, and a verifier stricter than the spec would
/// reject a conformant third-party vector. What is not tolerated is a missing
/// member or a different value.
fn check_protected_header(
  jws: &str,
  verification_method: &str,
) -> std::result::Result<(), crate::errors::AphError> {
  let encoded = match jws.split('.').next() {
    std::option::Option::Some(encoded) => encoded,
    // `split` on a `&str` always yields at least one item; refusing rather
    // than indexing keeps a future edit from turning this into a panic on
    // attacker-supplied text.
    std::option::Option::None => return std::result::Result::Err(malformed_header("is empty")),
  };
  let bytes = match super::base64url::decode(encoded) {
    std::result::Result::Ok(bytes) => bytes,
    std::result::Result::Err(_) => {
      return std::result::Result::Err(malformed_header("is not base64url"));
    }
  };
  let header: serde_json::Value = match serde_json::from_slice(&bytes) {
    std::result::Result::Ok(header) => header,
    std::result::Result::Err(_) => {
      return std::result::Result::Err(malformed_header("is not a JSON object"));
    }
  };

  // `alg` first and with its own code: this is §8.3 step 7, the one header
  // check §11 gives a dedicated error. It is also what rejects `alg: none`,
  // and what turns an EdDSA-in-JWS proof into a named refusal.
  match header.get("alg").and_then(serde_json::Value::as_str) {
    std::option::Option::Some(ALG) => {}
    std::option::Option::Some(other) => {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(other));
    }
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
        "a JWS protected header declaring no `alg` (§8.3 step 7)",
      ));
    }
  }

  for (name, expected) in [
    ("typ", serde_json::json!(TYP)),
    ("cty", serde_json::json!(CTY)),
    ("b64", serde_json::json!(false)),
    ("crit", serde_json::json!(["b64"])),
    ("kid", serde_json::json!(verification_method)),
  ] {
    match header.get(name) {
      std::option::Option::Some(found) if *found == expected => {}
      std::option::Option::Some(found) => {
        return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
          std::format!(
            "the JWS protected header's `{}` is `{}`; §8.2 requires `{}`",
            name, found, expected
          ),
        ));
      }
      std::option::Option::None => {
        return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
          std::format!("the JWS protected header omits `{}`, which §8.2 requires", name),
        ));
      }
    }
  }
  std::result::Result::Ok(())
}

/// `APH_E013` for a protected header that is not readable as one.
fn malformed_header(problem: &str) -> crate::errors::AphError {
  crate::errors::AphError::proof_chain_invalid(std::format!(
    "the JWS protected header {} (§8.2)",
    problem
  ))
}

#[cfg(test)]
mod tests {
  /// The two published P-256 test scalars, in the roles every suite and every
  /// published vector gives them: RFC 6979 A.2.5 is the principal's, RFC 7515
  /// A.3.1 is the notary's. They live in `proof_base::test_support` — see the
  /// constants there for the documents and the tripwire that pins them.
  const NOTARY_SCALAR: [u8; 32] = crate::crypto::proof_base::test_support::NOTARY_P256_SCALAR;
  const PRINCIPAL_SCALAR: [u8; 32] =
    crate::crypto::proof_base::test_support::PRINCIPAL_P256_SCALAR;

  fn key(scalar: &[u8; 32]) -> p256::ecdsa::SigningKey {
    crate::crypto::proof_base::test_support::p256_key(scalar)
  }

  fn fixture() -> crate::envelope::NotarizationEnvelope {
    crate::crypto::proof_base::test_support::single_proof_envelope()
  }

  fn notary_mut(
    envelope: &mut crate::envelope::NotarizationEnvelope,
  ) -> &mut crate::envelope::EnvelopeProof {
    crate::crypto::proof_base::proof_mut(envelope, crate::crypto::proof_base::ProofRole::Notary)
      .expect("fixture carries a notary proof")
  }

  /// The fixture, signed as a lone notary detached-JWS proof.
  fn signed() -> (
    crate::envelope::NotarizationEnvelope,
    p256::ecdsa::VerifyingKey,
  ) {
    let signing = key(&NOTARY_SCALAR);
    let verifying = *signing.verifying_key();
    let mut envelope = fixture();
    super::sign_envelope(&mut envelope, &signing).expect("the notary signs");
    (envelope, verifying)
  }

  /// Replaces the protected header of a signed proof, leaving the signature
  /// section alone — the shape of every header-tampering case below.
  fn with_header(
    envelope: &crate::envelope::NotarizationEnvelope,
    header_json: &serde_json::Value,
  ) -> crate::envelope::NotarizationEnvelope {
    let signature = envelope
      .proof
      .notary()
      .expect("lone proof")
      .proof_value
      .rsplit('.')
      .next()
      .expect("a compact JWS ends with its signature section")
      .to_string();
    let encoded = crate::crypto::base64url::encode(
      crate::crypto::jcs::canonicalize_rfc8785(header_json).as_bytes(),
    );
    let mut tampered = envelope.clone();
    crate::crypto::proof_base::proof_mut(
      &mut tampered,
      crate::crypto::proof_base::ProofRole::Notary,
    )
    .expect("lone proof")
    .proof_value = std::format!("{}..{}", encoded, signature);
    tampered
  }

  /// The §8.2 header this module mints, as a value tests can edit one member
  /// of. Built from the same constants `protected_header` uses so a rename
  /// cannot leave the tests asserting a header nobody produces.
  fn conformant_header(verification_method: &str) -> serde_json::Value {
    serde_json::json!({
      "alg": super::ALG,
      "b64": false,
      "crit": ["b64"],
      "cty": super::CTY,
      "kid": verification_method,
      "typ": super::TYP,
    })
  }

  #[test]
  fn sign_then_verify_round_trips() {
    // The load-bearing path for §8.2's second proof format. Before this
    // module, `JsonWebSignature2020` existed in this crate as a serde string
    // and one parse test: `verify_detached_jws` was a helper NOTHING
    // dispatched to from envelope verification, so the format was declarable
    // and uncheckable.
    let (envelope, key) = signed();
    super::verify_envelope(&envelope, &key).expect("what this module signs, it must verify");
  }

  #[test]
  fn the_proof_value_is_a_detached_compact_jws() {
    // "Detached" is the property §8.2 chose this format for: the payload
    // travels as the envelope itself, never inside the token. A regression
    // that embedded the base would put a full copy of the envelope inside the
    // envelope.
    let (envelope, _) = signed();
    let value = &envelope.proof.notary().expect("lone proof").proof_value;
    let sections: std::vec::Vec<&str> = value.split('.').collect();
    std::assert_eq!(sections.len(), 3, "compact serialization has three sections");
    std::assert!(sections[1].is_empty(), "the payload section must be empty");
  }

  #[test]
  fn signing_clears_the_cryptosuite_and_sets_the_type() {
    // §7.1.11: `cryptosuite` is "omitted for JsonWebSignature2020". Both
    // labels are inside the signed bytes (§7.2.1), so a signer that left a
    // stale `eddsa-jcs-2022` behind would emit a proof that contradicts its
    // own type AND cannot verify.
    let signing = key(&NOTARY_SCALAR);
    let verifying = *signing.verifying_key();
    let mut envelope = fixture();
    std::assert!(
      notary_mut(&mut envelope).cryptosuite.is_some(),
      "the golden fixture starts as a Data Integrity proof"
    );
    super::sign_envelope(&mut envelope, &signing).expect("the notary signs");
    let proof = envelope.proof.notary().expect("lone proof");
    std::assert_eq!(proof.r#type, "JsonWebSignature2020");
    std::assert!(proof.cryptosuite.is_none());
    super::verify_envelope(&envelope, &verifying).expect("and it still verifies");
  }

  #[test]
  fn the_header_carries_every_member_section_8_2_requires() {
    // §8.2 lists six members and this is the list, asserted against the
    // minted header rather than against prose. `kid` is checked against the
    // proof's own `verificationMethod` because that binding is what lets a
    // bare token be resolved without the envelope.
    let (envelope, _) = signed();
    let proof = envelope.proof.notary().expect("lone proof");
    let encoded = proof.proof_value.split('.').next().expect("header section");
    let decoded = crate::crypto::base64url::decode(encoded).expect("header is base64url");
    let header: serde_json::Value =
      serde_json::from_slice(&decoded).expect("header is a JSON object");
    std::assert_eq!(header, conformant_header(&proof.verification_method));
  }

  #[test]
  fn tampering_with_the_envelope_breaks_the_signature() {
    // The property the whole protocol rests on, through the JWS carriage: a
    // credential must not authorize a message it did not cover.
    let (mut envelope, key) = signed();
    envelope.credential_subject.communication.body_sha256 = "0".repeat(64);
    std::assert!(super::verify_envelope(&envelope, &key).is_err());
  }

  #[test]
  fn another_partys_key_does_not_verify() {
    // Verification must bind to the signing key, not merely confirm the token
    // parses. The stand-in for "somebody else" is the other PUBLISHED test
    // key — inventing a third P-256 scalar would mean shipping an
    // unpublished private key to make a negative test read prettier.
    let (envelope, _) = signed();
    let other = *key(&PRINCIPAL_SCALAR).verifying_key();
    std::assert!(super::verify_envelope(&envelope, &other).is_err());
  }

  #[test]
  fn a_data_integrity_proof_is_refused_by_type_not_by_signature() {
    // Dispatch guard. A `DataIntegrityProof` reaching this function carries
    // multibase bytes, not a JWS; reporting APH_E001 would send an operator
    // to check a key when the real problem is that the wrong verifier ran.
    let (mut envelope, key) = signed();
    notary_mut(&mut envelope).r#type =
      std::string::String::from(crate::crypto::proof_base::DATA_INTEGRITY_PROOF_TYPE);
    std::assert_eq!(
      super::verify_envelope(&envelope, &key).unwrap_err().code(),
      "APH_E010"
    );
  }

  #[test]
  fn alg_none_is_refused_as_an_unsupported_algorithm() {
    // §8.3 step 7 names this case outright: "Reject `alg: none`". The
    // signature check would refuse it anyway, but only APH_E010 tells an
    // operator that an algorithm downgrade was attempted rather than that a
    // key is misconfigured.
    let (envelope, key) = signed();
    let proof = envelope.proof.notary().expect("lone proof").clone();
    let mut header = conformant_header(&proof.verification_method);
    header["alg"] = serde_json::json!("none");
    let tampered = with_header(&envelope, &header);
    std::assert_eq!(
      super::verify_envelope(&tampered, &key).unwrap_err().code(),
      "APH_E010"
    );
  }

  #[test]
  fn an_eddsa_header_over_an_es256_signature_is_refused_by_name() {
    // Algorithm confusion: the token really is ES256, and the header claims
    // EdDSA. A verifier that never read the header would accept it and
    // report an EdDSA proof it never checked. §8.1 does make EdDSA-in-JWS
    // MUST-support — this refusal is the honest statement that this crate
    // does not implement it, not a claim that the combination is invalid.
    let (envelope, key) = signed();
    let proof = envelope.proof.notary().expect("lone proof").clone();
    let mut header = conformant_header(&proof.verification_method);
    header["alg"] = serde_json::json!("EdDSA");
    let tampered = with_header(&envelope, &header);
    std::assert_eq!(
      super::verify_envelope(&tampered, &key).unwrap_err().code(),
      "APH_E010"
    );
  }

  #[test]
  fn every_other_required_header_member_is_enforced() {
    // The remaining five §8.2 MUSTs, each dropped in turn. Enumerated in a
    // loop rather than as five tests so that adding a seventh required member
    // to `protected_header` without adding it here leaves an obvious hole.
    // These are APH_E013 rather than APH_E010: the proof BLOCK does not
    // conform, and only `alg` is an algorithm question (§8.3 step 7).
    let (envelope, key) = signed();
    let method = envelope
      .proof
      .notary()
      .expect("lone proof")
      .verification_method
      .clone();
    for member in ["typ", "cty", "b64", "crit", "kid"] {
      let mut header = conformant_header(&method);
      header
        .as_object_mut()
        .expect("the header is a JSON object")
        .remove(member);
      let tampered = with_header(&envelope, &header);
      std::assert_eq!(
        super::verify_envelope(&tampered, &key).unwrap_err().code(),
        "APH_E013",
        "a header omitting `{}` must be refused as a malformed proof block",
        member
      );
    }
  }

  #[test]
  fn a_kid_naming_a_different_key_is_refused() {
    // §8.2 pins `kid` to the verification method DID URL. Without the check,
    // a token could name one key in its header and be verified against
    // another — and a consumer reading the bare token would resolve the wrong
    // identity while the envelope still verified.
    let (envelope, key) = signed();
    let header = conformant_header("did:web:notary.example#some-other-key");
    let tampered = with_header(&envelope, &header);
    std::assert_eq!(
      super::verify_envelope(&tampered, &key).unwrap_err().code(),
      "APH_E013"
    );
  }

  #[test]
  fn a_malformed_header_is_refused_without_panicking() {
    // Attacker-controlled text reaches this decoder. Every unreadable shape
    // must be a typed refusal, never a panic in a verifier's task.
    let (envelope, key) = signed();
    for value in ["", "!!!..", "..", "not-a-jws", "e30..", "bm90IGpzb24..signature"] {
      let mut broken = envelope.clone();
      crate::crypto::proof_base::proof_mut(
        &mut broken,
        crate::crypto::proof_base::ProofRole::Notary,
      )
      .expect("lone proof")
      .proof_value = std::string::String::from(value);
      std::assert!(
        super::verify_envelope(&broken, &key).is_err(),
        "must refuse {:?}",
        value
      );
    }
  }

  #[test]
  fn unsigned_envelope_is_rejected_as_such() {
    // An empty proof value means nobody signed it, and that must be
    // distinguishable from a signature that failed to check.
    let (mut envelope, key) = signed();
    notary_mut(&mut envelope).proof_value = std::string::String::new();
    std::assert_eq!(
      super::verify_envelope(&envelope, &key).unwrap_err().code(),
      "APH_E001"
    );
  }

  #[test]
  fn signing_is_deterministic_so_a_vector_can_be_byte_compared() {
    // RFC 6979 determinism again, this time through the JWS construction —
    // header, payload encoding and signature all included. This is what makes
    // `examples/detached_jws_envelope.json` a byte-comparable published
    // vector rather than a value that changes on every regeneration.
    let (once, _) = signed();
    let (twice, _) = signed();
    std::assert_eq!(
      once.proof.notary().expect("lone proof").proof_value,
      twice.proof.notary().expect("lone proof").proof_value
    );
  }

  #[test]
  fn the_carriage_decides_the_signature_encoding() {
    // ⛔ The quirk worth two statements: an `ecdsa-jcs-2019` `proofValue` is
    // r||s while the signature INSIDE this JWS is DER — same crate, same
    // curve, same key, different carriage. Pinned by length, because a
    // "consistency" cleanup in either direction forks a wire, and the two
    // sides of the split are otherwise separated by three files.
    let signing = key(&NOTARY_SCALAR);
    let mut jws_envelope = fixture();
    super::sign_envelope(&mut jws_envelope, &signing).expect("JWS notary signature");
    let jws_value = &jws_envelope.proof.notary().expect("lone proof").proof_value;
    let inner = crate::crypto::base64url::decode(
      jws_value.rsplit('.').next().expect("signature section"),
    )
    .expect("the signature section is base64url");
    std::assert_ne!(inner.len(), 64, "the JWS carries DER, not r||s");

    let mut di_envelope = fixture();
    crate::crypto::ecdsa_jcs::sign_envelope(&mut di_envelope, &signing)
      .expect("Data Integrity notary signature");
    let di_raw = crate::crypto::multibase::base58btc_decode(
      &di_envelope.proof.notary().expect("lone proof").proof_value,
    )
    .expect("the proof value is multibase base58btc");
    std::assert_eq!(di_raw.len(), 64, "the Data Integrity proofValue is r||s");
  }
}
