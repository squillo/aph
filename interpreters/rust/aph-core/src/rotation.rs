//! RFC 0001 — the signed key-rotation attestation (spec/aph-0.2.md).
//!
//! One claim, made by the CURRENT key: *this named successor is mine.* What
//! it buys: a verifier can check that a successor was named BY ITS
//! PREDECESSOR rather than merely served from the same origin — §8.4.7's
//! bare overlap upgraded to a chain a stranger can walk. What it cannot buy,
//! per the RFC's own §5 and repeated here so no caller oversells it: a
//! stolen current key signs a rotation too; a verifier meeting an identity
//! for the first time has nothing to chain from (continuity, not genesis);
//! and it is no recovery from key LOSS, because the lost key can no longer
//! speak.
//!
//! Zero new cryptography (RFC 0001 §2.3): the statement is signed exactly as
//! a lone-proof envelope is — RFC 8785 JCS over the object with
//! `proof.proofValue` PRESENT AND EMPTIED (never removed; §8.2 records the
//! draft era that got that wrong), `eddsa-jcs-2022`, multibase proof value.
//! Publication (RFC 0001 §3.1): the DID Document property
//! [`DID_DOC_ROTATION_PROPERTY`], full-URI keyed so JSON-LD expansion
//! cannot drop it, atomic with the successor key's own entry.

/// The statement's `type` literal. A verifier refuses any other value: this
/// object is not a VC on purpose (RFC 0001 §2.4 — a VC invites
/// `credentialStatus`, whose freshness bound is the opposite of what a
/// rotation attestation needs).
pub const ROTATION_ATTESTATION_TYPE: &str = "AphRotationAttestation";

/// The DID Document property carrying attestations (RFC 0001 §3.1): an
/// array of statements, keyed by full URI so a JSON-LD-processing resolver
/// survives expansion without a context definition APH does not serve.
pub const DID_DOC_ROTATION_PROPERTY: &str = "https://w3id.org/aph/v1#rotationAttestation";

/// The successor a rotation attestation names: the key, its fragment, and
/// its activation bounds.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotationSuccessor {
  /// The fragment a later `proof.verificationMethod` will carry — the join
  /// key of the chain.
  pub kid: String,
  /// §8.1's JWS spelling (`EdDSA`, `ES256`) — NOT the §8.4.5 TXT spelling
  /// (`ed25519`, `p256`). The mapping between the two vocabularies is
  /// stated once in spec/aph-0.2.md §5 rather than rediscovered per
  /// implementation, exactly as RFC 0001 §2.2 asked.
  pub alg: String,
  /// The successor key bytes themselves, multibase. Naming a `kid` without
  /// the bytes would let whoever controls publication bind the `kid` to a
  /// key of their choosing — the attack this mechanism exists to stop.
  pub public_key_multibase: String,
  /// RFC 3339 activation lower bound, §8.4.5's vocabulary.
  pub not_before: String,
  /// RFC 3339 activation upper bound.
  pub not_after: String,
}

/// RFC 0001 §2.1's statement, byte-for-byte the published shape. Every
/// member is inside the signed bytes for the reason its §2.2 table states.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotationAttestation {
  /// `"0.2"` — the version that declares this statement.
  pub aph_version: String,
  /// Always [`ROTATION_ATTESTATION_TYPE`].
  #[serde(rename = "type")]
  pub r#type: String,
  /// Stable name for THIS statement, so a retraction or an operator's
  /// records can refer to exactly one attestation.
  pub id: String,
  /// The identity the statement is about.
  pub subject: String,
  /// The SPEAKER, as a DID URL including its `#kid` fragment. A verifier
  /// chains on this value; it is never inferred from where the record was
  /// found.
  pub predecessor: String,
  /// The key being named.
  pub successor: RotationSuccessor,
  /// Orders two attestations naming the same predecessor.
  pub created: String,
  /// §8.2's proof block, unchanged — the same shape an envelope carries.
  pub proof: crate::envelope::EnvelopeProof,
}

/// Canonical signing bytes: the statement with `proof.proofValue` present
/// and EMPTIED — §7.2.1's lone-proof base, "minus is not empty" honoured.
fn signing_input(attestation: &RotationAttestation) -> std::result::Result<String, String> {
  let mut working = attestation.clone();
  working.proof.proof_value = String::new();
  let value = serde_json::to_value(&working).map_err(|e| std::format!("{}", e))?;
  std::result::Result::Ok(crate::crypto::jcs::canonicalize_rfc8785(&value))
}

/// Verifies a rotation attestation against the PREDECESSOR's public key —
/// the key the verifier already trusts, resolved through §8.4 or remembered
/// from prior contact. Everything checkable is checked before the
/// signature, and every refusal is `APH_E024` carrying the specific defect,
/// because "the attestation is invalid" with no reason teaches an operator
/// nothing.
pub fn verify_rotation_attestation(
  attestation: &RotationAttestation,
  predecessor_key: &ed25519_dalek::VerifyingKey,
) -> std::result::Result<(), crate::errors::AphError> {
  let refuse = crate::errors::AphError::rotation_attestation_invalid;

  if attestation.r#type != ROTATION_ATTESTATION_TYPE {
    return std::result::Result::Err(refuse(std::format!(
      "type is `{}`, not `{ROTATION_ATTESTATION_TYPE}`",
      attestation.r#type
    )));
  }
  if attestation.aph_version != "0.2" {
    return std::result::Result::Err(refuse(std::format!(
      "aphVersion `{}` does not declare rotation attestations (they exist from 0.2)",
      attestation.aph_version
    )));
  }
  // The speaker must be a key OF the subject: a predecessor fragment under
  // any other DID is a statement about someone else's identity.
  let expected_prefix = std::format!("{}#", attestation.subject);
  if !attestation.predecessor.starts_with(&expected_prefix) {
    return std::result::Result::Err(refuse(std::format!(
      "predecessor `{}` is not a key of subject `{}`",
      attestation.predecessor, attestation.subject
    )));
  }
  // The proof must be BY the predecessor it names — the chain value and the
  // signing key are one claim, not two.
  if attestation.proof.verification_method != attestation.predecessor {
    return std::result::Result::Err(refuse(std::format!(
      "proof.verificationMethod `{}` is not the named predecessor `{}`",
      attestation.proof.verification_method, attestation.predecessor
    )));
  }
  if attestation.successor.alg != "EdDSA" && attestation.successor.alg != "ES256" {
    return std::result::Result::Err(refuse(std::format!(
      "successor.alg `{}` is outside §8.1's set (EdDSA, ES256 — JWS spellings, not TXT's)",
      attestation.successor.alg
    )));
  }
  // The successor bytes must BE a key of a codec this protocol carries;
  // an undecodable successor is a chain link to nothing.
  if crate::crypto::did_key::decode_multibase_key(&attestation.successor.public_key_multibase)
    .is_err()
  {
    return std::result::Result::Err(refuse(
      "successor.publicKeyMultibase does not decode as a supported multikey".to_string(),
    ));
  }
  // Activation bounds must be a real window, both parseable — fail-closed,
  // like every timestamp rule in this crate.
  let bounds = (
    chrono::DateTime::parse_from_rfc3339(&attestation.successor.not_before),
    chrono::DateTime::parse_from_rfc3339(&attestation.successor.not_after),
  );
  match bounds {
    (std::result::Result::Ok(from), std::result::Result::Ok(until)) if from < until => {}
    _ => {
      return std::result::Result::Err(refuse(
        "successor notBefore/notAfter are not a parseable, ordered RFC 3339 window".to_string(),
      ));
    }
  }
  // This implementation verifies the eddsa-jcs-2022 carriage; an ES256 or
  // JWS-carried attestation is refused BY NAME rather than falling through
  // to a wrong-algorithm signature failure — the same honesty arm the
  // envelope verifier carries.
  if attestation.proof.cryptosuite.as_deref() != std::option::Option::Some("eddsa-jcs-2022") {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      "rotation attestation proofs are verified here for eddsa-jcs-2022 only",
    ));
  }

  let canonical = signing_input(attestation)
    .map_err(|e| refuse(std::format!("the statement does not canonicalize: {e}")))?;
  let signature_bytes = crate::crypto::multibase::base58btc_decode(&attestation.proof.proof_value)
    .map_err(|_| refuse("proofValue is not multibase base58btc".to_string()))?;
  let signature_arr: [u8; 64] = match signature_bytes.as_slice().try_into() {
    std::result::Result::Ok(a) => a,
    std::result::Result::Err(_) => {
      return std::result::Result::Err(refuse(
        "proofValue is not a 64-byte Ed25519 signature".to_string(),
      ));
    }
  };
  let signature = ed25519_dalek::Signature::from_bytes(&signature_arr);
  ed25519_dalek::Verifier::verify(predecessor_key, canonical.as_bytes(), &signature)
    .map_err(|_| refuse("the predecessor's signature does not verify over the statement".to_string()))
}

/// Signs an attestation in place: `proof.proofValue` is computed over the
/// lone-proof base and written back multibase. Exists for the committed
/// test vectors and for operators minting real statements through the
/// reference; it accepts a caller-held signing key and never touches key
/// storage.
pub fn sign_rotation_attestation(
  attestation: &mut RotationAttestation,
  signing_key: &ed25519_dalek::SigningKey,
) -> std::result::Result<(), crate::errors::AphError> {
  attestation.proof.proof_value = String::new();
  let canonical = signing_input(attestation).map_err(|e| {
    crate::errors::AphError::rotation_attestation_invalid(std::format!(
      "the statement does not canonicalize: {e}"
    ))
  })?;
  let signature = ed25519_dalek::Signer::sign(signing_key, canonical.as_bytes());
  attestation.proof.proof_value =
    crate::crypto::multibase::base58btc_encode(&signature.to_bytes());
  std::result::Result::Ok(())
}

#[cfg(test)]
mod tests {
  // TEST KEY ONLY: RFC 8032 §7.1 TEST 1's secret key, the same published
  // vector the signing suite already cites. It authorizes nothing.
  const RFC8032_TEST1_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
    0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
    0x7f, 0x60,
  ];

  fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&RFC8032_TEST1_SEED)
  }

  fn attestation() -> super::RotationAttestation {
    let key = signing_key();
    let successor_multibase =
      crate::crypto::did_key::encode_ed25519(&key.verifying_key());
    let subject = "did:web:notary.squillo.com";
    super::RotationAttestation {
      aph_version: std::string::String::from("0.2"),
      r#type: std::string::String::from(super::ROTATION_ATTESTATION_TYPE),
      id: std::string::String::from("urn:uuid:00000000-0000-4000-8000-0000000000r1"),
      subject: subject.to_string(),
      predecessor: std::format!("{subject}#k1"),
      successor: super::RotationSuccessor {
        kid: std::string::String::from("k2"),
        alg: std::string::String::from("EdDSA"),
        // The successor key is illustratively the same test key: the chain
        // rule under test is predecessor-signs, not successor-differs.
        public_key_multibase: successor_multibase.trim_start_matches("did:key:").to_string(),
        not_before: std::string::String::from("2027-01-01T00:00:00Z"),
        not_after: std::string::String::from("2029-01-01T00:00:00Z"),
      },
      created: std::string::String::from("2026-08-29T00:00:00Z"),
      proof: crate::envelope::EnvelopeProof {
        r#type: std::string::String::from("DataIntegrityProof"),
        cryptosuite: std::option::Option::Some(std::string::String::from("eddsa-jcs-2022")),
        verification_method: std::format!("{subject}#k1"),
        created: std::string::String::from("2026-08-29T00:00:00Z"),
        proof_purpose: std::string::String::from("assertionMethod"),
        proof_value: std::string::String::new(),
        id: std::option::Option::None,
        previous_proof: std::option::Option::None,
      },
    }
  }

  #[test]
  fn a_signed_attestation_verifies_and_one_flipped_byte_refuses() {
    // The mechanism end to end: predecessor signs, verifier checks with the
    // predecessor's PUBLIC key, and integrity is all-or-nothing.
    let key = signing_key();
    let mut att = attestation();
    super::sign_rotation_attestation(&mut att, &key).expect("signing succeeds");
    super::verify_rotation_attestation(&att, &key.verifying_key())
      .expect("the predecessor's own statement verifies");

    let mut tampered = att.clone();
    tampered.successor.kid = std::string::String::from("k3");
    let err = super::verify_rotation_attestation(&tampered, &key.verifying_key())
      .expect_err("a renamed successor breaks the signature");
    std::assert_eq!(err.code(), "APH_E024");
  }

  #[test]
  fn the_speaker_must_be_a_key_of_the_subject_and_must_be_the_signer() {
    // The two structural rules RFC 0001 §2.2 makes load-bearing: the chain
    // value names a key OF the subject, and the proof is BY that key —
    // each refused by name, before any cryptography.
    let key = signing_key();
    let mut foreign = attestation();
    foreign.predecessor = std::string::String::from("did:web:other.example.com#k1");
    super::sign_rotation_attestation(&mut foreign, &key).expect("signs");
    let err = super::verify_rotation_attestation(&foreign, &key.verifying_key())
      .expect_err("a predecessor under another DID refuses");
    std::assert!(std::format!("{err}").contains("not a key of subject"));

    let mut mismatched = attestation();
    mismatched.proof.verification_method =
      std::string::String::from("did:web:notary.squillo.com#k9");
    super::sign_rotation_attestation(&mut mismatched, &key).expect("signs");
    let err = super::verify_rotation_attestation(&mismatched, &key.verifying_key())
      .expect_err("a proof by a different key than the named predecessor refuses");
    std::assert!(std::format!("{err}").contains("not the named predecessor"));
  }

  #[test]
  fn malformed_windows_algs_and_types_refuse_before_cryptography() {
    let key = signing_key();
    let mut backwards = attestation();
    backwards.successor.not_before = std::string::String::from("2030-01-01T00:00:00Z");
    super::sign_rotation_attestation(&mut backwards, &key).expect("signs");
    std::assert!(super::verify_rotation_attestation(&backwards, &key.verifying_key()).is_err());

    let mut txt_spelled = attestation();
    txt_spelled.successor.alg = std::string::String::from("ed25519");
    super::sign_rotation_attestation(&mut txt_spelled, &key).expect("signs");
    let err = super::verify_rotation_attestation(&txt_spelled, &key.verifying_key())
      .expect_err("the TXT spelling in the JWS slot is the named vocabulary trap");
    std::assert!(std::format!("{err}").contains("JWS spellings"));

    let mut wrong_type = attestation();
    wrong_type.r#type = std::string::String::from("VerifiableCredential");
    super::sign_rotation_attestation(&mut wrong_type, &key).expect("signs");
    std::assert!(super::verify_rotation_attestation(&wrong_type, &key.verifying_key()).is_err());
  }

  #[test]
  fn the_wire_shape_round_trips_and_refuses_unknown_members() {
    let key = signing_key();
    let mut att = attestation();
    super::sign_rotation_attestation(&mut att, &key).expect("signs");
    let json = serde_json::to_string(&att).expect("serializes");
    let back: super::RotationAttestation = serde_json::from_str(&json).expect("parses");
    std::assert_eq!(back, att);
    let smuggled = json.replacen('{', "{\"extra\":1,", 1);
    std::assert!(serde_json::from_str::<super::RotationAttestation>(&smuggled).is_err());
  }
}
