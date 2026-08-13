//! Port contract tests for the APH wire-type canon.
//!
//! Verifies trait-bound invariants on the public wire shapes shipped by
//! `aph_core` (Send + Sync + Clone + Debug + Eq) plus serde round-trip +
//! back-compat guarantees that adapters depend on.
//!
//! This file lives in `aph-conformance`, which depends ONLY on `aph_core`
//! per its Cargo.toml. All assertions target the public `aph_core` surface.

/// Compile-time witness: T must be `Send + Sync`.
fn assert_send_sync<T: std::marker::Send + std::marker::Sync>() {}

/// Compile-time witness: T must be `Send + Sync + Clone + Debug`.
fn assert_full_traits<
  T: std::marker::Send + std::marker::Sync + std::clone::Clone + std::fmt::Debug,
>() {
}

#[test]
fn notarization_envelope_is_send_sync_clone_debug() {
  // Test: NotarizationEnvelope must satisfy the trait bounds adapters expect.
  // Justification: notarization adapters cross `.await` boundaries; the wire
  // type MUST be Send + Sync; the audit-log stream + UI rendering paths need
  // Clone + Debug.
  assert_full_traits::<aph_core::NotarizationEnvelope>();
}

#[test]
fn linked_mandate_is_send_sync_clone_debug() {
  // Test: LinkedMandate must satisfy the same trait bounds as the envelope.
  // Justification: shipped as an `Option<LinkedMandate>` field on the
  // envelope; trait bounds must transitively propagate.
  assert_full_traits::<aph_core::LinkedMandate>();
}

#[test]
fn envelope_proof_is_send_sync_clone_debug() {
  // Test: EnvelopeProof carries the detached signature value; must be
  // Send + Sync + Clone + Debug for the same actor + stream reasons.
  assert_full_traits::<aph_core::EnvelopeProof>();
}

#[test]
fn envelope_proofs_union_is_send_sync_clone_debug() {
  // Test: EnvelopeProofs is the object-or-array union now sitting on
  // `NotarizationEnvelope.proof` (spec §7.1.11), so the envelope's own
  // bounds hold only if this type carries them too.
  // Justification: the envelope crosses `.await` boundaries in adapters; a
  // field type that lost Send would take the whole credential with it.
  assert_full_traits::<aph_core::envelope::EnvelopeProofs>();
}

#[test]
fn attestation_mode_is_send_sync_clone_debug() {
  // Test: AttestationMode travels inside `PolicyDescriptor` and is returned
  // by `verify_proof_structure`, so verification results cross the same
  // actor and stream boundaries the wire types do.
  // Justification: a verifier's reply channel carries
  // `Result<AttestationMode, AphError>`.
  assert_full_traits::<aph_core::envelope::AttestationMode>();
}

#[test]
fn credential_subject_is_send_sync_clone_debug() {
  // Test: CredentialSubject must satisfy the full trait bound set.
  // Justification: 6 nested sub-structs (human / agent / channel /
  // communication / policy / notarization) all participate.
  assert_full_traits::<aph_core::CredentialSubject>();
}

#[test]
fn aph_error_is_send_sync() {
  // Test: AphError must be Send + Sync so it crosses `.await` in actor
  // mailbox replies (e.g. a oneshot reply channel in an async host).
  // Justification: actor reply channels carry `Result<_, AphError>`.
  assert_send_sync::<aph_core::AphError>();
}

#[test]
fn linked_mandate_round_trips_with_both_ap2_fields_set() {
  // Test: AP2 cross-link — LinkedMandate MUST carry BOTH
  // `ap2_intent_mandate_uri` + `ap2_signed_payload_b64` through a serde
  // round-trip without loss.
  // Justification: verifiers that cannot dereference the AP2 URI rely on
  // the embedded base64 signed payload; both fields participate at once.
  let lm = aph_core::LinkedMandate {
    ap2_intent_mandate_uri: std::option::Option::Some(std::string::String::from(
      "urn:uuid:11111111-1111-4111-8111-111111111111",
    )),
    ap2_signed_payload_b64: std::option::Option::Some(std::string::String::from(
      "eyJwYXlsb2FkIjoidGVzdCJ9",
    )),
    // `vault_mutation` is a later additive field on `LinkedMandate`. This
    // test asserts the AP2 cross-link pair round-trips; the mutation mandate
    // is deliberately absent (`skip_serializing_if` keeps the wire form
    // byte-identical to what this test originally asserted).
    vault_mutation: std::option::Option::None,
  };
  let json = serde_json::to_string(&lm).expect("serialize");
  std::assert!(
    json.contains("\"ap2IntentMandateUri\""),
    "camelCase wire form for ap2IntentMandateUri MUST be present: {}",
    json
  );
  std::assert!(
    json.contains("\"ap2SignedPayloadB64\""),
    "camelCase wire form for ap2SignedPayloadB64 MUST be present: {}",
    json
  );
  let parsed: aph_core::LinkedMandate =
    serde_json::from_str(&json).expect("deserialize");
  std::assert_eq!(parsed, lm);
}

#[test]
fn linked_mandate_back_compat_omits_ap2_signed_payload_b64() {
  // Test: wire stability — old-shape JSON that lacks `ap2SignedPayloadB64`
  // MUST still parse, yielding `None` on the newer field.
  // Justification: additive wire surface — the `#[serde(default)]` contract.
  let old_json = std::string::String::from("{\"ap2IntentMandateUri\":\"urn:uuid:legacy\"}");
  let parsed: aph_core::LinkedMandate =
    serde_json::from_str(&old_json).expect("legacy JSON must deserialize");
  std::assert_eq!(
    parsed.ap2_intent_mandate_uri,
    std::option::Option::Some(std::string::String::from("urn:uuid:legacy"))
  );
  std::assert!(
    parsed.ap2_signed_payload_b64.is_none(),
    "missing ap2SignedPayloadB64 MUST default to None"
  );
}

#[test]
fn linked_mandate_back_compat_omits_both_fields() {
  // Test: an empty `{}` LinkedMandate JSON object MUST parse to both-None.
  // Justification: both fields are `#[serde(default)]`; the empty-object
  // shape is the limit case and exercises the deserializer's default path.
  let empty_json = std::string::String::from("{}");
  let parsed: aph_core::LinkedMandate =
    serde_json::from_str(&empty_json).expect("empty JSON object must deserialize");
  std::assert!(parsed.ap2_intent_mandate_uri.is_none());
  std::assert!(parsed.ap2_signed_payload_b64.is_none());
}

#[test]
fn aph_version_constant_pinned_to_zero_one() {
  // Test: the APH version pin is the literal string `"0.1"`.
  // Justification: every envelope's `aph_version` field MUST match this
  // value; conformance fixtures depend on it.
  std::assert_eq!(aph_core::APH_VERSION, "0.1");
}

#[test]
fn aph_credential_type_is_well_formed() {
  // Test: APH credential type constant is the spec-mandated VC type.
  // Justification: every envelope's `type[]` array MUST include this
  // value; round-trip fixtures depend on the literal string.
  std::assert_eq!(
    aph_core::APH_CREDENTIAL_TYPE,
    "AgentSendAuthorizationCredential"
  );
}
