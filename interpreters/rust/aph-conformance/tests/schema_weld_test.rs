//! The schema weld — the machine-readable spec, held to the vectors.
//!
//! WHY THIS EXISTS. `spec/schemas/` renders the wire shapes for adopters
//! who implement from JSON Schema rather than from Rust — and a schema
//! nobody validates anything against is documentation cosplaying as a
//! contract. The envelope schema was written by hand from the parsers'
//! member lists, which is exactly the hand-sync shape this repository has
//! now caught drifting twice (the Snapp bundle, the parity tables).
//!
//! WHAT IT PINS. Every committed vector — the v0.1 conformance corpus via
//! the manifest, and the v0.2 vectors by name — validates against the
//! envelope schema; the rotation attestation vector validates against its
//! own. A schema stricter than the vectors fails here immediately; a
//! schema looser than the parse is caught by the negative case: a member
//! smuggled into a golden must FAIL validation, or `additionalProperties`
//! quietly stopped meaning anything.
//!
//! ZERO `#[ignore]`.

fn repo_root() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn read_json(relative: &str) -> serde_json::Value {
  let path = repo_root().join(relative);
  let raw = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
  serde_json::from_str(&raw).unwrap_or_else(|e| std::panic!("{:?} is not JSON: {}", path, e))
}

/// The envelope schema with its cross-file `$ref`s resolved by inlining —
/// the two referenced schemas are small and local, and a resolver
/// dependency for two known files would be machinery without a customer.
fn envelope_schema() -> serde_json::Value {
  let mut schema = read_json("spec/schemas/notarization-envelope.schema.json");
  let status = read_json("spec/schemas/credential-status-entry.schema.json");
  let text = serde_json::to_string(&schema).expect("serializes");
  let replaced = text.replace(
    "\"credential-status-entry.schema.json\"",
    &std::format!(
      "\"#/$defs/credentialStatusEntry\"",
    ),
  );
  schema = serde_json::from_str(&replaced).expect("still JSON");
  let mut status_def = status;
  if let std::option::Option::Some(obj) = status_def.as_object_mut() {
    obj.remove("$schema");
    obj.remove("$id");
  }
  schema["$defs"]["credentialStatusEntry"] = status_def;
  schema
}

fn compiled_envelope_schema() -> jsonschema::Validator {
  jsonschema::validator_for(&envelope_schema())
    .unwrap_or_else(|e| std::panic!("the envelope schema does not compile: {}", e))
}

fn assert_valid(validator: &jsonschema::Validator, value: &serde_json::Value, name: &str) {
  let errors: std::vec::Vec<String> =
    validator.iter_errors(value).map(|e| std::format!("{} at {}", e, e.instance_path)).collect();
  std::assert!(
    errors.is_empty(),
    "{} does not validate against the envelope schema — the schema and the \
     vectors have parted, and the schema is the defect:\n  {}",
    name,
    errors.join("\n  ")
  );
}

#[test]
fn every_committed_vector_validates_against_the_envelope_schema() {
  let validator = compiled_envelope_schema();
  let manifest = read_json("examples/manifest.json");
  let conformance = manifest["conformance"]
    .as_array()
    .unwrap_or_else(|| std::panic!("the manifest has no conformance array"));
  std::assert!(!conformance.is_empty(), "an empty corpus welds nothing");
  for entry in conformance {
    let name = entry.as_str().expect("manifest entries are file names");
    let value = read_json(&std::format!("examples/{}", name));
    assert_valid(&validator, &value, name);
  }
  for name in ["v0.2/sealed_envelope.json", "v0.2/sealed_signed_envelope.json"] {
    let value = read_json(&std::format!("examples/{}", name));
    assert_valid(&validator, &value, name);
  }
}

#[test]
fn the_rotation_vector_validates_against_its_schema() {
  let mut schema = read_json("spec/schemas/rotation-attestation.schema.json");
  // Inline the shared proof definition the same way, for the same reason.
  let envelope = read_json("spec/schemas/notarization-envelope.schema.json");
  schema["properties"]["proof"] = serde_json::json!({ "$ref": "#/$defs/proof" });
  schema["$defs"] = serde_json::json!({ "proof": envelope["$defs"]["proof"] });
  let validator = jsonschema::validator_for(&schema)
    .unwrap_or_else(|e| std::panic!("the rotation schema does not compile: {}", e));
  let value = read_json("examples/v0.2/rotation_attestation.json");
  let errors: std::vec::Vec<String> =
    validator.iter_errors(&value).map(|e| std::format!("{}", e)).collect();
  std::assert!(errors.is_empty(), "the rotation vector does not validate:\n  {}", errors.join("\n  "));
}

#[test]
fn a_smuggled_member_fails_validation_or_additional_properties_died() {
  // The negative weld: strictness is only real if it refuses something.
  let validator = compiled_envelope_schema();
  let mut value = read_json("examples/audience_bound_envelope.json");
  value["credentialSubject"]["smuggled"] = serde_json::json!(1);
  std::assert!(
    !validator.is_valid(&value),
    "a member the parse would refuse validated cleanly — additionalProperties \
     has quietly stopped meaning anything"
  );
}
