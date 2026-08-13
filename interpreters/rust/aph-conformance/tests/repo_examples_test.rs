//! Canonical spec-repo example conformance.
//!
//! Reads every `*.json` file in the spec repository's `examples/` directory
//! (this crate lives at `<repo>/interpreters/rust/aph-conformance`, so the
//! examples resolve at `../../../examples` relative to the crate root) and
//! asserts each file is a strict-parse-clean `aph_core::envelope::NotarizationEnvelope`
//! (`deny_unknown_fields`) that survives parse → serialize → reparse with
//! `Eq` equality, AND that the reserialized output is value-identical to the
//! canonical example text. The value-equality pin is what catches
//! serializer-side drift (e.g. a field rename with a back-compat alias would
//! pass every self-round-trip test while emitting a wire name no other
//! implementation accepts).
//!
//! This test welds the interpreter to the spec repo's canonical examples:
//! a change on either side that breaks wire compatibility fails here first.
//!
//! ZERO `#[ignore]`. ZERO `use` statements.

/// Returns the absolute path of the spec repository's `examples/` directory.
fn examples_dir() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples")
}

/// Returns the sorted list of `*.json` file paths in the examples directory.
fn example_json_files() -> std::vec::Vec<std::path::PathBuf> {
  let dir = examples_dir();
  let entries = std::fs::read_dir(&dir)
    .unwrap_or_else(|e| std::panic!("failed to read examples dir {:?}: {}", dir, e));
  let mut files: std::vec::Vec<std::path::PathBuf> = entries
    .map(|entry| {
      entry
        .unwrap_or_else(|e| std::panic!("failed to read examples dir entry: {}", e))
        .path()
    })
    .filter(|path| {
      path.extension().and_then(std::ffi::OsStr::to_str) == std::option::Option::Some("json")
    })
    .collect();
  files.sort();
  files
}

#[test]
fn examples_directory_carries_at_least_seven_envelopes() {
  // Guards against a silently vacuous suite: if the path resolution broke
  // or the directory emptied, the per-file tests below would iterate zero
  // files and pass while proving nothing.
  let files = example_json_files();
  std::assert!(
    files.len() >= 7,
    "expected at least 7 example envelope JSON files in {:?}, found {}: {:?}",
    examples_dir(),
    files.len(),
    files
  );
}

#[test]
fn every_repo_example_strict_parses_and_round_trips() {
  // The weld between the published spec and this implementation: the
  // examples the spec repo hands to third-party implementers must parse
  // here, and what we emit must be value-identical to them. The value
  // pin is the part that catches serializer-side drift — a renamed field
  // with a back-compat alias would pass a parse-only test while emitting
  // a wire name no other implementation accepts.
  for path in example_json_files() {
    let json = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    // Strict parse: NotarizationEnvelope carries `deny_unknown_fields`, so
    // any field the interpreter does not model fails the suite here.
    let parsed: aph_core::envelope::NotarizationEnvelope = serde_json::from_str(&json)
      .unwrap_or_else(|e| std::panic!("{:?} failed strict parse: {}", path, e));
    let reserialized = serde_json::to_string(&parsed)
      .unwrap_or_else(|e| std::panic!("{:?} failed to serialize: {}", path, e));
    let reparsed: aph_core::envelope::NotarizationEnvelope =
      serde_json::from_str(&reserialized)
        .unwrap_or_else(|e| std::panic!("{:?} failed to reparse own output: {}", path, e));
    std::assert_eq!(
      parsed,
      reparsed,
      "{:?} parse → serialize → reparse round-trip mismatch",
      path
    );
    // Serializer-fidelity pin: what the interpreter EMITS must be
    // value-identical to the canonical example, not merely re-parseable by
    // the interpreter itself.
    let original_value: serde_json::Value = serde_json::from_str(&json)
      .unwrap_or_else(|e| std::panic!("{:?} is not valid JSON: {}", path, e));
    let reserialized_value = serde_json::to_value(&parsed)
      .unwrap_or_else(|e| std::panic!("{:?} failed to convert to value: {}", path, e));
    std::assert_eq!(
      reserialized_value,
      original_value,
      "{:?} reserialized output drifted from the canonical example",
      path
    );
  }
}

#[test]
fn every_repo_example_verifies_as_notary_attested() {
  // These are the documents the spec hands to third-party implementers, and
  // every one of them carries a single proof object with no
  // `attestationMode`. Adding the §7.1.11 chain shape must not change what
  // they mean: each must still pass the structural rules, and each must
  // resolve to `NotaryAttested` — the claim a notary alone can make. If a
  // future change made absence resolve to `PrincipalSigned`, this whole
  // corpus would start asserting a human signature nobody produced, and
  // nothing else in the suite would notice.
  for path in example_json_files() {
    let json = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    let parsed: aph_core::envelope::NotarizationEnvelope = serde_json::from_str(&json)
      .unwrap_or_else(|e| std::panic!("{:?} failed strict parse: {}", path, e));
    let mode = aph_core::verification::verify_proof_structure(&parsed)
      .unwrap_or_else(|e| std::panic!("{:?} failed §7.1.11 structure: {}", path, e));
    std::assert_eq!(
      mode,
      aph_core::envelope::AttestationMode::NotaryAttested,
      "{:?} must verify as NotaryAttested",
      path
    );
  }
}

#[test]
fn no_repo_example_carries_an_embedded_delegation_mandate_it_cannot_bind() {
  // `verify_embedded_mandate_binding` is a no-op when no mandate is
  // embedded, so running it over the corpus proves the published examples
  // are internally consistent: any example that later grows a
  // `delegationMandate` member must name this envelope's own human, agent
  // and mandate id, or it would be teaching implementers the exact staple
  // §7.1.7.1 exists to forbid.
  for path in example_json_files() {
    let json = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    let parsed: aph_core::envelope::NotarizationEnvelope = serde_json::from_str(&json)
      .unwrap_or_else(|e| std::panic!("{:?} failed strict parse: {}", path, e));
    aph_core::verification::verify_embedded_mandate_binding(&parsed)
      .unwrap_or_else(|e| std::panic!("{:?} embedded mandate does not bind: {}", path, e));
  }
}

#[test]
fn every_repo_example_is_w3c_vc_2_shaped() {
  // Checks the published examples independently of the in-source
  // fixtures: the documents implementers copy must themselves be valid
  // W3C VC 2.0 credentials, or we would be teaching a broken shape.
  for path in example_json_files() {
    let json = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    let parsed: aph_core::envelope::NotarizationEnvelope = serde_json::from_str(&json)
      .unwrap_or_else(|e| std::panic!("{:?} failed strict parse: {}", path, e));
    std::assert_eq!(
      parsed.aph_version,
      "0.1",
      "{:?} must pin aphVersion=0.1",
      path
    );
    std::assert!(
      parsed.context.len() >= 2,
      "{:?} @context must carry at least 2 entries, got {:?}",
      path,
      parsed.context
    );
    std::assert_eq!(
      parsed.context[0],
      "https://www.w3.org/ns/credentials/v2",
      "{:?} @context[0] must be the W3C VC 2.0 context",
      path
    );
    std::assert_eq!(
      parsed.context[1],
      "https://w3id.org/aph/v1",
      "{:?} @context[1] must be the APH v1 context",
      path
    );
    std::assert!(
      parsed.r#type.iter().any(|t| t == "VerifiableCredential"),
      "{:?} type must include VerifiableCredential",
      path
    );
    std::assert!(
      parsed
        .r#type
        .iter()
        .any(|t| t == "AgentSendAuthorizationCredential"),
      "{:?} type must include AgentSendAuthorizationCredential",
      path
    );
  }
}
