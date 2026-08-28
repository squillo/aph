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
        && path.file_name().and_then(std::ffi::OsStr::to_str)
          != std::option::Option::Some(MANIFEST_FILE)
    })
    .collect();
  files.sort();
  files
}

/// The corpus INVENTORY, which lives in the corpus directory and is not itself
/// a vector. Skipped by every enumerator: it is the one file in
/// `examples/*.json` that would fail envelope parsing for the honest reason
/// that it was never an envelope.
const MANIFEST_FILE: &str = "manifest.json";

/// The conformance file names the inventory claims, sorted.
fn manifest_conformance_files() -> std::vec::Vec<std::string::String> {
  let path = examples_dir().join(MANIFEST_FILE);
  let raw = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("could not read the corpus manifest {:?}: {}", path, e));
  let parsed: serde_json::Value = serde_json::from_str(&raw)
    .unwrap_or_else(|e| std::panic!("the corpus manifest {:?} is not valid JSON: {}", path, e));
  let mut names: std::vec::Vec<std::string::String> = parsed
    .get("conformance")
    .and_then(serde_json::Value::as_array)
    .unwrap_or_else(|| std::panic!("the corpus manifest has no `conformance` array"))
    .iter()
    .map(|entry| {
      entry
        .as_str()
        .unwrap_or_else(|| std::panic!("a `conformance` entry is not a string"))
        .to_string()
    })
    .collect();
  names.sort();
  names
}

#[test]
fn examples_directory_is_exactly_the_corpus_the_manifest_claims() {
  // Guards against a silently vacuous suite: if the path resolution broke or
  // the directory emptied, the per-file tests below would iterate zero files
  // and pass while proving nothing.
  //
  // WHY THIS IS SET EQUALITY AND NOT A FLOOR. It was `>= 12`, and the comment
  // beside it conceded "a thirteenth file is fine and passes" — which is
  // exactly the hole. A floor cannot see a vector ADDED and never classified,
  // and it cannot see one file swapped for another, because neither moves the
  // count. Both directions are checked here: a file on disk with no manifest
  // entry fails and names itself, and a manifest entry with no file fails too,
  // which catches a rename that a one-directional check reads as "still above
  // the floor". The inventory is the one place the corpus is enumerated, so
  // adding a vector is a deliberate two-file change rather than a silent one.
  let on_disk: std::vec::Vec<std::string::String> = example_json_files()
    .iter()
    .map(|path| {
      path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_else(|| std::panic!("a corpus path has no file name: {:?}", path))
        .to_string()
    })
    .collect();
  let claimed = manifest_conformance_files();

  let undeclared: std::vec::Vec<&std::string::String> =
    on_disk.iter().filter(|name| !claimed.contains(name)).collect();
  std::assert!(
    undeclared.is_empty(),
    "these files are in {:?} with no entry in {}: {:?}",
    examples_dir(),
    MANIFEST_FILE,
    undeclared
  );

  let missing: std::vec::Vec<&std::string::String> =
    claimed.iter().filter(|name| !on_disk.contains(name)).collect();
  std::assert!(
    missing.is_empty(),
    "{} claims these files that are not on disk: {:?}",
    MANIFEST_FILE,
    missing
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
fn every_repo_example_declares_the_mode_its_proof_structure_supports() {
  // These are the documents the spec hands to third-party implementers.
  // Every published example must pass the §7.1.11 structural rules, and the
  // mode each resolves to must match its wire shape: the single-object
  // corpus is `NotaryAttested` — the claim a notary alone can make; if
  // absence ever resolved to `PrincipalSigned`, those envelopes would start
  // asserting a human signature nobody produced. THREE examples carry a chain
  // and resolve to `PrincipalSigned`, and they are NAMED rather than counted,
  // so a fourth chain arriving unannounced fails here with its own file name
  // instead of behind an off-by-one: the same §7.3.1 credential under each
  // Data Integrity cryptosuite (`principal_signed`, `es256_signed`) plus
  // `ts_minted`, which the TypeScript implementation mints in that same shape.
  // Their cryptographic verification lives in
  // `principal_signed_example_test.rs`, `es256_signed_example_test.rs` and
  // `ts_minted_cross_verify.rs`; `detached_jws_envelope.json` is signed too
  // but is `NotaryAttested`, which is why it is absent from this list.
  // Issuance order (§7.2.1) is also checked corpus-wide here: vacuous for a
  // single proof, load-bearing for the chains.
  let mut principal_signed: std::vec::Vec<std::path::PathBuf> = std::vec::Vec::new();
  for path in example_json_files() {
    let json = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    let parsed: aph_core::envelope::NotarizationEnvelope = serde_json::from_str(&json)
      .unwrap_or_else(|e| std::panic!("{:?} failed strict parse: {}", path, e));
    let mode = aph_core::verification::verify_proof_structure(&parsed)
      .unwrap_or_else(|e| std::panic!("{:?} failed §7.1.11 structure: {}", path, e));
    aph_core::verification::verify_timestamp_order(&parsed)
      .unwrap_or_else(|e| std::panic!("{:?} failed §7.2.1 issuance order: {}", path, e));
    match mode {
      aph_core::envelope::AttestationMode::NotaryAttested => {
        std::assert!(
          !parsed.proof.is_chain(),
          "{:?} resolves NotaryAttested and must carry the single-object form",
          path
        );
      }
      aph_core::envelope::AttestationMode::PrincipalSigned => {
        std::assert!(
          parsed.proof.is_chain(),
          "{:?} resolves PrincipalSigned and must carry the chain form",
          path
        );
        principal_signed.push(path.clone());
      }
    }
  }
  let mut found: std::vec::Vec<&str> = principal_signed
    .iter()
    .filter_map(|path| path.file_name().and_then(std::ffi::OsStr::to_str))
    .collect();
  found.sort();
  std::assert_eq!(
    found,
    std::vec![
      "es256_signed_envelope.json",
      "principal_signed_envelope.json",
      "ts_minted_envelope.json"
    ],
    "the PrincipalSigned examples are exactly the signed §7.3.1 chains: one per Data Integrity cryptosuite, plus the TypeScript-minted artifact"
  );
}

#[test]
fn no_repo_example_carries_an_embedded_delegation_mandate_it_cannot_bind() {
  // `verify_embedded_mandate_binding` is a no-op when no mandate is
  // embedded, so running it over the corpus proves the published examples
  // are internally consistent. Since the signed §7.3.1 golden landed, this
  // is no longer vacuous for the whole corpus: that example embeds its
  // parent mandate, and it must name this envelope's own human, agent and
  // mandate id — anything else would be teaching implementers the exact
  // staple §7.1.7.1 exists to forbid.
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
