//! WHY THIS FILE EXISTS: canonicalization is the part of the protocol that
//! leans hardest on ECMAScript semantics, but it is not the only part that runs
//! on them. The strict parser, the §7.1.11 proof-structure gate and the §11
//! taxonomy are ordinary program logic — and "ordinary program logic that
//! happens to work on one runtime" is exactly the claim a second implementation
//! is supposed to be able to drop. This file runs that logic under the second
//! engine over the PUBLISHED corpus, so the second implementation's portability
//! claim covers the verifier's front half and not only its canonicalizer.
//!
//! WHAT IT PINS, per published example: that §8.3 step 1 strict parse succeeds,
//! that the §7.1.11 structure check agrees with the `attestationMode` LABEL,
//! and that canonicalization is a fixed point on a real document (the edge
//! values in the shared table are chosen; a document's numbers are whatever a
//! notary emitted). Then, from ONE published chain, four mutations that must
//! each refuse with `APH_E013` and one that must fail strict parse — the
//! refusal codes reachable without a signature, reaching the same verdicts
//! under a second engine.
//!
//! WHAT IT DOES NOT PIN: anything with a signature in it. A language engine has
//! no WebCrypto; those paths stay under the runtime that does. Nothing here is
//! signed and no key material appears — every mutation is made in memory
//! against a committed vector, which is never rewritten.

/// The published corpus directory. This crate sits at
/// `interpreters/rust/aph-js-harness`, so the examples resolve three levels up.
fn examples_dir() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples")
}

/// Every `*.json` in the corpus, enumerated from disk rather than remembered.
fn example_json_files() -> std::vec::Vec<std::path::PathBuf> {
  let dir = examples_dir();
  let entries = std::fs::read_dir(&dir)
    .unwrap_or_else(|error| std::panic!("could not read {}: {}", dir.display(), error));
  let mut files: std::vec::Vec<std::path::PathBuf> = entries
    .map(|entry| {
      entry
        .unwrap_or_else(|error| std::panic!("could not read a corpus entry: {error}"))
        .path()
    })
    .filter(|path| {
      path.extension().and_then(std::ffi::OsStr::to_str) == std::option::Option::Some("json")
    })
    .collect();
  files.sort();
  files
}

/// Reads a corpus file's TEXT, because strict parse is defined over bytes.
fn read_example(name: &str) -> std::string::String {
  let path = examples_dir().join(name);
  std::fs::read_to_string(&path)
    .unwrap_or_else(|error| std::panic!("could not read {}: {}", path.display(), error))
}

/// Wraps an envelope's text as the driver's request object.
fn request(text: &str) -> std::string::String {
  serde_json::to_string(&serde_json::json!({ "text": text }))
    .unwrap_or_else(|error| std::panic!("could not build the driver request: {error}"))
}

/// The published `PrincipalSigned` chain, the one vector every structure rule
/// can be reached from by removing something.
const CHAIN_VECTOR: &str = "principal_signed_envelope.json";

/// Applies one in-memory mutation to the published chain and returns its text.
///
/// The committed file is never touched. A mutated document has no valid
/// signature over it any more, which does not matter here: every rule this file
/// reaches runs BEFORE any signature is checked, and that ordering is the
/// reason the rules exist — `attestationMode` is a self-asserted string, so a
/// verifier that trusted the label would report a forged authorization as the
/// human's own.
fn mutated_chain(mutate: impl FnOnce(&mut serde_json::Value)) -> std::string::String {
  let mut document: serde_json::Value = serde_json::from_str(&read_example(CHAIN_VECTOR))
    .unwrap_or_else(|error| std::panic!("the published chain is not JSON: {error}"));
  mutate(&mut document);
  serde_json::to_string(&document)
    .unwrap_or_else(|error| std::panic!("could not reserialize the mutated chain: {error}"))
}

/// The proof at `index` of a document being mutated.
fn proof_at(document: &mut serde_json::Value, index: usize) -> &mut serde_json::Value {
  document
    .get_mut("proof")
    .and_then(|proof| proof.get_mut(index))
    .unwrap_or_else(|| std::panic!("the published chain has no proof at index {index}"))
}

#[test]
fn the_corpus_is_not_empty() {
  // Guards against a vacuous run: if path resolution broke or the directory
  // emptied, the per-file assertions below would iterate nothing and pass.
  //
  // The floor is the ENUMERATED corpus rather than a remembered number: seven
  // channel-shape fixtures, one registered-extensions fixture, and four signed
  // vectors — the eddsa-jcs-2022 chain, the ecdsa-jcs-2019 chain, the
  // JsonWebSignature2020 carriage, and the chain minted by the second
  // implementation itself. A thirteenth file is fine and passes here; a lost
  // one is not.
  std::assert!(
    example_json_files().len() >= 12,
    "the published corpus is smaller than the vectors this repository ships"
  );
}

#[test]
fn every_published_example_parses_and_its_structure_matches_its_label() {
  let mut engine = aph_js_harness::Engine::boot();

  for path in example_json_files() {
    let name = path
      .file_name()
      .and_then(std::ffi::OsStr::to_str)
      .unwrap_or_else(|| std::panic!("a corpus path has no file name: {}", path.display()))
      .to_string();
    let text = std::fs::read_to_string(&path)
      .unwrap_or_else(|error| std::panic!("could not read {}: {}", path.display(), error));

    let inspection: aph_js_harness::EnvelopeInspection =
      engine.call_json("inspectEnvelope", &request(&text));

    std::assert!(
      inspection.parsed,
      "{name} failed §8.3 step 1 strict parse under the second engine: {:?}",
      inspection.parse_error
    );
    std::assert!(
      inspection.structure_error.is_none(),
      "{name} passes the §7.1.11 structure check under the node suite and is refused here: {:?}",
      inspection.structure_error
    );
    // `verifyProofStructure` returns the mode the STRUCTURE proves, and it
    // refuses whenever that disagrees with the label in either direction. So
    // this equality is what "the label was earned" looks like from outside.
    std::assert_eq!(
      inspection.structure_mode, inspection.declared_mode,
      "{name}: the proven mode and the declared mode disagree under the second engine"
    );
    std::assert!(
      inspection.declared_mode.is_some(),
      "{name}: no attestation mode was reported, but §7.1.7 makes an absent one NotaryAttested"
    );
    std::assert_eq!(
      inspection.canonical_stable,
      std::option::Option::Some(true),
      "{name}: canonicalizing the canonical form did not reproduce it under the second engine"
    );
  }
}

#[test]
fn the_structure_rules_refuse_with_aph_e013_under_the_second_engine() {
  let mut engine = aph_js_harness::Engine::boot();

  // Each mutation removes exactly ONE thing that makes a two-element chain a
  // chain, and each is a real attack rather than a typo: relabel the mode,
  // unlink the countersignature, restate the notary's purpose as the
  // principal's, or collapse the two proof identities into one.
  let mutations: [(&str, std::string::String); 4] = [
    (
      "a two-element chain relabelled NotaryAttested",
      mutated_chain(|document| {
        document["credentialSubject"]["policy"]["attestationMode"] =
          serde_json::Value::String(std::string::String::from("NotaryAttested"));
      }),
    ),
    (
      "the notary proof with no previousProof to countersign",
      mutated_chain(|document| {
        let removed = proof_at(document, 1)
          .as_object_mut()
          .unwrap_or_else(|| std::panic!("the notary proof is not an object"))
          .remove("previousProof");
        // Asserted rather than discarded: if the published chain ever stops
        // carrying the member, this case silently stops testing anything.
        std::assert!(
          removed.is_some(),
          "the published chain's notary proof carries no previousProof to remove"
        );
      }),
    ),
    (
      "the notary proof claiming the principal's proofPurpose",
      mutated_chain(|document| {
        proof_at(document, 1)["proofPurpose"] =
          serde_json::Value::String(std::string::String::from("assertionMethod"));
      }),
    ),
    (
      "both proofs carrying one id",
      mutated_chain(|document| {
        let notary_id = proof_at(document, 1)["id"].clone();
        proof_at(document, 0)["id"] = notary_id;
      }),
    ),
  ];

  for (what, text) in mutations {
    let inspection: aph_js_harness::EnvelopeInspection =
      engine.call_json("inspectEnvelope", &request(&text));
    std::assert!(
      inspection.parsed,
      "{what}: this is a STRUCTURE case and must survive strict parse to reach it — {:?}",
      inspection.parse_error
    );
    let refusal = inspection.structure_error.unwrap_or_else(|| {
      std::panic!("{what}: admitted under the second engine, and §7.1.11 refuses it")
    });
    std::assert_eq!(
      refusal.code.as_deref(),
      std::option::Option::Some("APH_E013"),
      "{what}: refused under the wrong §11 code — {}",
      refusal.message
    );
  }
}

#[test]
fn an_unknown_member_is_a_strict_parse_failure_under_the_second_engine() {
  let mut engine = aph_js_harness::Engine::boot();
  // §7.1's forward-compatibility behaviour is to FAIL FAST on drift, so a
  // producer cannot smuggle a claim past a verifier that does not understand
  // it. The failure carries a JSON path and NO §11 code: §11 has no parse
  // variant, and reporting a typo as, say, APH_E001 would send an operator to
  // inspect key material.
  let text = mutated_chain(|document| {
    document["unrecognizedMember"] = serde_json::Value::Bool(true);
  });

  let inspection: aph_js_harness::EnvelopeInspection =
    engine.call_json("inspectEnvelope", &request(&text));
  std::assert!(
    !inspection.parsed,
    "an unknown top-level member was admitted under the second engine"
  );
  let failure = inspection
    .parse_error
    .unwrap_or_else(|| std::panic!("the parse failed with nothing describing it"));
  std::assert_eq!(
    failure.name, "AphParseError",
    "the strict-parse failure arrived as the wrong kind: {}",
    failure.message
  );
  std::assert_eq!(
    failure.path.as_deref(),
    std::option::Option::Some("$.unrecognizedMember"),
    "the failure named the wrong member; a path is the only actionable part of it"
  );
  std::assert!(
    failure.code.is_none(),
    "a strict-parse failure carried a §11 code, which would widen a closed set"
  );
}

#[test]
fn the_error_taxonomy_is_self_consistent_under_the_second_engine() {
  let mut engine = aph_js_harness::Engine::boot();
  let taxonomy: aph_js_harness::ErrorTaxonomy = engine.call_json("errorTaxonomy", "null");

  // Count-free on purpose. §11's set is closed, but a number written here would
  // be a second place to update when it changes — and the property worth
  // holding is that the two declarations in the module AGREE, which is checked
  // in both directions from the enumeration itself.
  std::assert!(
    !taxonomy.codes.is_empty(),
    "the taxonomy came back empty, so the module did not load"
  );
  std::assert_eq!(
    taxonomy.codes.len(),
    taxonomy.variants.len(),
    "the code list and the variant map are different sizes"
  );

  let mut previous: std::option::Option<&str> = std::option::Option::None;
  for code in &taxonomy.codes {
    std::assert!(
      code.len() == 8 && code.starts_with("APH_E") && code[5..].chars().all(|c| c.is_ascii_digit()),
      "{code} is not an APH_Ennn code"
    );
    // Ascending order is not decoration: the codes are cited by number
    // throughout the specification, and a list that drifted out of order is the
    // first sign that one was inserted rather than appended.
    if let std::option::Option::Some(earlier) = previous {
      std::assert!(
        earlier < code.as_str(),
        "{earlier} is listed before {code}, so the taxonomy is out of order or repeats"
      );
    }
    previous = std::option::Option::Some(code.as_str());

    let variant = taxonomy
      .variants
      .get(code)
      .unwrap_or_else(|| std::panic!("{code} has no variant name beside it"));
    std::assert!(!variant.is_empty(), "{code}'s variant name is empty");
  }

  for code in taxonomy.variants.keys() {
    std::assert!(
      taxonomy.codes.contains(code),
      "{code} has a variant name but is not in the code list"
    );
  }
}
