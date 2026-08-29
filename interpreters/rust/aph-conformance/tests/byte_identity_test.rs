//! WHY THIS FILE EXISTS: the protocol's portability guarantee is BYTE
//! identity — every surface that emits an envelope's canonical form must
//! produce the same bytes, because those bytes are what signatures cover.
//! Until this file, nothing in the workspace's DEFAULT test set compared
//! canonical output across implementations at all: every binding sits
//! outside the default members, so a plain `cargo test` measured aph-core
//! against nobody. This rig lives in a default member so the byte gate runs
//! on every run, not only when someone remembers to name a package.
//!
//! WHAT IT PINS — precisely, including what it does NOT prove:
//!
//! - DRIVEN HERE, always: aph-core's canonical emission over every corpus
//!   file — a fixed point under reparse, and byte-identical whether the
//!   document travels through `serde_json::Value` or through the strict
//!   typed model. (`repo_examples_test.rs` pins VALUE equality for the
//!   typed round trip; this file restates the claim in bytes, the currency
//!   signatures actually spend.)
//! - DRIVEN HERE, when `interpreters/typescript/dist` exists on disk: the
//!   second implementation's own RFC 8785 canonicalizer — the compiled
//!   TypeScript, evaluated under the embedded second ECMAScript engine via
//!   `aph-js-harness`, with no Node process taking part — over the same
//!   corpus, byte-for-byte against aph-core. This is the one genuinely
//!   independent serializer reachable in-process: it shares no code with
//!   the workspace.
//! - NOT DRIVEN HERE: the wasm, Python, Go-embedded-wasm and Elixir-NIF
//!   surfaces. Each is aph-core's own serializer recompiled behind a
//!   JSON-text boundary, so byte identity for them is an artifact and
//!   toolchain question, not a second opinion — and each is unreachable
//!   from an in-process default-member test for a structural reason (a
//!   wasm32 artifact needs a wasm runtime, the Python binding a linked
//!   libpython, a NIF a hosting BEAM). Their owning gates are named, out
//!   loud, by `every_shipping_surface_is_driven_here_or_announced`, which
//!   also fails when a new workspace member arrives unclassified.
//!
//! HOW A SKIP READS: absence of the compiled TypeScript is ANNOUNCED — a
//! `BYTE RIG SKIPPED` line on stderr naming exactly what was not measured —
//! never a silent pass, because a skip nobody sees is a gate that measures
//! nothing. The announcement is the floor, not the ceiling: the test
//! harness captures passing output, so the line is visible under
//! `--nocapture` and in any failing run — which is why a runner that has
//! built the TypeScript (or is about to claim cross-implementation
//! coverage) sets `APH_BYTE_RIG_REQUIRE_TS=1`, turning the skip into a
//! failure instead of a print.
//!
//! HOW A FAILURE READS: divergences are collected, not thrown on sight, so
//! one run reports every disagreeing file with both canonical texts and the
//! offset of the first disagreeing byte.
//!
//! ZERO `#[ignore]`. ZERO `use` statements.

/// Returns the absolute path of the spec repository's `examples/` directory.
fn examples_dir() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples")
}

/// The corpus INVENTORY, which lives in the corpus directory and is not
/// itself a vector.
const MANIFEST_FILE: &str = "manifest.json";

/// The strict-mode switch: set (to anything but `0` or empty) it turns the
/// announced TypeScript skip into a failure. Meant for any runner that has
/// already built `interpreters/typescript/dist` — there, a skip would mean
/// the rig quietly measured less than the runner believes it did.
const REQUIRE_TS_ENV: &str = "APH_BYTE_RIG_REQUIRE_TS";

/// Whether this run is allowed to skip the cross-implementation comparison.
fn ts_comparison_required() -> bool {
  std::env::var_os(REQUIRE_TS_ENV).is_some_and(|v| !v.is_empty() && v != "0")
}

/// The conformance corpus: every `(file name, file text)` the manifest
/// claims, in manifest order.
///
/// Enumerated from the manifest rather than the directory because the
/// manifest is the corpus's single declared inventory; the two-way
/// manifest-versus-disk census is `repo_examples_test.rs`'s pin and is not
/// repeated here. What IS guarded here is this rig's own vacuity: zero
/// files, a duplicate name (results come back matched by name), or a
/// claimed file that does not read all fail loudly rather than shrink the
/// corpus this rig silently measures.
fn corpus() -> std::vec::Vec<(std::string::String, std::string::String)> {
  let path = examples_dir().join(MANIFEST_FILE);
  let raw = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("could not read the corpus manifest {:?}: {}", path, e));
  let parsed: serde_json::Value = serde_json::from_str(&raw)
    .unwrap_or_else(|e| std::panic!("the corpus manifest {:?} is not valid JSON: {}", path, e));
  let names: std::vec::Vec<std::string::String> = parsed
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
  std::assert!(
    !names.is_empty(),
    "the corpus manifest names zero conformance files — every comparison in this rig would \
     run over nothing and pass"
  );
  let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
  for name in &names {
    std::assert!(
      seen.insert(name.as_str()),
      "the corpus manifest names {} twice — results are matched back by name, so a duplicate \
       would let one file's divergence hide behind its twin",
      name
    );
  }
  names
    .into_iter()
    .map(|name| {
      let file = examples_dir().join(&name);
      let text = std::fs::read_to_string(&file).unwrap_or_else(|e| {
        std::panic!("the manifest claims {:?} but it does not read: {}", file, e)
      });
      (name, text)
    })
    .collect()
}

/// The byte offset where two canonical texts first disagree.
fn first_difference(ours: &str, theirs: &str) -> usize {
  ours
    .bytes()
    .zip(theirs.bytes())
    .position(|(a, b)| a != b)
    .unwrap_or_else(|| ours.len().min(theirs.len()))
}

/// Renders one file's disagreement with everything a reader needs to act on.
/// The two labels name the emission paths being compared, because this rig
/// compares more than one pair and a mislabelled column would send a reader
/// debugging the wrong surface.
fn divergence(
  file: &str,
  left_label: &str,
  left: &str,
  right_label: &str,
  right: &str,
) -> std::string::String {
  std::format!(
    "  file: {file}\n    first differing byte: {}\n    {:<15}{left}\n    {:<15}{right}\n",
    first_difference(left, right),
    std::format!("{left_label}:"),
    std::format!("{right_label}:")
  )
}

#[test]
fn aph_core_canonical_bytes_are_stable_and_the_typed_model_loses_nothing() {
  // The always-on half of the rig — it needs no artifact and so can never
  // skip. Two byte-level claims per corpus file. FIXED POINT: canonicalizing
  // the canonical form reproduces it exactly, so there is one canonical byte
  // string per document, not a sequence that converges. THE TYPED MODEL IS
  // CANONICALLY LOSSLESS: strict-parsing into `NotarizationEnvelope` and
  // re-emitting yields the same canonical bytes as the raw JSON value — a
  // defaulted field that starts serializing, a rename, or a dropped member
  // would all move the bytes a signature covers, and this is where that
  // moves first on a plain `cargo test`.
  for (name, text) in corpus() {
    let parsed: serde_json::Value = serde_json::from_str(&text)
      .unwrap_or_else(|e| std::panic!("{} is not valid JSON: {}", name, e));
    let first = aph_core::canonicalize_rfc8785(&parsed);
    let reparsed: serde_json::Value = serde_json::from_str(&first).unwrap_or_else(|e| {
      std::panic!("{}: aph-core's own canonical output failed to reparse: {}", name, e)
    });
    let second = aph_core::canonicalize_rfc8785(&reparsed);
    std::assert!(
      first == second,
      "{}: canonical emission is not a fixed point — pass one and pass two disagree\n{}",
      name,
      divergence(&name, "pass one", &first, "pass two", &second)
    );

    let typed: aph_core::envelope::NotarizationEnvelope = serde_json::from_str(&text)
      .unwrap_or_else(|e| std::panic!("{} failed strict parse: {}", name, e));
    let reemitted = serde_json::to_value(&typed)
      .unwrap_or_else(|e| std::panic!("{} failed to convert to a value: {}", name, e));
    let through_types = aph_core::canonicalize_rfc8785(&reemitted);
    std::assert!(
      through_types == first,
      "{}: the typed model changed the canonical bytes — parse into \
       NotarizationEnvelope and re-emission no longer reproduce the raw document's \
       canonical form\n{}",
      name,
      divergence(&name, "raw value", &first, "typed model", &through_types)
    );
  }
}

#[test]
fn ts_canonical_bytes_match_aph_core_over_the_corpus_or_the_skip_is_loud() {
  // The cross-implementation half: the same corpus canonicalized by the one
  // genuinely independent serializer reachable in-process — the second
  // implementation's compiled canonicalizer under the embedded second
  // ECMAScript engine. These are the bytes signatures cover, so agreement
  // here is what lets an envelope minted by either implementation verify
  // under the other. The comparison happens on this side, where a mismatch
  // prints both outputs; the driver decides nothing.
  //
  // aph-core's canonicalizer documents two DELIBERATE divergences from
  // strict RFC 8785 (key order is UTF-8 byte order, floats are Rust
  // `Display`) that are invisible on real protocol documents and
  // signature-load-bearing where they show. If a corpus file ever carries a
  // value in that divergence class, this test goes red — which is correct:
  // that document's signature would not survive crossing implementations,
  // and the corpus teaches implementers what to emit.
  let entry = aph_js_harness::dist_entry();
  if !entry.is_file() {
    std::assert!(
      !ts_comparison_required(),
      "\n{REQUIRE_TS_ENV} is set, but {} is absent — this run PROMISED the \
       cross-implementation byte comparison and cannot perform it.\n\
       Build the second implementation first:\n\
       \x20   cd interpreters/typescript && npm install && npm run build\n",
      entry.display()
    );
    std::eprintln!(
      "BYTE RIG SKIPPED — typescript-under-second-engine: {} is absent (the second \
       implementation was never built), so canonical bytes were NOT compared across \
       implementations in this run. Build it: cd interpreters/typescript && npm install && \
       npm run build. To make this skip a failure instead, set {}=1.",
      entry.display(),
      REQUIRE_TS_ENV
    );
    return;
  }

  let corpus = corpus();
  let rows: std::vec::Vec<serde_json::Value> = corpus
    .iter()
    .map(|(name, text)| serde_json::json!({ "name": name, "json": text }))
    .collect();
  let request = serde_json::json!({ "canonicalize": rows }).to_string();

  let mut engine = aph_js_harness::Engine::boot();
  let results: std::vec::Vec<aph_js_harness::CaseResult> =
    engine.call_json("canonicalizeCases", &request);
  std::assert_eq!(
    results.len(),
    corpus.len(),
    "the second engine answered for a different number of files than the corpus holds"
  );

  let mut divergences: std::vec::Vec<std::string::String> = std::vec::Vec::new();
  for ((name, text), result) in corpus.iter().zip(results.iter()) {
    // Matched by NAME rather than trusted by position: a driver that dropped
    // a file would otherwise shift every later comparison onto the wrong
    // document and report a wall of failures with no real one among them.
    std::assert_eq!(
      result.name, *name,
      "the second engine's answers came back out of order"
    );
    let parsed: serde_json::Value = serde_json::from_str(text)
      .unwrap_or_else(|e| std::panic!("{} is not valid JSON: {}", name, e));
    let ours = aph_core::canonicalize_rfc8785(&parsed);

    match (&result.canonical, &result.threw) {
      (std::option::Option::Some(theirs), _) if *theirs == ours => {}
      (std::option::Option::Some(theirs), _) => {
        divergences.push(divergence(name, "aph-core", &ours, "second engine", theirs));
      }
      (std::option::Option::None, std::option::Option::Some(threw)) => {
        divergences.push(divergence(
          name,
          "aph-core",
          &ours,
          "second engine",
          &std::format!("REFUSED with {}: {}", threw.name, threw.message),
        ));
      }
      (std::option::Option::None, std::option::Option::None) => {
        divergences.push(divergence(
          name,
          "aph-core",
          &ours,
          "second engine",
          "nothing — the driver returned neither a result nor a refusal",
        ));
      }
    }
  }

  std::assert!(
    divergences.is_empty(),
    "\nTWO IMPLEMENTATIONS DISAGREE about an envelope's canonical bytes.\n\n\
     Each corpus file below canonicalizes differently under aph-core and under the second \
     implementation's compiled canonicalizer. These are the bytes signatures cover: a \
     divergence here means an envelope signed by one implementation cannot verify under \
     the other. Fix the implementation, never the corpus.\n\n{}",
    divergences.join("")
  );
}

#[test]
fn every_shipping_surface_is_driven_here_or_announced() {
  // The roster-level guard: a byte-identity rig that quietly never measured
  // a surface would be a gate that measures nothing for that surface, so
  // every workspace member OUTSIDE the default set must be classified here —
  // either driven by this rig or announced with the gate that owns its
  // bytes. The membership lists are read from the workspace manifest rather
  // than repeated, so a NEW binding crate arriving outside the default set
  // fails this test by name until someone decides, in this file, whether it
  // is drivable in-process. The two surfaces that are not workspace members
  // at all (the Elixir NIF and the TypeScript implementation under its own
  // runtime) cannot be discovered from the manifest and are announced
  // statically below.
  let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
  let manifest = std::fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
    std::panic!("could not read the workspace manifest {:?}: {}", manifest_path, e)
  });
  let members = quoted_entries(&manifest, "\nmembers = [");
  let defaults = quoted_entries(&manifest, "default-members = [");
  for name in &defaults {
    std::assert!(
      members.contains(name),
      "the workspace manifest lists default member {} that is not a member — the roster \
       parser no longer reads the manifest correctly",
      name
    );
  }
  let outside: std::vec::Vec<std::string::String> = members
    .iter()
    .filter(|member| !defaults.iter().any(|d| d == *member))
    .cloned()
    .collect();

  // Member name -> how its canonical bytes are measured. Every entry that is
  // not driven by this rig names the gate that owns it: each of these
  // surfaces is aph-core's serializer recompiled behind a JSON-text
  // boundary, so its byte identity is an artifact and toolchain question
  // answered by its own suite plus the committed-artifact byte diffs, not a
  // second opinion this rig could collect in-process.
  let classified: std::collections::BTreeMap<&str, &str> = [
    (
      "aph-ts",
      "the wasm binding (wasm32 target): cargo test -p aph-ts, and wasm-pack test --node aph-ts",
    ),
    (
      "aph-py",
      "the Python binding (needs a shared libpython): cargo test -p aph-py",
    ),
    (
      "aph-wasm-abi",
      "the raw-ABI wasm32 artifact the Go binding embeds and runs: interpreters/go, \
       go test ./... (the committed module is byte-diffed in CI)",
    ),
    (
      "aph-js-harness",
      "driven from this rig when interpreters/typescript/dist exists; its own suite: \
       cargo test -p aph-js-harness",
    ),
  ]
  .into_iter()
  .collect();

  let unclassified: std::vec::Vec<&std::string::String> = outside
    .iter()
    .filter(|member| !classified.contains_key(member.as_str()))
    .collect();
  std::assert!(
    unclassified.is_empty(),
    "these workspace members sit outside the default set and are not classified by the \
     byte rig — decide whether each is drivable in-process, then either drive it here or \
     announce its owning gate in this test: {:?}",
    unclassified
  );
  let stale: std::vec::Vec<&str> = classified
    .keys()
    .copied()
    .filter(|name| !outside.iter().any(|member| member.as_str() == *name))
    .collect();
  std::assert!(
    stale.is_empty(),
    "the byte rig classifies surfaces that are no longer non-default workspace members — \
     remove them so the roster stays exactly the set the manifest declares: {:?}",
    stale
  );

  for member in &outside {
    if member == "aph-js-harness" {
      if aph_js_harness::dist_entry().is_file() {
        // Driven, in this same run, by the corpus comparison test above.
        continue;
      }
      std::eprintln!(
        "BYTE RIG SKIPPED — typescript-under-second-engine: interpreters/typescript/dist \
         is absent, so this run did not compare canonical bytes across implementations. \
         See ts_canonical_bytes_match_aph_core_over_the_corpus_or_the_skip_is_loud."
      );
      continue;
    }
    std::eprintln!(
      "BYTE RIG DELEGATED — {}: aph-core's serializer recompiled; byte identity owned by: {}",
      member,
      classified[member.as_str()]
    );
  }
  std::eprintln!(
    "BYTE RIG DELEGATED — the Elixir NIF: hosted by the BEAM, unreachable from cargo by \
     design; byte identity owned by: interpreters/elixir, mix test"
  );
  std::eprintln!(
    "BYTE RIG DELEGATED — the TypeScript implementation under its own runtime: \
     interpreters/typescript, npm test (its canonicalizer's bytes ARE compared here, \
     under the second engine, whenever dist exists)"
  );
}

/// The quoted names inside the first bracketed list following `marker`.
///
/// Deliberately a string scan and not a manifest parser: the two arrays it
/// reads hold nothing but quoted crate names, and a real TOML dependency for
/// four names would be a heavier instrument than the job deserves. If the
/// manifest's shape ever changes enough to break the scan, the test fails by
/// panicking here, never by silently reading an empty roster.
fn quoted_entries(manifest: &str, marker: &str) -> std::vec::Vec<std::string::String> {
  let start = manifest.find(marker).unwrap_or_else(|| {
    std::panic!("the workspace manifest no longer contains `{marker}` — update the roster scan")
  }) + marker.len();
  let end = manifest[start..].find(']').unwrap_or_else(|| {
    std::panic!("the workspace manifest's `{marker}` list never closes — update the roster scan")
  }) + start;
  let names: std::vec::Vec<std::string::String> = manifest[start..end]
    .split('"')
    .skip(1)
    .step_by(2)
    .map(str::to_string)
    .collect();
  std::assert!(
    !names.is_empty(),
    "the workspace manifest's `{}` list read as empty — the scan broke, not the manifest",
    marker
  );
  names
}
