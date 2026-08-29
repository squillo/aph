//! The guardrail seals, counted — and the recipes held to the sources.
//!
//! WHY THIS EXISTS. Six guardrail families are SEALED: they refuse every
//! overlay, and the only change path is a new base version a verifier can
//! see. Until this walker, nothing in the repository even COUNTED the seals
//! — a `sealed = true` dropped in an edit would have vanished silently, and
//! the registry that says WHICH families are sealed lived only in prose
//! (the bundle README). A flag nobody counts and a list nobody checks are
//! the two halves of the same drift.
//!
//! WHAT IT PINS. Three welds over the SOURCES (never the compiled bundle,
//! which is a build artifact of these files):
//! 1. the sealed set the classifier sources declare EQUALS the set
//!    `SEALED_CANON.md` registers, both directions;
//! 2. the family census: every family `mod.n.md` declares has a source
//!    file, and the walker saw every one — a walker that silently saw
//!    nothing would pass every membership check;
//! 3. every label-shaped identifier a `how/` recipe excerpts exists
//!    VERBATIM in the classifier sources. The recipes quote real classifier
//!    code, and hand-abbreviated label names have shipped in them before —
//!    a recipe teaching a label that does not exist teaches an integrator
//!    to emit a value every verifier refuses.
//!
//! ZERO `#[ignore]`.

/// Repository root, three levels up from this crate.
fn repo_root() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn guardrails_root() -> std::path::PathBuf {
  repo_root().join("APH Guardrails/0.1.0")
}

/// The families `mod.n.md` declares, in declaration order — the load order,
/// and the one census of what exists.
fn declared_families() -> std::vec::Vec<String> {
  let path = guardrails_root().join("APH_GUARDRAILS/mod.n.md");
  let text = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
  let mut families = std::vec::Vec::new();
  for line in text.lines() {
    let trimmed = line.trim();
    if let std::option::Option::Some(rest) = trimmed.strip_prefix("mod ") {
      if let std::option::Option::Some(name) = rest.strip_suffix(" {};") {
        families.push(name.to_string());
      }
    }
  }
  std::assert!(
    !families.is_empty(),
    "mod.n.md declares no families; the declaration syntax has moved and \
     this walker must be re-anchored, not left passing vacuously"
  );
  families
}

/// Whether one family's source declares `sealed = true` inside its
/// `classifiers` block. Absence of the flag is UNSEALED — the sources write
/// the flag only when it is set, and the walker refuses a file it cannot
/// read rather than reporting it unsealed.
fn source_is_sealed(family: &str) -> bool {
  let path = guardrails_root().join(std::format!("APH_GUARDRAILS/{}.n.md", family));
  let text = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
  text.lines().any(|line| {
    let compact: String = line.split_whitespace().collect::<std::vec::Vec<&str>>().join(" ");
    compact == "sealed = true"
  })
}

/// The sealed set `SEALED_CANON.md` registers: every family named in
/// backticks in its table rows.
fn registered_sealed() -> std::collections::BTreeSet<String> {
  let path = guardrails_root().join("SEALED_CANON.md");
  let text = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
  let mut set = std::collections::BTreeSet::new();
  for line in text.lines() {
    if !line.starts_with("| `APH_") {
      continue;
    }
    let after = &line[3..];
    if let std::option::Option::Some(end) = after.find('`') {
      set.insert(after[..end].to_string());
    }
  }
  std::assert!(
    !set.is_empty(),
    "SEALED_CANON.md registers no families; the table has been rewritten and \
     this weld must be re-anchored"
  );
  set
}

#[test]
fn the_sources_and_the_registry_agree_on_the_sealed_set() {
  // Both directions, reported as the distinct defects they are: a source
  // seal the registry lacks is a seal with no stated reason; a registered
  // seal the sources lack is a promise the flags no longer keep.
  let families = declared_families();
  let from_sources: std::collections::BTreeSet<String> = families
    .iter()
    .filter(|family| source_is_sealed(family))
    .cloned()
    .collect();
  let from_registry = registered_sealed();

  let unregistered: std::vec::Vec<&String> =
    from_sources.difference(&from_registry).collect();
  std::assert!(
    unregistered.is_empty(),
    "sealed in the sources but absent from SEALED_CANON.md (a seal with no \
     stated reason): {:?}",
    unregistered
  );
  let unkept: std::vec::Vec<&String> = from_registry.difference(&from_sources).collect();
  std::assert!(
    unkept.is_empty(),
    "registered in SEALED_CANON.md but not sealed in the sources (a promise \
     the flags no longer keep): {:?}",
    unkept
  );
}

#[test]
fn every_declared_family_has_a_source_the_walker_actually_read() {
  // The census that keeps the membership test above from passing over
  // nothing: each declared family's file exists and was classified one way
  // or the other. The count is not pinned to a literal — mod.n.md is the
  // one census and adding a family there is the deliberate act — but zero
  // and duplicates are both refused.
  let families = declared_families();
  let unique: std::collections::BTreeSet<&String> = families.iter().collect();
  std::assert_eq!(
    unique.len(),
    families.len(),
    "mod.n.md declares a family twice; declaration order is load order and a \
     duplicate loads twice"
  );
  for family in &families {
    // source_is_sealed panics on an unreadable file, which is the point:
    // a family declared but absent must fail here by name.
    let _ = source_is_sealed(family);
  }
}

#[test]
fn every_label_a_recipe_excerpts_exists_verbatim_in_the_sources() {
  // The recipes under `how/` excerpt real classifier code, and their label
  // names have been hand-abbreviated before. A label is extracted from a
  // recipe only where it appears in DECLARATION SHAPE — `NAME {` — so prose
  // and tags cannot false-positive; the same shape is what collects the
  // declared labels from the sources.
  //
  // ONE exemption, and it is loud by construction: a recipe may declare a
  // label that ships nowhere — the overlay tutorial does, to show the
  // additive direction without minting vocabulary — ONLY when the word
  // HYPOTHETICAL appears inside that label's own block. The walker's first
  // ever run caught exactly this case and the recipe had already marked it;
  // the rule admits what is declared and still refuses what is merely
  // misspelled, which is the drift this weld exists for.
  fn declaration_shaped(text: &str) -> std::collections::BTreeSet<String> {
    let lines: std::vec::Vec<&str> = text.lines().collect();
    let mut labels = std::collections::BTreeSet::new();
    for (index, line) in lines.iter().enumerate() {
      let trimmed = line.trim_start();
      if let std::option::Option::Some(brace) = trimmed.find(" {") {
        let candidate = &trimmed[..brace];
        if candidate.len() >= 4
          && candidate
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
          && candidate.contains('_')
        {
          let marked_hypothetical = lines[index..std::cmp::min(index + 4, lines.len())]
            .iter()
            .any(|following| following.contains("HYPOTHETICAL"));
          if !marked_hypothetical {
            labels.insert(candidate.to_string());
          }
        }
      }
    }
    labels
  }

  let mut declared = std::collections::BTreeSet::new();
  for family in declared_families() {
    let path = guardrails_root().join(std::format!("APH_GUARDRAILS/{}.n.md", family));
    let text = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    declared.extend(declaration_shaped(&text));
    declared.insert(family);
  }

  let how = guardrails_root().join("how");
  let mut recipes = std::vec::Vec::new();
  let mut stack = std::vec![how.clone()];
  while let std::option::Option::Some(dir) = stack.pop() {
    for entry in std::fs::read_dir(&dir)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", dir, e))
    {
      let path = entry.expect("a readable directory entry").path();
      if path.is_dir() {
        stack.push(path);
      } else if path.extension().and_then(|s| s.to_str()) == std::option::Option::Some("json") {
        recipes.push(path);
      }
    }
  }
  std::assert!(
    !recipes.is_empty(),
    "no recipes under {:?}; the layout moved and this weld must be re-anchored",
    how
  );

  let mut ghosts = std::vec::Vec::new();
  for path in &recipes {
    let raw = std::fs::read_to_string(path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    let recipe: serde_json::Value = serde_json::from_str(&raw)
      .unwrap_or_else(|e| std::panic!("{:?} is not valid JSON: {}", path, e));
    let code = recipe
      .get("nlang_code")
      .and_then(serde_json::Value::as_str)
      .unwrap_or("");
    for label in declaration_shaped(code) {
      if !declared.contains(&label) {
        ghosts.push(std::format!(
          "{}: `{}`",
          path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
          label
        ));
      }
    }
  }
  std::assert!(
    ghosts.is_empty(),
    "recipes excerpt labels no classifier source declares — an integrator \
     taught these would emit values every verifier refuses:\n  {}",
    ghosts.join("\n  ")
  );
}
