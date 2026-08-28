//! Prose counts, welded to the inventory they describe.
//!
//! WHY THIS EXISTS. Two documents state the example corpus's size in prose —
//! `examples/README.md` and `skills/spec/SKILL.md` — and both went stale
//! TWICE in one day: once when the corpus grew and once when the stale copy
//! was corrected in one file and not the other. Both drifts were found by a
//! human reading; nothing checked them. A count in prose is a populator like
//! any other, and an unwelded populator drifts — the same finding, at the
//! same repository, as every vocabulary weld in this suite.
//!
//! WHAT IT PINS. The leading count each document claims equals the manifest's
//! conformance list length. The manifest is the one inventory
//! (`examples/manifest.json`); the prose is derived and must follow. Anchored
//! on the claim's surrounding words, so a rewrite that removes the claim
//! panics loudly — someone must then decide where the count now lives —
//! rather than silently measuring nothing.
//!
//! ZERO `#[ignore]`.

/// Repository root, three levels up from this crate.
fn repo_root() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// The manifest's conformance count — the number every prose claim must match.
fn conformance_count() -> usize {
  let path = repo_root().join("examples/manifest.json");
  let raw = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
  let manifest: serde_json::Value = serde_json::from_str(&raw)
    .unwrap_or_else(|e| std::panic!("the corpus manifest is not valid JSON: {e}"));
  manifest
    .get("conformance")
    .and_then(serde_json::Value::as_array)
    .unwrap_or_else(|| std::panic!("the corpus manifest has no `conformance` array"))
    .len()
}

/// The integer immediately before `suffix` on the first line of `path` that
/// contains `suffix`. Panics when no line carries the claim, because a claim
/// that moved is a decision for a person, not a silently-vacuous test.
fn claimed_count(relative: &str, suffix: &str) -> usize {
  let path = repo_root().join(relative);
  let text = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
  let line = text
    .lines()
    .find(|line| line.contains(suffix))
    .unwrap_or_else(|| {
      std::panic!("{} no longer contains a `{}` claim; re-anchor this weld", relative, suffix)
    });
  let before = &line[..line.find(suffix).unwrap_or(0)];
  let digits: String = before
    .chars()
    .rev()
    .skip_while(|c| c.is_whitespace())
    .take_while(|c| c.is_ascii_digit())
    .collect::<std::vec::Vec<char>>()
    .into_iter()
    .rev()
    .collect();
  digits.parse().unwrap_or_else(|_| {
    std::panic!(
      "{} carries `{}` with no integer before it; the claim has been rewritten:\n{}",
      relative, suffix, line
    )
  })
}

#[test]
fn the_examples_readme_count_is_the_manifests() {
  std::assert_eq!(
    claimed_count("examples/README.md", " example APH `NotarizationEnvelope` JSON files"),
    conformance_count(),
    "examples/README.md states a corpus size the manifest does not; \
     the manifest is the inventory and the prose follows it"
  );
}

#[test]
fn the_agent_skills_count_is_the_manifests() {
  std::assert_eq!(
    claimed_count("skills/spec/SKILL.md", " golden envelope JSON files"),
    conformance_count(),
    "skills/spec/SKILL.md states a corpus size the manifest does not — and an \
     agent LOADS that file to answer questions, so a stale count there is \
     actively taught rather than merely wrong"
  );
}
