//! The populators of the closed sets that are NOT the spec, the reference,
//! or the Snapp: the independent implementation, and the agent skill.
//!
//! WHY THIS EXISTS. Four artifacts now declare the same two vocabularies: the
//! specification, the Rust reference types, the N Lang Snapp, and the
//! independent TypeScript implementation. The first three are welded to each
//! other. The fourth was welded to nothing — and it drifted, silently, in the
//! commit that widened the other three.
//!
//! The escape is worth recording because it is instructive. When `service`
//! and `Mutation` were admitted, the independent implementation kept its
//! seven-member sets. Its own refusal tests still PASSED, because they used
//! `Mutation` as their example of a value that must be refused — and it was
//! still refused there. A green suite reported agreement while the two
//! implementations had begun reaching opposite verdicts on the same bytes,
//! which is the precise defect this wave exists to eliminate.
//!
//! WHAT IT PINS. Membership in both directions, against `aph-core`. Widen one
//! implementation without the other and this goes red. It reads the
//! TypeScript source rather than its build output, so it holds whether or not
//! anything has been compiled.
//!
//! The agent skill is the fifth, and it is the one a reader is most likely
//! to believe without checking. `skills/spec/SKILL.md` is what an agent loads
//! to answer protocol questions, so a stale vocabulary there does not merely
//! sit wrong in a file — it is actively taught. It was stale, by two values,
//! when this was written.
//!
//! ZERO `#[ignore]`.

/// Repository root, three levels up from this crate.
fn repo_root() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// The independent implementation's declaration of one vocabulary.
///
/// Parsed from the source rather than from `dist/`, so a stale or absent
/// build cannot make this pin vacuous — a test that silently measures
/// yesterday's bytes is worse than no test.
fn declared(const_name: &str) -> std::vec::Vec<String> {
  let path = repo_root().join("interpreters/typescript/src/types.ts");
  let source = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
  let opener = std::format!("export const {} = [", const_name);
  let start = source
    .find(&opener)
    .unwrap_or_else(|| std::panic!("`{}` is no longer declared in {:?}", const_name, path))
    + opener.len();
  let rest = &source[start..];
  let end = rest
    .find(']')
    .unwrap_or_else(|| std::panic!("`{}` has no closing bracket", const_name));
  rest[..end]
    .split(',')
    .map(str::trim)
    .filter(|entry| !entry.is_empty())
    .map(|entry| entry.trim_matches(|c| c == '\'' || c == '"').to_string())
    .collect()
}

/// Reports each direction as the distinct defect it is: a value the reference
/// admits and the independent implementation refuses strands a producer, and
/// the reverse admits an act no reference verifier can describe.
fn assert_same_membership(declared_here: &[String], reference: &[&'static str], what: &str) {
  let missing: std::vec::Vec<&str> = reference
    .iter()
    .copied()
    .filter(|label| !declared_here.iter().any(|d| d == label))
    .collect();
  std::assert!(
    missing.is_empty(),
    "the reference admits {} the independent implementation refuses: {:?}\n\
     Two conformant-claiming verifiers would reach opposite verdicts on the same bytes.",
    what,
    missing
  );
  let extra: std::vec::Vec<&String> = declared_here
    .iter()
    .filter(|d| !reference.iter().any(|label| *label == d.as_str()))
    .collect();
  std::assert!(
    extra.is_empty(),
    "the independent implementation admits {} the reference refuses: {:?}\n\
     It would mint envelopes the reference cannot parse.",
    what,
    extra
  );
}

#[test]
fn the_independent_implementation_agrees_on_the_channel_kind_vocabulary() {
  let reference: std::vec::Vec<&'static str> = aph_core::ChannelKind::ALL
    .iter()
    .map(aph_core::ChannelKind::label)
    .collect();
  assert_same_membership(&declared("CHANNEL_KINDS"), &reference, "channel kinds");
}

#[test]
fn the_independent_implementation_agrees_on_the_content_class_vocabulary() {
  let reference: std::vec::Vec<&'static str> = aph_core::ContentClass::ALL
    .iter()
    .map(aph_core::ContentClass::label)
    .collect();
  assert_same_membership(&declared("CONTENT_CLASSES"), &reference, "content classes");
}

/// The agent skill's declaration of one vocabulary.
///
/// Read from the skill's "Closed enums" list. The entries are backticked and
/// comma-separated, and each MAY carry a parenthetical gloss naming the RFC
/// that admitted it — the gloss is prose and is skipped, because what is
/// under test is membership, not how it is described.
fn skill_declared(bullet: &str) -> std::vec::Vec<String> {
  let path = repo_root().join("skills/spec/SKILL.md");
  let source = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
  let line = source
    .lines()
    .find(|line| line.starts_with(bullet))
    .unwrap_or_else(|| std::panic!("the skill no longer opens a line with `{}`", bullet));
  let start = line
    .find("): ")
    .unwrap_or_else(|| std::panic!("the `{}` line has no `): ` list opener:\n{}", bullet, line))
    + 3;
  let mut out = std::vec::Vec::new();
  let mut rest = &line[start..];
  while let std::option::Option::Some(open) = rest.find('`') {
    let after = &rest[open + 1..];
    let close = match after.find('`') {
      std::option::Option::Some(index) => index,
      std::option::Option::None => break,
    };
    out.push(after[..close].to_string());
    rest = &after[close + 1..];
  }
  std::assert!(
    !out.is_empty(),
    "the `{}` line enumerates nothing; it has been rewritten:\n{}",
    bullet,
    line
  );
  out
}

#[test]
fn the_agent_skill_agrees_on_the_channel_kind_vocabulary() {
  let reference: std::vec::Vec<&'static str> = aph_core::ChannelKind::ALL
    .iter()
    .map(aph_core::ChannelKind::label)
    .collect();
  assert_same_membership(
    &skill_declared("- **Channel kinds**"),
    &reference,
    "channel kinds",
  );
}

#[test]
fn the_agent_skill_agrees_on_the_content_class_vocabulary() {
  let reference: std::vec::Vec<&'static str> = aph_core::ContentClass::ALL
    .iter()
    .map(aph_core::ContentClass::label)
    .collect();
  assert_same_membership(
    &skill_declared("- **contentClass**"),
    &reference,
    "content classes",
  );
}

#[test]
fn the_independent_implementation_agrees_on_the_policy_decision_vocabulary() {
  // The vocabulary whose divergence motivated its closure: the independent
  // implementation refused an unrecognized decision from its first draft
  // while the reference accepted any string. Welded here so the two cannot
  // part again without a red gate.
  let reference: std::vec::Vec<&'static str> = aph_core::PolicyDecision::ALL
    .iter()
    .map(aph_core::PolicyDecision::label)
    .collect();
  assert_same_membership(&declared("POLICY_DECISIONS"), &reference, "policy decisions");
}
