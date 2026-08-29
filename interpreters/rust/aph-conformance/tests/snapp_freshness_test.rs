//! Snapp bundle freshness — the transpiler's output, never a hand-sync.
//!
//! WHY THIS EXISTS. The committed bundles under `snapp/` are GENERATED from
//! the N Lang sources (`nlang export`), and a recent revision proved the
//! failure mode this test forbids: a source change was mirrored into the
//! bundle BY HAND, faithfully on every prop but one — the hand wrote a
//! qualified type path where the transpiler emits an unqualified one — and
//! the bundle's own `integrity` digest went stale because only the exporter
//! refreshes it. Every membership weld stayed green, because welds compare
//! MEMBERS and a hand-sync gets members right; what drifts is everything
//! the welds don't enumerate.
//!
//! WHAT IT PINS. For each bundle: the committed content EQUALS a fresh
//! export of its sources, ignoring exactly two exporter-stamped fields —
//! `@snapp.date` (a wall-clock stamp, different on every run by design)
//! and `@snapp.integrity` (which covers the date, so it churns with it).
//! Everything else matching means the sources and the bundle tell one
//! story; a mismatch means someone edited one side alone, and the fix is
//! `nlang export` in the source directory, committed.
//!
//! ANNOUNCED SKIP, never silent: the transpiler is a proprietary tool not
//! present on every machine (public CI included). When `nlang` is not on
//! PATH this test prints `SNAPP FRESHNESS SKIPPED` and returns;
//! `APH_SNAPP_FRESHNESS_REQUIRE=1` turns the skip into a failure for
//! environments that guarantee the tool. The export writes INTO the
//! committed location, so the test snapshots the committed bytes first and
//! ALWAYS restores them before judging — the repository is bit-identical
//! after a run regardless of verdict.

fn repo_root() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn nlang_available() -> bool {
  std::process::Command::new("nlang")
    .arg("--version")
    .output()
    .map(|out| out.status.success())
    .unwrap_or(false)
}

fn skip_or_require(reason: &str) -> bool {
  if std::env::var("APH_SNAPP_FRESHNESS_REQUIRE").as_deref() == Ok("1") {
    std::panic!("{} (APH_SNAPP_FRESHNESS_REQUIRE=1 turns this skip into a failure)", reason);
  }
  std::eprintln!("SNAPP FRESHNESS SKIPPED: {}", reason);
  true
}

/// Bundle content with the two exporter-stamped fields removed, so equality
/// means "same sources", not "same second".
fn comparable(raw: &str, which: &str) -> serde_json::Value {
  let mut value: serde_json::Value = serde_json::from_str(raw)
    .unwrap_or_else(|e| std::panic!("{} is not valid JSON: {}", which, e));
  let stamp = value
    .get_mut("@snapp")
    .unwrap_or_else(|| std::panic!("{} has no @snapp header; re-anchor this test", which))
    .as_object_mut()
    .unwrap_or_else(|| std::panic!("{}'s @snapp header is not an object", which));
  std::assert!(
    stamp.remove("date").is_some() && stamp.remove("integrity").is_some(),
    "{}'s @snapp header no longer carries date+integrity; the exporter's \
     stamp shape moved and this test's ignore-list must move with it",
    which
  );
  value
}

fn assert_bundle_fresh(source_dir: &str, bundle: &str) {
  let bundle_path = repo_root().join("snapp").join(bundle);
  let committed = std::fs::read_to_string(&bundle_path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", bundle_path, e));

  let output = std::process::Command::new("nlang")
    .arg("export")
    .current_dir(repo_root().join(source_dir))
    .output()
    .unwrap_or_else(|e| std::panic!("running nlang export in {}: {}", source_dir, e));

  let exported = std::fs::read_to_string(&bundle_path)
    .unwrap_or_else(|e| std::panic!("failed to re-read {:?}: {}", bundle_path, e));
  // Restore the committed bytes BEFORE any assertion: the repository must be
  // bit-identical after this test whatever the verdict, and a panic below
  // must not leave a churned date/integrity in the working tree.
  std::fs::write(&bundle_path, &committed)
    .unwrap_or_else(|e| std::panic!("failed to restore {:?}: {}", bundle_path, e));

  std::assert!(
    output.status.success(),
    "nlang export failed in {} — the sources do not compile, which is a \
     defect wherever the bundle came from:\n{}",
    source_dir,
    String::from_utf8_lossy(&output.stderr)
  );
  std::assert_eq!(
    comparable(&committed, "the committed bundle"),
    comparable(&exported, "the fresh export"),
    "{} disagrees with a fresh export of {} — one side was edited alone \
     (a hand-sync, or a source change without re-export). Fix: run \
     `nlang export` in the source directory and commit the result.",
    bundle,
    source_dir
  );
}

#[test]
fn the_protocol_bundle_is_a_fresh_export_of_its_sources() {
  if !nlang_available() {
    if skip_or_require("nlang not on PATH; the protocol bundle was not checked") {
      return;
    }
  }
  assert_bundle_fresh("APH Spec/0.1.0", "aph@0.1.0-alpha.1.json");
}

#[test]
fn the_guardrail_bundle_is_a_fresh_export_of_its_sources() {
  if !nlang_available() {
    if skip_or_require("nlang not on PATH; the guardrail bundle was not checked") {
      return;
    }
  }
  assert_bundle_fresh("APH Guardrails/0.1.0", "aph_guardrails@0.1.0-alpha.1.json");
}
