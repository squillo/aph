//! N Lang example pins — every example compiles against THIS bundle, never a
//! remembered one.
//!
//! WHY THIS EXISTS. The example packages under `examples/nlang/` depend on the
//! committed Spec bundle `snapp/aph@0.1.0.nbin` by relative path and by the
//! SHA-256 of its bytes: the `integrity` field of each package's `@deps`
//! block. The bundle is re-emitted whenever the transpiler is reinstalled, and
//! the first re-emit after the examples landed moved the bytes under every
//! pin. Each package then failed the compiler's dependency rung (an integrity
//! mismatch, before a single test ran), and the failure was found downstream
//! by a consumer of the examples rather than by this repository's own gate. A
//! pin that is not welded to the bytes it names drifts silently; this file is
//! the weld.
//!
//! WHAT IT PINS. For every `examples/nlang/<name>/src/lib.n`, the hex digest
//! in its `integrity: "sha256-<hex>"` line EQUALS the SHA-256 of the committed
//! `snapp/aph@0.1.0.nbin`. Zero example packages is a failure too: the layout
//! moved and this weld must be re-anchored. When the first test fails, the fix
//! is the one-line re-pin documented in `examples/nlang/README.md`, committed
//! in the same change as the re-emit.
//!
//! No transpiler takes part, so this runs wherever `cargo test` runs, public
//! CI included, with no announced skip.

fn repo_root() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// SHA-256 of the committed bundle, lowercase hex, which is the alphabet the
/// compiler compares `integrity` in.
fn committed_bundle_sha256_hex() -> std::string::String {
  use sha2::Digest;
  let path = repo_root().join("snapp").join("aph@0.1.0.nbin");
  let bytes = std::fs::read(&path)
    .unwrap_or_else(|e| std::panic!("failed to read the committed bundle {:?}: {}", path, e));
  sha2::Sha256::digest(&bytes)
    .iter()
    .map(|byte| std::format!("{:02x}", byte))
    .collect()
}

/// Every example package's entry source, sorted, enumerated from disk rather
/// than remembered so a new package is covered the moment it exists.
fn example_sources() -> std::vec::Vec<std::path::PathBuf> {
  let dir = repo_root().join("examples").join("nlang");
  let mut sources: std::vec::Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", dir, e))
    .filter_map(|entry| entry.ok().map(|entry| entry.path()))
    .filter(|path| path.is_dir())
    .map(|path| path.join("src").join("lib.n"))
    .filter(|path| path.is_file())
    .collect();
  sources.sort();
  sources
}

/// The digest an example pins: the text between `"sha256-` and the closing
/// quote on its one `integrity:` line.
fn pinned_sha256(source: &str, path: &std::path::Path) -> std::string::String {
  let line = source
    .lines()
    .find(|line| line.trim_start().starts_with("integrity:"))
    .unwrap_or_else(|| std::panic!("{:?} has no integrity: line in its @deps block", path));
  let marker = "\"sha256-";
  let start = line
    .find(marker)
    .unwrap_or_else(|| std::panic!("{:?}: integrity is not of the form sha256-<hex>: {}", path, line))
    + marker.len();
  let rest = &line[start..];
  let end = rest
    .find('"')
    .unwrap_or_else(|| std::panic!("{:?}: unterminated integrity string: {}", path, line));
  rest[..end].to_string()
}

/// Pins: every example's `integrity` equals the committed bundle's SHA-256, so
/// a bundle re-emit that leaves the examples behind fails here, in the
/// re-emit's own change, instead of at a consumer's dependency rung.
#[test]
fn every_example_pins_the_committed_bundle_bytes() {
  let expected = committed_bundle_sha256_hex();
  let sources = example_sources();
  std::assert!(
    !sources.is_empty(),
    "no example packages under examples/nlang; the layout moved and this weld must be re-anchored"
  );
  let stale: std::vec::Vec<std::string::String> = sources
    .iter()
    .filter_map(|path| {
      let source = std::fs::read_to_string(path)
        .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
      let pinned = pinned_sha256(&source, path);
      (pinned != expected).then(|| std::format!("  {} pins {}", path.display(), pinned))
    })
    .collect();
  std::assert!(
    stale.is_empty(),
    "{} of {} example packages pin a bundle other than the committed snapp/aph@0.1.0.nbin \
     (sha256 {}); re-pin them in the same change as the re-emit, see examples/nlang/README.md:\n{}",
    stale.len(),
    sources.len(),
    expected,
    stale.join("\n")
  );
}

/// Pins: the compiler compares `integrity` as sixty-four lowercase hex digits,
/// not as the SRI base64 the protocol uses for vocabulary digests; a pin in the
/// wrong alphabet fails resolution even when it names the right bytes.
#[test]
fn every_pin_is_lowercase_hex_sha256_as_the_compiler_compares_it() {
  for path in example_sources() {
    let source = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    let pinned = pinned_sha256(&source, &path);
    std::assert_eq!(pinned.len(), 64, "{:?}: pin is not 64 hex digits: {}", path, pinned);
    std::assert!(
      pinned.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
      "{:?}: pin is not lowercase hex: {}",
      path,
      pinned
    );
  }
}
