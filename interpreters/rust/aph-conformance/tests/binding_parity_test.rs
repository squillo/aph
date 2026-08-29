//! The parity census — six operations, six export surfaces, one roster.
//!
//! WHY THIS EXISTS. The four language bindings promise the SAME operation
//! roster, and that contract grew from four operations to six with nothing
//! counting it: each surface was widened by hand, in one change, correctly —
//! and only the change's author knew the count. A contract nobody counts is
//! the standing drift finding of this repository applied to its own API:
//! the next widening that moves five surfaces and forgets the sixth would
//! ship two different protocols under one name, and every suite would stay
//! green because each surface's own tests test only itself.
//!
//! WHAT IT PINS. One canonical roster below — THE place a seventh operation
//! is added — against six textual extractions:
//! wasm/TS `js_name` exports, the pyo3 `#[pyfunction]` set AND its
//! `#[pymodule_export]` registrations (two independent populators in one
//! binding), the `rustler::init!` roster AND the `defdelegate` list
//! (likewise two), the Go `ExportedFunction` wrappers, and the wasm text
//! ABI's `extern "C"` exports. Membership is compared BOTH directions with
//! distinct messages; per-surface extras live in loud EXEMPT lists, each
//! entry carrying its reason; an extraction that finds nothing panics,
//! because a census over an empty population proves only that the anchor
//! moved.
//!
//! ZERO `#[ignore]`.

/// Repository root, three levels up from this crate.
fn repo_root() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn read(relative: &str) -> String {
  let path = repo_root().join(relative);
  std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e))
}

/// One operation, spelled the way each surface spells it. Adding operation
/// seven means adding ONE row here — every check below derives from it.
struct Operation {
  ts: &'static str,
  snake: &'static str, // pyfunction, pymodule_export, NIF init, defdelegate
  go_abi: &'static str, // ExportedFunction name AND wasm-abi extern
}

const ROSTER: [Operation; 6] = [
  Operation {
    ts: "parseEnvelopeJson",
    snake: "parse_envelope_json",
    go_abi: "aph_parse_envelope_json",
  },
  Operation {
    ts: "serializeEnvelope",
    snake: "serialize_envelope",
    go_abi: "aph_serialize_envelope",
  },
  Operation {
    ts: "verifyProofStructure",
    snake: "verify_proof_structure",
    go_abi: "aph_verify_proof_structure",
  },
  Operation {
    ts: "requireAttestationMode",
    snake: "require_attestation_mode",
    go_abi: "aph_require_attestation_mode",
  },
  Operation {
    ts: "mandateIsValidAt",
    snake: "mandate_is_valid_at",
    go_abi: "aph_mandate_is_valid_at",
  },
  Operation {
    ts: "verifyEmbeddedMandateBinding",
    snake: "verify_embedded_mandate_binding",
    go_abi: "aph_verify_embedded_mandate_binding",
  },
];

/// Exports a surface legitimately carries beyond the parity roster. Every
/// entry states its reason; an export not in the roster and not here fails.
const WASM_ABI_EXEMPT: [(&str, &str); 2] = [
  ("aph_alloc", "memory plumbing of the text ABI, not an operation"),
  ("aph_dealloc", "memory plumbing of the text ABI, not an operation"),
];
const PYMODULE_EXEMPT: [(&str, &str); 1] =
  [("AphError", "the exception TYPE the six operations raise, not an operation")];

fn identifier(rest: &str) -> Option<String> {
  let name: String = rest
    .chars()
    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
    .collect();
  if name.is_empty() { None } else { Some(name) }
}

/// Both-direction membership with distinct messages, minus loud exempts.
fn assert_census(
  surface: &str,
  found: &std::collections::BTreeSet<String>,
  expected: &[&str],
  exempt: &[(&str, &str)],
) {
  std::assert!(
    !found.is_empty(),
    "{}: the extraction found NOTHING — the anchor moved; re-anchor this \
     census rather than letting it count an empty population",
    surface
  );
  let missing: std::vec::Vec<&&str> =
    expected.iter().filter(|op| !found.contains(**op)).collect();
  std::assert!(
    missing.is_empty(),
    "{} is missing roster operations — a consumer of this surface gets a \
     narrower protocol than the other bindings promise: {:?}",
    surface,
    missing
  );
  let extra: std::vec::Vec<&String> = found
    .iter()
    .filter(|name| {
      !expected.contains(&name.as_str())
        && !exempt.iter().any(|(exempt_name, _)| exempt_name == name)
    })
    .collect();
  std::assert!(
    extra.is_empty(),
    "{} exports names the roster does not carry and the exempt list does \
     not explain — either add the operation to the ROSTER (all six surfaces \
     in one change) or exempt it here WITH its reason: {:?}",
    surface,
    extra
  );
}

#[test]
fn the_ts_wasm_surface_matches_the_roster() {
  let text = read("interpreters/rust/aph-ts/src/lib.rs");
  let mut found = std::collections::BTreeSet::new();
  for line in text.lines() {
    if let std::option::Option::Some(at) = line.find("js_name = ") {
      if let std::option::Option::Some(name) = identifier(&line[at + 10..]) {
        found.insert(name);
      }
    }
  }
  let expected: std::vec::Vec<&str> = ROSTER.iter().map(|op| op.ts).collect();
  assert_census("aph-ts js_name exports", &found, &expected, &[]);
}

#[test]
fn the_python_surface_matches_the_roster_twice() {
  // Two independent populators in one binding: the `#[pyfunction]`
  // attributes say what CAN be exported, the `#[pymodule_export]` uses say
  // what IS. Either drifting alone is a defect the other would mask.
  let text = read("interpreters/rust/aph-py/src/lib.rs");
  let expected: std::vec::Vec<&str> = ROSTER.iter().map(|op| op.snake).collect();

  let mut functions = std::collections::BTreeSet::new();
  let mut previous_was_attr = false;
  for line in text.lines() {
    let trimmed = line.trim();
    if previous_was_attr {
      if let std::option::Option::Some(rest) = trimmed.strip_prefix("pub fn ") {
        if let std::option::Option::Some(name) = identifier(rest) {
          functions.insert(name);
        }
      }
    }
    previous_was_attr = trimmed.contains("pyfunction");
  }
  assert_census("aph-py #[pyfunction] set", &functions, &expected, &[]);

  let mut registered = std::collections::BTreeSet::new();
  let mut previous_was_export = false;
  for line in text.lines() {
    let trimmed = line.trim();
    if previous_was_export {
      if let std::option::Option::Some(rest) = trimmed.strip_prefix("use super::") {
        if let std::option::Option::Some(name) = identifier(rest) {
          registered.insert(name);
        }
      }
    }
    previous_was_export = trimmed.contains("pymodule_export");
  }
  assert_census("aph-py #[pymodule_export] roster", &registered, &expected, &PYMODULE_EXEMPT);
}

#[test]
fn the_elixir_surface_matches_the_roster_twice() {
  // Same two-populator shape as Python: the NIF init roster is what the
  // native library registers, the defdelegates are what a caller of `APH`
  // can reach. The census walks both.
  let expected: std::vec::Vec<&str> = ROSTER.iter().map(|op| op.snake).collect();

  let native = read("interpreters/elixir/native/aph_nif/src/lib.rs");
  let init_at = native
    .find("rustler::init!")
    .unwrap_or_else(|| std::panic!("rustler::init! not found; re-anchor this census"));
  let after = &native[init_at..];
  let open = after.find('[').expect("the init roster opens with [");
  let close = after.find(']').expect("the init roster closes with ]");
  let mut nif_roster = std::collections::BTreeSet::new();
  for entry in after[open + 1..close].split(',') {
    if let std::option::Option::Some(name) = identifier(entry.trim()) {
      nif_roster.insert(name);
    }
  }
  assert_census("aph_nif rustler::init! roster", &nif_roster, &expected, &[]);

  let facade = read("interpreters/elixir/lib/aph.ex");
  let mut delegates = std::collections::BTreeSet::new();
  for line in facade.lines() {
    if let std::option::Option::Some(rest) = line.trim().strip_prefix("defdelegate ") {
      if let std::option::Option::Some(name) = identifier(rest) {
        delegates.insert(name);
      }
    }
  }
  assert_census("APH defdelegates", &delegates, &expected, &[]);
}

#[test]
fn the_go_surface_matches_the_roster() {
  let text = read("interpreters/go/aph.go");
  let mut found = std::collections::BTreeSet::new();
  for line in text.lines() {
    if let std::option::Option::Some(at) = line.find("ExportedFunction(\"") {
      if let std::option::Option::Some(name) = identifier(&line[at + 18..]) {
        found.insert(name);
      }
    }
  }
  let expected: std::vec::Vec<&str> = ROSTER.iter().map(|op| op.go_abi).collect();
  assert_census("go ExportedFunction wrappers", &found, &expected, &WASM_ABI_EXEMPT);
}

#[test]
fn the_wasm_abi_surface_matches_the_roster() {
  let text = read("interpreters/rust/aph-wasm-abi/src/lib.rs");
  let mut found = std::collections::BTreeSet::new();
  for line in text.lines() {
    let trimmed = line.trim();
    for prefix in ["pub extern \"C\" fn ", "pub unsafe extern \"C\" fn "] {
      if let std::option::Option::Some(rest) = trimmed.strip_prefix(prefix) {
        if let std::option::Option::Some(name) = identifier(rest) {
          found.insert(name);
        }
      }
    }
  }
  let expected: std::vec::Vec<&str> = ROSTER.iter().map(|op| op.go_abi).collect();
  assert_census("aph-wasm-abi extern \"C\" exports", &found, &expected, &WASM_ABI_EXEMPT);
}
