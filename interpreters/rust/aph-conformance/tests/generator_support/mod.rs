// Each generator in this directory compiles this module into its OWN test
// binary and uses a different slice of it, so whatever one generator leaves
// untouched reads as dead code in that binary. Allowing it keeps `cargo test`
// output about the protocol rather than about scaffolding.
#![allow(dead_code)]

//! The generator scaffold the published signed vectors share.
//!
//! # What a "generator" is here
//!
//! A published vector under `examples/` is never text-edited. It is REBUILT
//! from constants, re-signed through `aph-core`'s own signing path, and
//! byte-compared with the committed file. That makes drift impossible in the
//! only direction that matters: a change to canonicalization, serde
//! attributes, field order, or a signing base mints different bytes and fails
//! loudly, instead of leaving a published example that no implementation —
//! including this one — can verify.
//!
//! # Why it is a module rather than three copies
//!
//! `principal_signed_example_test.rs` established the pattern (fixed public
//! test keys documented alongside, real signing through `aph-core`, a
//! byte-identity test, `----8<----` cut-lines materialization) and carries its
//! own inline copy of it. The ES256 and detached-JWS vectors are the second
//! and third generators, and three inline copies of a comparison harness is
//! three chances for them to disagree about what "byte-identical" means.
//! Converting the Ed25519 generator to this module is a follow-on, not a
//! silent edit to a file that is already green.
//!
//! # No clock, no network, no key material
//!
//! Every timestamp in a vector is a constant chosen by its generator, and
//! every key is a PUBLISHED test vector — RFC 8032 §7.1 seeds on Ed25519, the
//! RFC 6979 A.2.5 and RFC 7515 A.3.1 scalars on P-256. Nothing here reads an
//! environment variable, a wall clock, or a socket.
//!
//! ZERO `#[ignore]`. ZERO `use` statements.

/// Absolute path of a published example, resolved from this crate's manifest
/// directory (`<repo>/interpreters/rust/aph-conformance`).
pub fn example_path(file_name: &str) -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("../../../examples")
    .join(file_name)
}

/// Serializes a signed envelope exactly as the published files carry it:
/// `serde_json::to_string_pretty` plus a trailing newline.
///
/// One function rather than a convention, because the trailing newline is
/// part of the byte comparison — a generator that forgot it would report the
/// whole file as drifted and print a replacement that drifts right back.
pub fn published_form(envelope: &aph_core::NotarizationEnvelope) -> std::string::String {
  std::format!(
    "{}\n",
    serde_json::to_string_pretty(envelope).expect("a signed envelope serializes")
  )
}

/// The committed bytes of a published example, or `None` when the file does
/// not exist yet.
///
/// Absence is a real state, not an error: a vector's first appearance is a
/// generator that mints bytes for a file nobody has written. Distinguishing
/// the two is what lets [`assert_matches_published`] print the same actionable
/// message in both cases instead of an `ENOENT`.
pub fn published_bytes(path: &std::path::Path) -> std::option::Option<std::string::String> {
  match std::fs::read_to_string(path) {
    std::result::Result::Ok(text) => std::option::Option::Some(text),
    std::result::Result::Err(error)
      if error.kind() == std::io::ErrorKind::NotFound =>
    {
      std::option::Option::None
    }
    std::result::Result::Err(error) => {
      std::panic!("failed to read {:?}: {}", path, error)
    }
  }
}

/// Parses a published example, failing with a message that says how to create
/// it when it is missing rather than surfacing a bare I/O error.
pub fn parse_published(path: &std::path::Path) -> aph_core::NotarizationEnvelope {
  let json = match published_bytes(path) {
    std::option::Option::Some(json) => json,
    std::option::Option::None => std::panic!(
      "{:?} has not been materialized yet; run this file's byte-identity test \
       and paste the block it prints between the ----8<---- cut lines",
      path
    ),
  };
  serde_json::from_str(&json)
    .unwrap_or_else(|e| std::panic!("{:?} failed strict parse: {}", path, e))
}

/// The byte-identity gate: the committed file MUST equal what the signing code
/// mints, and on mismatch the whole replacement is printed between cut lines
/// so the file can be corrected in one step.
///
/// Missing and drifted are one gate on purpose. Both mean "the bytes on disk
/// are not the bytes this code produces", both are fixed by the same paste,
/// and splitting them would give a first-time generator a failure mode that
/// says nothing about what to do next.
pub fn assert_matches_published(path: &std::path::Path, regenerated: &str) {
  let published = published_bytes(path);
  if published.as_deref() == std::option::Option::Some(regenerated) {
    return;
  }
  let problem = match published {
    std::option::Option::Some(_) => "has drifted from",
    std::option::Option::None => "does not exist and must be created with",
  };
  std::panic!(
    "{:?} {} the bytes the signing code mints.\nTo fix in ONE step, write that \
     file with EXACTLY the content between the cut lines (the final newline is \
     part of the content):\n----8<----\n{}----8<----",
    path,
    problem,
    regenerated
  );
}
