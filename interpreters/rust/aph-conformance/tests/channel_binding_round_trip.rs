//! Channel-binding spec presence + parseability tests.
//!
//! Verifies that the 3 binding specs ship as part of the conformance harness
//! and that each is non-empty (presence test, not content test).

const EMAIL_SPEC_PATH: &str = "specs/aph-email-binding-0.1.md";
const MEDIA_SPEC_PATH: &str = "specs/aph-media-binding-0.1.md";
const MCP_SPEC_PATH: &str = "specs/aph-mcp-binding-0.1.md";

#[test]
fn email_binding_spec_exists_and_non_empty() {
  // The binding specs ship WITH this crate and are what an implementer
  // reads to build an email transport. This guards against the file being
  // moved, renamed, or emptied so the crate silently loses its normative
  // companion doc. (Presence-only: no executable email vectors yet.)
  let crate_root = std::env::var("CARGO_MANIFEST_DIR")
    .expect("CARGO_MANIFEST_DIR set by cargo");
  let path = std::path::PathBuf::from(crate_root).join(EMAIL_SPEC_PATH);
  let content = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| panic!("failed to read {:?}: {}", path, e));
  assert!(!content.is_empty(), "email binding spec must not be empty");
  assert!(content.contains("APH"), "email spec must mention APH");
}

#[test]
fn media_binding_spec_exists_and_non_empty() {
  // Same shipped-doc guard for the chat-platform binding, which covers
  // five of the seven channel kinds.
  let crate_root = std::env::var("CARGO_MANIFEST_DIR")
    .expect("CARGO_MANIFEST_DIR set by cargo");
  let path = std::path::PathBuf::from(crate_root).join(MEDIA_SPEC_PATH);
  let content = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| panic!("failed to read {:?}: {}", path, e));
  assert!(!content.is_empty(), "media binding spec must not be empty");
  assert!(content.contains("Slack") || content.contains("Discord"),
    "media spec must mention at least one chat platform");
}

#[test]
fn mcp_binding_spec_exists_and_non_empty() {
  // Same guard for the MCP tool binding — the doc that defines the three
  // aph.* tool names and their JSON-RPC error codes for host integrators.
  let crate_root = std::env::var("CARGO_MANIFEST_DIR")
    .expect("CARGO_MANIFEST_DIR set by cargo");
  let path = std::path::PathBuf::from(crate_root).join(MCP_SPEC_PATH);
  let content = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| panic!("failed to read {:?}: {}", path, e));
  assert!(!content.is_empty(), "mcp binding spec must not be empty");
  assert!(content.contains("JSON-RPC") || content.contains("MCP"),
    "mcp spec must mention JSON-RPC or MCP");
}
