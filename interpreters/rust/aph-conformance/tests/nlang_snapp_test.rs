//! Round-trip: the published example envelopes against the N Lang Snapp.
//!
//! Three artifacts describe the same wire shape — the specification, the
//! Rust types in `aph-core`, and the N Lang types in the `APH Spec` Snapp.
//! The other suites in this crate weld the first two together. This one
//! welds in the third, by walking every key of every published example and
//! checking it against the block definitions in the compiled Snapp bundle.
//!
//! It reads the COMMITTED bundle (`snapp/aph@*.json`) rather than invoking
//! the N Lang compiler, so it runs anywhere `cargo test` runs and needs no
//! toolchain beyond Rust.
//!
//! What it catches, in both directions:
//!
//! - A key in a published example with no matching prop — the N Lang types
//!   have fallen behind the wire format.
//! - A required prop no example exercises — either the type declares
//!   something the protocol does not carry, or the example corpus has a
//!   gap. Both are worth knowing.
//!
//! ZERO `#[ignore]`.

/// Repository root, three levels up from this crate.
fn repo_root() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Loads the committed Snapp bundle's block definitions.
///
/// The bundle name carries a version, so it is discovered by extension
/// rather than hardcoded — a version bump must not silently skip this test.
fn snapp_blocks() -> serde_json::Map<String, serde_json::Value> {
  let dir = repo_root().join("snapp");
  let mut bundles: std::vec::Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", dir, e))
    .filter_map(|e| e.ok().map(|e| e.path()))
    .filter(|p| p.extension().and_then(|s| s.to_str()) == std::option::Option::Some("json"))
    .collect();
  bundles.sort();
  let bundle = bundles
    .last()
    .unwrap_or_else(|| std::panic!("no compiled Snapp bundle in {:?}", dir));

  let raw = std::fs::read_to_string(bundle)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", bundle, e));
  let value: serde_json::Value = serde_json::from_str(&raw)
    .unwrap_or_else(|e| std::panic!("{:?} is not valid JSON: {}", bundle, e));

  value
    .get("mod")
    .and_then(|m| m.get("*"))
    .and_then(|m| m.get("blocks"))
    .and_then(|b| b.as_object())
    .cloned()
    .unwrap_or_else(|| std::panic!("{:?} has no mod.*.blocks", bundle))
}

/// Returns the sorted list of published example envelopes.
fn example_files() -> std::vec::Vec<std::path::PathBuf> {
  let dir = repo_root().join("examples");
  let mut files: std::vec::Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", dir, e))
    .filter_map(|e| e.ok().map(|e| e.path()))
    .filter(|p| p.extension().and_then(|s| s.to_str()) == std::option::Option::Some("json"))
    .collect();
  files.sort();
  files
}

/// Maps a camelCase wire key to the snake_case prop name it should have.
///
/// `@context` is the one key with no identifier form at all; the Snapp
/// documents it as the prop `context`, and that exception is encoded here
/// rather than left implicit.
fn wire_key_to_prop(key: &str) -> String {
  if key == "@context" {
    return String::from("context");
  }
  let mut out = String::with_capacity(key.len() + 4);
  for ch in key.chars() {
    if ch.is_ascii_uppercase() {
      out.push('_');
      out.push(ch.to_ascii_lowercase());
    } else {
      out.push(ch);
    }
  }
  out
}

/// What a non-primitive prop points at.
enum PropTarget {
  /// A block with props, e.g. `<$::*::AgentRef>`.
  Block(String),
  /// An enum inside a container block. The compiler emits a qualified path
  /// in a different shape than a plain block reference:
  /// `<$<*, VaultMutation, VaultMutationKind>>`.
  Enum {
    container: String,
    name: String,
  },
}

/// Resolves what a prop points at, or `None` for primitives (`atom`).
fn prop_target(prop: &serde_json::Value) -> std::option::Option<PropTarget> {
  let t = prop.get("type")?.as_str()?;
  let inner = t.trim_start_matches('<').trim_end_matches('>');

  // Qualified form: `$<*, Container, EnumName>`.
  if let std::option::Option::Some(rest) = inner.strip_prefix("$<") {
    let body = rest.trim_end_matches('>');
    let parts: std::vec::Vec<&str> = body.split(',').map(|s| s.trim()).collect();
    if parts.len() == 3 {
      return std::option::Option::Some(PropTarget::Enum {
        container: String::from(parts[1]),
        name: String::from(parts[2]),
      });
    }
    return std::option::Option::None;
  }

  // Plain form: `$::*::Name`.
  inner
    .rsplit("::")
    .next()
    .map(|n| PropTarget::Block(String::from(n)))
}

/// The discriminator key for an internally tagged enum on the wire. The tag
/// name is a serialization detail the N Lang enum does not carry, so it is
/// pinned here from spec §7.5.3.
const ENUM_TAG_KEY: &str = "kind";

/// Validates an internally tagged enum object, e.g.
/// `{"kind": "WriteInto", "dest_vault_id": "..."}`, against the variants
/// the Snapp declares.
fn check_enum(
  json: &serde_json::Map<String, serde_json::Value>,
  container: &str,
  enum_name: &str,
  blocks: &serde_json::Map<String, serde_json::Value>,
  path: &str,
  missing: &mut std::vec::Vec<String>,
) {
  let variants = match blocks
    .get(container)
    .and_then(|b| b.get("enum"))
    .and_then(|e| e.as_object())
  {
    std::option::Option::Some(v) => v,
    std::option::Option::None => {
      missing.push(std::format!(
        "{}: Snapp block `{}` declares no enum for `{}`",
        path, container, enum_name
      ));
      return;
    }
  };

  let tag = match json.get(ENUM_TAG_KEY).and_then(|v| v.as_str()) {
    std::option::Option::Some(t) => t,
    std::option::Option::None => {
      missing.push(std::format!(
        "{}: internally tagged enum object has no `{}` discriminator",
        path, ENUM_TAG_KEY
      ));
      return;
    }
  };

  let variant = match variants.get(tag) {
    std::option::Option::Some(v) => v,
    std::option::Option::None => {
      missing.push(std::format!(
        "{}: `{}` is not a declared variant of `{}`",
        path, tag, enum_name
      ));
      return;
    }
  };

  // Every remaining key must be an item of that variant. A unit variant
  // such as `Revoke` declares no items, so any extra key is a mismatch.
  let empty = serde_json::Map::new();
  let items = variant
    .get("items")
    .and_then(|i| i.as_object())
    .unwrap_or(&empty);
  for key in json.keys() {
    if key == ENUM_TAG_KEY {
      continue;
    }
    if !items.contains_key(key) {
      missing.push(std::format!(
        "{}.{}: variant `{}` of `{}` declares no such item",
        path, key, tag, enum_name
      ));
    }
  }
}

/// `Positional` and `Directional` are N Lang's untyped collection atoms.
/// A prop of either type is a leaf as far as this check is concerned:
/// `recipientAddressing` is deliberately opaque (spec §7.4), and string
/// arrays have no sub-structure to verify.
fn is_opaque_collection(name: &str) -> bool {
  name == "Positional" || name == "Directional"
}

/// Walks a JSON object against a block definition, recursing into nested
/// objects, and records every key that has no matching prop.
fn check_object(
  json: &serde_json::Map<String, serde_json::Value>,
  block_name: &str,
  blocks: &serde_json::Map<String, serde_json::Value>,
  path: &str,
  missing: &mut std::vec::Vec<String>,
  seen: &mut std::collections::BTreeSet<String>,
) {
  let props = match blocks
    .get(block_name)
    .and_then(|b| b.get("props"))
    .and_then(|p| p.as_object())
  {
    std::option::Option::Some(p) => p,
    std::option::Option::None => {
      missing.push(std::format!(
        "{}: Snapp has no block `{}` with props",
        path, block_name
      ));
      return;
    }
  };

  for (key, value) in json {
    let prop_name = wire_key_to_prop(key);
    let prop = match props.get(&prop_name) {
      std::option::Option::Some(p) => p,
      std::option::Option::None => {
        missing.push(std::format!(
          "{}.{}: no prop `{}` on block `{}`",
          path, key, prop_name, block_name
        ));
        continue;
      }
    };
    seen.insert(std::format!("{}.{}", block_name, prop_name));

    // Recurse only into nested objects whose prop names another block.
    // A null means the optional field is absent, which proves nothing
    // about its shape.
    if let serde_json::Value::Object(child) = value {
      match prop_target(prop) {
        std::option::Option::Some(PropTarget::Block(child_block)) => {
          if !is_opaque_collection(&child_block) {
            check_object(
              child,
              &child_block,
              blocks,
              &std::format!("{}.{}", path, key),
              missing,
              seen,
            );
          }
        }
        std::option::Option::Some(PropTarget::Enum { container, name }) => {
          check_enum(
            child,
            &container,
            &name,
            blocks,
            &std::format!("{}.{}", path, key),
            missing,
          );
        }
        std::option::Option::None => {}
      }
    }

    // A block-typed prop may also carry an ARRAY of objects on the wire:
    // `proof` is the untagged §7.1.11 union, a single proof object or a
    // two-element chain. Walking each element against the same block is
    // what lets a chain-form example exercise the chain-only props (`id`,
    // `previous_proof`) that no single-object example can ever reach.
    // String arrays (`type`, `actChain`, `allowedChannels`) have no object
    // elements, so this loop is vacuous for them.
    if let serde_json::Value::Array(items) = value {
      match prop_target(prop) {
        std::option::Option::Some(PropTarget::Block(child_block))
          if !is_opaque_collection(&child_block) =>
        {
          for (index, item) in items.iter().enumerate() {
            if let serde_json::Value::Object(child) = item {
              check_object(
                child,
                &child_block,
                blocks,
                &std::format!("{}.{}[{}]", path, key, index),
                missing,
                seen,
              );
            }
          }
        }
        _ => {}
      }
    }
  }
}

#[test]
fn every_published_example_key_maps_to_a_declared_prop() {
  // The direction that catches the N Lang types falling behind the wire
  // format: a key exists in a published example that no block declares.
  let blocks = snapp_blocks();
  let files = example_files();
  std::assert!(
    files.len() >= 7,
    "expected at least 7 published examples, found {}",
    files.len()
  );

  let mut missing: std::vec::Vec<String> = std::vec::Vec::new();
  let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

  for path in &files {
    let raw = std::fs::read_to_string(path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    let value: serde_json::Value = serde_json::from_str(&raw)
      .unwrap_or_else(|e| std::panic!("{:?} is not valid JSON: {}", path, e));
    let obj = value
      .as_object()
      .unwrap_or_else(|| std::panic!("{:?} is not a JSON object", path));
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("?");

    check_object(
      obj,
      "NotarizationEnvelope",
      &blocks,
      name,
      &mut missing,
      &mut seen,
    );
  }

  std::assert!(
    missing.is_empty(),
    "published example keys with no matching N Lang prop:\n  {}",
    missing.join("\n  ")
  );
}

#[test]
fn every_required_envelope_prop_is_exercised_by_an_example() {
  // The opposite direction: a required prop no example carries. Either the
  // Snapp declares something the protocol does not actually send, or the
  // example corpus has a hole. Optional props are exempt — an extension
  // that no example uses is expected, not a defect.
  let blocks = snapp_blocks();
  let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
  let mut missing: std::vec::Vec<String> = std::vec::Vec::new();

  for path in example_files() {
    let raw = std::fs::read_to_string(&path).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    check_object(
      value.as_object().unwrap(),
      "NotarizationEnvelope",
      &blocks,
      "",
      &mut missing,
      &mut seen,
    );
  }

  // Walk the blocks the envelope actually reaches, and require that each
  // of their non-optional props was seen in at least one example.
  // `DelegationMandate` joined the reachable set when the signed §7.3.1
  // golden landed: it embeds the full parent mandate, so every required
  // mandate prop — `principal_signature` above all — is now exercised.
  let reachable = [
    "NotarizationEnvelope",
    "CredentialSubject",
    "HumanPrincipalRef",
    "AgentRef",
    "ChannelDescriptor",
    "CommunicationDescriptor",
    "PolicyDescriptor",
    "NotarizationMetadata",
    "NotaryServiceRef",
    "EnvelopeProof",
    "DelegationMandate",
  ];

  let mut unexercised: std::vec::Vec<String> = std::vec::Vec::new();
  for block_name in reachable {
    let props = blocks
      .get(block_name)
      .and_then(|b| b.get("props"))
      .and_then(|p| p.as_object())
      .unwrap_or_else(|| std::panic!("Snapp has no block `{}`", block_name));
    for (prop_name, prop) in props {
      let optional = prop
        .get("@attrs")
        .and_then(|a| a.as_object())
        .map(|a| a.keys().any(|k| k.contains("optional")))
        .unwrap_or(false);
      if optional {
        continue;
      }
      if !seen.contains(&std::format!("{}.{}", block_name, prop_name)) {
        unexercised.push(std::format!("{}.{}", block_name, prop_name));
      }
    }
  }

  std::assert!(
    unexercised.is_empty(),
    "required N Lang props no published example exercises:\n  {}",
    unexercised.join("\n  ")
  );
}

#[test]
fn the_principal_signed_golden_exercises_the_chain_and_mandate_props() {
  // Before the signed §7.3.1 golden landed, five declared props existed in
  // the Snapp that NO published example ever reached: the chain-only proof
  // members (`id`, `previous_proof`), the mode label (`attestation_mode`),
  // the embedded grant (`delegation_mandate`), and the human's own
  // signature on it (`principal_signature`). This pins that the corpus now
  // exercises all five — remove or break the golden and the N Lang types
  // for the protocol's STRONGER mode go back to being dead declarations no
  // example validates.
  let blocks = snapp_blocks();
  let mut missing: std::vec::Vec<String> = std::vec::Vec::new();
  let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
  for path in example_files() {
    let raw = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    let value: serde_json::Value = serde_json::from_str(&raw)
      .unwrap_or_else(|e| std::panic!("{:?} is not valid JSON: {}", path, e));
    check_object(
      value
        .as_object()
        .unwrap_or_else(|| std::panic!("{:?} is not a JSON object", path)),
      "NotarizationEnvelope",
      &blocks,
      "",
      &mut missing,
      &mut seen,
    );
  }
  for required in [
    "EnvelopeProof.id",
    "EnvelopeProof.previous_proof",
    "PolicyDescriptor.attestation_mode",
    "PolicyDescriptor.delegation_mandate",
    "DelegationMandate.principal_signature",
  ] {
    std::assert!(
      seen.contains(required),
      "the example corpus no longer exercises `{}` against the Snapp types",
      required
    );
  }
}

#[test]
fn wire_key_mapping_handles_the_documented_exceptions() {
  // The camelCase-to-snake_case rule is mechanical, but two keys are
  // called out in the Snapp because they are not: `@context` has no
  // identifier form, and `type` is spelled as-is rather than escaped.
  // Pinning the mapping here keeps the walker above honest.
  std::assert_eq!(wire_key_to_prop("@context"), "context");
  std::assert_eq!(wire_key_to_prop("type"), "type");
  std::assert_eq!(wire_key_to_prop("aphVersion"), "aph_version");
  std::assert_eq!(wire_key_to_prop("bodySha256"), "body_sha256");
  std::assert_eq!(wire_key_to_prop("ap2IntentMandateUri"), "ap2_intent_mandate_uri");
}
