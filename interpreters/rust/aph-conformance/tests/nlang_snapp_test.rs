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
/// One named block's `props`, wherever the bundle declares it.
///
/// The exporter nests a child block inside its parent's `blocks` map — the
/// `VaultMutationKind` enum lives under `VaultMutation`, not beside it — so
/// a lookup that only reads the top level finds the parents and misses every
/// child. Resolving one level down as well keeps these pins asking about the
/// declaration rather than about the serialization's nesting, which has
/// already changed shape once under a toolchain bump.
fn block_props<'a>(
  blocks: &'a serde_json::Map<String, serde_json::Value>,
  block_name: &str,
) -> std::option::Option<&'a serde_json::Map<String, serde_json::Value>> {
  if let std::option::Option::Some(props) = blocks
    .get(block_name)
    .and_then(|b| b.get("props"))
    .and_then(|p| p.as_object())
  {
    return std::option::Option::Some(props);
  }
  blocks
    .values()
    .filter_map(|parent| parent.get("blocks").and_then(|n| n.as_object()))
    .find_map(|nested| {
      nested
        .get(block_name)
        .and_then(|b| b.get("props"))
        .and_then(|p| p.as_object())
    })
}

/// One named block's `enum` variants, wherever the bundle declares it.
///
/// The twin of [`block_props`], and it exists because a block is one of two
/// things. A RECORD declares `props`; an ENUM declares `enum`, and its
/// variants may themselves carry `items`. Demanding `props` from an enum
/// reports "no such block" for a block that is right there — which is a
/// false negative that reads exactly like a real drift, and is the worst
/// kind of alarm to have.
fn block_enum<'a>(
  blocks: &'a serde_json::Map<String, serde_json::Value>,
  block_name: &str,
) -> std::option::Option<&'a serde_json::Map<String, serde_json::Value>> {
  if let std::option::Option::Some(variants) = blocks
    .get(block_name)
    .and_then(|b| b.get("enum"))
    .and_then(|e| e.as_object())
  {
    return std::option::Option::Some(variants);
  }
  blocks
    .values()
    .filter_map(|parent| parent.get("blocks").and_then(|n| n.as_object()))
    .find_map(|nested| {
      nested
        .get(block_name)
        .and_then(|b| b.get("enum"))
        .and_then(|e| e.as_object())
    })
}

/// The PROTOCOL bundle's blocks.
///
/// The bundle name carries a version, so it is discovered by prefix rather
/// than hardcoded — a version bump must not silently skip this test. But it
/// is discovered by the `aph@` prefix rather than by extension alone,
/// because `snapp/` holds more than one bundle: the guardrail vocabulary
/// ships beside the protocol as `aph_guardrails@<version>.json`, and it has
/// a different shape (classifiers, not `mod.*.blocks`).
///
/// An earlier form of this took the LAST `*.json` in sorted order. That was
/// correct while exactly one bundle existed and silently wrong the moment a
/// second one landed — `_` sorts after `@`, so the sibling won and every pin
/// in this file began asking the wrong artifact. Selecting by prefix, and
/// REFUSING on anything other than exactly one match, is what makes a new
/// sibling a loud failure instead of a quiet re-target.
fn snapp_blocks() -> serde_json::Map<String, serde_json::Value> {
  let dir = repo_root().join("snapp");
  let mut bundles: std::vec::Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", dir, e))
    .filter_map(|e| e.ok().map(|e| e.path()))
    .filter(|p| p.extension().and_then(|s| s.to_str()) == std::option::Option::Some("json"))
    .filter(|p| {
      p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with("aph@"))
        .unwrap_or(false)
    })
    .collect();
  bundles.sort();
  std::assert_eq!(
    bundles.len(),
    1,
    "expected exactly one `aph@*.json` protocol bundle in {:?}, found {:?} — \
     a second one means two artifacts claim to be the protocol Snapp, and \
     these pins cannot silently choose between them",
    dir,
    bundles
  );
  let bundle = &bundles[0];

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
///
/// The corpus INVENTORY (`manifest.json`) shares the directory and is skipped
/// by name: it is the one file in `examples/*.json` that is not an envelope,
/// so every key-level check below would report its keys as envelope props with
/// no N Lang home. Enumerating a directory means owning what else lives there.
fn example_files() -> std::vec::Vec<std::path::PathBuf> {
  let dir = repo_root().join("examples");
  let mut files: std::vec::Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", dir, e))
    .filter_map(|e| e.ok().map(|e| e.path()))
    .filter(|p| {
      p.extension().and_then(|s| s.to_str()) == std::option::Option::Some("json")
        && p.file_name().and_then(|s| s.to_str()) != std::option::Option::Some("manifest.json")
    })
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
  // An ENUM block is validated by MEMBERSHIP, not by props: the object's
  // keys must be declared variants. A variant's own `items` are its shape,
  // and are deliberately not walked further here — this pin is about the
  // example corpus naming things the Snapp declares, and a variant name is
  // the thing being named.
  if let std::option::Option::Some(variants) = block_enum(&blocks, block_name) {
    // An enum rides the wire INTERNALLY TAGGED: a `kind` discriminator
    // naming the variant, plus that variant's own `items` as siblings. So
    // the tag selects which shape the remaining keys are checked against —
    // checking them against the variant NAMES instead would reject every
    // payload field, which is the shape of a false alarm rather than a
    // finding.
    let tag = match json.get("kind").and_then(serde_json::Value::as_str) {
      std::option::Option::Some(t) => t,
      std::option::Option::None => {
        missing.push(std::format!(
          "{}: enum `{}` is written without a `kind` discriminator",
          path, block_name
        ));
        return;
      }
    };
    let variant = match variants.get(tag) {
      std::option::Option::Some(v) => v,
      std::option::Option::None => {
        missing.push(std::format!(
          "{}.kind: `{}` is not a declared variant of enum `{}`",
          path, tag, block_name
        ));
        return;
      }
    };
    seen.insert(std::format!("{}.{}", block_name, tag));
    let items = variant
      .get("items")
      .and_then(serde_json::Value::as_object)
      .cloned()
      .unwrap_or_default();
    for key in json.keys() {
      if key == "kind" {
        continue;
      }
      if !items.contains_key(key.as_str()) {
        missing.push(std::format!(
          "{}.{}: variant `{}` of enum `{}` declares no item `{}`",
          path, key, tag, block_name, key
        ));
      }
    }
    return;
  }

  let props = match block_props(&blocks, block_name) {
    std::option::Option::Some(p) => p,
    std::option::Option::None => {
      missing.push(std::format!(
        "{}: Snapp has no block `{}` with props or variants",
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
    let props = block_props(&blocks, block_name)
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

/// Every `SCREAMING`/PascalCase variant the Snapp's `Vocabulary` block
/// declares, mapped to its u8 discriminant.
///
/// The Snapp flattens both closed vocabularies into one `Vocabulary` enum, so
/// this returns the union and the callers below select their own members by
/// name. Returning the union rather than guessing a split is deliberate: a
/// split that guessed wrong would fail for the wrong reason.
/// One NAMED enum's members from the Snapp's `Vocabulary` block.
///
/// Asks for the enum BY NAME rather than merging every enum in the block.
/// An earlier bundle shape flattened all five vocabularies into one map, so
/// `Slack` and `Reply` shared a namespace at discriminant 0 and a ChannelKind
/// lookup could be satisfied by a ContentClass member that happened to be
/// spelled the same. Naming the enum makes each pin answer about its own
/// vocabulary, which is what the tests below have always claimed to check.
fn snapp_vocabulary_discriminants(enum_name: &str) -> std::collections::BTreeMap<String, u64> {
  let blocks = snapp_blocks();
  let vocabulary = blocks
    .get("Vocabulary")
    .and_then(serde_json::Value::as_object)
    .unwrap_or_else(|| std::panic!("the Snapp has no `Vocabulary` block"));
  let declared = vocabulary
    .get("blocks")
    .and_then(serde_json::Value::as_object)
    .unwrap_or_else(|| std::panic!("`Vocabulary` declares no nested `blocks`"));
  let variants = declared
    .get(enum_name)
    .and_then(serde_json::Value::as_object)
    .and_then(|body| body.get("enum"))
    .and_then(serde_json::Value::as_object)
    .unwrap_or_else(|| {
      std::panic!("`Vocabulary` declares no `{}` enum", enum_name)
    });

  let mut out = std::collections::BTreeMap::new();
  for (name, body) in variants {
    if let std::option::Option::Some(discriminant) =
      body.get("const").and_then(serde_json::Value::as_u64)
    {
      out.insert(name.clone(), discriminant);
    }
  }
  out
}

#[test]
fn the_snapp_and_the_reference_agree_on_the_channel_kind_vocabulary() {
  // WHY THIS EXISTS. The Snapp is a SECOND POPULATOR of the same closed
  // vocabulary: `aph-core` declares `ChannelKind` and the Snapp declares u8
  // discriminants for the same members, and until this test nothing compared
  // them. A type is a claim about what COULD be written; only a populator
  // says what IS — so two populators with no reconciliation is not a
  // duplication smell, it is a drift channel with no alarm on it.
  //
  // WHAT IT PINS, and the ordering is the point: it is armed BEFORE the
  // service-act revision widens the set. When that revision adds a member to
  // `ChannelKind::ALL`, THIS TEST GOES RED until the Snapp's `Vocabulary`
  // block gains the matching variant. That is the whole purpose — a widening
  // that moved only one populator would otherwise ship two vocabularies
  // numbered differently, and the discriminants are wire-adjacent.
  //
  // Membership is compared, not discriminant VALUES: the Snapp assigns
  // positions across a flattened union, so the values are its business. What
  // must never diverge is WHICH MEMBERS EXIST.
  let snapp = snapp_vocabulary_discriminants("ChannelKind");
  let mut missing_from_snapp = std::vec::Vec::new();
  for kind in aph_core::ChannelKind::ALL {
    // The Snapp spells variants in PascalCase; the wire spelling is the
    // reference's `label()`. `GoogleChat` <-> `google_chat` is the pair most
    // likely to drift, which is why the mapping is derived rather than typed.
    let pascal: String = kind
      .label()
      .split('_')
      .map(|part| {
        let mut chars = part.chars();
        match chars.next() {
          std::option::Option::Some(first) => {
            first.to_uppercase().collect::<String>() + chars.as_str()
          }
          std::option::Option::None => String::new(),
        }
      })
      .collect();
    if !snapp.contains_key(&pascal) {
      missing_from_snapp.push(std::format!("{} (expected Snapp variant `{}`)", kind.label(), pascal));
    }
  }
  std::assert!(
    missing_from_snapp.is_empty(),
    "the reference declares channel kinds the Snapp's `Vocabulary` block does not: {:?}\n\
     Add the variant to the Snapp in the SAME change that widened the reference.",
    missing_from_snapp
  );
}

#[test]
fn the_snapp_and_the_reference_agree_on_the_content_class_vocabulary() {
  // The twin of the channel-kind pin above; see it for the full reasoning.
  // `DM` is this set's drift candidate — it is the one member whose wire
  // spelling is not PascalCase, so a naive transform yields `Dm` and the
  // populators part company on a value that still looks right.
  let snapp = snapp_vocabulary_discriminants("ContentClass");
  let mut missing_from_snapp = std::vec::Vec::new();
  for class in aph_core::ContentClass::ALL {
    // The Snapp spells this set exactly as the wire does EXCEPT `DM`, which
    // it writes `Dm`; both spellings are accepted here because the Snapp's
    // casing is its own and only MEMBERSHIP is under test.
    let label = class.label();
    let alternate = std::format!(
      "{}{}",
      label.chars().next().unwrap_or(' ').to_uppercase(),
      label.chars().skip(1).collect::<String>().to_lowercase()
    );
    if !snapp.contains_key(label) && !snapp.contains_key(&alternate) {
      missing_from_snapp.push(label.to_string());
    }
  }
  std::assert!(
    missing_from_snapp.is_empty(),
    "the reference declares content classes the Snapp's `Vocabulary` block does not: {:?}\n\
     Add the variant to the Snapp in the SAME change that widened the reference.",
    missing_from_snapp
  );
}

#[test]
fn the_snapp_and_the_reference_agree_on_the_policy_decision_vocabulary() {
  // The Snapp declared `PolicyDecision` as an enum from the start; the
  // REFERENCE was the last populator carrying it as an unvalidated String,
  // which an audit found only because the independent implementation
  // disagreed with it. Welded like its two siblings above; the spellings
  // are PascalCase on the wire and in the Snapp alike, so no casing
  // alternate is needed.
  let snapp = snapp_vocabulary_discriminants("PolicyDecision");
  let mut missing_from_snapp = std::vec::Vec::new();
  for decision in aph_core::PolicyDecision::ALL {
    if !snapp.contains_key(decision.label()) {
      missing_from_snapp.push(decision.label());
    }
  }
  std::assert!(
    missing_from_snapp.is_empty(),
    "the reference declares policy decisions the Snapp's `Vocabulary` block does not: {:?}",
    missing_from_snapp
  );
  std::assert_eq!(
    snapp.len(),
    aph_core::PolicyDecision::ALL.len(),
    "the Snapp declares policy decisions the reference does not"
  );
}
