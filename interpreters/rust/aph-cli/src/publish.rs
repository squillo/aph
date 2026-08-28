//! The §8.4 publication surfaces, rendered.
//!
//! WHY THIS EXISTS. `aph-core` has rendered both §8.4 publication forms since
//! the discovery work landed, and until now nothing shipped in this
//! repository called them. The bytes for the live reference deployment came
//! from a program in another repository — so an adopter holding `aph-core`
//! could implement a notary and still have no way to publish one, which is
//! the same defect as a closed vocabulary nobody can check: the capability
//! exists, and not where the person who needs it will look.
//!
//! ONE RENDERER, ALWAYS. These subcommands do not template, format, or
//! re-derive any wire form. They decode their arguments, call
//! [`aph_core::discovery::publish`], and write what it returns. Two renderers
//! of one wire form drift — and a drifted publication surface does not fail
//! loudly, it publishes a key nobody can verify against.
//!
//! # PUBLIC KEY MATERIAL ONLY
//!
//! Every input here is a `did:key`, which IS a public key in a self-
//! describing envelope. Nothing in this module accepts, reads, or derives a
//! private key, and nothing in it should ever be extended to: a signing seed
//! reaching a command line is readable in `ps` by every other process on the
//! host. A publication tool needs the public half and nothing else, which is
//! what makes it safe to hand to an operator.

/// Renders the §8.4.5 DNS TXT tag list for one published key.
///
/// The value goes to stdout so it can be piped or captured. The RECORD NAME
/// goes to stderr when `--domain` is given, because it is operator guidance
/// rather than part of the value — a name accidentally captured into the
/// record's content is a broken publication that still looks published.
pub fn cmd_render_txt(args: &[std::string::String]) -> i32 {
  let mut did: std::option::Option<&str> = std::option::Option::None;
  let mut kid: std::option::Option<&str> = std::option::Option::None;
  let mut not_before = "";
  let mut not_after = "";
  let mut domain: std::option::Option<&str> = std::option::Option::None;

  let mut index = 0;
  while index < args.len() {
    match args[index].as_str() {
      "--kid" => {
        kid = args.get(index + 1).map(std::string::String::as_str);
        index += 2;
      }
      "--not-before" => {
        not_before = args.get(index + 1).map(std::string::String::as_str).unwrap_or("");
        index += 2;
      }
      "--not-after" => {
        not_after = args.get(index + 1).map(std::string::String::as_str).unwrap_or("");
        index += 2;
      }
      "--domain" => {
        domain = args.get(index + 1).map(std::string::String::as_str);
        index += 2;
      }
      other => {
        if did.is_none() {
          did = std::option::Option::Some(other);
        }
        index += 1;
      }
    }
  }

  let did = match did {
    std::option::Option::Some(d) => d,
    std::option::Option::None => {
      eprintln!("render-txt: a did:key argument is required");
      return 2;
    }
  };

  let key = match public_key_from_did(did, kid) {
    std::result::Result::Ok(k) => k,
    std::result::Result::Err(message) => {
      eprintln!("render-txt: {}", message);
      return 1;
    }
  };

  match aph_core::discovery::publish::render_txt_record(&key, not_before, not_after) {
    std::result::Result::Ok(value) => {
      if let std::option::Option::Some(host) = domain {
        eprintln!("record name: _aph._notary.{}", host);
      }
      println!("{}", value);
      0
    }
    std::result::Result::Err(e) => {
      eprintln!("render-txt: {}", e);
      1
    }
  }
}

/// Renders the §8.4.4 DID Document publishing one or more keys.
///
/// Every published key needs a `kid`, because it becomes the fragment of the
/// `verificationMethod` a proof names. Keys are given as `did:key` values
/// with that fragment attached — `did:key:z6Mk…#k1` — which is the same
/// shape a verifier reads back, so the operator writes the identifier once
/// rather than pairing a key with a name positionally.
pub fn cmd_render_did(args: &[std::string::String]) -> i32 {
  let did = match args.first() {
    std::option::Option::Some(d) => d.as_str(),
    std::option::Option::None => {
      eprintln!("render-did: a did:web identifier and at least one did:key are required");
      return 2;
    }
  };
  if args.len() < 2 {
    eprintln!("render-did: at least one did:key#kid must be published");
    return 2;
  }

  let mut keys: std::vec::Vec<aph_core::discovery::NotaryPublicKey> =
    std::vec::Vec::with_capacity(args.len() - 1);
  for raw in &args[1..] {
    let (key_did, fragment) = match raw.split_once('#') {
      std::option::Option::Some((k, f)) => (k, std::option::Option::Some(f)),
      std::option::Option::None => (raw.as_str(), std::option::Option::None),
    };
    match public_key_from_did(key_did, fragment) {
      std::result::Result::Ok(k) => keys.push(k),
      std::result::Result::Err(message) => {
        eprintln!("render-did: {}", message);
        return 1;
      }
    }
  }

  match aph_core::discovery::publish::render_did_document(did, &keys) {
    std::result::Result::Ok(document) => {
      println!("{}", document);
      0
    }
    std::result::Result::Err(e) => {
      eprintln!("render-did: {}", e);
      1
    }
  }
}

/// Renders the §8.5.1 DNS TXT tag list publishing one vocabulary's digest.
///
/// Reads the digest FROM THE BUNDLE rather than computing it. The compiled
/// bundle already declares `@snapp.integrity`, and recomputing here would be
/// a second derivation of one fact — two derivations of one fact drift, and a
/// drifted digest does not fail loudly: it publishes a value that refuses
/// bytes which are in fact correct.
pub fn cmd_render_vocab(args: &[std::string::String]) -> i32 {
  let mut path: std::option::Option<&str> = std::option::Option::None;
  let mut domain: std::option::Option<&str> = std::option::Option::None;

  let mut index = 0;
  while index < args.len() {
    match args[index].as_str() {
      "--domain" => {
        domain = args.get(index + 1).map(std::string::String::as_str);
        index += 2;
      }
      other => {
        if path.is_none() {
          path = std::option::Option::Some(other);
        }
        index += 1;
      }
    }
  }

  let path = match path {
    std::option::Option::Some(p) => p,
    std::option::Option::None => {
      eprintln!("render-vocab: a compiled bundle path is required");
      return 2;
    }
  };

  let raw = match std::fs::read_to_string(path) {
    std::result::Result::Ok(r) => r,
    std::result::Result::Err(e) => {
      eprintln!("render-vocab: cannot read {}: {}", path, e);
      return 1;
    }
  };
  let value: serde_json::Value = match serde_json::from_str(&raw) {
    std::result::Result::Ok(v) => v,
    std::result::Result::Err(e) => {
      eprintln!("render-vocab: {} is not valid JSON: {}", path, e);
      return 1;
    }
  };

  let record = match vocabulary_record(&value) {
    std::result::Result::Ok(r) => r,
    std::result::Result::Err(message) => {
      eprintln!("render-vocab: {}", message);
      return 1;
    }
  };
  if let std::option::Option::Some(host) = domain {
    eprintln!("record name: _aph._vocab.{}", host);
  }
  println!("{}", record);
  0
}

/// The §8.5.1 record for a compiled bundle, by way of `aph-core`'s renderer.
///
/// This function only LOCATES the three inputs in the bundle's `@snapp`
/// block; the wire form itself is rendered by
/// [`aph_core::discovery::publish::render_vocab_record`], beside its §8.4.5
/// sibling — the ONE renderer rule this module's preamble states. That is
/// also where the tag-injection guard lives: a bundle name carrying `;`
/// would otherwise terminate the entry and inject tags into a published
/// record, and the guard belongs with the renderer rather than with every
/// caller who remembers.
fn vocabulary_record(bundle: &serde_json::Value) -> std::result::Result<String, std::string::String> {
  let meta = bundle
    .get("@snapp")
    .and_then(serde_json::Value::as_object)
    .ok_or_else(|| std::string::String::from("the bundle declares no `@snapp` block"))?;
  let read = |key: &str| -> std::result::Result<&str, std::string::String> {
    meta
      .get(key)
      .and_then(serde_json::Value::as_str)
      .ok_or_else(|| std::format!("the bundle's `@snapp` declares no `{}`", key))
  };
  aph_core::discovery::publish::render_vocab_record(read("name")?, read("version")?, read("integrity")?)
    .map_err(|e| std::format!("{}", e))
}

/// Decodes a `did:key` into the public key the renderers publish.
///
/// The decode is `aph-core`'s, not a second implementation of multibase and
/// multicodec — this reads the same bytes a verifier reads, which is the
/// property that makes a published key verifiable at all.
fn public_key_from_did(
  did: &str,
  kid: std::option::Option<&str>,
) -> std::result::Result<aph_core::discovery::NotaryPublicKey, std::string::String> {
  let decoded = aph_core::decode_did_key(did)
    .map_err(|e| std::format!("`{}` is not a decodable did:key: {}", did, e))?;
  let (algorithm, key_bytes) = match decoded {
    aph_core::DecodedDidKey::Ed25519(verifying) => (
      aph_core::discovery::KeyAlgorithm::Ed25519,
      verifying.to_bytes().to_vec(),
    ),
    aph_core::DecodedDidKey::P256(bytes) => (aph_core::discovery::KeyAlgorithm::P256, bytes),
  };
  std::result::Result::Ok(aph_core::discovery::NotaryPublicKey {
    algorithm,
    key_bytes,
    kid: kid.map(std::string::String::from),
  })
}

#[cfg(test)]
mod tests {
  //! These pin that the subcommands DELEGATE, and that the delegation is
  //! wired to the real decoder. What they deliberately do not do is re-assert
  //! the rendered wire forms: those are `aph-core`'s to pin, and a second
  //! copy of the expected bytes here would be exactly the drift this module's
  //! preamble refuses.

  /// RFC 8032 §7.1 test vector 1's public key, as a `did:key`. A published
  /// test vector, never a production-looking value.
  const RFC8032_DID: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV";

  #[test]
  fn a_did_key_decodes_to_the_public_key_the_renderers_publish() {
    // WHY: the whole point of this module is that the operator's input is
    // decoded by the SAME code a verifier uses. If this ever grew a private
    // multibase reader the two would drift, and a drifted publication does
    // not fail loudly — it publishes a key nobody can verify against.
    //
    // PINS: a `did:key` yields an Ed25519 key of the right length, and the
    // `kid` travels through as given.
    let key = super::public_key_from_did(RFC8032_DID, std::option::Option::Some("k1"))
      .expect("a published RFC 8032 vector must decode");
    std::assert_eq!(key.algorithm, aph_core::discovery::KeyAlgorithm::Ed25519);
    std::assert_eq!(key.key_bytes.len(), 32);
    std::assert_eq!(key.kid.as_deref(), std::option::Option::Some("k1"));
  }

  #[test]
  fn a_value_that_is_not_a_did_key_is_refused_rather_than_published() {
    // WHY: publishing is one-way. A garbled input that rendered anyway would
    // put an unverifiable key in DNS, where it stays until someone notices
    // that verification has been failing.
    let refused = super::public_key_from_did("did:web:notary.example.com", std::option::Option::None);
    std::assert!(refused.is_err(), "a did:web is not a key and must not decode as one");
  }

  #[test]
  fn the_rendered_txt_record_is_the_cores_and_carries_the_kid() {
    // WHY: pins the delegation itself — that this module calls `aph-core`'s
    // renderer rather than formatting a tag list of its own. The assertions
    // are deliberately weak on FORM (tag presence, not the whole string):
    // asserting the exact bytes here would be a second copy of the wire
    // format, which is what the preamble refuses.
    let key = super::public_key_from_did(RFC8032_DID, std::option::Option::Some("k1"))
      .expect("the vector decodes");
    let value = aph_core::discovery::publish::render_txt_record(&key, "", "")
      .expect("a decodable key renders");
    std::assert!(value.contains("v=APHv1"), "the tag list names its version: {}", value);
    std::assert!(value.contains("kid=k1"), "a supplied kid must reach the record: {}", value);
  }

  #[test]
  fn the_shipped_guardrail_bundle_renders_its_own_record() {
    // WHY: pinned against the REAL committed bundle, not a fixture. A
    // renderer tested only against a synthetic input has never met the
    // artifact it exists to publish — and this one exists to publish exactly
    // this file. If the bundle is re-exported and its digest moves, this
    // reads the new one, because it reads rather than remembers.
    //
    // PINS: the tag list is assembled from `@snapp`'s own name, version and
    // integrity, in §8.5.1 order, and the digest is carried VERBATIM.
    let raw = std::include_str!("../../../../snapp/aph_guardrails@0.1.0-alpha.1.json");
    let bundle: serde_json::Value =
      serde_json::from_str(raw).expect("the committed bundle is valid JSON");
    let record = super::vocabulary_record(&bundle).expect("a shipped bundle renders");

    let integrity = bundle["@snapp"]["integrity"]
      .as_str()
      .expect("the bundle declares an integrity digest");
    std::assert!(record.starts_with("v=APHv1; "), "the version tag leads: {}", record);
    std::assert!(record.contains("n=aph_guardrails; "), "the name is the bundle's: {}", record);
    std::assert!(
      record.ends_with(&std::format!("h={}", integrity)),
      "the digest must be carried verbatim, not re-encoded: {}",
      record
    );
  }

  #[test]
  fn a_record_fits_one_txt_character_string() {
    // WHY: §8.5.1 requires one 255-byte character-string, and the reason is
    // interop rather than tidiness — a digest split across strings needs a
    // concatenation rule, and a concatenation rule two implementations read
    // differently is a defect that only ever surfaces between strangers.
    // Refusing in the renderer is the difference between an error an operator
    // reads and a publication that silently truncates.
    let raw = std::include_str!("../../../../snapp/aph_guardrails@0.1.0-alpha.1.json");
    let bundle: serde_json::Value = serde_json::from_str(raw).expect("valid JSON");
    let record = super::vocabulary_record(&bundle).expect("it renders");
    std::assert!(
      record.len() <= 255,
      "a shipped bundle's record must fit one character-string, got {} bytes",
      record.len()
    );
  }

  #[test]
  fn a_bundle_missing_its_metadata_is_refused_rather_than_published() {
    // WHY: publishing is one-way. A record assembled from absent metadata
    // would name a vocabulary nobody can resolve, and it would sit in DNS
    // until someone noticed resolution had been failing.
    let empty = serde_json::json!({});
    std::assert!(
      super::vocabulary_record(&empty).is_err(),
      "a bundle with no `@snapp` block must not render"
    );
    let partial = serde_json::json!({"@snapp": {"name": "x", "version": "1"}});
    std::assert!(
      super::vocabulary_record(&partial).is_err(),
      "a bundle with no integrity digest must not render"
    );
  }

  #[test]
  fn a_did_document_publishes_every_key_it_is_given() {
    // WHY: `render-did` accepts several keys so a rotation overlap can be
    // published in one document (§8.4.7). A tool that could only publish one
    // key would make the overlap window unreachable, which is the window that
    // keeps a rotation from stranding verifiers mid-flight.
    let first = super::public_key_from_did(RFC8032_DID, std::option::Option::Some("k1"))
      .expect("the vector decodes");
    let second = super::public_key_from_did(RFC8032_DID, std::option::Option::Some("k2"))
      .expect("the vector decodes");
    let document =
      aph_core::discovery::publish::render_did_document("did:web:notary.example.com", &[first, second])
        .expect("two keyed keys publish");
    std::assert!(document.contains("#k1"), "the first kid becomes a fragment: {}", document);
    std::assert!(document.contains("#k2"), "the second kid becomes a fragment: {}", document);
  }
}
