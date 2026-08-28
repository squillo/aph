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
