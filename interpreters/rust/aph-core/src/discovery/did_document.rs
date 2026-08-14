//! `did:web` DID Document parsing and verification-method lookup.
//!
//! Spec §8.4.4 resolves a notary key by fetching
//! `https://<domain>/.well-known/did.json` and locating the
//! `verificationMethod` entry the proof names. The fetch belongs to an
//! adapter; the parsing and the lookup rules live here.
//!
//! The trust model is the TLS certificate chain that validated the origin —
//! the same property that backs OAuth issuer URLs and BIMI.

/// A DID Document, parsed to the fields APH needs.
///
/// Deliberately NOT `deny_unknown_fields`: a DID Document is a general W3C
/// artifact that legitimately carries much more than APH reads (services,
/// authentication relationships, other proof purposes). Rejecting those
/// would make APH unable to verify notaries with ordinary DID Documents.
#[derive(std::fmt::Debug, std::clone::Clone, serde::Serialize, serde::Deserialize)]
pub struct DidDocument {
  /// The document's own DID.
  pub id: String,
  /// Published keys. Absent in a document that delegates all keys by
  /// reference, which APH cannot use.
  #[serde(default, rename = "verificationMethod")]
  pub verification_method: std::vec::Vec<VerificationMethod>,
  /// DID URLs approved for the `assertionMethod` proof purpose.
  #[serde(default, rename = "assertionMethod")]
  pub assertion_method: std::vec::Vec<serde_json::Value>,
}

/// One entry of a DID Document's `verificationMethod` array.
#[derive(std::fmt::Debug, std::clone::Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationMethod {
  /// Full DID URL of this key, including its fragment.
  pub id: String,
  /// Key type, e.g. `Multikey`.
  #[serde(rename = "type")]
  pub r#type: String,
  /// DID that controls this key.
  #[serde(default)]
  pub controller: std::option::Option<String>,
  /// Multibase-encoded multicodec public key.
  #[serde(default, rename = "publicKeyMultibase")]
  pub public_key_multibase: std::option::Option<String>,
  /// JWK-encoded public key. Parsed only far enough to report that APH
  /// does not yet consume this form.
  #[serde(default, rename = "publicKeyJwk")]
  pub public_key_jwk: std::option::Option<serde_json::Value>,
}

/// Parses a DID Document from the bytes an adapter fetched.
pub fn parse_did_document(
  json: &str,
) -> std::result::Result<DidDocument, crate::errors::AphError> {
  match serde_json::from_str::<DidDocument>(json) {
    std::result::Result::Ok(doc) => std::result::Result::Ok(doc),
    // A document that will not parse is indistinguishable, from a
    // verifier's seat, from an unreachable notary.
    std::result::Result::Err(_) => {
      std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable)
    }
  }
}

impl DidDocument {
  /// Returns `true` if `did_url` is listed for the `assertionMethod` proof
  /// purpose, which is the purpose APH envelope proofs declare.
  ///
  /// Entries may be plain DID URL strings or embedded objects with an `id`;
  /// both forms are recognized.
  pub fn allows_assertion(&self, did_url: &str) -> bool {
    self.assertion_method.iter().any(|entry| match entry {
      serde_json::Value::String(s) => s == did_url,
      serde_json::Value::Object(o) => {
        o.get("id").and_then(|v| v.as_str()) == std::option::Option::Some(did_url)
      }
      _ => false,
    })
  }

  /// Finds the key a proof's `verificationMethod` names (spec §8.4.4
  /// steps 5–6).
  ///
  /// When the DID URL carries no fragment, the document must publish
  /// exactly one key: guessing among several would let the document's
  /// ordering decide which key verifies a credential.
  pub fn resolve_key(
    &self,
    did_url: &str,
  ) -> std::result::Result<super::NotaryPublicKey, crate::errors::AphError> {
    let parsed = super::DidUrl::parse(did_url);
    let entry = match parsed.fragment {
      std::option::Option::Some(_) => self
        .verification_method
        .iter()
        .find(|vm| vm.id == did_url)
        // Also accept an entry recorded as a bare fragment relative to the
        // document, which some producers emit.
        .or_else(|| {
          let want = std::format!("#{}", parsed.fragment.clone().unwrap_or_default());
          self.verification_method.iter().find(|vm| vm.id == want)
        }),
      std::option::Option::None => {
        if self.verification_method.len() == 1 {
          self.verification_method.first()
        } else {
          std::option::Option::None
        }
      }
    };

    let entry = match entry {
      std::option::Option::Some(e) => e,
      // The document was fetched and parsed; it simply names no key
      // matching the queried DID URL (or names several and the URL carries
      // no fragment to choose by). That is "not published" (APH_E014), not
      // a signature defect: the E001 this arm returned before the taxonomy
      // had a word for absence accused the envelope of a forgery no key
      // was ever obtained to check.
      std::option::Option::None => {
        return std::result::Result::Err(crate::errors::AphError::notary_key_not_published(
          std::format!("DID Document names no verificationMethod matching `{}`", did_url),
        ));
      }
    };

    let multibase = match entry.public_key_multibase.as_deref() {
      std::option::Option::Some(m) => m,
      std::option::Option::None => {
        // publicKeyJwk is legal in a DID Document but not yet consumed
        // here; say so plainly instead of reporting a bad signature.
        return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
          "verificationMethod without publicKeyMultibase (publicKeyJwk not supported)",
        ));
      }
    };

    match crate::crypto::did_key::decode_multibase_key(multibase)? {
      crate::crypto::did_key::DecodedDidKey::Ed25519(key) => {
        std::result::Result::Ok(super::NotaryPublicKey {
          algorithm: super::KeyAlgorithm::Ed25519,
          key_bytes: key.as_bytes().to_vec(),
          kid: parsed.fragment,
        })
      }
      crate::crypto::did_key::DecodedDidKey::P256(bytes) => {
        std::result::Result::Ok(super::NotaryPublicKey {
          algorithm: super::KeyAlgorithm::P256,
          key_bytes: bytes,
          kid: parsed.fragment,
        })
      }
    }
  }
}

#[cfg(test)]
mod tests {
  /// The DID Document printed in spec §8.4.4.
  const SPEC_EXAMPLE: &str = r#"{
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:web:notary.example.com",
    "verificationMethod": [
      {
        "id": "did:web:notary.example.com#k1",
        "type": "Multikey",
        "controller": "did:web:notary.example.com",
        "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"
      }
    ],
    "assertionMethod": ["did:web:notary.example.com#k1"]
  }"#;

  #[test]
  fn parses_the_spec_example_document() {
    // The literal example from the specification must parse, or operators
    // copying it would publish something this verifier cannot read.
    let doc = super::parse_did_document(SPEC_EXAMPLE).unwrap();
    std::assert_eq!(doc.id, "did:web:notary.example.com");
    std::assert_eq!(doc.verification_method.len(), 1);
  }

  #[test]
  fn resolves_the_key_named_by_the_fragment() {
    // The proof names a specific key; resolution must return that one.
    let doc = super::parse_did_document(SPEC_EXAMPLE).unwrap();
    let key = doc.resolve_key("did:web:notary.example.com#k1").unwrap();
    std::assert_eq!(key.algorithm, crate::discovery::KeyAlgorithm::Ed25519);
    std::assert_eq!(key.key_bytes.len(), 32);
    std::assert_eq!(key.kid.as_deref(), Some("k1"));
  }

  #[test]
  fn unknown_fragment_does_not_fall_back_to_another_key() {
    // Falling back to "some other key in the document" would let a
    // document owner verify a proof under a key the proof never named.
    let doc = super::parse_did_document(SPEC_EXAMPLE).unwrap();
    std::assert!(doc.resolve_key("did:web:notary.example.com#k9").is_err());
  }

  #[test]
  fn fragmentless_url_resolves_only_when_the_document_is_unambiguous() {
    // With one key, no fragment is unambiguous. With two, silently picking
    // the first would make document ordering security-relevant.
    let doc = super::parse_did_document(SPEC_EXAMPLE).unwrap();
    std::assert!(doc.resolve_key("did:web:notary.example.com").is_ok());

    let multi = r#"{
      "id": "did:web:n.example",
      "verificationMethod": [
        {"id":"did:web:n.example#a","type":"Multikey","publicKeyMultibase":"z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"},
        {"id":"did:web:n.example#b","type":"Multikey","publicKeyMultibase":"z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"}
      ]
    }"#;
    let doc = super::parse_did_document(multi).unwrap();
    std::assert!(doc.resolve_key("did:web:n.example").is_err());
  }

  #[test]
  fn unknown_document_fields_are_tolerated() {
    // A DID Document carries far more than APH reads. Strict parsing here
    // would make ordinary, valid documents unusable.
    // Note the ## delimiters: this document contains `"#hub"`, and the
    // sequence `"#` would otherwise close an r#"..."# literal early.
    let doc = r##"{
      "@context": ["https://www.w3.org/ns/did/v1"],
      "id": "did:web:n.example",
      "service": [{"id":"#hub","type":"Hub","serviceEndpoint":"https://n.example/hub"}],
      "authentication": ["did:web:n.example#k1"],
      "verificationMethod": [
        {"id":"did:web:n.example#k1","type":"Multikey","publicKeyMultibase":"z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"}
      ]
    }"##;
    std::assert!(super::parse_did_document(doc).unwrap().resolve_key("did:web:n.example#k1").is_ok());
  }

  #[test]
  fn assertion_method_membership_is_reported() {
    // APH proofs declare proofPurpose "assertionMethod"; a caller enforcing
    // that needs to know whether the key is listed for it.
    let doc = super::parse_did_document(SPEC_EXAMPLE).unwrap();
    std::assert!(doc.allows_assertion("did:web:notary.example.com#k1"));
    std::assert!(!doc.allows_assertion("did:web:notary.example.com#k2"));
  }

  #[test]
  fn jwk_only_entry_reports_unsupported_rather_than_bad_signature() {
    // publicKeyJwk is legal but unimplemented. The distinction matters: an
    // operator should learn to publish multibase, not hunt a key mismatch.
    let doc = r#"{
      "id": "did:web:n.example",
      "verificationMethod": [
        {"id":"did:web:n.example#k1","type":"JsonWebKey","publicKeyJwk":{"kty":"OKP"}}
      ]
    }"#;
    let parsed = super::parse_did_document(doc).unwrap();
    std::assert_eq!(
      parsed.resolve_key("did:web:n.example#k1").unwrap_err().code(),
      "APH_E010"
    );
  }

  #[test]
  fn malformed_json_reports_the_notary_as_unreachable() {
    // From the verifier's seat an unparseable document and an unreachable
    // origin are the same failure: no key was obtained.
    std::assert_eq!(
      super::parse_did_document("{not json").unwrap_err().code(),
      "APH_E008"
    );
  }
}
