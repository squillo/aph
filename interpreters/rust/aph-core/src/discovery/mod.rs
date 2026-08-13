//! Notary key discovery — the parsing half.
//!
//! Spec §8.4 defines three ways a verifier recovers a notary's public key
//! with no prior trust relationship: `did:key` (offline), a DNS TXT record,
//! and a `did:web` DID Document over HTTPS.
//!
//! **Only parsing lives here.** Fetching — DNS queries and HTTPS requests —
//! is deliberately excluded so this crate stays offline, dependency-light,
//! and fully testable: every rule below is exercised against fixed strings
//! rather than a live network. A companion adapter crate performs the I/O
//! and feeds the results to these functions.
//!
//! `did:key` needs no fetching at all, so it is complete in
//! [`crate::crypto::did_key`] rather than here.
//!
//! The modules divide as follows. [`dns_txt`] and [`did_document`] parse the
//! two fetched wire forms; [`publish`] renders those same two forms, so the
//! pair is round-trip testable without a network; [`ports`] declares the two
//! narrow one-method ports an adapter implements to do the fetching; and
//! [`composer`] dispatches across mechanisms in the §8.4.6 preference order
//! with no silent downgrade from a stronger mechanism to a weaker one.

pub mod composer;
pub mod did_document;
pub mod dns_txt;
pub mod ports;
pub mod publish;

/// Signing algorithm a discovered key is pinned to.
///
/// The algorithm travels WITH the key rather than being inferred from its
/// length, so a verifier never guesses which primitive to use.
#[derive(std::fmt::Debug, std::clone::Clone, std::marker::Copy, std::cmp::PartialEq, std::cmp::Eq)]
pub enum KeyAlgorithm {
  /// Ed25519 — the `eddsa-jcs-2022` cryptosuite.
  Ed25519,
  /// NIST P-256 — the `ecdsa-jcs-2019` cryptosuite.
  P256,
}

impl KeyAlgorithm {
  /// Parses the `alg` tag of a DNS TXT record (spec §8.4.5).
  ///
  /// The tag values are lowercase and closed; anything else is `APH_E010`
  /// rather than a silent fallback to a default algorithm.
  pub fn from_dns_tag(tag: &str) -> std::result::Result<Self, crate::errors::AphError> {
    match tag {
      "ed25519" => std::result::Result::Ok(Self::Ed25519),
      "p256" => std::result::Result::Ok(Self::P256),
      other => std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(other)),
    }
  }
}

/// A notary public key recovered from a discovery mechanism.
#[derive(std::fmt::Debug, std::clone::Clone, std::cmp::PartialEq, std::cmp::Eq)]
pub struct NotaryPublicKey {
  /// Algorithm this key must be used with.
  pub algorithm: KeyAlgorithm,
  /// Raw public key bytes (32 for Ed25519, 33 compressed for P-256).
  pub key_bytes: std::vec::Vec<u8>,
  /// Key identifier, when the source supplied one. Matched against the
  /// fragment of `proof.verificationMethod` to pick among several keys.
  pub kid: std::option::Option<String>,
}

impl NotaryPublicKey {
  /// Converts to an Ed25519 verifying key, or fails if this key is a
  /// different algorithm or not a valid curve point.
  pub fn to_ed25519(
    &self,
  ) -> std::result::Result<ed25519_dalek::VerifyingKey, crate::errors::AphError> {
    if self.algorithm != KeyAlgorithm::Ed25519 {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
        "expected ed25519 key",
      ));
    }
    let arr: [u8; 32] = match self.key_bytes.as_slice().try_into() {
      std::result::Result::Ok(a) => a,
      std::result::Result::Err(_) => {
        return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
      }
    };
    match ed25519_dalek::VerifyingKey::from_bytes(&arr) {
      std::result::Result::Ok(k) => std::result::Result::Ok(k),
      std::result::Result::Err(_) => {
        std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature)
      }
    }
  }
}

/// A parsed `proof.verificationMethod` DID URL.
#[derive(std::fmt::Debug, std::clone::Clone, std::cmp::PartialEq, std::cmp::Eq)]
pub struct DidUrl {
  /// The DID without any fragment, e.g. `did:web:notary.example.com`.
  pub did: String,
  /// The fragment after `#`, when present — the key identifier.
  pub fragment: std::option::Option<String>,
}

impl DidUrl {
  /// Splits a DID URL into its DID and fragment.
  pub fn parse(input: &str) -> Self {
    match input.split_once('#') {
      std::option::Option::Some((did, fragment)) => Self {
        did: String::from(did),
        fragment: std::option::Option::Some(String::from(fragment)),
      },
      std::option::Option::None => Self {
        did: String::from(input),
        fragment: std::option::Option::None,
      },
    }
  }

  /// Returns the `did:web` method-specific identifier, if this is a
  /// `did:web` DID.
  pub fn web_identifier(&self) -> std::option::Option<&str> {
    self.did.strip_prefix("did:web:")
  }

  /// Builds the HTTPS URL of the DID Document for a `did:web` DID
  /// (spec §8.4.4 step 2).
  ///
  /// Per the `did:web` method, colons in the identifier map to path
  /// segments, and an identifier with no path resolves under
  /// `/.well-known/`. Each segment is percent-decoded AFTER the split,
  /// which is how a port written `%3A8443` stays attached to the host
  /// instead of becoming a path segment.
  pub fn web_document_url(&self) -> std::option::Option<String> {
    let identifier = self.web_identifier()?;
    // Order matters: split on ':' FIRST, then percent-decode each segment.
    // Decoding first would turn a `%3A` port separator into a real colon
    // and split the port off as a path segment.
    let mut parts = identifier.split(':');
    let host = percent_decode(parts.next()?);
    if host.is_empty() {
      return std::option::Option::None;
    }
    let path_segments: std::vec::Vec<String> = parts
      .filter(|p| !p.is_empty())
      .map(percent_decode)
      .collect();
    if path_segments.is_empty() {
      std::option::Option::Some(std::format!("https://{}/.well-known/did.json", host))
    } else {
      std::option::Option::Some(std::format!(
        "https://{}/{}/did.json",
        host,
        path_segments.join("/")
      ))
    }
  }

  /// Returns the registrable-domain portion used to build the DNS TXT name
  /// (spec §8.4.5 step 1), i.e. the host without any path segments.
  pub fn dns_txt_name(&self) -> std::option::Option<String> {
    let identifier = self.web_identifier()?;
    let host = percent_decode(identifier.split(':').next()?);
    // A port is not part of a DNS name, so it is dropped here even though
    // the HTTPS URL keeps it.
    let host = host.split(':').next().unwrap_or_default().to_string();
    if host.is_empty() {
      return std::option::Option::None;
    }
    std::option::Option::Some(std::format!("_aph._notary.{}", host))
  }
}

/// Decodes `%XX` escapes. Invalid escapes are left verbatim rather than
/// erroring: the DID is used to build a URL that will simply fail to
/// resolve, which is a clearer outcome than a parse error here.
fn percent_decode(input: &str) -> String {
  let bytes = input.as_bytes();
  let mut out = String::with_capacity(input.len());
  let mut i = 0usize;
  while i < bytes.len() {
    if bytes[i] == b'%' && i + 2 < bytes.len() {
      let hex = &input[i + 1..i + 3];
      // A malformed escape falls through to the literal-copy path below.
      if let std::result::Result::Ok(b) = u8::from_str_radix(hex, 16) {
        out.push(b as char);
        i += 3;
        continue;
      }
    }
    out.push(bytes[i] as char);
    i += 1;
  }
  out
}

#[cfg(test)]
mod tests {
  #[test]
  fn did_url_splits_fragment() {
    // The fragment is the key identifier used to pick among several
    // published keys; losing it would make rotation ambiguous.
    let url = super::DidUrl::parse("did:web:notary.example.com#k1");
    std::assert_eq!(url.did, "did:web:notary.example.com");
    std::assert_eq!(url.fragment.as_deref(), Some("k1"));
  }

  #[test]
  fn did_url_without_fragment_parses() {
    // A DID with no fragment is legal — it means "the document's only key".
    let url = super::DidUrl::parse("did:web:notary.example.com");
    std::assert_eq!(url.fragment, None);
  }

  #[test]
  fn plain_did_web_resolves_under_well_known() {
    // Spec §8.4.4: an identifier with no path segments lives at
    // /.well-known/did.json.
    let url = super::DidUrl::parse("did:web:notary.example.com#k1");
    std::assert_eq!(
      url.web_document_url().unwrap(),
      "https://notary.example.com/.well-known/did.json"
    );
  }

  #[test]
  fn path_segments_replace_the_well_known_prefix() {
    // Colons map to path segments, and a pathful did:web does NOT use
    // /.well-known — getting this backwards fetches the wrong document.
    let url = super::DidUrl::parse("did:web:example.com:notaries:alice");
    std::assert_eq!(
      url.web_document_url().unwrap(),
      "https://example.com/notaries/alice/did.json"
    );
  }

  #[test]
  fn percent_encoded_port_survives_colon_mapping() {
    // A port is written %3A precisely so it is not mistaken for a path
    // separator; decoding must happen before the split.
    let url = super::DidUrl::parse("did:web:localhost%3A8443");
    std::assert_eq!(
      url.web_document_url().unwrap(),
      "https://localhost:8443/.well-known/did.json"
    );
  }

  #[test]
  fn dns_txt_name_uses_the_host_only() {
    // Spec §8.4.5: the TXT record sits at the registrable domain, not at a
    // name derived from the DID's path segments.
    let url = super::DidUrl::parse("did:web:example.com:notaries:alice#k1");
    std::assert_eq!(url.dns_txt_name().unwrap(), "_aph._notary.example.com");
  }

  #[test]
  fn dns_name_drops_a_port() {
    // A port belongs in the HTTPS URL but never in a DNS name; leaving it
    // in would produce a name that can never resolve.
    let url = super::DidUrl::parse("did:web:localhost%3A8443");
    std::assert_eq!(url.dns_txt_name().unwrap(), "_aph._notary.localhost");
  }

  #[test]
  fn did_key_has_no_web_or_dns_derivation() {
    // did:key is resolved offline (§8.4.3); asking for a URL or DNS name
    // must yield nothing rather than a nonsense host.
    let url = super::DidUrl::parse("did:key:z6MkfAkf");
    std::assert_eq!(url.web_document_url(), None);
    std::assert_eq!(url.dns_txt_name(), None);
  }

  #[test]
  fn algorithm_tags_are_a_closed_set() {
    // An unrecognized alg must be APH_E010, never a default — silently
    // assuming Ed25519 for an unknown tag would be a downgrade.
    std::assert_eq!(
      super::KeyAlgorithm::from_dns_tag("ed25519").unwrap(),
      super::KeyAlgorithm::Ed25519
    );
    std::assert_eq!(
      super::KeyAlgorithm::from_dns_tag("p256").unwrap(),
      super::KeyAlgorithm::P256
    );
    std::assert_eq!(
      super::KeyAlgorithm::from_dns_tag("Ed25519").unwrap_err().code(),
      "APH_E010"
    );
    std::assert_eq!(super::KeyAlgorithm::from_dns_tag("rsa").unwrap_err().code(), "APH_E010");
  }

  #[test]
  fn to_ed25519_refuses_a_p256_key() {
    // Algorithm confusion guard: bytes that happen to be the right length
    // must not be reinterpreted under the wrong primitive.
    let key = super::NotaryPublicKey {
      algorithm: super::KeyAlgorithm::P256,
      key_bytes: std::vec![7u8; 32],
      kid: None,
    };
    std::assert_eq!(key.to_ed25519().unwrap_err().code(), "APH_E010");
  }

  #[test]
  fn to_ed25519_rejects_a_wrong_length_key() {
    // Discovered bytes are attacker-influenced; a short key must error
    // rather than panic on the fixed-size conversion.
    let key = super::NotaryPublicKey {
      algorithm: super::KeyAlgorithm::Ed25519,
      key_bytes: std::vec![7u8; 16],
      kid: None,
    };
    std::assert!(key.to_ed25519().is_err());
  }
}
