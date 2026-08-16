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
//! pair is round-trip testable without a network; [`ports`] declares the
//! narrow one-method ports an adapter implements to do the fetching; and
//! [`composer`] dispatches across mechanisms in the §8.4.6 preference order
//! with no silent downgrade from a stronger mechanism to a weaker one.
//!
//! Two members here serve a surface that is NOT key discovery: revocation
//! status (§6.3.3) is anchored in the same `did:web` origin, so
//! [`DidUrl::web_status_url`] derives its endpoint through the very same
//! percent-decode-then-split rule as the DID Document URL, and
//! [`same_origin`] is the one origin comparison this crate makes. They live
//! beside `DidUrl` rather than in [`crate::credential_status`] because a
//! second implementation of either rule is how two surfaces anchored in one
//! domain quietly stop agreeing about what that domain is.

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
    self.web_url_with_leaf("did.json")
  }

  /// Builds the HTTPS URL of the DERIVED revocation status endpoint for a
  /// `did:web` DID (spec §6.3.3.2 step 2).
  ///
  /// §6.3.3.2 defines this by reference — "apply §8.4.4 step 2's rule … then
  /// suffix `/.well-known/aph-status.json` in place of
  /// `/.well-known/did.json`" — so it shares [`Self::web_document_url`]'s
  /// derivation exactly and differs only in the last path segment. Sharing
  /// the body is the point: the two endpoints must agree about the host, or
  /// the same-origin binding of §6.3.3.2 compares an origin against one the
  /// same DID would never have produced.
  ///
  /// This is the origin a verifier trusts. The `statusListCredential` value
  /// an envelope carries is NEVER used to derive it — it is only ever bound
  /// against it by [`same_origin`].
  pub fn web_status_url(&self) -> std::option::Option<String> {
    self.web_url_with_leaf(crate::credential_status::STATUS_ENDPOINT_LEAF)
  }

  /// The shared `did:web` URL derivation: percent-decode-after-split, then
  /// `leaf` as the final path segment.
  ///
  /// One body for both endpoints (§8.4.4 step 2 and §6.3.3.2 step 2). The
  /// ordering comment below is the whole reason this is not two functions.
  fn web_url_with_leaf(&self, leaf: &str) -> std::option::Option<String> {
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
      std::option::Option::Some(std::format!("https://{}/.well-known/{}", host, leaf))
    } else {
      std::option::Option::Some(std::format!(
        "https://{}/{}/{}",
        host,
        path_segments.join("/"),
        leaf
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

/// The normalized `https:` origin of an absolute URL: `scheme://host:port`
/// with the default port made explicit.
///
/// `None` — meaning "no origin can be compared" — for anything that is not
/// an absolute `https:` URL this crate is willing to reason about. That
/// includes an `http:` URL (no TLS anchor, and the TLS name IS the trust
/// model of §8.4.4), a URL carrying userinfo, and a host with a
/// percent-escape. All three are refusals rather than best-effort parses:
/// this function's answers gate a fetch, so an ambiguous URL must fail
/// closed rather than be normalized into whatever the parser guessed.
///
/// No URL crate is introduced, and none is needed: the grammar an APH origin
/// comparison reads is the authority component of an absolute `https:` URL
/// and nothing more. Every shape outside that grammar is `None` rather than
/// a partial parse, which is why the narrowness is safe here and would not
/// be in a general-purpose URL type.
pub fn https_origin(url: &str) -> std::option::Option<String> {
  // The scheme is ASCII case-insensitive per RFC 3986, but the authority is
  // matched exactly except for the host's case, handled below. Compared over
  // BYTES: slicing a `&str` by a fixed index would panic on a leading
  // multi-byte character, and this input is attacker-influenced. A prefix
  // that matched is all-ASCII, so byte 8 is a char boundary.
  let rest = match url.as_bytes().get(..8) {
    std::option::Option::Some(prefix) if prefix.eq_ignore_ascii_case(b"https://") => &url[8..],
    _ => return std::option::Option::None,
  };
  // The authority ends at the first '/', '?' or '#'.
  let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
  let authority = &rest[..authority_end];
  if authority.is_empty() {
    return std::option::Option::None;
  }
  // `https://notary.example.com@evil.example/x` has host `evil.example`.
  // A comparison that skipped this would read the userinfo as the host and
  // call an attacker's origin the notary's own — the single most likely way
  // to get §6.3.3.2's binding wrong.
  if authority.contains('@') {
    return std::option::Option::None;
  }
  // A percent-escape in the authority means the host is not literal, so what
  // this function would compare is not what a client would connect to.
  if authority.contains('%') {
    return std::option::Option::None;
  }
  let (host, port) = if let std::option::Option::Some(bracket) = authority.strip_prefix('[') {
    // IPv6 literal: the host runs to the closing bracket, and any port
    // follows it. Splitting on ':' without this would cut the address up.
    let close = bracket.find(']')?;
    let host = &authority[..close + 2];
    let remainder = &bracket[close + 1..];
    match remainder {
      "" => (host, ""),
      _ => (host, remainder.strip_prefix(':')?),
    }
  } else {
    match authority.split_once(':') {
      std::option::Option::Some((host, port)) => {
        // A second colon in a non-bracketed authority is malformed.
        if port.contains(':') {
          return std::option::Option::None;
        }
        (host, port)
      }
      std::option::Option::None => (authority, ""),
    }
  };
  if host.is_empty() {
    return std::option::Option::None;
  }
  // An empty port component means the scheme default, which is how
  // `https://host:/x` and `https://host/x` name one origin.
  let port: u16 = if port.is_empty() {
    443
  } else {
    match port.parse::<u16>() {
      std::result::Result::Ok(p) => p,
      std::result::Result::Err(_) => return std::option::Option::None,
    }
  };
  std::option::Option::Some(std::format!("https://{}:{}", host.to_ascii_lowercase(), port))
}

/// True when two absolute URLs share an origin — identical scheme, host and
/// port (spec §6.3.3.2).
///
/// This is the crate's ONLY origin comparison, and it is deliberately
/// public: an adapter guarding a redirect asks exactly the same question a
/// verifier binding a `statusListCredential` asks, and two implementations
/// of "same origin" is how one of them ends up wrong. A URL that is not an
/// absolute `https:` URL is never same-origin with anything, which is how
/// §6.3.3.2's "MUST use the `https:` scheme" is enforced by the same call
/// that enforces the binding.
pub fn same_origin(a: &str, b: &str) -> bool {
  match (https_origin(a), https_origin(b)) {
    (std::option::Option::Some(left), std::option::Option::Some(right)) => left == right,
    _ => false,
  }
}

/// Test-only scaffolding shared by the modules that exercise the async
/// ports.
#[cfg(test)]
pub(crate) mod test_support {
  /// Drives a future to completion on the calling thread.
  ///
  /// `aph-core` carries no async runtime — this crate stays I/O-free and
  /// dependency-light — so the tests supply the dozen lines of `std` needed
  /// to poll a future rather than pulling in `tokio` to await a fake that is
  /// already `Ready`. One copy, in one place, because a second poller is a
  /// second set of soundness assumptions about waking.
  pub(crate) fn block_on<F: std::future::Future>(future: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl std::task::Wake for ThreadWaker {
      fn wake(self: std::sync::Arc<Self>) {
        self.0.unpark();
      }
    }
    let waker = std::task::Waker::from(std::sync::Arc::new(ThreadWaker(std::thread::current())));
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
      match std::future::Future::poll(future.as_mut(), &mut context) {
        std::task::Poll::Ready(value) => return value,
        std::task::Poll::Pending => std::thread::park(),
      }
    }
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
  fn status_endpoint_mirrors_the_document_url_and_differs_only_in_its_leaf() {
    // §6.3.3.2 step 2 defines the status endpoint BY REFERENCE to §8.4.4
    // step 2. Pinning the two side by side is what keeps that reference
    // true: if one derivation ever drifted, the same-origin binding would
    // compare the envelope's URL against an origin the DID never produces,
    // and every status check would refuse a conformant notary.
    let plain = super::DidUrl::parse("did:web:aph-notary.squillo.com#k1");
    std::assert_eq!(
      plain.web_document_url().unwrap(),
      "https://aph-notary.squillo.com/.well-known/did.json"
    );
    std::assert_eq!(
      plain.web_status_url().unwrap(),
      "https://aph-notary.squillo.com/.well-known/aph-status.json"
    );
    let pathful = super::DidUrl::parse("did:web:example.com:notaries:alice");
    std::assert_eq!(
      pathful.web_document_url().unwrap(),
      "https://example.com/notaries/alice/did.json"
    );
    std::assert_eq!(
      pathful.web_status_url().unwrap(),
      "https://example.com/notaries/alice/aph-status.json"
    );
    // A `%3A` port must stay on the host for the status endpoint too — the
    // decode-after-split ordering is shared, not re-implemented.
    let ported = super::DidUrl::parse("did:web:localhost%3A8443");
    std::assert_eq!(
      ported.web_status_url().unwrap(),
      "https://localhost:8443/.well-known/aph-status.json"
    );
  }

  #[test]
  fn same_origin_compares_scheme_host_and_port() {
    // §6.3.3.2: "identical scheme, host and port". A path difference is
    // ALLOWED — that is how a notary points at a second list — and every
    // other difference is a refusal.
    let derived = "https://aph-notary.squillo.com/.well-known/aph-status.json";
    std::assert!(super::same_origin(
      derived,
      "https://aph-notary.squillo.com/status/list-2.json"
    ));
    // Host case and an explicit default port are the same origin; a client
    // would connect to the same place, and refusing them would refuse a
    // conformant notary for a spelling.
    std::assert!(super::same_origin(
      derived,
      "https://APH-Notary.Squillo.com:443/.well-known/aph-status.json"
    ));
    std::assert!(!super::same_origin(derived, "https://evil.example/x.json"));
    std::assert!(!super::same_origin(
      derived,
      "https://aph-notary.squillo.com:8443/x.json"
    ));
    // A subdomain is a different host, however similar it reads.
    std::assert!(!super::same_origin(
      derived,
      "https://aph-notary.squillo.com.evil.example/x.json"
    ));
  }

  #[test]
  fn https_origin_refuses_the_shapes_that_disguise_a_host() {
    // Each of these has been a real-world origin-check bypass. `None` here
    // makes `same_origin` false, which under §6.3.3.2 means "reject and do
    // not fetch" — the fail-closed direction.
    // Userinfo: the HOST is `evil.example`.
    std::assert_eq!(
      super::https_origin("https://aph-notary.squillo.com@evil.example/x"),
      None
    );
    // No TLS anchor at all, and §8.4.4's trust model IS the certificate.
    std::assert_eq!(super::https_origin("http://aph-notary.squillo.com/x"), None);
    // A percent-escaped authority is not a literal host.
    std::assert_eq!(super::https_origin("https://ev%69l.example/x"), None);
    // Scheme-relative and relative references name no origin.
    std::assert_eq!(super::https_origin("//aph-notary.squillo.com/x"), None);
    std::assert_eq!(super::https_origin("/.well-known/aph-status.json"), None);
    std::assert_eq!(super::https_origin("https://"), None);
    // A non-numeric or out-of-range port is malformed, not "the default".
    std::assert_eq!(super::https_origin("https://host:99999/x"), None);
    std::assert_eq!(super::https_origin("https://host:https/x"), None);
    // A leading multi-byte character must not panic the byte-index slice.
    std::assert_eq!(super::https_origin("\u{127}ttps://host/x"), None);
  }

  #[test]
  fn https_origin_normalizes_the_default_port_and_ipv6_literals() {
    // The normalization is what lets `same_origin` be a string comparison.
    // IPv6 is included because splitting an authority on ':' without
    // bracket handling cuts an address into a bogus host and port.
    std::assert_eq!(
      super::https_origin("https://host/x").unwrap(),
      "https://host:443"
    );
    std::assert_eq!(
      super::https_origin("https://host:/x").unwrap(),
      "https://host:443"
    );
    std::assert_eq!(
      super::https_origin("https://[2001:db8::1]:8443/x").unwrap(),
      "https://[2001:db8::1]:8443"
    );
    std::assert!(super::same_origin(
      "https://[2001:db8::1]/a",
      "https://[2001:DB8::1]:443/b"
    ));
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
