//! Notary key PUBLICATION — the rendering half of §8.4 discovery.
//!
//! [`super::dns_txt`] and [`super::did_document`] parse the two wire forms a
//! verifier fetches. This module is their exact inverse: it renders the DNS
//! TXT tag-list of spec §8.4.5 and the `did:web` DID Document of spec
//! §8.4.4 from the same [`super::NotaryPublicKey`] the parsers produce.
//!
//! Rendering lives beside parsing on purpose. §8.4 only works if a notary's
//! published key is one a stranger's verifier can read, and the cheapest
//! honest proof of that is a round trip with no network in it: render, then
//! parse with this crate's own parser, then compare. Every property test
//! below is that loop. The goldens are the other half — a round trip proves
//! the two halves agree with each other, only a pinned byte string proves
//! they agree with the specification.
//!
//! **No I/O.** Writing a zone file and serving `/.well-known/did.json` are
//! an operator's or an adapter's job; this module returns strings.
//!
//! Error-code convention, matching what the parsers already do:
//!
//! - `APH_E001` for key MATERIAL that cannot be published — a wrong-length
//!   key, or an Ed25519 key that is not a curve point. These are exactly the
//!   failures [`super::NotaryPublicKey::to_ed25519`] and
//!   [`crate::crypto::did_key::decode_multibase_key`] report on the read
//!   side, so a caller sees one code per cause in both directions.
//! - `APH_E010` for record STRUCTURE that cannot be published — a missing
//!   `kid`, a malformed `did`, a non-RFC-3339 window bound, a reserved
//!   character in a tag value. [`super::dns_txt::parse_txt_record`] already
//!   uses `APH_E010` for structural rejections (wrong `v`, absent `alg`),
//!   and the closed §11 code set has no dedicated "bad publication input"
//!   code; adding one is a v0.2 question.
//!
//! Two deliberate asymmetries, both load-bearing:
//!
//! - [`render_txt_record`] checks the key's LENGTH but not whether an
//!   Ed25519 key is a valid curve point. The DNS form carries raw bytes and
//!   the parser applies no curve check, so a stricter renderer could not
//!   reproduce the specification's own printed example — the 32 bytes in
//!   §8.4.5 do not decompress to a point on the curve. See
//!   `txt_rendering_does_not_require_a_valid_curve_point`.
//! - [`render_did_document`] DOES require a valid curve point, because
//!   `publicKeyMultibase` is read back through
//!   [`crate::crypto::did_key::decode_multibase_key`], which decompresses
//!   it. Publishing bytes that fail there publishes a key no verifier can
//!   resolve.
//!
//! Not emitted: the optional `did` tag of §8.4.5. [`super::NotaryPublicKey`]
//! carries no DID, so there is nothing to render it from; a record without
//! it is fully conformant, and `kid` already disambiguates.
//!
//! Operational note: a DNS TXT character-string is capped at 255 bytes
//! (RFC 1035 §3.3.14). A record with a long `kid` plus both window bounds
//! can exceed that and must be published as several concatenated
//! character-strings. Splitting is the zone author's job — this module
//! returns the logical value, because that is what
//! [`super::dns_txt::parse_txt_record`] consumes after a resolver has
//! rejoined the pieces.

/// The only tag-list version this implementation emits (spec §8.4.5 `v`).
///
/// [`super::dns_txt`] holds the same literal privately for the parse
/// direction; the round-trip tests below are what keep the two in step.
const APH_TXT_VERSION: &str = "APHv1";

/// The DID Core v1 JSON-LD context, as printed in the §8.4.4 example.
const DID_CONTEXT_V1: &str = "https://www.w3.org/ns/did/v1";

/// `verificationMethod[].type` for a multibase-encoded key, as printed in
/// the §8.4.4 example.
const VERIFICATION_METHOD_TYPE: &str = "Multikey";

/// Multicodec varint prefix for an Ed25519 public key (`0xed01`).
///
/// [`crate::crypto::did_key`] holds these same bytes privately for the
/// decode direction. They are repeated here rather than shared because this
/// module may not edit that one; `ed25519_multibase_matches_the_did_key_encoder`
/// pins the two copies together against that module's public encoder.
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Multicodec varint prefix for a P-256 public key (`0x1200`, varint-encoded
/// as two bytes). Duplicated from [`crate::crypto::did_key`] for the same
/// reason as [`ED25519_MULTICODEC`], and pinned by
/// `p256_did_document_round_trips_through_the_parser`.
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];

/// Length of a raw Ed25519 public key.
const ED25519_KEY_LEN: usize = 32;

/// Length of a compressed SEC1 P-256 point.
const P256_KEY_LEN: usize = 33;

/// Renders a §8.4.5 DNS TXT tag-list publishing one notary key.
///
/// The value goes at `_aph._notary.<domain>` — see
/// [`super::DidUrl::dns_txt_name`], which derives that name from the DID a
/// proof names.
///
/// Tags are emitted in the order the two §8.4.5 examples print them:
/// `v`, `alg`, `kid`, `k`, `notBefore`, `notAfter`, separated by `"; "`.
/// `v`, `alg` and `k` are required and always present; `k` is base64url
/// with no padding (RFC 7515 §2). `kid` is emitted only when
/// `key.kid` is `Some`, and each window bound only when its argument is
/// non-empty — an optional tag with an empty value (`kid=;`) would be read
/// back as a key identifier of `""`, which matches no proof's
/// `verificationMethod` fragment, so it is refused rather than emitted.
///
/// # Arguments
///
/// * `key` — the key to publish. Its `kid` travels inside it.
/// * `not_before` — RFC 3339 lower bound, or `""` to omit the tag.
/// * `not_after` — RFC 3339 upper bound, or `""` to omit the tag.
///
/// # Errors
///
/// * `APH_E001` if `key.key_bytes` is not the length its algorithm fixes.
/// * `APH_E010` if `key.kid` is `Some("")`, is surrounded by whitespace, or
///   contains `;` or a control character — any of which would corrupt the
///   tag-list rather than travel inside it.
/// * `APH_E010` if a supplied window bound is not an RFC 3339 timestamp, or
///   if `not_before` is later than `not_after`. Both would publish a key
///   [`super::dns_txt::AphTxtRecord::is_valid_at`] can never accept, since
///   it fails closed on an unparseable bound.
pub fn render_txt_record(
  key: &super::NotaryPublicKey,
  not_before: &str,
  not_after: &str,
) -> std::result::Result<String, crate::errors::AphError> {
  check_key_len(key)?;
  if let std::option::Option::Some(kid) = key.kid.as_deref() {
    check_txt_tag_value("kid", kid)?;
  }

  // An empty (or whitespace-only) argument means "omit this tag". A bound
  // that has any content at all is validated verbatim — RFC 3339 parsing
  // itself rejects surrounding whitespace, `;`, and control characters, so
  // what survives here is safe to concatenate into the tag-list.
  let lower = if not_before.trim().is_empty() {
    std::option::Option::None
  } else {
    std::option::Option::Some(parse_window_bound("notBefore", not_before)?)
  };
  let upper = if not_after.trim().is_empty() {
    std::option::Option::None
  } else {
    std::option::Option::Some(parse_window_bound("notAfter", not_after)?)
  };
  let inverted = match (lower, upper) {
    (std::option::Option::Some(lo), std::option::Option::Some(hi)) => lo > hi,
    _ => false,
  };
  if inverted {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      std::format!(
        "notBefore `{}` is after notAfter `{}`; the published key would never be valid",
        not_before,
        not_after
      ),
    ));
  }

  let mut out = String::with_capacity(128);
  out.push_str("v=");
  out.push_str(APH_TXT_VERSION);
  out.push_str("; alg=");
  out.push_str(dns_alg_tag(key.algorithm));
  if let std::option::Option::Some(kid) = key.kid.as_deref() {
    out.push_str("; kid=");
    out.push_str(kid);
  }
  out.push_str("; k=");
  out.push_str(&crate::crypto::base64url::encode(&key.key_bytes));
  if lower.is_some() {
    out.push_str("; notBefore=");
    out.push_str(not_before);
  }
  if upper.is_some() {
    out.push_str("; notAfter=");
    out.push_str(not_after);
  }
  std::result::Result::Ok(out)
}

/// Renders a §8.4.4 DID Document publishing one or more notary keys.
///
/// The result is what an operator serves at the URL
/// [`super::DidUrl::web_document_url`] derives — `/.well-known/did.json`
/// for a path-less `did:web`.
///
/// Every key becomes one `verificationMethod` entry whose `id` is
/// `<did>#<kid>`, and every such id is also listed in `assertionMethod`.
/// That second list is not decoration: `assertionMethod` is the proof
/// purpose APH envelope proofs declare, so a document that omits it
/// publishes a key a purpose-checking verifier will refuse to use. See
/// [`super::did_document::DidDocument::allows_assertion`], the read side of
/// the same rule.
///
/// Output is [`crate::crypto::jcs::canonicalize_rfc8785`] — the same
/// canonical form this crate signs over. Two consequences are wanted:
/// serialization cannot fail, and a re-published document is byte-identical
/// unless its content actually changed, which is what lets a §8.4.8 pinning
/// verifier hash the document and detect real drift instead of whitespace.
///
/// # Errors
///
/// * `APH_E010` if `did` is not a DID with a non-empty method and
///   method-specific identifier, contains whitespace or a control
///   character, or already carries a `#fragment` (this function appends
///   one).
/// * `APH_E010` if `keys` is empty — a document with no key publishes
///   nothing.
/// * `APH_E010` if any key has no `kid`. The `kid` becomes the fragment of
///   `verificationMethod[].id`, and §8.4.4 step 5 matches a proof's DID URL
///   against that id; without one there is no id to match, and two
///   fragmentless keys would collide on a single id. A missing `kid` is
///   therefore an error and never a silently unpublished key.
/// * `APH_E010` if a `kid` is empty, contains `#`, whitespace, or a control
///   character, or repeats another key's `kid`.
/// * `APH_E001` if a key's bytes are the wrong length for its algorithm, or
///   an Ed25519 key is not a valid curve point.
pub fn render_did_document(
  did: &str,
  keys: &[super::NotaryPublicKey],
) -> std::result::Result<String, crate::errors::AphError> {
  check_did(did)?;
  if keys.is_empty() {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      "a DID Document must publish at least one verificationMethod",
    ));
  }

  let mut seen: std::vec::Vec<&str> = std::vec::Vec::with_capacity(keys.len());
  let mut methods: std::vec::Vec<serde_json::Value> = std::vec::Vec::with_capacity(keys.len());
  let mut assertion: std::vec::Vec<serde_json::Value> = std::vec::Vec::with_capacity(keys.len());

  for key in keys {
    let kid = match key.kid.as_deref() {
      std::option::Option::Some(k) => k,
      std::option::Option::None => {
        return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
          "every published key needs a kid: it becomes the fragment of \
           verificationMethod[].id, which is what a proof's verificationMethod \
           is matched against (§8.4.4 step 5)",
        ));
      }
    };
    check_did_fragment(kid)?;
    if seen.contains(&kid) {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
        std::format!(
          "two keys share the kid `{}`; their verificationMethod ids would be \
           identical and resolution would depend on document order",
          kid
        ),
      ));
    }
    seen.push(kid);

    let id = std::format!("{}#{}", did, kid);
    let multibase = multibase_public_key(key)?;
    assertion.push(serde_json::Value::String(id.clone()));
    methods.push(serde_json::json!({
      "controller": did,
      "id": id,
      "publicKeyMultibase": multibase,
      "type": VERIFICATION_METHOD_TYPE,
    }));
  }

  let document = serde_json::json!({
    "@context": [DID_CONTEXT_V1],
    "assertionMethod": serde_json::Value::Array(assertion),
    "id": did,
    "verificationMethod": serde_json::Value::Array(methods),
  });
  std::result::Result::Ok(crate::crypto::jcs::canonicalize_rfc8785(&document))
}

/// The `alg` tag value for an algorithm — the inverse of
/// [`super::KeyAlgorithm::from_dns_tag`].
///
/// Exhaustive over the enum on purpose: adding an algorithm without giving
/// it a wire tag then fails to compile rather than publishing a record with
/// a guessed `alg`.
fn dns_alg_tag(algorithm: super::KeyAlgorithm) -> &'static str {
  match algorithm {
    super::KeyAlgorithm::Ed25519 => "ed25519",
    super::KeyAlgorithm::P256 => "p256",
  }
}

/// Raw byte length an algorithm's public key must have — the invariant
/// [`super::NotaryPublicKey::key_bytes`] documents.
fn expected_key_len(algorithm: super::KeyAlgorithm) -> usize {
  match algorithm {
    super::KeyAlgorithm::Ed25519 => ED25519_KEY_LEN,
    super::KeyAlgorithm::P256 => P256_KEY_LEN,
  }
}

/// Refuses a key whose byte count does not match its declared algorithm.
///
/// `APH_E001` mirrors what [`super::NotaryPublicKey::to_ed25519`] and
/// [`crate::crypto::did_key::decode_multibase_key`] return for the same
/// defect on the read side.
fn check_key_len(
  key: &super::NotaryPublicKey,
) -> std::result::Result<(), crate::errors::AphError> {
  if key.key_bytes.len() != expected_key_len(key.algorithm) {
    return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
  }
  std::result::Result::Ok(())
}

/// Refuses a tag value that would not survive the tag-list round trip.
///
/// Three ways it would not: an empty value publishes a tag that reads back
/// as `Some("")`; leading or trailing whitespace is stripped by
/// [`super::dns_txt::parse_txt_record`], so the value that comes back is
/// not the one that went in; and a `;` or control character ends the tag
/// early, letting one value inject or truncate later tags.
fn check_txt_tag_value(
  tag: &str,
  value: &str,
) -> std::result::Result<(), crate::errors::AphError> {
  if value.is_empty() {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      std::format!("{} is present but empty; omit the tag instead", tag),
    ));
  }
  if value.trim() != value {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      std::format!(
        "{} `{}` begins or ends with whitespace, which the tag-list parser strips",
        tag, value
      ),
    ));
  }
  if let std::option::Option::Some(bad) =
    value.chars().find(|c| *c == ';' || c.is_control())
  {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      std::format!(
        "{} contains {:?}, which would terminate or inject a tag-list entry",
        tag, bad
      ),
    ));
  }
  std::result::Result::Ok(())
}

/// Parses a window bound so an unpublishable one is caught before it ships.
///
/// [`super::dns_txt::AphTxtRecord::is_valid_at`] fails CLOSED on a bound it
/// cannot parse, so `notAfter=next-tuesday` would not merely be ignored —
/// it would make the key permanently invalid at every verifier.
fn parse_window_bound(
  tag: &str,
  value: &str,
) -> std::result::Result<chrono::DateTime<chrono::FixedOffset>, crate::errors::AphError> {
  match chrono::DateTime::parse_from_rfc3339(value) {
    std::result::Result::Ok(t) => std::result::Result::Ok(t),
    std::result::Result::Err(_) => {
      std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(std::format!(
        "{} `{}` is not an RFC 3339 timestamp; verifiers fail closed on a bound \
         they cannot parse, so the key would never be valid",
        tag, value
      )))
    }
  }
}

/// Refuses a `did` this module cannot safely suffix with `#kid`.
fn check_did(did: &str) -> std::result::Result<(), crate::errors::AphError> {
  // Reuse the crate's own DID URL splitter so "has a fragment" means here
  // exactly what it means to a verifier reading the document back.
  let parsed = super::DidUrl::parse(did);
  if parsed.fragment.is_some() {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      std::format!(
        "did `{}` already carries a fragment; render_did_document appends `#kid` itself",
        did
      ),
    ));
  }
  let method_and_id = match parsed.did.strip_prefix("did:") {
    std::option::Option::Some(rest) => rest,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
        std::format!("`{}` is not a DID", did),
      ));
    }
  };
  let (method, identifier) = match method_and_id.split_once(':') {
    std::option::Option::Some(pair) => pair,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
        std::format!("did `{}` has no method-specific identifier", did),
      ));
    }
  };
  if method.is_empty() || identifier.is_empty() {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      std::format!("did `{}` has an empty method or identifier", did),
    ));
  }
  if let std::option::Option::Some(bad) =
    did.chars().find(|c| c.is_whitespace() || c.is_control())
  {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      std::format!("did `{}` contains {:?}, which no DID may contain", did, bad),
    ));
  }
  std::result::Result::Ok(())
}

/// Refuses a `kid` that cannot serve as a DID URL fragment.
///
/// RFC 3986 lets a fragment hold `/` and `?`, so those pass. `#` cannot
/// appear — [`super::DidUrl::parse`] splits on the FIRST `#`, so a second
/// one would silently move part of the identifier into the fragment.
fn check_did_fragment(kid: &str) -> std::result::Result<(), crate::errors::AphError> {
  if kid.is_empty() {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      "kid is empty; verificationMethod[].id needs a fragment to be addressable",
    ));
  }
  if let std::option::Option::Some(bad) = kid
    .chars()
    .find(|c| *c == '#' || c.is_whitespace() || c.is_control())
  {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      std::format!("kid `{}` contains {:?}, which a DID URL fragment may not hold", kid, bad),
    ));
  }
  std::result::Result::Ok(())
}

/// Encodes a key as the `publicKeyMultibase` value of a `verificationMethod`
/// — a multicodec prefix plus the raw key, in multibase base58btc.
///
/// This is byte-identical to the payload of a `did:key` identifier, which is
/// why [`crate::crypto::did_key::decode_multibase_key`] reads both. The
/// base58 itself comes from [`crate::crypto::multibase`]; nothing is
/// hand-rolled here.
///
/// An Ed25519 key is decompressed first, via
/// [`super::NotaryPublicKey::to_ed25519`]: the reader decompresses too, so
/// bytes that fail that step would publish a key nobody can resolve.
fn multibase_public_key(
  key: &super::NotaryPublicKey,
) -> std::result::Result<String, crate::errors::AphError> {
  check_key_len(key)?;
  let prefix = match key.algorithm {
    super::KeyAlgorithm::Ed25519 => {
      key.to_ed25519()?;
      ED25519_MULTICODEC
    }
    super::KeyAlgorithm::P256 => P256_MULTICODEC,
  };
  let mut payload = std::vec::Vec::with_capacity(prefix.len() + key.key_bytes.len());
  payload.extend_from_slice(&prefix);
  payload.extend_from_slice(&key.key_bytes);
  std::result::Result::Ok(crate::crypto::multibase::base58btc_encode(&payload))
}

#[cfg(test)]
mod tests {
  // `proptest!` resolves identifiers from `proptest::prelude` in the caller's
  // scope, so this one import is required by the macro rather than chosen.
  // Every other path below stays fully qualified per house style.
  use proptest::prelude::*;

  /// The 32 key bytes behind the §8.4.5 example record's `k` tag, recovered
  /// from the specification's own base64url text. Written out as bytes so
  /// the goldens below encode them independently instead of re-encoding
  /// whatever this crate's decoder produced.
  const SPEC_TXT_KEY_BYTES: [u8; 32] = [
    0xd9, 0x57, 0x37, 0x1e, 0x97, 0x20, 0xd5, 0x73, 0xa8, 0xc4, 0x20, 0x53, 0xd2, 0xa6, 0x50,
    0x61, 0x1f, 0x16, 0x94, 0x09, 0x41, 0xa6, 0xf5, 0xb4, 0x9d, 0x5c, 0x11, 0xc8, 0x92, 0x39,
    0x3a, 0xec,
  ];

  /// The 32 key bytes behind the §8.4.4 example document's
  /// `publicKeyMultibase`, recovered from the specification's own base58btc
  /// text. Unlike [`SPEC_TXT_KEY_BYTES`] these ARE a valid Ed25519 curve
  /// point, which is why the DID-document goldens can use them.
  const SPEC_DID_KEY_BYTES: [u8; 32] = [
    0x94, 0x96, 0x6b, 0x7c, 0x08, 0xe4, 0x05, 0x77, 0x5f, 0x8d, 0xe6, 0xcc, 0x1c, 0x45, 0x08,
    0xf6, 0xeb, 0x22, 0x73, 0x2a, 0x98, 0x18, 0xa9, 0x3f, 0xa3, 0xa8, 0x80, 0x36, 0x7b, 0x68,
    0x39, 0xfa,
  ];

  /// The single-key TXT record printed in spec §8.4.5, verbatim.
  const SPEC_TXT_SINGLE: &str =
    "v=APHv1; alg=ed25519; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw";

  /// The rotation-window TXT record printed in spec §8.4.5, verbatim.
  const SPEC_TXT_ROTATION: &str = "v=APHv1; alg=ed25519; kid=k1; \
     k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw; notBefore=2026-05-21T00:00:00Z; \
     notAfter=2027-05-21T00:00:00Z";

  /// The `did:web` DID used by both §8.4.4 and §8.4.5 examples.
  const SPEC_DID: &str = "did:web:notary.example.com";

  fn spec_txt_key(kid: std::option::Option<&str>) -> crate::discovery::NotaryPublicKey {
    crate::discovery::NotaryPublicKey {
      algorithm: crate::discovery::KeyAlgorithm::Ed25519,
      key_bytes: SPEC_TXT_KEY_BYTES.to_vec(),
      kid: kid.map(String::from),
    }
  }

  fn spec_did_key(kid: std::option::Option<&str>) -> crate::discovery::NotaryPublicKey {
    crate::discovery::NotaryPublicKey {
      algorithm: crate::discovery::KeyAlgorithm::Ed25519,
      key_bytes: SPEC_DID_KEY_BYTES.to_vec(),
      kid: kid.map(String::from),
    }
  }

  /// Builds a guaranteed-valid Ed25519 public key from an arbitrary seed, so
  /// property tests can vary key material without generating byte strings
  /// that are not points on the curve.
  fn ed25519_from_seed(seed: &[u8]) -> std::vec::Vec<u8> {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(seed);
    ed25519_dalek::SigningKey::from_bytes(&arr)
      .verifying_key()
      .to_bytes()
      .to_vec()
  }

  // ── Goldens: agreement with the normative text ──────────────────────

  #[test]
  fn spec_single_key_example_is_reproduced_byte_for_byte() {
    // A round trip only proves this module agrees with its own parser; both
    // halves could drift together into a dialect no other implementation
    // reads. This pins the exact string spec §8.4.5 prints — tag order,
    // "; " separator, unpadded base64url and all — so a drift in either
    // direction fails here instead of in someone else's resolver.
    std::assert_eq!(
      super::render_txt_record(&spec_txt_key(None), "", "").unwrap(),
      SPEC_TXT_SINGLE
    );
  }

  #[test]
  fn spec_rotation_example_is_reproduced_byte_for_byte() {
    // The second §8.4.5 example is the shape an operator publishes during a
    // §8.4.7 overlap, and it fixes where the optional tags sit: kid BEFORE
    // k, the two bounds after it. Pinned separately from the single-key
    // golden because only this one can catch a reordering.
    std::assert_eq!(
      super::render_txt_record(
        &spec_txt_key(Some("k1")),
        "2026-05-21T00:00:00Z",
        "2027-05-21T00:00:00Z"
      )
      .unwrap(),
      SPEC_TXT_ROTATION
    );
  }

  #[test]
  fn spec_did_document_example_is_reproduced() {
    // The golden for §8.4.4: same id, same controller, same Multikey type,
    // and the same publicKeyMultibase string the specification prints —
    // which also pins this module's multicodec prefix, since a wrong prefix
    // yields a different base58 string entirely. Key order is JCS
    // (lexicographic), the canonical form the rest of the crate signs over.
    let rendered = super::render_did_document(SPEC_DID, &[spec_did_key(Some("k1"))]).unwrap();
    std::assert_eq!(
      rendered,
      // Delimited r##"…"## because these fragments contain both `"` and
      // `#`; the shorter r#"…"# form would end a literal early.
      concat!(
        r##"{"@context":["https://www.w3.org/ns/did/v1"],"##,
        r##""assertionMethod":["did:web:notary.example.com#k1"],"##,
        r##""id":"did:web:notary.example.com","##,
        r##""verificationMethod":[{"controller":"did:web:notary.example.com","##,
        r##""id":"did:web:notary.example.com#k1","##,
        r##""publicKeyMultibase":"z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV","##,
        r##""type":"Multikey"}]}"##
      )
    );
  }

  // ── Round trips, both directions ────────────────────────────────────

  #[test]
  fn parsed_spec_records_render_back_to_the_spec_text() {
    // The other direction of W2a.3: parse first, then render. A renderer
    // that only satisfied render-then-parse could still normalize a record
    // an operator already published, which would change the bytes served at
    // a name that other verifiers have cached or pinned.
    for original in [SPEC_TXT_SINGLE, SPEC_TXT_ROTATION] {
      let parsed = crate::discovery::dns_txt::parse_txt_record(original).unwrap();
      let rendered = super::render_txt_record(
        &parsed.public_key(),
        parsed.not_before.as_deref().unwrap_or_default(),
        parsed.not_after.as_deref().unwrap_or_default(),
      )
      .unwrap();
      std::assert_eq!(rendered, original);
    }
  }

  #[test]
  fn did_document_rendering_survives_a_parse_and_resolve_cycle() {
    // Parse-first direction for §8.4.4: a document read off the wire, its
    // key resolved out, and re-rendered must come back byte-identical.
    // Without that, republishing an unchanged key would break a §8.4.8
    // pinning verifier that hashes the document it saw.
    let first = super::render_did_document(SPEC_DID, &[spec_did_key(Some("k1"))]).unwrap();
    let doc = crate::discovery::did_document::parse_did_document(&first).unwrap();
    let key = doc.resolve_key("did:web:notary.example.com#k1").unwrap();
    std::assert_eq!(super::render_did_document(&doc.id, &[key]).unwrap(), first);
  }

  proptest! {
    #[test]
    // The property that makes publication trustworthy: whatever a notary
    // publishes, this crate's own parser must recover the SAME key — same
    // algorithm, same bytes, same kid. Run over arbitrary key material and
    // both algorithms because a renderer that only handles the fixtures
    // would still ship a key nobody can read. Optional tags vary too, so
    // the presence/absence branches are both exercised.
    fn txt_record_round_trips_for_arbitrary_keys(
      raw in prop::collection::vec(any::<u8>(), 32),
      use_p256 in any::<bool>(),
      kid in prop::option::of("[a-zA-Z0-9_.-]{1,16}"),
      with_window in any::<bool>(),
    ) {
      let mut key_bytes = raw;
      let algorithm = if use_p256 {
        // A compressed SEC1 point is 33 bytes with a 0x02/0x03 parity byte.
        key_bytes.insert(0, 0x02);
        crate::discovery::KeyAlgorithm::P256
      } else {
        crate::discovery::KeyAlgorithm::Ed25519
      };
      let key = crate::discovery::NotaryPublicKey { algorithm, key_bytes, kid };
      let (not_before, not_after) = if with_window {
        ("2026-05-21T00:00:00Z", "2027-05-21T00:00:00Z")
      } else {
        ("", "")
      };

      let rendered = super::render_txt_record(&key, not_before, not_after).unwrap();
      let parsed = crate::discovery::dns_txt::parse_txt_record(&rendered).unwrap();
      let recovered = parsed.public_key();
      prop_assert_eq!(&recovered, &key);
    }

    #[test]
    // Rotation is the reason a document holds several keys at once (§8.4.7),
    // and the whole point of the kid fragment is that a verifier gets back
    // the key its proof named. This asserts that for EVERY key in an
    // arbitrary published set, not just the first — a renderer that emitted
    // one id for all of them would pass a single-key test and then make
    // resolution depend on document order.
    fn did_document_resolves_every_key_it_publishes(
      seeds in prop::collection::vec(prop::collection::vec(any::<u8>(), 32), 1..4),
      p256_flags in prop::collection::vec(any::<bool>(), 1..4),
    ) {
      let keys: std::vec::Vec<crate::discovery::NotaryPublicKey> = seeds
        .iter()
        .enumerate()
        .map(|(i, seed)| {
          let use_p256 = *p256_flags.get(i).unwrap_or(&false);
          let (algorithm, key_bytes) = if use_p256 {
            // 0x02 is the SEC1 parity byte of a compressed point; the 32
            // seed bytes stand in for the x coordinate. decode_multibase_key
            // checks the length, not the point, so any 33 bytes round-trip.
            let mut b = std::vec![0x02u8];
            b.extend_from_slice(seed);
            (crate::discovery::KeyAlgorithm::P256, b)
          } else {
            (crate::discovery::KeyAlgorithm::Ed25519, ed25519_from_seed(seed))
          };
          crate::discovery::NotaryPublicKey {
            algorithm,
            key_bytes,
            kid: std::option::Option::Some(std::format!("k{}", i)),
          }
        })
        .collect();

      let rendered = super::render_did_document(SPEC_DID, &keys).unwrap();
      let doc = crate::discovery::did_document::parse_did_document(&rendered).unwrap();
      for key in &keys {
        let kid = key.kid.clone().unwrap_or_default();
        let did_url = std::format!("{}#{}", SPEC_DID, kid);
        prop_assert!(doc.allows_assertion(&did_url));
        let resolved = doc.resolve_key(&did_url).unwrap();
        prop_assert_eq!(&resolved, key);
      }
    }
  }

  // ── Selection across several published records ───────────────────────

  #[test]
  fn rendered_records_are_selectable_by_kid_at_one_name() {
    // §8.4.5 lets several TXT records share `_aph._notary.<domain>` during a
    // rotation overlap, and the verifier picks by kid. Rendering has to
    // produce records that survive that selection, or a rotating notary
    // becomes unresolvable exactly when both keys are live.
    let old = super::render_txt_record(
      &spec_txt_key(Some("k1")),
      "2026-05-21T00:00:00Z",
      "2027-05-21T00:00:00Z",
    )
    .unwrap();
    let new = super::render_txt_record(
      &crate::discovery::NotaryPublicKey {
        algorithm: crate::discovery::KeyAlgorithm::Ed25519,
        key_bytes: SPEC_DID_KEY_BYTES.to_vec(),
        kid: std::option::Option::Some(String::from("k2")),
      },
      "2027-01-01T00:00:00Z",
      "2028-01-01T00:00:00Z",
    )
    .unwrap();
    let records = std::vec![old, new];
    let picked =
      crate::discovery::dns_txt::select_key(&records, Some("k2"), "2027-03-01T00:00:00Z")
        .unwrap()
        .expect("the rendered k2 record is published and inside its window");
    std::assert_eq!(picked.key_bytes, SPEC_DID_KEY_BYTES.to_vec());
  }

  // ── Optional tags ───────────────────────────────────────────────────

  #[test]
  fn absent_optional_tags_leave_no_trace() {
    // `kid=;` is a defect: an empty optional tag reads back
    // as Some("") and then matches no proof's verificationMethod fragment,
    // which is worse than the tag being absent. Absent must mean absent —
    // no empty tag, no doubled or trailing separator.
    let rendered = super::render_txt_record(&spec_txt_key(None), "", "").unwrap();
    std::assert!(!rendered.contains("kid"), "{}", rendered);
    std::assert!(!rendered.contains("notBefore"), "{}", rendered);
    std::assert!(!rendered.contains("notAfter"), "{}", rendered);
    std::assert!(!rendered.contains(";;"), "{}", rendered);
    std::assert!(!rendered.ends_with(';'), "{}", rendered);
  }

  #[test]
  fn a_whitespace_only_window_bound_counts_as_absent() {
    // Callers plumb these through from config, where an unset value often
    // arrives as blank rather than empty. Treating "  " as a timestamp would
    // publish a key that fails closed at every verifier.
    let rendered = super::render_txt_record(&spec_txt_key(None), "   ", "\t").unwrap();
    std::assert_eq!(rendered, SPEC_TXT_SINGLE);
  }

  #[test]
  fn empty_kid_is_refused_rather_than_emitted_bare() {
    // Some("") is a caller bug, and the two ways of hiding it — emitting
    // `kid=` or silently dropping the tag — both mislead: the first
    // publishes an unmatchable key, the second publishes a key under a
    // different identity than the caller asked for.
    let key = spec_txt_key(Some(""));
    std::assert_eq!(
      super::render_txt_record(&key, "", "").unwrap_err().code(),
      "APH_E010"
    );
  }

  // ── Tag-list integrity ──────────────────────────────────────────────

  #[test]
  fn a_kid_containing_a_semicolon_cannot_inject_tags() {
    // The kid is opaque and may come from a tenant, so it is untrusted text
    // being concatenated into a tag-list. `k1; alg=p256` would append a
    // second alg tag that the parser honours — an algorithm downgrade
    // written by whoever names the key.
    let key = spec_txt_key(Some("k1; alg=p256"));
    std::assert_eq!(
      super::render_txt_record(&key, "", "").unwrap_err().code(),
      "APH_E010"
    );
  }

  #[test]
  fn a_kid_with_surrounding_whitespace_is_refused() {
    // The parser trims tag values, so ` k1 ` would come back as `k1`: the
    // record would round-trip to a DIFFERENT key identifier than the caller
    // published, quietly. Refusing keeps render and parse in agreement.
    std::assert!(super::render_txt_record(&spec_txt_key(Some(" k1")), "", "").is_err());
    std::assert!(super::render_txt_record(&spec_txt_key(Some("k1\n")), "", "").is_err());
  }

  #[test]
  fn non_rfc3339_window_bound_is_refused() {
    // is_valid_at fails CLOSED on an unparseable bound, so a typo here does
    // not degrade to "no window" — it makes the key permanently invalid
    // everywhere. Catching it at publication is the only cheap moment.
    let key = spec_txt_key(Some("k1"));
    std::assert_eq!(
      super::render_txt_record(&key, "next tuesday", "").unwrap_err().code(),
      "APH_E010"
    );
    std::assert!(super::render_txt_record(&key, "", "2027-05-21").is_err());
  }

  #[test]
  fn an_inverted_window_is_refused() {
    // notAfter before notBefore publishes a key that is valid at no instant
    // at all. Each bound parses, so only the comparison catches it.
    let key = spec_txt_key(Some("k1"));
    std::assert_eq!(
      super::render_txt_record(&key, "2027-05-21T00:00:00Z", "2026-05-21T00:00:00Z")
        .unwrap_err()
        .code(),
      "APH_E010"
    );
  }

  // ── Algorithm tags ──────────────────────────────────────────────────

  #[test]
  fn alg_tags_round_trip_through_the_parser_helper() {
    // dns_alg_tag is the inverse of KeyAlgorithm::from_dns_tag, but they
    // live in different modules and nothing in the type system ties them
    // together. If either side's spelling drifted — `Ed25519`, `ES256`,
    // `p-256` — records would render that no verifier accepts.
    for algorithm in [
      crate::discovery::KeyAlgorithm::Ed25519,
      crate::discovery::KeyAlgorithm::P256,
    ] {
      let tag = super::dns_alg_tag(algorithm);
      std::assert_eq!(
        crate::discovery::KeyAlgorithm::from_dns_tag(tag).unwrap(),
        algorithm
      );
    }
  }

  #[test]
  fn p256_renders_the_lowercase_wire_tag() {
    // Pinned literally because §8.4.5 fixes the tag values as a closed,
    // lowercase set and the round-trip test above would still pass if both
    // sides agreed on a wrong spelling.
    let key = crate::discovery::NotaryPublicKey {
      algorithm: crate::discovery::KeyAlgorithm::P256,
      key_bytes: std::vec![0x02u8; 33],
      kid: std::option::Option::None,
    };
    std::assert!(
      super::render_txt_record(&key, "", "").unwrap().contains("alg=p256"),
      "expected a lowercase p256 alg tag"
    );
  }

  // ── Key material ────────────────────────────────────────────────────

  #[test]
  fn wrong_key_length_is_refused_for_each_algorithm() {
    // NotaryPublicKey documents 32 bytes for Ed25519 and 33 for a
    // compressed P-256 point. Publishing anything else publishes a key that
    // fails at the verifier with a signature error, sending an operator to
    // hunt a signing bug instead of a publication bug.
    let short_ed = crate::discovery::NotaryPublicKey {
      algorithm: crate::discovery::KeyAlgorithm::Ed25519,
      key_bytes: std::vec![1u8; 31],
      kid: std::option::Option::None,
    };
    let long_p256 = crate::discovery::NotaryPublicKey {
      algorithm: crate::discovery::KeyAlgorithm::P256,
      key_bytes: std::vec![2u8; 65],
      kid: std::option::Option::Some(String::from("k1")),
    };
    std::assert_eq!(
      super::render_txt_record(&short_ed, "", "").unwrap_err().code(),
      "APH_E001"
    );
    std::assert_eq!(
      super::render_did_document(SPEC_DID, &[long_p256]).unwrap_err().code(),
      "APH_E001"
    );
  }

  #[test]
  fn txt_rendering_does_not_require_a_valid_curve_point() {
    // Deliberate asymmetry, and the specification forces it: the 32 bytes in
    // the §8.4.5 example do NOT decompress to a point on Ed25519. The DNS
    // form carries raw bytes and its parser applies no curve check, so a
    // renderer that validated here could not reproduce the normative
    // example — see spec_single_key_example_is_reproduced_byte_for_byte.
    let key = spec_txt_key(None);
    std::assert!(key.to_ed25519().is_err(), "fixture assumption broke");
    std::assert!(super::render_txt_record(&key, "", "").is_ok());
  }

  #[test]
  fn did_document_refuses_a_non_curve_point_ed25519_key() {
    // The other half of that asymmetry. publicKeyMultibase is read back
    // through decode_multibase_key, which decompresses the point, so bytes
    // that fail here would publish a verificationMethod every verifier
    // rejects — silence at publication would move the failure to a stranger
    // who cannot fix it.
    std::assert_eq!(
      super::render_did_document(SPEC_DID, &[spec_txt_key(Some("k1"))])
        .unwrap_err()
        .code(),
      "APH_E001"
    );
  }

  #[test]
  fn ed25519_multibase_matches_the_did_key_encoder() {
    // This module keeps its own copy of the Ed25519 multicodec prefix
    // because it may not edit crypto::did_key. That duplication is only
    // safe while the two agree, so it is pinned against did_key's public
    // encoder: publicKeyMultibase IS the payload of a did:key identifier.
    let key = spec_did_key(Some("k1"));
    let expected = crate::crypto::did_key::encode_ed25519(&key.to_ed25519().unwrap());
    let rendered = super::render_did_document(SPEC_DID, &[key]).unwrap();
    let doc = crate::discovery::did_document::parse_did_document(&rendered).unwrap();
    std::assert_eq!(
      doc.verification_method[0].public_key_multibase.as_deref(),
      expected.strip_prefix("did:key:")
    );
  }

  #[test]
  fn p256_did_document_round_trips_through_the_parser() {
    // Pins this module's copy of the P-256 multicodec (0x1200 → 0x80 0x24)
    // against did_key's decoder. A wrong prefix would still produce a
    // plausible z-string, and only a decode catches it; there is no P-256
    // encoder to compare against as there is for Ed25519.
    let key = crate::discovery::NotaryPublicKey {
      algorithm: crate::discovery::KeyAlgorithm::P256,
      key_bytes: {
        let mut b = std::vec![0x03u8];
        b.extend_from_slice(&SPEC_DID_KEY_BYTES);
        b
      },
      kid: std::option::Option::Some(String::from("p1")),
    };
    let rendered = super::render_did_document(SPEC_DID, std::slice::from_ref(&key)).unwrap();
    let doc = crate::discovery::did_document::parse_did_document(&rendered).unwrap();
    std::assert_eq!(
      doc.resolve_key("did:web:notary.example.com#p1").unwrap(),
      key
    );
  }

  // ── DID Document structure ──────────────────────────────────────────

  #[test]
  fn every_published_key_is_listed_for_assertion_method() {
    // assertionMethod is the proof purpose APH envelope
    // proofs declare. A document that publishes a verificationMethod but
    // omits it from assertionMethod publishes a key a purpose-checking
    // verifier will refuse — the worst outcome, since the key resolves and
    // then is rejected.
    let keys = std::vec![spec_did_key(Some("k1")), spec_did_key(Some("k2"))];
    let rendered = super::render_did_document(SPEC_DID, &keys).unwrap();
    let doc = crate::discovery::did_document::parse_did_document(&rendered).unwrap();
    std::assert!(doc.allows_assertion("did:web:notary.example.com#k1"));
    std::assert!(doc.allows_assertion("did:web:notary.example.com#k2"));
  }

  #[test]
  fn did_document_requires_a_kid_on_every_key() {
    // A key with no kid has no fragment, so it has no addressable
    // verificationMethod id (§8.4.4 step 5) and two such keys would collide
    // on one id. Omitting it silently would publish a document whose
    // resolution depends on array order; erroring says which key to name.
    std::assert_eq!(
      super::render_did_document(SPEC_DID, &[spec_did_key(None)])
        .unwrap_err()
        .code(),
      "APH_E010"
    );
  }

  #[test]
  fn did_document_refuses_duplicate_kids() {
    // Two entries with the same id make resolve_key return whichever comes
    // first, which turns document ordering into a security-relevant
    // property — the exact failure the parser's
    // fragmentless-resolution rule exists to prevent.
    let keys = std::vec![spec_did_key(Some("k1")), spec_did_key(Some("k1"))];
    std::assert_eq!(
      super::render_did_document(SPEC_DID, &keys).unwrap_err().code(),
      "APH_E010"
    );
  }

  #[test]
  fn did_document_refuses_a_kid_that_breaks_the_fragment() {
    // DidUrl::parse splits on the FIRST '#', so a kid containing one would
    // move part of itself into the DID and resolve against a different
    // document entirely. Whitespace is refused for the same reason: the id
    // would not be a valid DID URL.
    std::assert!(super::render_did_document(SPEC_DID, &[spec_did_key(Some("k1#k2"))]).is_err());
    std::assert!(super::render_did_document(SPEC_DID, &[spec_did_key(Some("k 1"))]).is_err());
  }

  #[test]
  fn did_document_refuses_a_did_that_already_carries_a_fragment() {
    // This function appends `#kid` itself; a did that arrives with one would
    // yield `...#k1#k1`, whose fragment is `k1#k1` and matches no proof.
    std::assert_eq!(
      super::render_did_document("did:web:notary.example.com#k1", &[spec_did_key(Some("k1"))])
        .unwrap_err()
        .code(),
      "APH_E010"
    );
  }

  #[test]
  fn did_document_refuses_a_string_that_is_not_a_did() {
    // Every id in the document is built by prefixing this argument, so a
    // non-DID here yields a document full of identifiers no resolver can
    // dereference. Rejecting at the top keeps that from being published.
    for bad in ["notary.example.com", "did:", "did:web", "did::x", "did:web:"] {
      std::assert!(
        super::render_did_document(bad, &[spec_did_key(Some("k1"))]).is_err(),
        "accepted `{}` as a DID",
        bad
      );
    }
  }

  #[test]
  fn did_document_refuses_an_empty_key_set() {
    // A document with no verificationMethod publishes nothing while looking
    // like a successful publication — a notary would believe its key was
    // live and every verifier would see an unresolvable DID.
    std::assert_eq!(
      super::render_did_document(SPEC_DID, &[]).unwrap_err().code(),
      "APH_E010"
    );
  }
}
