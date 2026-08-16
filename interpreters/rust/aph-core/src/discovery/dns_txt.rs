//! DNS TXT key publication — tag-list parsing and key selection.
//!
//! Spec §8.4.5 publishes a notary's key at `_aph._notary.<domain>` as a
//! DKIM-style tag-list. This module parses those records and applies the
//! selection rules; the DNS query itself belongs to an adapter.
//!
//! The trust model is domain ownership, exactly as DKIM anchors email
//! signing keys to the sending domain.

/// One parsed TXT record from `_aph._notary.<domain>`.
#[derive(std::fmt::Debug, std::clone::Clone, std::cmp::PartialEq, std::cmp::Eq)]
pub struct AphTxtRecord {
  /// Algorithm from the required `alg` tag.
  pub algorithm: super::KeyAlgorithm,
  /// Raw public key bytes decoded from the required `k` tag.
  pub key_bytes: std::vec::Vec<u8>,
  /// Optional `kid`, disambiguating multiple keys at one DNS name.
  pub kid: std::option::Option<String>,
  /// Optional `did`, binding this entry to a specific DID URL.
  pub did: std::option::Option<String>,
  /// Optional RFC 3339 `notBefore`.
  pub not_before: std::option::Option<String>,
  /// Optional RFC 3339 `notAfter`.
  pub not_after: std::option::Option<String>,
}

/// The only tag-list version this implementation accepts.
const APH_TXT_VERSION: &str = "APHv1";

impl AphTxtRecord {
  /// Returns the discovered key in the crate's common form.
  pub fn public_key(&self) -> super::NotaryPublicKey {
    super::NotaryPublicKey {
      algorithm: self.algorithm,
      key_bytes: self.key_bytes.clone(),
      kid: self.kid.clone(),
    }
  }

  /// Checks the optional validity window against an RFC 3339 instant
  /// (spec §8.4.5 step 3c).
  ///
  /// Fails closed: an unparseable timestamp on either side counts as
  /// outside the window rather than being ignored, so a malformed record
  /// cannot widen a key's lifetime.
  pub fn is_valid_at(&self, now_rfc3339: &str) -> bool {
    let now = match chrono::DateTime::parse_from_rfc3339(now_rfc3339) {
      std::result::Result::Ok(t) => t,
      std::result::Result::Err(_) => return false,
    };
    if let std::option::Option::Some(nb) = self.not_before.as_deref() {
      match chrono::DateTime::parse_from_rfc3339(nb) {
        std::result::Result::Ok(t) if now >= t => {}
        _ => return false,
      }
    }
    if let std::option::Option::Some(na) = self.not_after.as_deref() {
      match chrono::DateTime::parse_from_rfc3339(na) {
        std::result::Result::Ok(t) if now <= t => {}
        _ => return false,
      }
    }
    true
  }
}

/// Parses one TXT record value as an APH tag-list (spec §8.4.5 step 3a).
///
/// Rejects a record whose `v` is not `APHv1` or that is missing `alg` or
/// `k`, so a partially-written or foreign TXT record at the same name can
/// never be mistaken for a key.
pub fn parse_txt_record(
  value: &str,
) -> std::result::Result<AphTxtRecord, crate::errors::AphError> {
  let mut version: std::option::Option<&str> = std::option::Option::None;
  let mut alg: std::option::Option<&str> = std::option::Option::None;
  let mut k: std::option::Option<&str> = std::option::Option::None;
  let mut kid: std::option::Option<String> = std::option::Option::None;
  let mut did: std::option::Option<String> = std::option::Option::None;
  let mut not_before: std::option::Option<String> = std::option::Option::None;
  let mut not_after: std::option::Option<String> = std::option::Option::None;

  for pair in value.split(';') {
    let pair = pair.trim();
    if pair.is_empty() {
      continue;
    }
    // Split on the FIRST '=' only: base64url payloads and RFC 3339
    // timestamps may themselves contain no '=', but splitting greedily
    // would still be wrong for any future tag that does.
    let (tag, tag_value) = match pair.split_once('=') {
      std::option::Option::Some((t, v)) => (t.trim(), v.trim()),
      // A bare token is not a tag-list entry; ignore it rather than
      // failing the whole record, matching DKIM's tolerance.
      std::option::Option::None => continue,
    };
    match tag {
      "v" => version = std::option::Option::Some(tag_value),
      "alg" => alg = std::option::Option::Some(tag_value),
      "k" => k = std::option::Option::Some(tag_value),
      "kid" => kid = std::option::Option::Some(String::from(tag_value)),
      "did" => did = std::option::Option::Some(String::from(tag_value)),
      "notBefore" => not_before = std::option::Option::Some(String::from(tag_value)),
      "notAfter" => not_after = std::option::Option::Some(String::from(tag_value)),
      // Unknown tags are ignored so the format can grow without breaking
      // existing verifiers (DKIM does the same).
      _ => {}
    }
  }

  if version != std::option::Option::Some(APH_TXT_VERSION) {
    return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
      "TXT record is not v=APHv1",
    ));
  }
  let algorithm = match alg {
    std::option::Option::Some(a) => super::KeyAlgorithm::from_dns_tag(a)?,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
        "TXT record missing required alg tag",
      ));
    }
  };
  let key_b64 = match k {
    std::option::Option::Some(v) => v,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
    }
  };
  let key_bytes = crate::crypto::base64url::decode(key_b64)
    .map_err(|_| crate::errors::AphError::InvalidEnvelopeSignature)?;

  // The length is part of what `alg` claims: 32 raw bytes for Ed25519, 33
  // SEC1-compressed for P-256. Without this check a value in some OTHER
  // encoding that happens to also be alphabet-valid base64url — every
  // base58btc string is — decodes to garbage of the wrong length and
  // becomes a "key" that only fails later, at verification, wearing an
  // invalid-signature error instead of naming the malformed record.
  let expected_len = match algorithm {
    super::KeyAlgorithm::Ed25519 => 32usize,
    super::KeyAlgorithm::P256 => 33usize,
  };
  if key_bytes.len() != expected_len {
    return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
  }

  std::result::Result::Ok(AphTxtRecord {
    algorithm,
    key_bytes,
    kid,
    did,
    not_before,
    not_after,
  })
}

/// Applies the selection rules of spec §8.4.5 step 3 across every TXT
/// record returned for a name.
///
/// Records that fail to parse are skipped rather than aborting the search:
/// a domain may host unrelated or malformed TXT records at the same name,
/// and one bad record must not deny a valid key sitting beside it.
///
/// When `kid` is given, only a record with that exact `kid` is accepted —
/// this is what makes key rotation unambiguous while both keys are
/// published side by side.
///
/// The one distinction worth spelling out, because it is not obvious which
/// side an expired key falls on: a matching key whose window has CLOSED is
/// `Err(APH_E003)` — published and failed, so the caller MUST reject and
/// never advance — while records that hold no APH candidate at all are
/// [`super::DiscoveryOutcome::Absent`]. A verifier that advanced past the
/// expired case would let whoever can expire or corrupt a record choose the
/// trust anchor.
///
/// An earlier revision returned `Err(NotaryServiceUnreachable)` for the
/// absent case, which was a mislabel twice over: the service was perfectly
/// reachable, and spelling absence as an error made it indistinguishable
/// from failure at every call site.
pub fn select_key(
  records: &[String],
  kid: std::option::Option<&str>,
  now_rfc3339: &str,
) -> std::result::Result<
  super::DiscoveryOutcome<super::NotaryPublicKey>,
  crate::errors::AphError,
> {
  let mut saw_candidate = false;
  for raw in records {
    let record = match parse_txt_record(raw) {
      std::result::Result::Ok(r) => r,
      std::result::Result::Err(_) => continue,
    };
    if let std::option::Option::Some(want) = kid {
      match record.kid.as_deref() {
        std::option::Option::Some(have) if have == want => {}
        // Either this record names a different key, or it names none while
        // the caller asked for a specific one. Neither is a match.
        _ => continue,
      }
    }
    saw_candidate = true;
    if record.is_valid_at(now_rfc3339) {
      return std::result::Result::Ok(super::DiscoveryOutcome::Found(record.public_key()));
    }
  }
  // Having SEEN a candidate is the whole reason this loop keeps a flag: it is
  // what separates "the key exists but its window has closed" (a failure the
  // caller must stop on) from "no such key was published" (an absence the
  // caller may advance past). The operator's next step differs, and so does
  // the verifier's (§8.4.6).
  if saw_candidate {
    std::result::Result::Err(crate::errors::AphError::mandate_expired(
      "notary key outside its notBefore/notAfter window",
    ))
  } else {
    std::result::Result::Ok(super::DiscoveryOutcome::Absent)
  }
}

#[cfg(test)]
mod tests {
  /// The single-key example printed in spec §8.4.5.
  const SPEC_EXAMPLE: &str =
    "v=APHv1; alg=ed25519; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw";

  #[test]
  fn parses_the_spec_example_record() {
    // The literal example from the specification must parse, or the
    // document and the implementation disagree on the format operators
    // will copy.
    let r = super::parse_txt_record(SPEC_EXAMPLE).unwrap();
    std::assert_eq!(r.algorithm, crate::discovery::KeyAlgorithm::Ed25519);
    std::assert_eq!(r.key_bytes.len(), 32);
    std::assert_eq!(r.kid, None);
  }

  #[test]
  fn parses_the_spec_rotation_example() {
    // The rotation example carries kid plus both window bounds — the shape
    // a notary publishes while two keys overlap.
    let raw = "v=APHv1; alg=ed25519; kid=k1; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw; \
               notBefore=2026-05-21T00:00:00Z; notAfter=2027-05-21T00:00:00Z";
    let r = super::parse_txt_record(raw).unwrap();
    std::assert_eq!(r.kid.as_deref(), Some("k1"));
    std::assert_eq!(r.not_before.as_deref(), Some("2026-05-21T00:00:00Z"));
    std::assert_eq!(r.not_after.as_deref(), Some("2027-05-21T00:00:00Z"));
  }

  #[test]
  fn a_key_of_the_wrong_length_for_its_alg_is_refused() {
    // A base58btc string is alphabet-valid base64url, so a record written
    // in the WRONG ENCODING decodes "successfully" — to 34 bytes of
    // garbage. Only the length check catches it at the record, where the
    // operator can see which record is malformed, rather than at signature
    // verification where it reads as a bad signature. This is the exact
    // shape an early implementation published before the encoding was
    // settled, so the refusal is a migration pin as much as a format one.
    let base58_key = "v=APHv1; alg=ed25519; k=z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy";
    std::assert!(super::parse_txt_record(base58_key).is_err());
  }

  #[test]
  fn wrong_version_is_refused() {
    // The `v` tag is the guard against reading a future or foreign format
    // with today's rules.
    let err = super::parse_txt_record("v=APHv2; alg=ed25519; k=AAAA").unwrap_err();
    std::assert_eq!(err.code(), "APH_E010");
    std::assert!(super::parse_txt_record("alg=ed25519; k=AAAA").is_err());
  }

  #[test]
  fn missing_required_tags_are_refused() {
    // A record without alg or k is not a key. Accepting a partial record
    // could mean verifying under a guessed algorithm.
    std::assert!(super::parse_txt_record("v=APHv1; k=AAAA").is_err());
    std::assert!(super::parse_txt_record("v=APHv1; alg=ed25519").is_err());
  }

  #[test]
  fn unknown_tags_are_ignored_for_forward_compatibility() {
    // DKIM-style tolerance: a tag added in a later revision must not stop
    // today's verifier from reading the key.
    let raw = std::format!("{}; futureTag=whatever", SPEC_EXAMPLE);
    std::assert!(super::parse_txt_record(&raw).is_ok());
  }

  #[test]
  fn non_base64url_key_is_refused_not_panicking() {
    // The k tag is attacker-influenced text; it must error rather than
    // panic or yield truncated key bytes.
    std::assert!(super::parse_txt_record("v=APHv1; alg=ed25519; k=!!!not-base64!!!").is_err());
  }

  #[test]
  fn validity_window_bounds_are_inclusive_and_fail_closed() {
    // Both edges count as valid; a malformed timestamp counts as invalid,
    // so a broken record cannot extend a key's life.
    let raw = "v=APHv1; alg=ed25519; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw; \
               notBefore=2026-05-21T00:00:00Z; notAfter=2027-05-21T00:00:00Z";
    let r = super::parse_txt_record(raw).unwrap();
    std::assert!(r.is_valid_at("2026-05-21T00:00:00Z"));
    std::assert!(r.is_valid_at("2027-05-21T00:00:00Z"));
    std::assert!(!r.is_valid_at("2026-05-20T23:59:59Z"));
    std::assert!(!r.is_valid_at("2027-05-21T00:00:01Z"));
    std::assert!(!r.is_valid_at("not-a-timestamp"));
  }

  #[test]
  fn selection_picks_the_record_matching_the_kid() {
    // Rotation correctness: with two keys published, the verifier must use
    // the one the proof's verificationMethod fragment names, not the first.
    let old = "v=APHv1; alg=ed25519; kid=k1; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw";
    let new = "v=APHv1; alg=ed25519; kid=k2; k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let records = std::vec![String::from(old), String::from(new)];
    let picked = match super::select_key(&records, Some("k2"), "2026-06-01T00:00:00Z").unwrap() {
      crate::discovery::DiscoveryOutcome::Found(key) => key,
      crate::discovery::DiscoveryOutcome::Absent => std::panic!("k2 is published and valid"),
    };
    std::assert_eq!(picked.kid.as_deref(), Some("k2"));
  }

  #[test]
  fn selection_skips_malformed_records_beside_a_valid_one() {
    // A domain may hold unrelated TXT records at the same name; one bad
    // neighbour must not deny an otherwise valid key.
    let records = std::vec![
      String::from("v=spf1 include:example.com ~all"),
      String::from("garbage"),
      String::from(SPEC_EXAMPLE),
    ];
    std::assert!(std::matches!(
      super::select_key(&records, None, "2026-06-01T00:00:00Z").unwrap(),
      crate::discovery::DiscoveryOutcome::Found(_)
    ));
  }

  #[test]
  fn expired_key_is_a_failure_and_absent_key_is_not() {
    // Spec §8.4.6: "published and failed" (expired) must stop an ordered
    // chain — advancing past it lets whoever can expire a record choose the
    // trust anchor — while "not published" (absent) merely means this
    // mechanism was never offered, and the chain may advance. The two
    // therefore have DIFFERENT TYPES here, not different codes: an earlier
    // revision spelled absence `Err(NotaryServiceUnreachable)`, which made
    // it indistinguishable from failure at every call site.
    let expired = "v=APHv1; alg=ed25519; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw; \
                   notAfter=2026-01-01T00:00:00Z";
    let records = std::vec![String::from(expired)];
    std::assert_eq!(
      super::select_key(&records, None, "2026-06-01T00:00:00Z").unwrap_err().code(),
      "APH_E003"
    );
    std::assert_eq!(
      super::select_key(&[], None, "2026-06-01T00:00:00Z").unwrap(),
      crate::discovery::DiscoveryOutcome::Absent,
      "an empty record set is absence, not an error"
    );
    // Records exist at the name but none is an APH record: still absence —
    // the notary published nothing HERE, whatever else the domain hosts.
    let unrelated = std::vec![String::from("v=spf1 include:example.com ~all")];
    std::assert_eq!(
      super::select_key(&unrelated, None, "2026-06-01T00:00:00Z").unwrap(),
      crate::discovery::DiscoveryOutcome::Absent
    );
  }

  #[test]
  fn a_requested_kid_never_falls_back_to_an_unlabelled_record() {
    // If the proof names a specific key, an unlabelled record is not a
    // substitute — silently accepting one would defeat rotation. The
    // outcome is ABSENCE, not failure: the named key is simply not
    // published via this mechanism, and an ordered chain may look for it
    // at the next one. (Forged absence buys an attacker nothing here:
    // advancing leads to did:web, which is anchored in a TLS certificate
    // for the same domain — a bar DNS forgery does not clear.)
    let records = std::vec![String::from(SPEC_EXAMPLE)];
    std::assert_eq!(
      super::select_key(&records, Some("k9"), "2026-06-01T00:00:00Z").unwrap(),
      crate::discovery::DiscoveryOutcome::Absent
    );
  }
}
