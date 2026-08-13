//! `did:key` — self-describing notary identifiers.
//!
//! `did:key` is the first and preferred key-discovery mechanism (spec §8.4.6)
//! because it needs no network at all: the public key IS the identifier. A
//! verifier that receives `issuer: "did:key:z6Mk..."` can decode the key from
//! that string and check the signature entirely offline.
//!
//! The identifier is a multicodec-prefixed public key in multibase base58btc
//! (spec §8.4.3). The prefixes APH uses are `0xed01` for Ed25519 and `0x1200`
//! for P-256, both varint-encoded — `0x1200` becomes the two bytes
//! `0x80 0x24`, which is why the constants below are not simply the codec
//! numbers written out.

/// Multicodec varint prefix for an Ed25519 public key (`0xed01`).
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
/// Multicodec varint prefix for a P-256 public key (`0x1200`).
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];

/// The `did:key:` URI scheme prefix.
const DID_KEY_PREFIX: &str = "did:key:";

/// A public key decoded from a `did:key` identifier.
#[derive(std::fmt::Debug, std::clone::Clone, std::cmp::PartialEq, std::cmp::Eq)]
pub enum DecodedDidKey {
  /// Ed25519 verifying key — the `eddsa-jcs-2022` cryptosuite.
  Ed25519(std::boxed::Box<ed25519_dalek::VerifyingKey>),
  /// Compressed P-256 point — the `ecdsa-jcs-2019` cryptosuite. Returned as
  /// raw bytes so callers that do not need ES256 pay nothing to parse it.
  P256(std::vec::Vec<u8>),
}

/// Builds the `did:key` identifier for an Ed25519 public key.
///
/// This is how a notary derives the DID it publishes as `issuer`, so it must
/// agree exactly with what verifiers decode.
pub fn encode_ed25519(key: &ed25519_dalek::VerifyingKey) -> String {
  let mut payload = std::vec::Vec::with_capacity(2 + 32);
  payload.extend_from_slice(&ED25519_MULTICODEC);
  payload.extend_from_slice(key.as_bytes());
  std::format!("{}{}", DID_KEY_PREFIX, super::multibase::base58btc_encode(&payload))
}

/// Decodes a `did:key` identifier into the public key it names.
///
/// Every failure path returns `APH_E001`: a verifier that cannot decode the
/// issuer's key must refuse the envelope, never fall through to accepting it.
pub fn decode(did: &str) -> std::result::Result<DecodedDidKey, crate::errors::AphError> {
  let encoded = match did.strip_prefix(DID_KEY_PREFIX) {
    std::option::Option::Some(rest) => rest,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
    }
  };
  decode_multibase_key(encoded)
}

/// Decodes a multicodec-prefixed public key in multibase base58btc.
///
/// This is the payload half of a `did:key` identifier, and is also exactly
/// what a DID Document's `publicKeyMultibase` field carries — so `did:web`
/// discovery reuses this decoder rather than reimplementing it.
pub fn decode_multibase_key(
  encoded: &str,
) -> std::result::Result<DecodedDidKey, crate::errors::AphError> {
  let bytes = super::multibase::base58btc_decode(encoded)?;
  if bytes.len() < 3 {
    return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
  }
  let (prefix, key_bytes) = bytes.split_at(2);

  if prefix == ED25519_MULTICODEC {
    let arr: [u8; 32] = match key_bytes.try_into() {
      std::result::Result::Ok(a) => a,
      // Wrong length for the declared codec: the identifier is malformed.
      std::result::Result::Err(_) => {
        return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
      }
    };
    return match ed25519_dalek::VerifyingKey::from_bytes(&arr) {
      std::result::Result::Ok(k) => {
        std::result::Result::Ok(DecodedDidKey::Ed25519(std::boxed::Box::new(k)))
      }
      // Well-formed length but not a valid curve point.
      std::result::Result::Err(_) => {
        std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature)
      }
    };
  }

  if prefix == P256_MULTICODEC {
    // Compressed SEC1 point: 33 bytes with a 0x02/0x03 parity byte.
    if key_bytes.len() != 33 {
      return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
    }
    return std::result::Result::Ok(DecodedDidKey::P256(key_bytes.to_vec()));
  }

  // A codec APH does not define. Refuse rather than guess at the algorithm.
  std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(std::format!(
    "did:key multicodec 0x{:02x}{:02x}",
    prefix[0],
    prefix[1]
  )))
}

#[cfg(test)]
mod tests {
  fn sample_key() -> ed25519_dalek::VerifyingKey {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    sk.verifying_key()
  }

  #[test]
  fn encode_decode_round_trip() {
    // A notary derives its issuer DID from its key; a verifier reverses that
    // derivation. If the two disagree, no self-issued envelope verifies.
    let key = sample_key();
    let did = super::encode_ed25519(&key);
    match super::decode(&did).unwrap() {
      super::DecodedDidKey::Ed25519(decoded) => std::assert_eq!(*decoded, key),
      other => std::panic!("expected Ed25519, got {:?}", other),
    }
  }

  #[test]
  fn ed25519_dids_use_the_z6mk_prefix() {
    // The 0xed01 multicodec plus base58btc always yields "z6Mk..." for a
    // 32-byte key. Pinning it catches a wrong multicodec prefix, which would
    // otherwise produce identifiers no other implementation can resolve.
    let did = super::encode_ed25519(&sample_key());
    std::assert!(did.starts_with("did:key:z6Mk"), "got {}", did);
  }

  #[test]
  fn published_example_issuer_decodes() {
    // The issuer DID from the repository's published example envelopes must
    // decode with this implementation — otherwise the examples we hand to
    // implementers cannot be verified by our own reference code.
    let did = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV";
    std::assert!(matches!(
      super::decode(did).unwrap(),
      super::DecodedDidKey::Ed25519(_)
    ));
  }

  #[test]
  fn non_did_key_input_is_rejected() {
    // did:web and DNS discovery are different mechanisms with their own
    // resolvers; this decoder must not silently accept their identifiers.
    std::assert!(super::decode("did:web:notary.example").is_err());
    std::assert!(super::decode("z6MkfAkf").is_err());
  }

  #[test]
  fn unknown_multicodec_reports_unsupported_algorithm() {
    // A key type APH does not define must surface as APH_E010 rather than a
    // generic signature failure, so an operator can tell the two apart.
    let payload = super::super::multibase::base58btc_encode(&[0x99u8, 0x01, 1, 2, 3]);
    let err = super::decode(&std::format!("did:key:{}", payload)).unwrap_err();
    std::assert_eq!(err.code(), "APH_E010");
  }

  #[test]
  fn truncated_key_is_rejected_not_panicking() {
    // Attacker-controlled input: a correct multicodec with a short key must
    // error rather than panic on the fixed-size array conversion.
    let payload = super::super::multibase::base58btc_encode(&[0xed, 0x01, 1, 2, 3]);
    std::assert!(super::decode(&std::format!("did:key:{}", payload)).is_err());
  }
}
