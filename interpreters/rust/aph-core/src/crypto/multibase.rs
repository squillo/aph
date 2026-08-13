//! Multibase base58btc — the encoding APH proof values and `did:key`
//! identifiers use.
//!
//! Multibase prefixes an encoded string with a character naming its base;
//! `z` is base58btc. A proof value therefore looks like `z3Wgv...`, and a
//! `did:key` identifier like `did:key:z6Mk...`.
//!
//! This is wire-visible in every envelope, so the encoding must match other
//! implementations byte-for-byte. base58btc is deterministic, so any correct
//! implementation agrees.

/// Multibase tag for base58btc.
const BASE58BTC_TAG: char = 'z';

/// Encodes bytes as multibase base58btc (a `z`-prefixed string).
pub fn base58btc_encode(input: &[u8]) -> String {
  let mut out = String::with_capacity(1 + input.len() * 2);
  out.push(BASE58BTC_TAG);
  out.push_str(&bs58::encode(input).into_string());
  out
}

/// Decodes a multibase base58btc string.
///
/// Returns `APH_E001` when the string lacks the `z` tag or is not valid
/// base58 — an unreadable proof value must fail verification rather than be
/// silently treated as an empty signature.
pub fn base58btc_decode(input: &str) -> std::result::Result<std::vec::Vec<u8>, crate::errors::AphError> {
  let body = match input.strip_prefix(BASE58BTC_TAG) {
    std::option::Option::Some(b) => b,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
    }
  };
  match bs58::decode(body).into_vec() {
    std::result::Result::Ok(bytes) => std::result::Result::Ok(bytes),
    std::result::Result::Err(_) => {
      std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature)
    }
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn round_trip_preserves_bytes() {
    // The encoding carries signatures and public keys; a lossy round trip
    // would corrupt a proof value in transit.
    let data = [1u8, 2, 3, 250, 255, 0, 128];
    let encoded = super::base58btc_encode(&data);
    std::assert!(encoded.starts_with('z'));
    std::assert_eq!(super::base58btc_decode(&encoded).unwrap(), data.to_vec());
  }

  #[test]
  fn leading_zero_bytes_survive() {
    // base58 drops leading zeros unless they are encoded as '1' characters.
    // A public key beginning with a zero byte would otherwise decode short
    // and fail signature verification for non-obvious reasons.
    let data = [0u8, 0, 0, 42];
    let encoded = super::base58btc_encode(&data);
    std::assert_eq!(super::base58btc_decode(&encoded).unwrap(), data.to_vec());
  }

  #[test]
  fn missing_multibase_tag_is_rejected() {
    // Bare base58 without the 'z' tag is a different encoding. Accepting it
    // would mean guessing at the base, so it fails closed.
    std::assert!(super::base58btc_decode("6MkfAkf").is_err());
  }

  #[test]
  fn invalid_base58_is_rejected_not_panicking() {
    // Proof values arrive from the wire: characters outside the base58
    // alphabet (0, O, I, l) must produce an error, never a panic.
    std::assert!(super::base58btc_decode("z0OIl").is_err());
  }

  #[test]
  fn empty_payload_round_trips() {
    // A bare "z" is a legal encoding of zero bytes; it must not be confused
    // with a missing tag.
    std::assert_eq!(super::base58btc_decode("z").unwrap(), std::vec::Vec::<u8>::new());
  }
}
