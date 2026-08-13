//! Base64url (RFC 4648 §5, no padding) helpers used by the JWS modules.
//!
//! Vendored so the APH crate stands alone; the encoding is identical to
//! the helpers used by the wider agent-card / payment-mandate ecosystem
//! (`URL_SAFE_NO_PAD`).

pub(crate) fn encode(data: &[u8]) -> String {
  use base64::Engine;
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub(crate) fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
  use base64::Engine;
  base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_encode_decode_roundtrip() {
    // These helpers replaced the originals this module was vendored from,
    // so the round-trip is the proof the substitution preserved behavior —
    // every JWS signing input and signature passes through them.
    let data = b"mandate payload bytes";
    let encoded = encode(data);
    let decoded = decode(&encoded).unwrap();
    assert_eq!(decoded, data);
  }

  #[test]
  fn test_encode_is_unpadded_urlsafe() {
    // Alphabet and padding are wire-visible in every JWS token, so this
    // pins the exact variant (url-safe, unpadded); a switch to standard
    // base64 would break every deployed verifier.
    // Two bytes would end in '=' under padded base64; 0xFF/0xEF force
    // characters that differ between the standard and url-safe alphabets.
    let encoded = encode(&[0xFFu8, 0xEF]);
    assert_eq!(encoded, "_-8");
    assert!(!encoded.contains('='), "must not be padded");
    assert!(!encoded.contains('+') && !encoded.contains('/'));
  }

  #[test]
  fn test_decode_rejects_invalid_input() {
    // decode() runs on attacker-controlled JWS sections; garbage must
    // return Err (which callers turn into "unverified") and never panic.
    assert!(decode("not!!valid@@base64").is_err());
  }

  #[test]
  fn test_encode_empty() {
    // Empty input is a real case — the detached-JWS payload section is
    // always empty — so both directions must handle it without special
    // casing.
    assert_eq!(encode(b""), "");
    assert_eq!(decode("").unwrap(), Vec::<u8>::new());
  }

  #[test]
  fn test_decode_rejects_padding() {
    // URL_SAFE_NO_PAD requires no padding, so a padded encoding of otherwise
    // valid bytes is rejected — each byte string has one accepted text form.
    assert!(decode("QQ==").is_err());
  }

  #[test]
  fn test_decode_rejects_standard_alphabet() {
    // Standard-alphabet '+' and '/' are invalid under the url-safe alphabet.
    assert!(decode("+a/b").is_err());
  }

  #[test]
  fn test_decode_rejects_nonzero_trailing_bits() {
    // The engine rejects non-canonical trailing bits: "QR" has them, "QQ"
    // does not (decodes to [65]).
    assert!(decode("QR").is_err());
    assert_eq!(decode("QQ").unwrap(), vec![65u8]);
  }
}
