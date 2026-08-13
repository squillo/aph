//! RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! Canonical JSON serialization used to produce the byte string that
//! detached-JWS signatures cover. Handles payloads that may contain
//! numeric amounts.
//!
//! Interop note: keys are sorted by Rust `String` `Ord` (byte order), not
//! the RFC 8785 UTF-16 code-unit order, and float formatting is Rust
//! `Display` rather than the ECMAScript Number-to-string algorithm. This
//! is the deployed wire behavior — existing signatures were produced over
//! exactly this output, so it must not be "corrected".

/// Produces a JCS-style canonical JSON string (the deployed APH dialect —
/// diverges from strict RFC 8785; see the interop notes).
///
/// Keys are sorted by Rust `String` `Ord` (byte order); numbers are
/// formatted via Rust `Display` (integers without a decimal point).
///
/// Interop note: key ordering is Rust byte order and floats use Rust
/// `Display` formatting; see the module docs for why this diverges from
/// strict RFC 8785 and must stay as-is.
pub fn canonicalize_rfc8785(value: &serde_json::Value) -> String {
  match value {
    serde_json::Value::Object(map) => {
      let mut keys: Vec<&String> = map.keys().collect();
      keys.sort();
      let entries: Vec<String> = keys
        .into_iter()
        .map(|k| {
          format!(
            "{}:{}",
            serde_json::to_string(k).unwrap(),
            canonicalize_rfc8785(&map[k])
          )
        })
        .collect();
      format!("{{{}}}", entries.join(","))
    }
    serde_json::Value::Array(arr) => {
      let items: Vec<String> = arr.iter().map(canonicalize_rfc8785).collect();
      format!("[{}]", items.join(","))
    }
    serde_json::Value::Number(n) => format_es_number(n),
    _ => serde_json::to_string(value).unwrap(),
  }
}

/// Formats a JSON number for the deployed APH canonical form.
///
/// - Integers: no decimal point.
/// - Floats: Rust `Display` output (shortest round-trip; note this matches
///   ECMAScript output for common values but diverges for exponent-range
///   magnitudes such as `1e21` — see the module interop notes).
fn format_es_number(n: &serde_json::Number) -> String {
  if let Some(i) = n.as_i64() {
    return i.to_string();
  }
  if let Some(u) = n.as_u64() {
    return u.to_string();
  }
  if let Some(f) = n.as_f64() {
    if f == 0.0 {
      return "0".to_string();
    }
    // Rust's default f64 Display already yields shortest-round-trip output
    // with no trailing zeros (1.5 not 1.50, 2 not 2.0); no post-processing
    // happens here, and none may be added — these are signed bytes.
    return format!("{}", f);
  }
  n.to_string()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_key_ordering() {
    // Key order IS the signature: a verifier re-canonicalizes the received
    // envelope and compares bytes, so any change to ordering invalidates
    // every signature ever issued.
    let val = serde_json::json!({"z": 1, "a": 2, "m": 3});
    assert_eq!(canonicalize_rfc8785(&val), r#"{"a":2,"m":3,"z":1}"#);
  }

  #[test]
  fn test_nested_objects() {
    // Sorting must recurse: envelopes are deeply nested (credentialSubject
    // → channel → recipientAddressing), so ordering that applied only at
    // the top level would produce unstable bytes for real payloads.
    let val = serde_json::json!({"b": {"z": true, "a": false}, "a": [1, 2]});
    assert_eq!(
      canonicalize_rfc8785(&val),
      r#"{"a":[1,2],"b":{"a":false,"z":true}}"#
    );
  }

  #[test]
  fn test_integer_formatting() {
    // Integers must serialize without a decimal point — bodySize and
    // decisionLatencyMs are integers inside signed envelopes, and "42.0"
    // would change the canonical bytes.
    let val = serde_json::json!(42);
    assert_eq!(canonicalize_rfc8785(&val), "42");
  }

  #[test]
  fn test_negative_integer() {
    // Guards the as_i64 branch: negatives must keep a plain leading minus
    // with no other decoration.
    let val = serde_json::json!(-17);
    assert_eq!(canonicalize_rfc8785(&val), "-17");
  }

  #[test]
  fn test_zero() {
    // Zero has three plausible spellings ("0", "0.0", "-0"); only one can
    // be canonical, so it is pinned explicitly.
    let val = serde_json::json!(0);
    assert_eq!(canonicalize_rfc8785(&val), "0");
  }

  #[test]
  fn test_string_escaping() {
    // Escaping is delegated to serde_json rather than reimplemented; this
    // pins that delegation, since a hand-rolled escaper that differed by
    // one byte would silently break cross-implementation verification.
    let val = serde_json::json!({"key": "hello \"world\""});
    let canonical = canonicalize_rfc8785(&val);
    assert!(canonical.contains(r#"\"world\""#));
  }

  #[test]
  fn test_deterministic_across_calls() {
    // Canonicalization must be a pure function: a signer and a verifier in
    // different processes must derive identical bytes from equal input.
    let val = serde_json::json!({"c": 3, "a": 1, "b": 2});
    let r1 = canonicalize_rfc8785(&val);
    let r2 = canonicalize_rfc8785(&val);
    assert_eq!(r1, r2);
  }

  #[test]
  fn test_null_and_bool() {
    // Explicit nulls are part of the signed bytes (several envelope fields
    // serialize as null rather than being omitted), so null and bool
    // literals must survive canonicalization unchanged and in sorted order.
    let val = serde_json::json!({"n": null, "t": true, "f": false});
    assert_eq!(
      canonicalize_rfc8785(&val),
      r#"{"f":false,"n":null,"t":true}"#
    );
  }

  #[test]
  fn test_jcs_idempotent_double_canonicalize() {
    // Verification re-canonicalizes text that was itself canonical output,
    // so the function must be a fixed point — otherwise a round-tripped
    // envelope would hash differently than the one that was signed.
    let val = serde_json::json!({"z": [3, 1], "a": {"y": null, "x": true}});
    let once = canonicalize_rfc8785(&val);
    let parsed: serde_json::Value = serde_json::from_str(&once).unwrap();
    let twice = canonicalize_rfc8785(&parsed);
    assert_eq!(once, twice);
  }

  #[test]
  fn test_empty_object_and_array() {
    // Zero-entry join paths must not emit stray separators.
    assert_eq!(canonicalize_rfc8785(&serde_json::json!({})), "{}");
    assert_eq!(canonicalize_rfc8785(&serde_json::json!([])), "[]");
    assert_eq!(canonicalize_rfc8785(&serde_json::json!([[], [[]]])), "[[],[[]]]");
  }

  #[test]
  fn test_negative_zero_formats_as_zero() {
    // The `f == 0.0` guard normalizes -0.0 → "0" (both compare equal to 0.0).
    let neg_zero: serde_json::Value = serde_json::from_str("-0").unwrap();
    let neg_zero_f: serde_json::Value = serde_json::from_str("-0.0").unwrap();
    assert_eq!(canonicalize_rfc8785(&neg_zero), "0");
    assert_eq!(canonicalize_rfc8785(&neg_zero_f), "0");
  }

  #[test]
  fn test_large_and_small_float_rust_display_divergence() {
    // Deliberate divergence from ECMAScript: Rust Display never uses
    // scientific notation. Pinned so a future "RFC-compliance fix" that
    // would change these signed bytes fails loudly here.
    let big: serde_json::Value = serde_json::from_str("1e21").unwrap();
    let small: serde_json::Value = serde_json::from_str("5e-7").unwrap();
    assert_eq!(canonicalize_rfc8785(&big), "1000000000000000000000");
    assert_eq!(canonicalize_rfc8785(&small), "0.0000005");
  }

  #[test]
  fn test_integer_extremes_exact() {
    // Pins the as_i64/as_u64 branch order at the boundaries: values above
    // i64::MAX must take the u64 path and stay exact rather than falling
    // through to the lossy f64 branch.
    assert_eq!(canonicalize_rfc8785(&serde_json::json!(i64::MAX)), "9223372036854775807");
    assert_eq!(canonicalize_rfc8785(&serde_json::json!(i64::MIN)), "-9223372036854775808");
    assert_eq!(canonicalize_rfc8785(&serde_json::json!(u64::MAX)), "18446744073709551615");
  }

  #[test]
  fn test_float_source_formatting_never_leaks() {
    // Trailing zeros and uppercase exponents in the source text must not
    // survive canonicalization — only the parsed numeric value matters.
    let a: serde_json::Value = serde_json::from_str("1.50").unwrap();
    let b: serde_json::Value = serde_json::from_str("2.0").unwrap();
    let c: serde_json::Value = serde_json::from_str("1E+2").unwrap();
    assert_eq!(canonicalize_rfc8785(&a), "1.5");
    assert_eq!(canonicalize_rfc8785(&b), "2");
    assert_eq!(canonicalize_rfc8785(&c), "100");
  }

  #[test]
  fn test_duplicate_keys_last_value_wins() {
    // Dedup is serde_json Map behavior (last key wins on parse), pinned here
    // so canonicalization over parsed input is stable regardless of source.
    let v: serde_json::Value = serde_json::from_str(r#"{"a":1,"a":2}"#).unwrap();
    assert_eq!(canonicalize_rfc8785(&v), r#"{"a":2}"#);
  }

  #[test]
  fn test_astral_plane_key_sort_is_utf8_byte_order() {
    // Deployed behavior sorts keys by UTF-8 byte order: U+E000 (ee80..),
    // U+FF61 (efbd..), then U+10000 (f090..). RFC 8785 UTF-16 order would
    // place the surrogate-pair U+10000 before U+E000 — that divergence is
    // deliberate and signature-load-bearing.
    let v = serde_json::json!({"\u{10000}": 3, "\u{FF61}": 2, "\u{E000}": 1});
    let out = canonicalize_rfc8785(&v);
    let e000 = out.find('\u{E000}').unwrap();
    let ff61 = out.find('\u{FF61}').unwrap();
    let astral = out.find('\u{10000}').unwrap();
    assert!(e000 < ff61 && ff61 < astral, "got: {}", out);
  }

  #[test]
  fn test_parser_recursion_limit_shields_canonicalize() {
    // serde_json's own recursion limit (128) rejects pathologically nested
    // input BEFORE canonicalize_rfc8785's recursive walk ever runs, so the
    // canonicalizer cannot be driven to a stack overflow via untrusted JSON.
    let deep_ok = format!("{}1{}", "[".repeat(120), "]".repeat(120));
    let parsed: serde_json::Value = serde_json::from_str(&deep_ok).unwrap();
    assert_eq!(canonicalize_rfc8785(&parsed).len(), 241);
    let too_deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
    assert!(serde_json::from_str::<serde_json::Value>(&too_deep).is_err());
  }
}
