//! `aph-ts` — WebAssembly bindings for the APH protocol types.
//!
//! Every envelope crossing the JS boundary crosses as JSON TEXT, in BOTH
//! directions: parsing takes a JSON string, serializing returns one. This
//! is a structural safety property, not a convenience. The previous
//! `serde-wasm-bindgen` route carried envelopes as `JsValue`, and a JS
//! number is always an `f64` — so an integer field re-entering Rust could
//! arrive widened to a float. `aph_core::EnvelopeProofs` is an untagged
//! object-or-array union, and untagged matching is exactly the place where
//! a widened number can silently change which arm deserializes. JSON text
//! has one integer spelling, so the widening cannot occur at all.
//!
//! A TypeScript consumer pairs these exports with `JSON.parse` /
//! `JSON.stringify`:
//!
//! ```text
//! const envelope = JSON.parse(parseEnvelopeJson(text)); // plain object
//! const text2    = serializeEnvelope(JSON.stringify(envelope));
//! const mode     = verifyProofStructure(text);          // §7.1.11 gate
//! requireAttestationMode(text, "PrincipalSigned");      // §8.3.1 step 1a
//! ```

/// Strict-parses `json` into the canonical envelope type, stringifying the
/// parse error. Shared by every export so the boundary has ONE parse path.
fn parse_envelope(
  json: &str,
) -> std::result::Result<aph_core::NotarizationEnvelope, std::string::String> {
  serde_json::from_str(json).map_err(|e| std::format!("{}", e))
}

/// Strict-parses `json` and re-emits it as canonical compact JSON text —
/// the one operation both text-boundary directions reduce to.
fn roundtrip_envelope_json(
  json: &str,
) -> std::result::Result<std::string::String, std::string::String> {
  let envelope = parse_envelope(json)?;
  serde_json::to_string(&envelope).map_err(|e| std::format!("{}", e))
}

/// Runs `aph_core::verify_proof_structure` on JSON text and returns the
/// mode's wire label on success, or the `APH_E*`-prefixed error message.
fn verify_proof_structure_impl(
  json: &str,
) -> std::result::Result<&'static str, std::string::String> {
  let envelope = parse_envelope(json)?;
  match aph_core::verify_proof_structure(&envelope) {
    std::result::Result::Ok(mode) => std::result::Result::Ok(mode.label()),
    std::result::Result::Err(e) => std::result::Result::Err(std::format!("{}", e)),
  }
}

/// Runs `aph_core::require_mode` on JSON text. `required` must be a wire
/// spelling (`PrincipalSigned` | `NotaryAttested`); anything else is an
/// error rather than a silent default, because a typo that defaulted to the
/// weaker mode would BE the downgrade this gate exists to refuse.
fn require_attestation_mode_impl(
  json: &str,
  required: &str,
) -> std::result::Result<(), std::string::String> {
  let required_mode = match required {
    "PrincipalSigned" => aph_core::AttestationMode::PrincipalSigned,
    "NotaryAttested" => aph_core::AttestationMode::NotaryAttested,
    other => {
      return std::result::Result::Err(std::format!(
        "unknown attestation mode `{}`: expected `PrincipalSigned` or `NotaryAttested`",
        other
      ));
    }
  };
  let envelope = parse_envelope(json)?;
  aph_core::require_mode(&envelope, required_mode).map_err(|e| std::format!("{}", e))
}

/// Parse a JSON string as an APH `NotarizationEnvelope` and return the
/// envelope re-emitted as canonical compact JSON text.
///
/// A successful return proves the input satisfied the strict
/// (`deny_unknown_fields`) envelope schema; the caller obtains a plain JS
/// object with `JSON.parse` on the result. Throws a JS error (the parse
/// message) on any deviation from the canonical shape.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = parseEnvelopeJson)]
pub fn parse_envelope_json(
  json: &str,
) -> std::result::Result<std::string::String, wasm_bindgen::JsValue> {
  roundtrip_envelope_json(json).map_err(|e| wasm_bindgen::JsValue::from_str(&e))
}

/// Serialize an envelope, given as JSON text (e.g. `JSON.stringify` of a
/// JS object), back to canonical compact JSON text.
///
/// The input must conform to the canonical `NotarizationEnvelope` shape;
/// any deviation throws a JS error. The envelope never crosses the
/// boundary as a `JsValue` — see the module docs for why.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = serializeEnvelope)]
pub fn serialize_envelope(
  json: &str,
) -> std::result::Result<std::string::String, wasm_bindgen::JsValue> {
  roundtrip_envelope_json(json).map_err(|e| wasm_bindgen::JsValue::from_str(&e))
}

/// Verify the §7.1.11 proof-chain structural rules on an envelope given as
/// JSON text, returning the attestation mode the STRUCTURE supports:
/// `"PrincipalSigned"` or `"NotaryAttested"`.
///
/// This is the check that detects a forged `PrincipalSigned` label — a
/// label written above a structure that does not support it throws
/// `APH_E013`. A successful return says the structure is sound; it says
/// NOTHING about whether any signature verifies.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = verifyProofStructure)]
pub fn verify_proof_structure(
  json: &str,
) -> std::result::Result<std::string::String, wasm_bindgen::JsValue> {
  verify_proof_structure_impl(json)
    .map(std::string::String::from)
    .map_err(|e| wasm_bindgen::JsValue::from_str(&e))
}

/// Refuse an envelope (given as JSON text) whose DECLARED attestation mode
/// is weaker than `required` (`"PrincipalSigned"` | `"NotaryAttested"`),
/// throwing `APH_E012` — the §8.3.1 step-1a no-downgrade gate.
///
/// The label alone is not evidence: a caller MUST also run
/// [`verify_proof_structure`], which is what rejects a forged
/// `PrincipalSigned` label. Calling this function alone accepts one.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = requireAttestationMode)]
pub fn require_attestation_mode(
  json: &str,
  required: &str,
) -> std::result::Result<(), wasm_bindgen::JsValue> {
  require_attestation_mode_impl(json, required)
    .map_err(|e| wasm_bindgen::JsValue::from_str(&e))
}

#[cfg(test)]
mod tests {
  /// The published `PrincipalSigned` golden — the chain form of the
  /// `EnvelopeProofs` union, embedded at compile time so the crate's tests
  /// exercise the same bytes the repository publishes.
  const PRINCIPAL_SIGNED_GOLDEN: &str =
    std::include_str!("../../../../examples/principal_signed_envelope.json");

  /// A legacy pre-chain envelope — the single-object form of the union.
  const LEGACY_SLACK_REPLY: &str =
    std::include_str!("../../../../examples/slack_reply_envelope.json");

  #[test]
  fn the_principal_signed_golden_round_trips_as_json_text() {
    // WHY: the JSON-text boundary exists to protect the untagged
    // `EnvelopeProofs` union from JS-number integer widening, and the CHAIN
    // arm is the one a forged label imitates — so the published
    // `PrincipalSigned` golden must survive the text route with its arm and
    // every integer intact. Pins: chain-arm preservation, value-equality of
    // the reparsed envelope, and exact `bodySize` integer fidelity.
    let text = crate::roundtrip_envelope_json(PRINCIPAL_SIGNED_GOLDEN)
      .expect("the published golden must round-trip through the text route");
    let first: aph_core::NotarizationEnvelope =
      serde_json::from_str(PRINCIPAL_SIGNED_GOLDEN).expect("the golden strict-parses");
    let second: aph_core::NotarizationEnvelope =
      serde_json::from_str(&text).expect("the re-emitted text strict-parses");
    std::assert_eq!(first, second, "the round trip must be value-lossless");
    std::assert!(
      second.proof.is_chain(),
      "the golden's two-element chain must survive as the chain arm"
    );
    std::assert_eq!(
      second.credential_subject.communication.body_size, 1842,
      "an integer field must cross the boundary without widening"
    );
  }

  #[test]
  fn a_legacy_single_proof_envelope_round_trips_as_json_text() {
    // WHY: the union has two arms and the previous JsValue route put BOTH
    // at risk; this pins the other one. A pre-chain envelope (single-object
    // `proof`, no `attestationMode`) must cross the text boundary
    // value-lossless and come back as the single arm — never silently
    // promoted to a chain.
    let text = crate::roundtrip_envelope_json(LEGACY_SLACK_REPLY)
      .expect("a legacy envelope must round-trip through the text route");
    let first: aph_core::NotarizationEnvelope =
      serde_json::from_str(LEGACY_SLACK_REPLY).expect("the legacy envelope strict-parses");
    let second: aph_core::NotarizationEnvelope =
      serde_json::from_str(&text).expect("the re-emitted text strict-parses");
    std::assert_eq!(first, second, "the round trip must be value-lossless");
    std::assert!(
      !second.proof.is_chain(),
      "a single-object proof must survive as the single arm"
    );
  }

  #[test]
  fn the_structure_gate_reads_both_goldens_and_detects_a_forged_label() {
    // WHY: `verifyProofStructure` is exported precisely so a TS consumer
    // can detect a forged `PrincipalSigned` label (§7.1.11). Pins the
    // honest readings of both published forms AND the forgery rejection:
    // writing the label above a single-object proof must surface APH_E013
    // through the text boundary, code included, so a TS caller can match
    // on it.
    std::assert_eq!(
      crate::verify_proof_structure_impl(PRINCIPAL_SIGNED_GOLDEN)
        .expect("the golden satisfies §7.1.11"),
      "PrincipalSigned"
    );
    std::assert_eq!(
      crate::verify_proof_structure_impl(LEGACY_SLACK_REPLY)
        .expect("a legacy envelope satisfies §7.1.11"),
      "NotaryAttested"
    );
    let mut forged: serde_json::Value =
      serde_json::from_str(LEGACY_SLACK_REPLY).expect("the legacy envelope parses as JSON");
    forged["credentialSubject"]["policy"]["attestationMode"] =
      serde_json::Value::String(std::string::String::from("PrincipalSigned"));
    let forged_text =
      serde_json::to_string(&forged).expect("the forged envelope serializes");
    let err = crate::verify_proof_structure_impl(&forged_text)
      .expect_err("a PrincipalSigned label above a single proof must be rejected");
    std::assert!(
      err.contains("APH_E013"),
      "the rejection must carry the APH_E013 code, got: {}",
      err
    );
  }

  #[test]
  fn requiring_principal_signed_refuses_the_weaker_mode() {
    // WHY: `requireAttestationMode` is the §8.3.1 step-1a no-downgrade
    // gate; a verifier requiring `PrincipalSigned` MUST refuse
    // `NotaryAttested` rather than silently accept the weaker claim. Pins
    // the refusal (APH_E012, code visible to TS), both accepting paths,
    // and that an unrecognized mode string errors instead of defaulting —
    // a typo that defaulted weak would BE the downgrade.
    crate::require_attestation_mode_impl(PRINCIPAL_SIGNED_GOLDEN, "PrincipalSigned")
      .expect("the golden satisfies a PrincipalSigned-only policy");
    crate::require_attestation_mode_impl(LEGACY_SLACK_REPLY, "NotaryAttested")
      .expect("a legacy envelope satisfies a NotaryAttested requirement");
    let err =
      crate::require_attestation_mode_impl(LEGACY_SLACK_REPLY, "PrincipalSigned")
        .expect_err("NotaryAttested must not satisfy a PrincipalSigned requirement");
    std::assert!(
      err.contains("APH_E012"),
      "the refusal must carry the APH_E012 code, got: {}",
      err
    );
    std::assert!(
      crate::require_attestation_mode_impl(LEGACY_SLACK_REPLY, "Notarized").is_err(),
      "an unknown mode string must error, never default to a mode"
    );
  }
}
