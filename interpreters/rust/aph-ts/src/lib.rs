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
//!
//! # Export parity with `aph-py` and the Elixir binding
//!
//! This crate, the sibling Python binding and the Elixir binding under
//! `interpreters/elixir` expose the SAME six envelope-facing operations —
//! parse, serialize, verify-structure, require-mode, mandate-validity, and
//! embedded-mandate-binding — with the same semantics
//! and the same error identity (an APH code a caller can match exactly). That
//! parity is a CONTRACT, stated in all three so it cannot drift silently: a
//! function added to one binding is owed to the other two in the same change,
//! or the divergence is justified where it happens. All three cross envelopes
//! as JSON TEXT in both directions for the reason the boundary note above
//! states; the parity contract exists so the four bindings also cannot drift
//! in WHAT they teach.
//!
//! The Elixir member is spelled in BEAM idiom — `{:ok, result} | {:error,
//! code}` rather than a thrown value, with the APH code as the wire string —
//! and its NIF crate is excluded from this workspace outright rather than
//! merely from `default-members`, because mix drives that build. Neither
//! difference is a divergence in the surface: same four operations, same
//! semantics, same code strings.

/// Strict-parses `json` into the canonical envelope type, stringifying the
/// parse error. Shared by every export so the boundary has ONE parse path.
fn parse_envelope(
  json: &str,
) -> std::result::Result<aph_core::NotarizationEnvelope, std::string::String> {
  // Delegates to the core's shared strict-parse entry, so the wire-version
  // rules (sealedPayload's declaration check today) hold at THIS boundary
  // by construction rather than by re-implementation.
  aph_core::parse_envelope_json(json)
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
  // One meaning, one place: the spellings live in aph-core's `FromStr`, the
  // inverse of `label()`. This shim used to carry its own copy of this match
  // — as did every sibling binding — and four copies of the downgrade gate's
  // vocabulary is four places a typo could become the downgrade.
  let required_mode: aph_core::AttestationMode = required.parse()?;
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

/// Whether a Delegation Mandate (given as JSON text) is valid at `at`
/// (RFC 3339), per the mandate's own `validFrom`/`validUntil` window.
///
/// The semantics are `aph-core`'s, verbatim: an unparseable timestamp — in
/// the argument OR in the mandate — yields `false`, never an exception,
/// because the core documents "parsing failure returns false" and a binding
/// that invented stricter semantics would be a SECOND definition of one
/// check. What IS refused here is a mandate that does not strict-parse:
/// that is the JSON boundary's job in every export of this crate.
fn mandate_is_valid_at_impl(
  mandate_json: &str,
  at: &str,
) -> std::result::Result<bool, std::string::String> {
  let mandate: aph_core::DelegationMandate =
    serde_json::from_str(mandate_json).map_err(|e| std::format!("{}", e))?;
  std::result::Result::Ok(mandate.is_valid_at(at))
}

#[wasm_bindgen::prelude::wasm_bindgen(js_name = mandateIsValidAt)]
pub fn mandate_is_valid_at(
  mandate_json: &str,
  at: &str,
) -> std::result::Result<bool, wasm_bindgen::JsValue> {
  mandate_is_valid_at_impl(mandate_json, at).map_err(|e| wasm_bindgen::JsValue::from_str(&e))
}

/// Verify the §7.1.7.1 binding between an envelope (given as JSON text) and
/// the Delegation Mandate embedded at `policy.delegationMandate`: the three
/// identity equalities, the window, and the mandate's own signatures'
/// presence rules — everything `aph-core`'s check performs, nothing more.
///
/// An envelope with NO embedded mandate returns ok, exactly as the core
/// does: absence of the optional block is not a binding failure. Throws the
/// `AphError` text (code included) on any violation.
fn verify_embedded_mandate_binding_impl(
  json: &str,
) -> std::result::Result<(), std::string::String> {
  let envelope = parse_envelope(json)?;
  aph_core::verify_embedded_mandate_binding(&envelope).map_err(|e| std::format!("{}", e))
}

#[wasm_bindgen::prelude::wasm_bindgen(js_name = verifyEmbeddedMandateBinding)]
pub fn verify_embedded_mandate_binding(
  json: &str,
) -> std::result::Result<(), wasm_bindgen::JsValue> {
  verify_embedded_mandate_binding_impl(json).map_err(|e| wasm_bindgen::JsValue::from_str(&e))
}

#[cfg(test)]
mod tests {
  /// The corpus directory, resolved at RUNTIME — the compile-time constants
  /// below name specific files and can never see a new one, which is the
  /// hole the corpus test closes.
  fn examples_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples")
  }

  #[test]
  fn every_conformance_file_strict_parses_through_this_binding() {
    // WHY: until this test, this binding's ONLY view of the corpus was the
    // fixtures embedded at compile time — a golden carrying a NEW FIELD
    // would land in `examples/` and this crate would compile and pass having
    // never parsed it. An audit found the Go binding's corpus gate with
    // exactly that hole ("is JSON", never parsed), and the same absence here
    // was just quieter, being no gate at all.
    //
    // PINS: every conformance entry in `examples/manifest.json` strict-parses
    // and round-trips through this binding's own boundary function, so every
    // FUTURE golden exercises it the day it lands.
    let manifest_path = examples_dir().join("manifest.json");
    let raw = std::fs::read_to_string(&manifest_path)
      .unwrap_or_else(|e| std::panic!("could not read {}: {}", manifest_path.display(), e));
    let manifest: serde_json::Value = serde_json::from_str(&raw)
      .unwrap_or_else(|e| std::panic!("the corpus manifest is not valid JSON: {e}"));
    let entries = manifest
      .get("conformance")
      .and_then(serde_json::Value::as_array)
      .unwrap_or_else(|| std::panic!("the corpus manifest has no `conformance` array"));
    std::assert!(!entries.is_empty(), "an empty inventory would verify nothing");
    for entry in entries {
      let name = entry
        .as_str()
        .unwrap_or_else(|| std::panic!("a `conformance` entry is not a string"));
      let path = examples_dir().join(name);
      let document = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| std::panic!("could not read {}: {}", path.display(), e));
      super::roundtrip_envelope_json(&document).unwrap_or_else(|e| {
        std::panic!("{} is named in the manifest and does not strict-parse: {}", name, e)
      });
    }
  }

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
    // The literal is the point: comparing against a constant the test knows
    // INDEPENDENTLY of the parse is what detects a widened integer, so it is
    // pinned by hand and MOVES WITH THE GOLDEN — 427 is the byte length of
    // `examples/principal_signed_body.txt`, the published body this golden
    // attests since the body-hash vector landed.
    std::assert_eq!(
      second.credential_subject.communication.body_size, 427,
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

  #[test]
  fn the_goldens_embedded_mandate_answers_validity_at_both_sides_of_its_window() {
    // WHY: `mandateIsValidAt` is one of the two verification exports the
    // parity contract owes every binding, and its inputs here are DERIVED
    // from the published golden rather than invented — the mandate is the
    // one embedded at `policy.delegationMandate`, and the timestamps sit
    // inside and after its own validFrom/validUntil window, so nothing in
    // this test asserts a fact the corpus does not already carry.
    //
    // PINS: true inside the window; false after it; false for garbage time
    // (the core's documented "parsing failure returns false", delegated and
    // not re-invented); and a refusal for a mandate that is not JSON.
    let envelope: serde_json::Value =
      serde_json::from_str(PRINCIPAL_SIGNED_GOLDEN).expect("the golden parses as JSON");
    let mandate = serde_json::to_string(&envelope["credentialSubject"]["policy"]["delegationMandate"])
      .expect("the embedded mandate serializes");
    std::assert!(super::mandate_is_valid_at_impl(&mandate, "2026-05-21T12:00:00Z").expect("valid call"));
    std::assert!(!super::mandate_is_valid_at_impl(&mandate, "2026-06-01T00:00:00Z").expect("valid call"));
    std::assert!(!super::mandate_is_valid_at_impl(&mandate, "not-a-timestamp").expect("valid call"));
    std::assert!(super::mandate_is_valid_at_impl("{not json", "2026-05-21T12:00:00Z").is_err());
  }

  #[test]
  fn the_goldens_mandate_binding_verifies_and_a_broken_binding_refuses() {
    // WHY: the other verification export owed by the parity contract. The
    // admit half runs the WHOLE core check against the published golden; the
    // refusal is derived by ONE text edit, in view of the reader, that
    // breaks an identity equality the binding requires.
    super::verify_embedded_mandate_binding_impl(PRINCIPAL_SIGNED_GOLDEN)
      .expect("the published golden's embedded mandate binds");

    // The refusal: retarget the embedded mandate's `agentDid` so the
    // §7.1.7.1 identity equality (`mandate.agentDid == subject.agent.id`)
    // fails, and nothing else moves.
    let mut envelope: serde_json::Value =
      serde_json::from_str(PRINCIPAL_SIGNED_GOLDEN).expect("the golden parses as JSON");
    envelope["credentialSubject"]["policy"]["delegationMandate"]["agentDid"] =
      serde_json::Value::String(std::string::String::from("did:web:other-agent.example"));
    let broken = serde_json::to_string(&envelope).expect("it serializes");
    let err = super::verify_embedded_mandate_binding_impl(&broken)
      .expect_err("a retargeted mandate must refuse to bind");
    std::assert!(
      err.contains("APH_E"),
      "the refusal carries a protocol code, because the BINDING check sits \
       above the parse layer: {}",
      err
    );
  }

  #[test]
  fn a_closed_set_value_this_build_does_not_define_is_refused_through_the_text_boundary() {
    // WHY: §7.1.5 and §7.1.6 close the channel and content-class
    // vocabularies, and `aph-core` now models them as closed TYPES — so an
    // unrecognized value is a strict-parse refusal (§8.3 step 1) rather than
    // a string that rides through. What this test exists for is the HOP: the
    // refusal is produced deep inside `serde_json` as a custom error and this
    // boundary stringifies it with `format!("{}", e)`, so nothing but a test
    // says whether the offending value and the closed set are still in the
    // text a JS caller reads. A message flattened to "invalid value" would
    // still refuse and would still be useless.
    //
    // PINS, per field: the refusal happens; the offending VALUE survives the
    // stringification; the closed SET survives, `google_chat` included, since
    // that irregular spelling is the one a producer most plausibly got wrong;
    // and the message claims NO `APH_E` code, because §8.3 step 1 is the layer
    // below the taxonomy and a parse dressed as a protocol verdict would send
    // a reader to inspect key material over a typo.
    for (pointer, offending, member) in [
      (
        ["credentialSubject", "channel", "kind"],
        "carrier_pigeon",
        "google_chat",
      ),
      (
        ["credentialSubject", "communication", "contentClass"],
        "Digest",
        "BulkSend",
      ),
      (
        ["credentialSubject", "policy", "decision"],
        "Sometimes",
        "NeverAllow",
      ),
    ] {
      let mut document: serde_json::Value =
        serde_json::from_str(LEGACY_SLACK_REPLY).expect("the legacy envelope parses as JSON");
      document[pointer[0]][pointer[1]][pointer[2]] =
        serde_json::Value::String(std::string::String::from(offending));
      let text = serde_json::to_string(&document).expect("the edited envelope serializes");
      let err = crate::roundtrip_envelope_json(&text)
        .expect_err("a value outside the closed set must be refused, never carried");
      std::assert!(
        err.contains(offending),
        "the refusal must name the offending value `{}`, got: {}",
        offending,
        err
      );
      std::assert!(
        err.contains("closed set") && err.contains(member),
        "the refusal must name the closed set (including `{}`), got: {}",
        member,
        err
      );
      std::assert!(
        !err.starts_with("APH_E"),
        "a strict-parse refusal must not claim a protocol code, got: {}",
        err
      );
    }
  }

  #[test]
  fn the_draft_vector_parses_and_its_downgrade_refuses_at_this_boundary() {
    // The shared strict-parse entry (hoisted to the core) means the
    // v0.2-draft wire-version rule holds at THIS boundary by construction;
    // this test is the proof at the boundary, not a re-implementation.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("../../../examples/v0.2-draft/sealed_envelope.json");
    let vector = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    super::parse_envelope(&vector).expect("the 0.2-draft vector strict-parses here");

    let downgraded = vector.replace("\"aphVersion\": \"0.2\"", "\"aphVersion\": \"0.1\"");
    let err = super::parse_envelope(&downgraded)
      .expect_err("the same member on a 0.1 wire is malformed for the version it claims");
    std::assert!(err.contains("not declared"), "the refusal names the rule: {err}");
  }
}
