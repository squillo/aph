//! The wasm32 smoke suite.
//!
//! The four native module tests in src/lib.rs prove the JSON-text boundary
//! logic; none of them prove the WASM BOUNDARY itself — the
//! `#[wasm_bindgen]` exports, the `JsValue` error path, and the compiled
//! wasm32 artifact a TS consumer actually loads. This suite runs the
//! published golden through that real boundary under Node
//! (`wasm-pack test --node aph-ts`).
#![cfg(target_arch = "wasm32")]

/// The published `PrincipalSigned` golden, embedded at compile time so the
/// wasm binary needs no filesystem at run time.
const PRINCIPAL_SIGNED_GOLDEN: &str =
  std::include_str!("../../../../examples/principal_signed_envelope.json");

#[wasm_bindgen_test::wasm_bindgen_test]
fn the_golden_crosses_the_real_wasm_boundary_intact() {
  // WHY: the suspected untagged-union wasm deserialization break was killed
  // structurally when the boundary became JSON text, but until now nothing
  // executed the exported functions AS wasm — a regression in the
  // `wasm_bindgen` glue (or a future return to `JsValue` payloads) would
  // ship invisible to the native tests. Pins: the golden parses through the
  // exported entry point, the structural gate names its mode
  // `PrincipalSigned`, re-serialization is byte-identical to the parse
  // output, and `bodySize` survives as a bare integer (the exact value the
  // union break would have widened or dropped).
  let parsed = aph_ts::parse_envelope_json(PRINCIPAL_SIGNED_GOLDEN)
    .expect("the published golden must parse across the wasm boundary");
  let mode = aph_ts::verify_proof_structure(&parsed)
    .expect("the golden's proof chain must satisfy the structural gate");
  assert_eq!(
    mode, "PrincipalSigned",
    "the golden's two-proof chain supports exactly the PrincipalSigned mode"
  );
  let reserialized = aph_ts::serialize_envelope(&parsed)
    .expect("a value that parsed must re-serialize");
  assert_eq!(
    parsed, reserialized,
    "parse and serialize must agree on canonical compact text"
  );
  assert!(
    parsed.contains("\"bodySize\":1842"),
    "bodySize must survive the boundary as a bare integer"
  );
  aph_ts::require_attestation_mode(&parsed, "PrincipalSigned")
    .expect("the no-downgrade gate must admit the mode the structure proves");
}
