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
    // 427 is the byte length of `examples/principal_signed_body.txt`, the
    // golden's published body since the body-hash vector landed. Pinned as a
    // literal for the same reason as the native twin: a constant the test
    // knows independently of the parse is what detects a widened integer.
    parsed.contains("\"bodySize\":427"),
    "bodySize must survive the boundary as a bare integer"
  );
  aph_ts::require_attestation_mode(&parsed, "PrincipalSigned")
    .expect("the no-downgrade gate must admit the mode the structure proves");
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn a_closed_set_refusal_crosses_the_real_wasm_boundary_with_its_message_intact() {
  // WHY: this suite's whole reason is the half the native tests cannot reach —
  // the `#[wasm_bindgen]` exports and the `JsValue` ERROR path — and until now
  // it exercised only the admitting half, so the error path it names was never
  // once executed. §7.1.5 is the case that makes that gap matter: an
  // unrecognized channel kind is a strict-parse refusal (§8.3 step 1) whose
  // message is built deep inside `serde_json`, stringified, and only then
  // turned into a `JsValue` — three hops, none of them observed from Rust.
  //
  // PINS: the exported entry point REFUSES rather than carrying the value
  // through; the thrown value is a JS STRING a caller can read (not an opaque
  // handle); the offending value and the closed set both survive all three
  // hops, `google_chat` included; and the message claims no `APH_E` code,
  // because §8.3 step 1 is the layer below the taxonomy.
  //
  // The refused document is derived from the published golden by a TEXT edit,
  // in view of the reader, and the exactly-once check keeps that derivation
  // honest: if the corpus is reformatted the test fails at the edit instead of
  // silently asserting something about an unmodified envelope.
  const ANCHOR: &str = "\"kind\": \"slack\",";
  assert_eq!(
    PRINCIPAL_SIGNED_GOLDEN.matches(ANCHOR).count(),
    1,
    "the derivation must edit exactly one place in the published golden"
  );
  let refused = PRINCIPAL_SIGNED_GOLDEN.replace(ANCHOR, "\"kind\": \"squillo\",");

  let err = aph_ts::parse_envelope_json(&refused)
    .expect_err("a channel kind outside the closed set must be refused, never carried");
  let message = err
    .as_string()
    .expect("the refusal must cross the boundary as a string a JS caller can read");
  assert!(
    message.contains("carrier_pigeon"),
    "the refusal must name the offending value, got: {}",
    message
  );
  assert!(
    message.contains("closed set") && message.contains("google_chat"),
    "the refusal must name the closed set, got: {}",
    message
  );
  assert!(
    !message.starts_with("APH_E"),
    "a strict-parse refusal must not claim a protocol code, got: {}",
    message
  );
}
