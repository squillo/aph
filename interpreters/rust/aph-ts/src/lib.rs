//! `aph-ts` — WebAssembly bindings for the APH protocol types.
//!
//! Re-exports `aph_core::NotarizationEnvelope` and helpers via
//! `wasm-bindgen` so a TypeScript consumer can `import { parseEnvelopeJson }
//! from 'aph-ts'` and round-trip JSON envelopes against the
//! canonical Rust types.

/// Parse a JSON string into an APH NotarizationEnvelope.
///
/// Returns a `JsValue` representing the parsed envelope (structure mirrors
/// the canonical Rust shape), or throws a JS error on parse failure.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = parseEnvelopeJson)]
pub fn parse_envelope_json(
  json: &str,
) -> std::result::Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue> {
  let envelope: aph_core::NotarizationEnvelope = serde_json::from_str(json)
    .map_err(|e| wasm_bindgen::JsValue::from_str(&std::format!("{}", e)))?;
  // json_compatible(): maps (e.g. the opaque `recipientAddressing` object)
  // must surface as plain JS objects, not ES2015 Maps — this data is
  // JSON-derived and JS consumers expect JSON semantics.
  let serializer = serde_wasm_bindgen::Serializer::json_compatible();
  serde::Serialize::serialize(&envelope, &serializer)
    .map_err(|e| wasm_bindgen::JsValue::from_str(&std::format!("{}", e)))
}

/// Serialize a JsValue-shaped envelope back to a JSON string.
///
/// The input `value` must conform to the canonical `NotarizationEnvelope`
/// shape; any deviation surfaces as a JS error.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = serializeEnvelope)]
pub fn serialize_envelope(
  value: wasm_bindgen::JsValue,
) -> std::result::Result<std::string::String, wasm_bindgen::JsValue> {
  let envelope: aph_core::NotarizationEnvelope =
    serde_wasm_bindgen::from_value(value)
      .map_err(|e| wasm_bindgen::JsValue::from_str(&std::format!("{}", e)))?;
  serde_json::to_string(&envelope)
    .map_err(|e| wasm_bindgen::JsValue::from_str(&std::format!("{}", e)))
}
