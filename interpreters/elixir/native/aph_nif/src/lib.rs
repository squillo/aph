//! `aph_nif` — the native half of the APH Elixir binding.
//!
//! Every envelope crossing the BEAM boundary crosses as JSON TEXT, in BOTH
//! directions: parsing takes a binary, serializing returns one. This is a
//! structural safety property, not a convenience, and it is the SAME rule the
//! wasm binding enforces at the JS boundary and the pyo3 binding at the Python
//! one.
//!
//! `aph_core::EnvelopeProofs` is an untagged object-or-array union, and
//! untagged matching is exactly where a value that changed shape can silently
//! change which arm deserializes. A term route — envelopes as Elixir maps and
//! lists — hands that decision to a SECOND deserializer reading whatever the
//! caller's terms happen to hold.
//!
//! The BEAM makes that hazard easy to underestimate, which is precisely why it
//! is written down here: Erlang integers are arbitrary precision, so the
//! integer-widening trap that motivates the rule in JS and Python does not
//! bite on this boundary. The trap that DOES bite is the ENCODER — a map/list
//! encoder must pick one arm of the union with no schema to consult, and a
//! caller who decoded an envelope, edited it and handed the terms back can
//! produce a one-element proof list or a float `bodySize` without noticing.
//! JSON text has one spelling of each, so the only union and number parser
//! that ever runs is `serde_json`'s.
//!
//! # ⛔ Why every function in this file is trivially thin
//!
//! This is a TESTABILITY rule, not a style preference, and it is forced by the
//! hosting relationship. A pyo3 extension embeds CPython inside Rust, so
//! `cargo test` can start an interpreter and drive that whole boundary. A
//! rustler NIF is the inverse — Rust embedded IN the BEAM — and there is no
//! supported way to embed the BEAM in a Rust test binary. `mix test` is
//! therefore the ONLY gate that ever exercises the term boundary.
//!
//! The mitigation is architectural rather than procedural: every exported
//! function is decode-binary → call `aph_core` → encode-result, and NOTHING
//! else. All behaviour then lives in `aph_core`, already under `cargo test`,
//! and what only `mix test` covers shrinks to term glue. A wrapper in this
//! file that grows a branch, a default, or a coercion is a DEFECT precisely
//! because cargo cannot reach it.
//!
//! That is also why this crate has no `#[cfg(test)]` module and is built
//! `cdylib`-only: a Rust test binary here would need the `enif_*` symbols the
//! BEAM supplies at load time and has no way to obtain them. The behavioural
//! tests live in `aph-core`; the boundary tests live in ExUnit.
//!
//! # The one branch above `aph_core`, and why it is duplicated
//!
//! [`require_attestation_mode_impl`] matches the caller's `required` spelling
//! before dispatching. That branch exists identically in both sibling
//! bindings, and it must: the alternative — letting an unrecognized spelling
//! fall through to a default — would BE the downgrade the gate refuses. It is
//! deliberate duplication across the three bindings and has to stay identical
//! in all three.

// The sibling bindings spell every path in full and this file follows that,
// with ONE exception. Whether a function receives the caller's environment is
// decided by rustler's macro from the first argument's TYPE NAME — it compares
// the last path segment to `Env` — so this is the one spot where the type's
// spelling is load-bearing input to a macro rather than a style choice, and it
// is written the way the library's own examples write it. `Term` comes along
// because it is the paired return type.
use rustler::Env;
use rustler::Term;

// Atoms are registered once at load time rather than built per call: the atom
// table is never garbage collected, so producing atoms from runtime input is
// unbounded growth. These two are the only atoms this boundary emits.
rustler::atoms! {
  ok,
  error,
}

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

/// Runs `aph_core::verify_proof_structure` on JSON text and returns the mode's
/// wire label on success, or the `APH_E*`-prefixed error message.
fn verify_proof_structure_impl(
  json: &str,
) -> std::result::Result<std::string::String, std::string::String> {
  let envelope = parse_envelope(json)?;
  match aph_core::verify_proof_structure(&envelope) {
    std::result::Result::Ok(mode) => {
      std::result::Result::Ok(std::string::String::from(mode.label()))
    }
    std::result::Result::Err(e) => std::result::Result::Err(std::format!("{}", e)),
  }
}

/// Runs `aph_core::require_mode` on JSON text. `required` must be a wire
/// spelling (`PrincipalSigned` | `NotaryAttested`); anything else is an error
/// rather than a silent default, because a typo that defaulted to the weaker
/// mode would BE the downgrade this gate exists to refuse.
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

/// Whether a Delegation Mandate JSON is valid at `at` (RFC 3339). The
/// semantics are `aph-core`'s verbatim — an unparseable timestamp yields
/// `false`, never an error, because the core documents "parsing failure
/// returns false" and a binding that invented stricter semantics would be a
/// SECOND definition of one check. A mandate that does not strict-parse is
/// the error case: that is the JSON boundary's job in every export here.
fn mandate_is_valid_at_impl(
  mandate_json: &str,
  at: &str,
) -> std::result::Result<bool, std::string::String> {
  let mandate: aph_core::DelegationMandate =
    serde_json::from_str(mandate_json).map_err(|e| std::format!("{}", e))?;
  std::result::Result::Ok(mandate.is_valid_at(at))
}

/// Runs `aph_core::verify_embedded_mandate_binding` on envelope JSON text.
/// An envelope with NO embedded mandate is ok, exactly as the core has it:
/// absence of the optional block is not a binding failure.
fn verify_embedded_mandate_binding_impl(
  json: &str,
) -> std::result::Result<(), std::string::String> {
  let envelope = parse_envelope(json)?;
  aph_core::verify_embedded_mandate_binding(&envelope).map_err(|e| std::format!("{}", e))
}

/// Encodes a text result as `{:ok, binary} | {:error, binary}`.
///
/// Refusals are RETURN VALUES here rather than raised NIF exceptions: a
/// refused envelope is an ordinary outcome on this boundary, and an exception
/// would force every caller into a `try`. Raising is reserved for a caller who
/// broke the calling convention — see the decode note on the exports below.
fn encode_text_result<'a>(
  env: Env<'a>,
  result: std::result::Result<std::string::String, std::string::String>,
) -> Term<'a> {
  match result {
    std::result::Result::Ok(text) => rustler::Encoder::encode(&(ok(), text), env),
    std::result::Result::Err(message) => {
      rustler::Encoder::encode(&(error(), message), env)
    }
  }
}

/// Encodes a valueless result as `:ok | {:error, binary}` — the BEAM's
/// spelling for a success that carries nothing, which is what the
/// no-downgrade gate returns.
fn encode_unit_result<'a>(
  env: Env<'a>,
  result: std::result::Result<(), std::string::String>,
) -> Term<'a> {
  match result {
    std::result::Result::Ok(()) => rustler::Encoder::encode(&ok(), env),
    std::result::Result::Err(message) => {
      rustler::Encoder::encode(&(error(), message), env)
    }
  }
}

// Every export below takes its arguments as owned `String`. That costs one
// copy per call and buys two things worth more than the copy: the signature
// carries no borrow of a caller-owned term, and a caller who hands over a map,
// a list or a number fails to decode and is REFUSED by rustler with `:badarg`
// rather than silently coerced. There is no arity anywhere in this file that
// accepts a term-shaped envelope, and that absence is the boundary rule made
// structural instead of documented.

/// `APH.Native.parse_envelope_json/1`.
#[rustler::nif]
fn parse_envelope_json<'a>(
  env: Env<'a>,
  json: std::string::String,
) -> Term<'a> {
  encode_text_result(env, roundtrip_envelope_json(&json))
}

/// `APH.Native.serialize_envelope/1`.
#[rustler::nif]
fn serialize_envelope<'a>(
  env: Env<'a>,
  json: std::string::String,
) -> Term<'a> {
  encode_text_result(env, roundtrip_envelope_json(&json))
}

/// `APH.Native.verify_proof_structure/1`.
#[rustler::nif]
fn verify_proof_structure<'a>(
  env: Env<'a>,
  json: std::string::String,
) -> Term<'a> {
  encode_text_result(env, verify_proof_structure_impl(&json))
}

/// `APH.Native.require_attestation_mode/2`.
#[rustler::nif]
fn require_attestation_mode<'a>(
  env: Env<'a>,
  json: std::string::String,
  required: std::string::String,
) -> Term<'a> {
  encode_unit_result(env, require_attestation_mode_impl(&json, &required))
}

/// `APH.Native.mandate_is_valid_at/2`.
#[rustler::nif]
fn mandate_is_valid_at<'a>(
  env: Env<'a>,
  mandate_json: std::string::String,
  at: std::string::String,
) -> Term<'a> {
  match mandate_is_valid_at_impl(&mandate_json, &at) {
    std::result::Result::Ok(valid) => rustler::Encoder::encode(&(ok(), valid), env),
    std::result::Result::Err(message) => rustler::Encoder::encode(&(error(), message), env),
  }
}

/// `APH.Native.verify_embedded_mandate_binding/1`.
#[rustler::nif]
fn verify_embedded_mandate_binding<'a>(
  env: Env<'a>,
  json: std::string::String,
) -> Term<'a> {
  encode_unit_result(env, verify_embedded_mandate_binding_impl(&json))
}

// The module name is the Erlang spelling of `APH.Native`; the BEAM looks the
// NIFs up under exactly this atom, so it must track the Elixir module name
// character for character. The explicit function list is this rustler
// release's registration form.
rustler::init!(
  "Elixir.APH.Native",
  [
    parse_envelope_json,
    serialize_envelope,
    verify_proof_structure,
    require_attestation_mode,
    mandate_is_valid_at,
    verify_embedded_mandate_binding
  ]
);
