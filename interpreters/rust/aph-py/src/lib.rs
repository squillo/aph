//! `aph-py` — Python bindings for the APH protocol types.
//!
//! Every envelope crossing the Python boundary crosses as JSON TEXT, in BOTH
//! directions: parsing takes a JSON string, serializing returns one. This is
//! a structural safety property, not a convenience, and it is the SAME rule
//! `aph-ts` enforces at the JS boundary for the same reason.
//!
//! `aph_core::EnvelopeProofs` is an untagged object-or-array union, and
//! untagged matching is exactly where a number that changed shape can
//! silently change which arm deserializes. A Python-object route — via
//! `pythonize` or any `dict`/`list` bridge — hands that decision to a SECOND
//! deserializer reading whatever the caller's objects happen to hold, and a
//! Python `float` is an IEEE-754 double exactly like a JS `number`: a caller
//! who edits a parsed envelope in Python can trivially hand `bodySize` back as
//! a float, or as an integer past 2^53 that a double silently rounds. JSON
//! text has one integer spelling, so the whole class of bug is unreachable —
//! the only number parser that runs is `serde_json`'s, and the boundary test
//! named for 2^53 + 1 is the tripwire that fires if that ever stops being true.
//!
//! A Python consumer pairs these exports with `json.loads` / `json.dumps`:
//!
//! ```text
//! import aph, json
//! envelope = json.loads(aph.parse_envelope_json(text))   # plain dict
//! text2    = aph.serialize_envelope(json.dumps(envelope))
//! mode     = aph.verify_proof_structure(text)            # §7.1.11 gate
//! aph.require_attestation_mode(text, "PrincipalSigned")  # §8.3.1 step 1a
//! ```
//!
//! # Parity contract with `aph-ts` and the Elixir binding
//!
//! This crate, `aph-ts` and the Elixir binding under `interpreters/elixir` are
//! three BINDINGS of one reference implementation, not three implementations.
//! They export the same operations with the same semantics and the same error
//! text, spelled in each language's idiom:
//!
//! | `aph-ts` (JS)            | `aph` (Python)             | `aph` (Elixir)                   |
//! |--------------------------|----------------------------|----------------------------------|
//! | `parseEnvelopeJson`      | `parse_envelope_json`      | `APH.parse_envelope_json/1`      |
//! | `serializeEnvelope`      | `serialize_envelope`       | `APH.serialize_envelope/1`       |
//! | `verifyProofStructure`   | `verify_proof_structure`   | `APH.verify_proof_structure/1`   |
//! | `requireAttestationMode` | `require_attestation_mode` | `APH.require_attestation_mode/2` |
//!
//! No binding may grow an operation, a semantic, or an error spelling the
//! others lack: bindings that teach different things about one protocol are
//! how a protocol acquires several meanings. Operatively — a change to this
//! surface is unfinished until the same change lands in the other two, and the
//! reverse. Independence from the reference is a different artifact entirely —
//! an implementation written from the specification and the published vectors,
//! sharing no code with this workspace — and no binding is or claims to be one.
//!
//! The Elixir member returns `{:ok, result} | {:error, code}` rather than
//! raising, because that is the BEAM's spelling for a refusal that is an
//! ordinary outcome; the APH code still travels as the wire STRING, so a
//! caller matches `APH_E013` there exactly as one matches it on `str(e)` here.
//! Its NIF crate is excluded from the Rust workspace outright rather than
//! merely from `default-members`, because mix drives that build.
//!
//! # Errors
//!
//! Every refusal raises `aph.AphError` carrying the reference
//! implementation's own message, which for a protocol refusal begins with the
//! `APH_E*` code. A Python caller matches the code exactly as a TypeScript
//! caller matches it on the thrown message:
//!
//! ```text
//! try:
//!     aph.verify_proof_structure(text)
//! except aph.AphError as e:
//!     if str(e).startswith("APH_E013"):
//!         ...   # a PrincipalSigned label above a structure that cannot bear it
//! ```
//!
//! Shape refusals (a field APH never defined, a malformed document) carry the
//! serde message instead of a code, because there is no protocol error to
//! name yet — the same distinction the JS binding surfaces.

// The single exception every export raises — ONE type, because the code lives
// in the message: a caller distinguishes `APH_E012` from `APH_E013` by reading
// it, not by catching a different class, and that is what keeps this binding's
// error identity equal to the JS binding's, which has only a thrown message to
// carry a code in. The fourth argument is the Python-visible docstring (a `//`
// comment rather than `///` because the doc belongs to the expansion, not to
// the macro call).
pyo3::create_exception!(
  aph,
  AphError,
  pyo3::exceptions::PyException,
  "Raised when an APH envelope is malformed or refused. The message carries the `APH_E*` code for protocol refusals."
);

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

/// Parse a JSON string as an APH `NotarizationEnvelope` and return the
/// envelope re-emitted as canonical compact JSON text.
///
/// A successful return proves the input satisfied the strict
/// (`deny_unknown_fields`) envelope schema; the caller obtains a plain `dict`
/// with `json.loads` on the result. Raises `AphError` on any deviation from
/// the canonical shape.
#[pyo3::pyfunction]
pub fn parse_envelope_json(json: &str) -> pyo3::PyResult<std::string::String> {
  roundtrip_envelope_json(json).map_err(AphError::new_err)
}

/// Serialize an envelope, given as JSON text (e.g. `json.dumps` of a `dict`),
/// back to canonical compact JSON text.
///
/// The input must conform to the canonical `NotarizationEnvelope` shape; any
/// deviation raises `AphError`. The envelope never crosses the boundary as a
/// Python object — see the module docs for why.
#[pyo3::pyfunction]
pub fn serialize_envelope(json: &str) -> pyo3::PyResult<std::string::String> {
  roundtrip_envelope_json(json).map_err(AphError::new_err)
}

/// Verify the §7.1.11 proof-chain structural rules on an envelope given as
/// JSON text, returning the attestation mode the STRUCTURE supports:
/// `"PrincipalSigned"` or `"NotaryAttested"`.
///
/// This is the check that detects a forged `PrincipalSigned` label — a label
/// written above a structure that does not support it raises `APH_E013`. A
/// successful return says the structure is sound; it says NOTHING about
/// whether any signature verifies.
#[pyo3::pyfunction]
pub fn verify_proof_structure(json: &str) -> pyo3::PyResult<std::string::String> {
  let envelope = parse_envelope(json).map_err(AphError::new_err)?;
  match aph_core::verify_proof_structure(&envelope) {
    std::result::Result::Ok(mode) => {
      std::result::Result::Ok(std::string::String::from(mode.label()))
    }
    std::result::Result::Err(e) => {
      std::result::Result::Err(AphError::new_err(std::format!("{}", e)))
    }
  }
}

/// Refuse an envelope (given as JSON text) whose DECLARED attestation mode is
/// weaker than `required` (`"PrincipalSigned"` | `"NotaryAttested"`), raising
/// `APH_E012` — the §8.3.1 step-1a no-downgrade gate.
///
/// An unrecognized `required` spelling is an error rather than a silent
/// default, because a typo that defaulted to the weaker mode would BE the
/// downgrade this gate exists to refuse.
///
/// The label alone is not evidence: a caller MUST also run
/// [`verify_proof_structure`], which is what rejects a forged
/// `PrincipalSigned` label. Calling this function alone accepts one.
#[pyo3::pyfunction]
pub fn require_attestation_mode(json: &str, required: &str) -> pyo3::PyResult<()> {
  // One meaning, one place: the spellings live in aph-core's `FromStr` (the
  // inverse of `label()`); this binding only wraps the message in its
  // exception type. Four copies of the downgrade gate's vocabulary was four
  // places a typo could become the downgrade.
  let required_mode: aph_core::AttestationMode =
    required.parse().map_err(AphError::new_err)?;
  let envelope = parse_envelope(json).map_err(AphError::new_err)?;
  aph_core::require_mode(&envelope, required_mode)
    .map_err(|e| AphError::new_err(std::format!("{}", e)))
}

/// APH (Agent per Human) protocol envelope types — a binding of the Rust
/// reference implementation. Envelopes cross as JSON text in both directions.
#[pyo3::pymodule]
mod aph {
  // `#[pymodule_export]` is the declarative module macro's own syntax for
  // naming an item's Python export; it is consumed by the outer `#[pymodule]`
  // expansion, so these `use` lines are macro input, not imports the code
  // dispatches through.
  #[pymodule_export]
  use super::AphError;
  #[pymodule_export]
  use super::parse_envelope_json;
  #[pymodule_export]
  use super::require_attestation_mode;
  #[pymodule_export]
  use super::serialize_envelope;
  #[pymodule_export]
  use super::verify_proof_structure;
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
    // WHY: the JSON-text boundary exists to keep the untagged
    // `EnvelopeProofs` union out of a second deserializer's hands, and the
    // CHAIN arm is the one a forged label imitates — so the published
    // `PrincipalSigned` golden must survive the text route with its arm
    // intact. Pins: the export runs under a live interpreter (this is the
    // deployed condition, not a Rust-only path), the round trip is
    // value-lossless, and the two-element chain survives as the chain arm.
    pyo3::Python::attach(|_py| {
      let text = crate::parse_envelope_json(PRINCIPAL_SIGNED_GOLDEN)
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
    });
  }

  #[test]
  fn a_legacy_single_proof_envelope_round_trips_as_json_text() {
    // WHY: the union has two arms and an object route puts BOTH at risk;
    // this pins the other one. A pre-chain envelope (single-object `proof`,
    // no `attestationMode`) must cross the text boundary value-lossless and
    // come back as the single arm — never silently promoted to a chain.
    pyo3::Python::attach(|_py| {
      let text = crate::serialize_envelope(LEGACY_SLACK_REPLY)
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
    });
  }

  #[test]
  fn an_integer_no_double_can_hold_survives_the_text_boundary() {
    // WHY: this is the boundary rule's whole reason, stated as an
    // experiment rather than an assertion. 2^53 + 1 is the smallest positive
    // integer IEEE-754 doubles cannot represent — a Python `float` or a JS
    // `number` rounds it to 2^53 — so a `bodySize` of that value is a
    // tripwire that fires the instant an object round-trip is introduced on
    // either side. Pins: exact u64 fidelity across the text boundary.
    const BEYOND_DOUBLE: u64 = 9_007_199_254_740_993;
    pyo3::Python::attach(|_py| {
      let mut widened: serde_json::Value =
        serde_json::from_str(LEGACY_SLACK_REPLY).expect("the legacy envelope parses as JSON");
      widened["credentialSubject"]["communication"]["bodySize"] =
        serde_json::Value::from(BEYOND_DOUBLE);
      let input = serde_json::to_string(&widened).expect("the widened envelope serializes");
      let text = crate::parse_envelope_json(&input)
        .expect("a u64 bodySize must cross the text boundary");
      let parsed: aph_core::NotarizationEnvelope =
        serde_json::from_str(&text).expect("the re-emitted text strict-parses");
      std::assert_eq!(
        parsed.credential_subject.communication.body_size,
        BEYOND_DOUBLE,
        "an integer beyond double precision must cross without rounding"
      );
    });
  }

  #[test]
  fn the_structure_gate_reads_both_goldens_and_raises_aph_e013_on_a_forged_label() {
    // WHY: `verify_proof_structure` is exported precisely so a Python
    // consumer can detect a forged `PrincipalSigned` label (§7.1.11). Pins
    // the honest readings of both published forms AND the forgery rejection
    // as a PYTHON refusal: the raised object must be `aph.AphError` and
    // `str(e)` must carry `APH_E013`, which is exactly what a `except
    // aph.AphError` / `str(e).startswith(...)` caller matches on — the same
    // identity the JS binding surfaces on its thrown message.
    pyo3::Python::attach(|py| {
      std::assert_eq!(
        crate::verify_proof_structure(PRINCIPAL_SIGNED_GOLDEN)
          .expect("the golden satisfies §7.1.11"),
        "PrincipalSigned"
      );
      std::assert_eq!(
        crate::verify_proof_structure(LEGACY_SLACK_REPLY)
          .expect("a legacy envelope satisfies §7.1.11"),
        "NotaryAttested"
      );
      let mut forged: serde_json::Value =
        serde_json::from_str(LEGACY_SLACK_REPLY).expect("the legacy envelope parses as JSON");
      forged["credentialSubject"]["policy"]["attestationMode"] =
        serde_json::Value::String(std::string::String::from("PrincipalSigned"));
      let forged_text = serde_json::to_string(&forged).expect("the forged envelope serializes");
      let err = crate::verify_proof_structure(&forged_text)
        .expect_err("a PrincipalSigned label above a single proof must be rejected");
      std::assert!(
        err.is_instance_of::<crate::AphError>(py),
        "the refusal must reach Python as aph.AphError"
      );
      let message = err.value(py).to_string();
      std::assert!(
        message.starts_with("APH_E013"),
        "str(e) must lead with the APH_E013 code, got: {}",
        message
      );
    });
  }

  #[test]
  fn requiring_principal_signed_raises_aph_e012_on_the_weaker_mode() {
    // WHY: `require_attestation_mode` is the §8.3.1 step-1a no-downgrade
    // gate; a verifier requiring `PrincipalSigned` MUST refuse
    // `NotaryAttested` rather than silently accept the weaker claim. Pins the
    // refusal (APH_E012 visible in `str(e)` on an `aph.AphError`), both
    // accepting paths, and that an unrecognized mode string raises instead of
    // defaulting — a typo that defaulted weak would BE the downgrade.
    pyo3::Python::attach(|py| {
      crate::require_attestation_mode(PRINCIPAL_SIGNED_GOLDEN, "PrincipalSigned")
        .expect("the golden satisfies a PrincipalSigned-only policy");
      crate::require_attestation_mode(LEGACY_SLACK_REPLY, "NotaryAttested")
        .expect("a legacy envelope satisfies a NotaryAttested requirement");
      let err = crate::require_attestation_mode(LEGACY_SLACK_REPLY, "PrincipalSigned")
        .expect_err("NotaryAttested must not satisfy a PrincipalSigned requirement");
      std::assert!(
        err.is_instance_of::<crate::AphError>(py),
        "the refusal must reach Python as aph.AphError"
      );
      let message = err.value(py).to_string();
      std::assert!(
        message.starts_with("APH_E012"),
        "str(e) must lead with the APH_E012 code, got: {}",
        message
      );
      std::assert!(
        crate::require_attestation_mode(LEGACY_SLACK_REPLY, "Notarized").is_err(),
        "an unknown mode string must raise, never default to a mode"
      );
    });
  }

  #[test]
  fn a_shape_refusal_raises_the_same_exception_without_a_code() {
    // WHY: the module docs promise two refusal shapes on ONE exception type —
    // protocol refusals lead with `APH_E*`, shape refusals carry the serde
    // message — and a caller who catches `aph.AphError` must get both. Pins:
    // an unknown field (the `deny_unknown_fields` rule) raises AphError, and
    // its message is NOT dressed up with a protocol code it did not earn.
    pyo3::Python::attach(|py| {
      let mut smuggled: serde_json::Value =
        serde_json::from_str(LEGACY_SLACK_REPLY).expect("the legacy envelope parses as JSON");
      smuggled["credentialSubject"]["notAField"] = serde_json::Value::Bool(true);
      let smuggled_text = serde_json::to_string(&smuggled).expect("it serializes");
      let err = crate::parse_envelope_json(&smuggled_text)
        .expect_err("an unknown credentialSubject field must be a hard error");
      std::assert!(
        err.is_instance_of::<crate::AphError>(py),
        "a shape refusal must reach Python as aph.AphError too"
      );
      let message = err.value(py).to_string();
      std::assert!(
        !message.starts_with("APH_E"),
        "a shape refusal must not claim a protocol code, got: {}",
        message
      );
    });
  }
}
