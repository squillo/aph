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
/// Whether a Delegation Mandate (given as JSON text) is valid at `at`
/// (RFC 3339), per the mandate's own `validFrom`/`validUntil` window.
///
/// The semantics are `aph-core`'s, verbatim: an unparseable timestamp — in
/// the argument OR in the mandate — yields `False`, never an exception,
/// because the core documents "parsing failure returns false" and a binding
/// that invented stricter semantics would be a SECOND definition of one
/// check. What IS refused (`AphError`) is a mandate that does not
/// strict-parse: that is the JSON boundary's job in every export here.
#[pyo3::pyfunction]
pub fn mandate_is_valid_at(mandate_json: &str, at: &str) -> pyo3::PyResult<bool> {
  let mandate: aph_core::DelegationMandate =
    serde_json::from_str(mandate_json).map_err(|e| AphError::new_err(std::format!("{}", e)))?;
  std::result::Result::Ok(mandate.is_valid_at(at))
}

/// Verify the §7.1.7.1 binding between an envelope (given as JSON text) and
/// the Delegation Mandate embedded at `policy.delegationMandate`: the three
/// identity equalities, the window, and the mandate's own signatures'
/// presence rules — everything `aph-core`'s check performs, nothing more.
///
/// An envelope with NO embedded mandate returns without raising, exactly as
/// the core does: absence of the optional block is not a binding failure.
/// Raises `AphError` (code included in the text) on any violation.
#[pyo3::pyfunction]
pub fn verify_embedded_mandate_binding(json: &str) -> pyo3::PyResult<()> {
  let envelope = parse_envelope(json).map_err(AphError::new_err)?;
  aph_core::verify_embedded_mandate_binding(&envelope)
    .map_err(|e| AphError::new_err(std::format!("{}", e)))
}

#[pyo3::pymodule]
mod aph {
  // `#[pymodule_export]` is the declarative module macro's own syntax for
  // naming an item's Python export; it is consumed by the outer `#[pymodule]`
  // expansion, so these `use` lines are macro input, not imports the code
  // dispatches through.
  #[pymodule_export]
  use super::AphError;
  #[pymodule_export]
  use super::mandate_is_valid_at;
  #[pymodule_export]
  use super::parse_envelope_json;
  #[pymodule_export]
  use super::require_attestation_mode;
  #[pymodule_export]
  use super::serialize_envelope;
  #[pymodule_export]
  use super::verify_embedded_mandate_binding;
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

  #[test]
  fn a_closed_set_value_this_build_does_not_define_raises_with_the_value_in_the_message() {
    // WHY: §7.1.5 and §7.1.6 close the channel and content-class vocabularies,
    // and `aph-core` models them as closed TYPES — so an unrecognized value is
    // a strict-parse refusal (§8.3 step 1) rather than a string that rides
    // through. What needs a test is the HOP: the refusal is produced inside
    // `serde_json` as a custom error, stringified with `format!("{}", e)` and
    // then wrapped in `AphError`, and nothing but this says whether the
    // offending value and the closed set survive into `str(e)`. A message
    // flattened to "invalid value" would still refuse and still be useless to
    // the producer who has to fix it.
    //
    // PINS, per field: the refusal reaches Python as `aph.AphError`; the
    // offending VALUE survives; the closed SET survives, including the
    // irregular spellings a producer most plausibly gets wrong; and `str(e)`
    // claims NO `APH_E` code, because §8.3 step 1 is the layer below the
    // taxonomy — the same two-shape distinction the module docs promise.
    pyo3::Python::attach(|py| {
      for (pointer, offending, member) in [
        (["credentialSubject", "channel", "kind"], "carrier_pigeon", "google_chat"),
        (["credentialSubject", "policy", "decision"], "Sometimes", "NeverAllow"),
        (
          ["credentialSubject", "communication", "contentClass"],
          "Digest",
          "BulkSend",
        ),
      ] {
        let mut document: serde_json::Value =
          serde_json::from_str(LEGACY_SLACK_REPLY).expect("the legacy envelope parses as JSON");
        document[pointer[0]][pointer[1]][pointer[2]] =
          serde_json::Value::String(std::string::String::from(offending));
        let text = serde_json::to_string(&document).expect("the edited envelope serializes");
        let err = crate::parse_envelope_json(&text)
          .expect_err("a value outside the closed set must be refused, never carried");
        std::assert!(
          err.is_instance_of::<crate::AphError>(py),
          "the refusal must reach Python as aph.AphError"
        );
        let message = err.value(py).to_string();
        std::assert!(
          message.contains(offending),
          "str(e) must name the offending value `{}`, got: {}",
          offending,
          message
        );
        std::assert!(
          message.contains("closed set") && message.contains(member),
          "str(e) must name the closed set (including `{}`), got: {}",
          member,
          message
        );
        std::assert!(
          !message.starts_with("APH_E"),
          "a strict-parse refusal must not claim a protocol code, got: {}",
          message
        );
      }
    });
  }

  /// The published corpus directory, resolved at RUNTIME.
  ///
  /// This crate sits at `interpreters/rust/aph-py`, so the examples are three
  /// levels up from the manifest directory — one level shallower than the
  /// `include_str!` paths above, which resolve relative to this SOURCE FILE
  /// rather than to the crate root.
  fn examples_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples")
  }

  /// The corpus INVENTORY, which is not itself a vector — see the test below.
  const MANIFEST_FILE: &str = "manifest.json";

  /// Every top-level `*.json` in the corpus, enumerated from disk and sorted,
  /// with the inventory itself skipped by name.
  fn example_json_names() -> std::collections::BTreeSet<std::string::String> {
    let dir = examples_dir();
    let entries = std::fs::read_dir(&dir)
      .unwrap_or_else(|error| std::panic!("could not read {}: {}", dir.display(), error));
    let mut names: std::collections::BTreeSet<std::string::String> =
      std::collections::BTreeSet::new();
    for entry in entries {
      let entry =
        entry.unwrap_or_else(|error| std::panic!("could not read a corpus entry: {error}"));
      let path = entry.path();
      if path.extension().and_then(std::ffi::OsStr::to_str)
        != std::option::Option::Some("json")
      {
        continue;
      }
      let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_else(|| std::panic!("a corpus path has no file name: {}", path.display()))
        .to_string();
      if name == MANIFEST_FILE {
        continue;
      }
      names.insert(name);
    }
    names
  }


  #[test]
  fn the_goldens_embedded_mandate_answers_validity_at_both_sides_of_its_window() {
    // WHY: `mandate_is_valid_at` is one of the two verification exports the
    // parity contract owes every binding; inputs DERIVED from the published
    // golden — the embedded mandate, and timestamps inside/after its own
    // window — so nothing asserts a fact the corpus does not carry.
    // PINS: true inside; false after; false for garbage time (the core's
    // documented "parsing failure returns false", delegated not re-invented);
    // AphError for a mandate that is not JSON.
    let envelope: serde_json::Value =
      serde_json::from_str(PRINCIPAL_SIGNED_GOLDEN).expect("the golden parses as JSON");
    let mandate =
      serde_json::to_string(&envelope["credentialSubject"]["policy"]["delegationMandate"])
        .expect("the embedded mandate serializes");
    std::assert!(super::mandate_is_valid_at(&mandate, "2026-05-21T12:00:00Z").expect("ok"));
    std::assert!(!super::mandate_is_valid_at(&mandate, "2026-06-01T00:00:00Z").expect("ok"));
    std::assert!(!super::mandate_is_valid_at(&mandate, "not-a-timestamp").expect("ok"));
    std::assert!(super::mandate_is_valid_at("{not json", "2026-05-21T12:00:00Z").is_err());
  }

  #[test]
  fn the_goldens_mandate_binding_verifies_and_a_broken_binding_refuses() {
    // WHY: the other owed verification export. Admit half runs the WHOLE
    // core check on the published golden; the refusal retargets the embedded
    // mandate's `agentDid` so one §7.1.7.1 identity equality fails and
    // nothing else moves.
    super::verify_embedded_mandate_binding(PRINCIPAL_SIGNED_GOLDEN)
      .expect("the published golden's embedded mandate binds");
    let mut envelope: serde_json::Value =
      serde_json::from_str(PRINCIPAL_SIGNED_GOLDEN).expect("the golden parses as JSON");
    envelope["credentialSubject"]["policy"]["delegationMandate"]["agentDid"] =
      serde_json::Value::String(std::string::String::from("did:web:other-agent.example"));
    let broken = serde_json::to_string(&envelope).expect("it serializes");
    std::assert!(
      super::verify_embedded_mandate_binding(&broken).is_err(),
      "a retargeted mandate must refuse to bind"
    );
  }

  #[test]
  fn every_conformance_file_strict_parses_through_this_binding() {
    // WHY: the set-equality test above compares NAMES, and an audit found
    // that name-level inventory was this binding's ONLY runtime view of the
    // corpus — a golden carrying a NEW FIELD would pass inventory without
    // this boundary ever parsing the field. The Go binding's twin of this
    // gate had exactly that hole, and the throwaway probe that covered it
    // was, by definition, not standing coverage.
    //
    // PINS: every conformance entry strict-parses AND round-trips through
    // this binding's own entry function, so every FUTURE golden exercises
    // the boundary the day it lands, with nobody remembering to add a test.
    let manifest_path = examples_dir().join(MANIFEST_FILE);
    let raw = std::fs::read_to_string(&manifest_path)
      .unwrap_or_else(|e| std::panic!("could not read {}: {}", manifest_path.display(), e));
    let manifest: serde_json::Value = serde_json::from_str(&raw)
      .unwrap_or_else(|e| std::panic!("the corpus manifest is not valid JSON: {e}"));
    for entry in manifest
      .get("conformance")
      .and_then(serde_json::Value::as_array)
      .unwrap_or_else(|| std::panic!("the corpus manifest has no `conformance` array"))
    {
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

  #[test]
  fn the_corpus_on_disk_is_exactly_the_corpus_the_manifest_claims() {
    // WHY: the two fixtures above are embedded at COMPILE TIME, which is right
    // for a deep test — the bytes under assertion are the bytes the repository
    // publishes, welded in — and wrong as the crate's only view of the corpus.
    // `include_str!` names two files and can never see a third, so a
    // vocabulary change could land in `examples/` and this crate would compile
    // and pass having never opened it. A count would not have helped either: a
    // floor of "at least twelve" passes forever, and swapping one file for
    // another leaves a count unmoved.
    //
    // PINS: SET EQUALITY in BOTH directions, read at RUNTIME, between the
    // conformance list in `examples/manifest.json` and the top-level `*.json`
    // files on disk. A file on disk with no manifest entry fails and names
    // itself — the direction that catches a vector nobody classified. A
    // manifest entry with no file fails too, which catches a deletion or a
    // rename that a one-directional check reads as "fewer files, still above
    // the floor". Also pins that the two embedded fixtures are members of that
    // declared set, so the compile-time names and the runtime inventory cannot
    // drift apart.
    let manifest_path = examples_dir().join(MANIFEST_FILE);
    let raw = std::fs::read_to_string(&manifest_path).unwrap_or_else(|error| {
      std::panic!(
        "could not read the corpus manifest {}: {}",
        manifest_path.display(),
        error
      )
    });
    let manifest: serde_json::Value = serde_json::from_str(&raw)
      .unwrap_or_else(|error| std::panic!("the corpus manifest is not valid JSON: {error}"));
    let claimed: std::collections::BTreeSet<std::string::String> = manifest
      .get("conformance")
      .and_then(serde_json::Value::as_array)
      .unwrap_or_else(|| std::panic!("the corpus manifest has no `conformance` array"))
      .iter()
      .map(|entry| {
        entry
          .as_str()
          .unwrap_or_else(|| std::panic!("a `conformance` entry is not a string"))
          .to_string()
      })
      .collect();
    // An empty inventory would make every comparison below pass by comparing
    // nothing against nothing, which is the failure mode this test exists to
    // end rather than reproduce.
    std::assert!(
      !claimed.is_empty(),
      "the corpus manifest claims no conformance files"
    );

    let on_disk = example_json_names();
    let undeclared: std::vec::Vec<&std::string::String> =
      on_disk.difference(&claimed).collect();
    std::assert!(
      undeclared.is_empty(),
      "these files are in {} with no entry in {}: {:?}",
      examples_dir().display(),
      MANIFEST_FILE,
      undeclared
    );
    let missing: std::vec::Vec<&std::string::String> = claimed.difference(&on_disk).collect();
    std::assert!(
      missing.is_empty(),
      "{} claims these files that are not on disk: {:?}",
      MANIFEST_FILE,
      missing
    );

    for embedded in [
      "principal_signed_envelope.json",
      "slack_reply_envelope.json",
    ] {
      std::assert!(
        claimed.contains(embedded),
        "{embedded} is embedded by name in this crate and is not in the conformance manifest"
      );
    }
  }

  #[test]
  fn every_excluded_corpus_file_is_on_disk_and_says_why_it_is_excluded() {
    // WHY: the excluded list is the half of the inventory that rots quietly. A
    // conformance claim that silently covered a deliberately non-conformant
    // document would be false, and an exclusion naming a file nobody can find
    // any more is an exclusion for something that stopped existing.
    //
    // PINS: every excluded path resolves on disk, and every one carries a
    // non-empty reason — an exclusion with no stated reason is one the next
    // reader cannot tell from an oversight.
    let raw = std::fs::read_to_string(examples_dir().join(MANIFEST_FILE))
      .unwrap_or_else(|error| std::panic!("could not read the corpus manifest: {error}"));
    let manifest: serde_json::Value = serde_json::from_str(&raw)
      .unwrap_or_else(|error| std::panic!("the corpus manifest is not valid JSON: {error}"));
    let excluded = manifest
      .get("excluded")
      .and_then(serde_json::Value::as_array)
      .unwrap_or_else(|| std::panic!("the corpus manifest has no `excluded` array"));
    for entry in excluded {
      let path = entry
        .get("path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| std::panic!("an `excluded` entry carries no `path`"));
      let reason = entry
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| std::panic!("{path} is excluded with no `reason`"));
      std::assert!(
        !reason.trim().is_empty(),
        "{path} is excluded with an empty reason"
      );
      let resolved = examples_dir().join(path);
      std::assert!(
        resolved.exists(),
        "{path} is excluded in {} and is not on disk at {}",
        MANIFEST_FILE,
        resolved.display()
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
