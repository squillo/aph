//! The `--json` verdict shape for `aph validate`, and the classification that
//! fills it in.
//!
//! **Why this exists.** `aph validate` has always refused a value outside one
//! of §7.1's closed vocabularies, naming the value and printing the whole set
//! in the same breath. Three separate downstream implementations still asked
//! what an unrecognized value meant, because reading that sentence meant
//! running a command none of them ran. A guarantee only a human at a terminal
//! can reach is not reachable from a build, so this module gives the SAME
//! verdict a machine-readable form a CI gate can branch on. It adds a
//! rendering, never a second decision: the accepted/refused call and the exit
//! code are made once, upstream, and both renderings read it.
//!
//! **What it deliberately does not do.** It never softens a refusal — there is
//! no permissive mode, no downgrade to a warning, and no error code. A
//! closed-vocabulary refusal happens at STRICT PARSE, spec §8.3 step 1, which
//! sits BELOW the protocol's closed `APH_E***` set; naming an `APH_E` code
//! here would invent one the specification does not define, and a consumer
//! that routed on it would be routing on fiction. The report names the LAYER
//! that refused instead.

/// The single JSON object `aph validate --json` writes to stdout.
///
/// **Stability.** This shape is public surface. The fields below keep their
/// names and their meanings; new fields and new `reason` values may be added.
/// A consumer therefore branches on `ok` FIRST and treats an unrecognized
/// `reason` as a refusal — never as a pass.
///
/// Field order here is the order on the wire (serde derive emits declaration
/// order), so the verdict reads left to right in a CI log: what happened,
/// then which envelope or which refusal, then the detail.
#[derive(serde::Serialize)]
pub struct ValidateReport {
  /// The verdict, and the ONE field a consumer must branch on: `true` exactly
  /// when the envelope strict-parsed. It mirrors the process exit code —
  /// `true` is exit 0, `false` is exit 1 — so a gate may read either, and the
  /// two can never disagree because one call produces both.
  pub ok: bool,
  /// The admitted envelope's `id`. Present only when `ok` is `true`.
  #[serde(skip_serializing_if = "std::option::Option::is_none")]
  pub id: std::option::Option<std::string::String>,
  /// The admitted envelope's `issuer` (the notary DID). Present only when
  /// `ok` is `true`.
  #[serde(skip_serializing_if = "std::option::Option::is_none")]
  pub issuer: std::option::Option<std::string::String>,
  /// Which layer refused: `"parse"` for anything the strict parser rejected,
  /// `"io"` when the input could not be read at all. Present only when `ok`
  /// is `false`.
  ///
  /// This field carries the honesty the error taxonomy cannot: there is no
  /// `code` member because §8.3 step 1 is below the closed `APH_E***` set, so
  /// `layer` names where the refusal came from rather than pretending it came
  /// from the protocol's error vocabulary.
  #[serde(skip_serializing_if = "std::option::Option::is_none")]
  pub layer: std::option::Option<&'static str>,
  /// What kind of refusal: `"closed_set"`, `"malformed"`, or `"unreadable"`.
  /// Present only when `ok` is `false`.
  #[serde(skip_serializing_if = "std::option::Option::is_none")]
  pub reason: std::option::Option<&'static str>,
  /// Byte-for-byte the line the same run prints to stderr WITHOUT `--json`.
  /// Present only when `ok` is `false`.
  ///
  /// Carried verbatim rather than reworded so a consumer that logs this
  /// object and a human who ran the plain command are reading the same words,
  /// including the `line`/`column` the strict parser appended.
  #[serde(skip_serializing_if = "std::option::Option::is_none")]
  pub message: std::option::Option<std::string::String>,
  /// Dotted WIRE path of the field whose value is outside its closed set —
  /// camelCase, so it can be pasted into a search of the consumer's own
  /// document. Present only when `reason` is `"closed_set"`.
  #[serde(skip_serializing_if = "std::option::Option::is_none")]
  pub field: std::option::Option<&'static str>,
  /// The offending value exactly as it appeared on the wire. Present only
  /// when `reason` is `"closed_set"`.
  #[serde(skip_serializing_if = "std::option::Option::is_none")]
  pub value: std::option::Option<std::string::String>,
  /// The complete closed set, in spec order. Present only when `reason` is
  /// `"closed_set"`.
  ///
  /// A consumer that reads this never has to hard-code the vocabulary to
  /// produce a useful message, which is the whole point: the set travels with
  /// the refusal that cites it.
  #[serde(skip_serializing_if = "std::option::Option::is_none")]
  pub allowed: std::option::Option<std::vec::Vec<&'static str>>,
}

impl ValidateReport {
  /// The admitted verdict (exit 0), naming WHICH envelope was admitted so a
  /// gate that validates several can tell them apart in its log.
  pub fn accepted(id: &str, issuer: &str) -> Self {
    Self {
      ok: true,
      id: std::option::Option::Some(id.to_string()),
      issuer: std::option::Option::Some(issuer.to_string()),
      layer: std::option::Option::None,
      reason: std::option::Option::None,
      message: std::option::Option::None,
      field: std::option::Option::None,
      value: std::option::Option::None,
      allowed: std::option::Option::None,
    }
  }

  /// The refused verdict (exit 1). `message` is the exact stderr line the
  /// same run produces without `--json`.
  pub fn refused(message: &str, refusal: Refusal) -> Self {
    let (layer, reason) = match refusal {
      Refusal::Unreadable => ("io", "unreadable"),
      Refusal::ClosedSet(_) => ("parse", "closed_set"),
      Refusal::Malformed => ("parse", "malformed"),
    };
    let hit = match refusal {
      Refusal::ClosedSet(hit) => std::option::Option::Some(hit),
      _ => std::option::Option::None,
    };
    Self {
      ok: false,
      id: std::option::Option::None,
      issuer: std::option::Option::None,
      layer: std::option::Option::Some(layer),
      reason: std::option::Option::Some(reason),
      message: std::option::Option::Some(message.to_string()),
      field: hit.as_ref().map(|hit| hit.field),
      value: hit.as_ref().map(|hit| hit.value.clone()),
      allowed: hit.map(|hit| hit.allowed),
    }
  }

  /// Render as ONE line, which is what makes the output pipeable into a
  /// line-oriented tool without a JSON stream reader.
  ///
  /// Serialization cannot fail for this shape — every field is a bool, a
  /// string, or a list of strings, and `serde_json` only refuses a map with
  /// non-string keys or a non-finite float — but a CLI must not panic on an
  /// impossible branch, so the fallback still carries the verdict a gate
  /// reads.
  pub fn render(&self) -> std::string::String {
    match serde_json::to_string(self) {
      std::result::Result::Ok(line) => line,
      std::result::Result::Err(_) => std::format!("{{\"ok\":{}}}", self.ok),
    }
  }
}

/// One closed-vocabulary field caught carrying a value its set does not
/// define, with the set that refused it.
pub struct ClosedSetHit {
  /// Dotted wire path of the field, e.g. `credentialSubject.channel.kind`.
  pub field: &'static str,
  /// The value found there.
  pub value: std::string::String,
  /// Every member of the closed set, in spec order.
  pub allowed: std::vec::Vec<&'static str>,
}

/// Why `validate` refused, at the granularity the report distinguishes.
pub enum Refusal {
  /// The input could not be read at all — no such file, or a broken stdin.
  /// Nothing about an envelope was decided, so this is an I/O-layer failure
  /// and not a verdict on any bytes.
  Unreadable,
  /// A closed vocabulary was handed a value it does not define. This is the
  /// refusal downstream implementations ask about, and the only one that
  /// carries the offending value and the whole allowed set.
  ClosedSet(ClosedSetHit),
  /// Anything else the strict parser refused: JSON that is not JSON, a
  /// missing field, an unknown field, a value of the wrong type.
  Malformed,
}

impl Refusal {
  /// Decide which refusal a strict-parse failure over `raw` was.
  ///
  /// This is a SECOND, lenient pass over the same bytes rather than a read of
  /// the strict parser's message. Parsing an error string would make a stable
  /// machine contract depend on prose that exists to be read by humans and is
  /// free to be reworded; instead the raw document is walked to the fields
  /// whose TYPES close a vocabulary, and each candidate is offered to that
  /// type's own `FromStr`. The allowed set likewise comes from the type's
  /// `ALL` rather than being restated here — one vocabulary, one place, the
  /// same discipline `aph-core` applies to its own serde impls.
  ///
  /// When an envelope is wrong in more than one way, the report's `message`
  /// names the first thing the strict parser reached while `reason` may name
  /// the closed-set value it found here. Both are true and the envelope is
  /// refused either way; the closed-set finding is reported in preference
  /// because it is the one a consumer can act on without reading prose.
  pub fn classify(raw: &str) -> Self {
    let document: serde_json::Value = match serde_json::from_str(raw) {
      std::result::Result::Ok(document) => document,
      // Not even JSON, so no field can be inspected and "malformed" is the
      // only thing that can honestly be said about it.
      std::result::Result::Err(_) => return Self::Malformed,
    };
    let subject = match document.get("credentialSubject") {
      std::option::Option::Some(subject) => subject,
      std::option::Option::None => return Self::Malformed,
    };
    // Checked in wire order, so an envelope wrong in both places reports the
    // one a reader reaches first in their own document. Both allowed sets are
    // spelled out from the owning type's `ALL`, never written out here.
    let channel_allowed: std::vec::Vec<&'static str> = aph_core::envelope::ChannelKind::ALL
      .into_iter()
      .map(|kind| kind.label())
      .collect();
    let channel_kind = out_of_set::<aph_core::envelope::ChannelKind>(
      "credentialSubject.channel.kind",
      subject.get("channel").and_then(|channel| channel.get("kind")),
      &channel_allowed,
    );
    if let std::option::Option::Some(hit) = channel_kind {
      return Self::ClosedSet(hit);
    }
    let content_allowed: std::vec::Vec<&'static str> = aph_core::envelope::ContentClass::ALL
      .into_iter()
      .map(|class| class.label())
      .collect();
    let content_class = out_of_set::<aph_core::envelope::ContentClass>(
      "credentialSubject.communication.contentClass",
      subject
        .get("communication")
        .and_then(|communication| communication.get("contentClass")),
      &content_allowed,
    );
    if let std::option::Option::Some(hit) = content_class {
      return Self::ClosedSet(hit);
    }
    // The §7.1.7 set joined the closure after the first two; a consumer's CI
    // reading `--json` deserves the same precise refusal for it, not
    // "malformed".
    let decision_allowed: std::vec::Vec<&'static str> = aph_core::envelope::PolicyDecision::ALL
      .into_iter()
      .map(|decision| decision.label())
      .collect();
    let decision = out_of_set::<aph_core::envelope::PolicyDecision>(
      "credentialSubject.policy.decision",
      subject.get("policy").and_then(|policy| policy.get("decision")),
      &decision_allowed,
    );
    if let std::option::Option::Some(hit) = decision {
      return Self::ClosedSet(hit);
    }
    Self::Malformed
  }
}

/// Offer one candidate value to a closed type's `FromStr`, and describe the
/// miss when it misses.
///
/// Returns `None` — no finding — when the field is absent or is not a string
/// at all: those are shape failures the strict parser already refuses under
/// its own message, and claiming a closed-set violation for them would report
/// the wrong thing.
fn out_of_set<T: std::str::FromStr>(
  field: &'static str,
  found: std::option::Option<&serde_json::Value>,
  allowed: &[&'static str],
) -> std::option::Option<ClosedSetHit> {
  let text = found?.as_str()?;
  if <T as std::str::FromStr>::from_str(text).is_ok() {
    return std::option::Option::None;
  }
  std::option::Option::Some(ClosedSetHit {
    field,
    value: text.to_string(),
    allowed: allowed.to_vec(),
  })
}

#[cfg(test)]
mod tests {
  /// Take a golden fixture as a LENIENT `Value` and set one member of the
  /// object at `parent` (an RFC 6901 JSON Pointer), so a test can build an
  /// envelope the strict types could never construct. Every negative case
  /// below starts from real published bytes rather than a hand-written stub,
  /// which is what keeps a fixture-shape change from leaving these tests
  /// passing against a document nobody ships.
  fn golden_with(parent: &str, key: &str, value: serde_json::Value) -> std::string::String {
    let mut document: serde_json::Value =
      serde_json::from_str(aph_conformance::golden_envelopes()[0]).unwrap();
    let target = document
      .pointer_mut(parent)
      .unwrap_or_else(|| std::panic!("fixture 1 has no object at {}", parent));
    target[key] = value;
    serde_json::to_string(&document).unwrap()
  }

  #[test]
  fn unknown_channel_kind_is_reported_as_closed_set_with_value_and_set() {
    // THE reason this lane exists. Three downstream implementations asked
    // what an unrecognized channel kind meant; the CLI already refused it but
    // only in prose. This pins that the machine-readable verdict names the
    // refusal by kind, hands back the offending value, and carries the whole
    // closed set — so a consumer can write the message they were asking us
    // for without hard-coding the vocabulary.
    let raw = golden_with(
      "/credentialSubject/channel",
      "kind",
      serde_json::Value::String("carrier_pigeon".to_string()),
    );
    // The premise: these bytes really are refused by the strict parser.
    let strict: std::result::Result<aph_core::envelope::NotarizationEnvelope, _> =
      serde_json::from_str(&raw);
    std::assert!(strict.is_err(), "an out-of-set channel kind must not strict-parse");

    let report = super::ValidateReport::refused("invalid envelope: x", super::Refusal::classify(&raw));
    std::assert!(!report.ok, "an out-of-set value is a refusal");
    std::assert_eq!(report.layer, std::option::Option::Some("parse"));
    std::assert_eq!(report.reason, std::option::Option::Some("closed_set"));
    std::assert_eq!(
      report.field,
      std::option::Option::Some("credentialSubject.channel.kind")
    );
    std::assert_eq!(report.value.as_deref(), std::option::Option::Some("carrier_pigeon"));
    // DERIVED, not restated. A literal list here would be a fourth copy of
    // the vocabulary, and it drifted within hours of being written: this
    // assertion was authored against the seven-member set and `service`
    // landed in the same wave. Deriving means a widening updates the
    // expectation and still proves the report carries the WHOLE set.
    std::assert_eq!(
      report.allowed,
      std::option::Option::Some(
        aph_core::envelope::ChannelKind::ALL
          .iter()
          .map(aph_core::envelope::ChannelKind::label)
          .collect::<std::vec::Vec<&'static str>>()
      )
    );
  }

  #[test]
  fn reported_allowed_set_is_the_type_and_not_a_second_copy() {
    // `aph-core` refuses to restate its wire spellings in serde attributes
    // because a second copy of a vocabulary is free to drift from the first.
    // This report is a third surface that could drift the same way, so it is
    // pinned to `ChannelKind::ALL` itself: adding a channel kind to the enum
    // must change this output with no edit here, and an edit here that
    // disagreed with the enum must fail.
    let raw = golden_with(
      "/credentialSubject/channel",
      "kind",
      serde_json::Value::String("carrier-pigeon".to_string()),
    );
    let expected: std::vec::Vec<&'static str> = aph_core::envelope::ChannelKind::ALL
      .into_iter()
      .map(|kind| kind.label())
      .collect();
    std::assert!(!expected.is_empty(), "an empty set would make this vacuous");
    let report = super::ValidateReport::refused("invalid envelope: x", super::Refusal::classify(&raw));
    std::assert_eq!(report.allowed, std::option::Option::Some(expected));
  }

  #[test]
  fn unknown_content_class_is_reported_as_closed_set() {
    // §7.1.6 is the OTHER closed vocabulary the wire types model, and it is
    // the one a reader forgets. Without this test the report would be correct
    // for channel kinds and silently generic for content classes, which is
    // exactly the asymmetry that sends a fourth report.
    let raw = golden_with(
      "/credentialSubject/communication",
      "contentClass",
      serde_json::Value::String("Shout".to_string()),
    );
    let report = super::ValidateReport::refused("invalid envelope: x", super::Refusal::classify(&raw));
    std::assert_eq!(report.reason, std::option::Option::Some("closed_set"));
    std::assert_eq!(
      report.field,
      std::option::Option::Some("credentialSubject.communication.contentClass")
    );
    std::assert_eq!(report.value.as_deref(), std::option::Option::Some("Shout"));
    // DERIVED for the same reason as its twin above.
    std::assert_eq!(
      report.allowed,
      std::option::Option::Some(
        aph_core::envelope::ContentClass::ALL
          .iter()
          .map(aph_core::envelope::ContentClass::label)
          .collect::<std::vec::Vec<&'static str>>()
      )
    );
  }

  #[test]
  fn broken_json_is_malformed_and_never_closed_set() {
    // The distinction the shape exists to draw. If truncated bytes reported
    // `closed_set`, a consumer would chase a vocabulary problem that is not
    // there — and `value`/`allowed` would have to be invented, which is
    // worse than saying less.
    let raw = aph_conformance::golden_envelopes()[0];
    let truncated = &raw[..raw.len() / 2];
    let report =
      super::ValidateReport::refused("invalid envelope: x", super::Refusal::classify(truncated));
    std::assert_eq!(report.reason, std::option::Option::Some("malformed"));
    std::assert_eq!(report.field, std::option::Option::None);
    std::assert_eq!(report.value, std::option::Option::None);
    std::assert_eq!(report.allowed, std::option::Option::None);
  }

  #[test]
  fn unknown_field_is_malformed_not_closed_set() {
    // The near-miss case: well-formed JSON with every closed vocabulary in
    // range, refused only by `deny_unknown_fields`. The lenient pass must
    // find nothing and say `malformed`, because a report that guessed
    // `closed_set` whenever the strict parse failed would be a coin flip
    // dressed as a diagnosis.
    let raw = golden_with(
      "/credentialSubject",
      "smuggled",
      serde_json::Value::String("claim".to_string()),
    );
    let strict: std::result::Result<aph_core::envelope::NotarizationEnvelope, _> =
      serde_json::from_str(&raw);
    std::assert!(strict.is_err(), "an unknown field must not strict-parse");
    let report = super::ValidateReport::refused("invalid envelope: x", super::Refusal::classify(&raw));
    std::assert_eq!(report.reason, std::option::Option::Some("malformed"));
  }

  #[test]
  fn unreadable_input_reports_the_io_layer() {
    // A missing file is not a statement about any envelope. Reporting it as
    // a parse refusal would tell a gate that bytes were examined and found
    // wanting when none were ever read.
    let report =
      super::ValidateReport::refused("invalid envelope: cannot read x", super::Refusal::Unreadable);
    std::assert_eq!(report.layer, std::option::Option::Some("io"));
    std::assert_eq!(report.reason, std::option::Option::Some("unreadable"));
  }

  #[test]
  fn every_golden_fixture_renders_the_accepted_shape() {
    // The positive half of the contract, over the whole published corpus: an
    // admitted envelope renders one line carrying `"ok":true` plus the two
    // identifying fields and NONE of the refusal fields. A report that leaked
    // a `reason` onto a pass would break every consumer branching on `ok`.
    for raw in aph_conformance::golden_envelopes() {
      let envelope: aph_core::envelope::NotarizationEnvelope = serde_json::from_str(raw).unwrap();
      let line = super::ValidateReport::accepted(&envelope.id, &envelope.issuer).render();
      std::assert!(line.starts_with("{\"ok\":true,"), "unexpected shape: {}", line);
      std::assert!(!line.contains("\"reason\""), "pass must carry no reason: {}", line);
      std::assert!(!line.contains("\"layer\""), "pass must carry no layer: {}", line);
      std::assert!(line.contains(&envelope.id), "pass must name the envelope: {}", line);
      std::assert!(!line.contains('\n'), "the report is one line: {}", line);
    }
  }

  #[test]
  fn rendered_refusal_is_one_line_and_omits_absent_fields() {
    // Pins the two properties a shell gate depends on: the object is a single
    // line, so it survives `$(...)` and a line-oriented log, and absent
    // members are omitted rather than emitted as `null` — `jq -r .field` on a
    // malformed verdict must say `null`, not a quoted empty string that reads
    // like a real path.
    let raw = aph_conformance::golden_envelopes()[0];
    let line = super::ValidateReport::refused(
      "invalid envelope: expected value at line 1 column 1",
      super::Refusal::classify(&raw[..4]),
    )
    .render();
    std::assert!(!line.contains('\n'), "the report is one line: {}", line);
    std::assert!(line.starts_with("{\"ok\":false,"), "unexpected shape: {}", line);
    std::assert!(!line.contains("\"id\""), "refusal carries no id: {}", line);
    std::assert!(!line.contains("\"allowed\""), "malformed carries no set: {}", line);
    std::assert!(line.contains("\"message\":\"invalid envelope: "), "message verbatim: {}", line);
  }
}
