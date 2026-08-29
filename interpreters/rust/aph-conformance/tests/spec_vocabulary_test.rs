//! The normative specification as a POPULATOR of the closed §7.1 vocabularies.
//!
//! Three artifacts declare the same two closed sets: the specification, the
//! Rust types in `aph-core`, and the N Lang types in the compiled Snapp
//! bundle. `nlang_snapp_test.rs` welds the second to the third. This file
//! welds the FIRST to the second, which until now was welded to nothing —
//! the spec's enum tables were prose, and prose drifts without an alarm.
//!
//! Why that gap is worth an alarm: the spec is what an implementer BUILDS
//! FROM. A widening that moved the type but not the table publishes a kind
//! no implementer can learn about; a widening that moved the table but not
//! the type publishes a kind the reference refuses. Both surface as the same
//! field report — a good-faith implementation emitting a value the reference
//! rejects — which is the report `rfcs/0004-vendor-extension-channel-kind.md`
//! was opened on.
//!
//! And the specification restates each vocabulary TWICE: once in the mandate
//! tables (§6.2) and once in the envelope tables (§7.1.5, §7.1.6). Every
//! restatement is checked, not just the envelope one, because the §6.2
//! content-class row carries an erratum recording that this exact drift has
//! already happened once — that row read "etc." while §7.1.6 was closed, so
//! two conformant notaries could have emitted values the other rejected.
//!
//! ZERO `#[ignore]`.

/// Repository root, three levels up from this crate.
fn repo_root() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// The normative specification's text.
fn spec_markdown() -> String {
  let path = repo_root().join("spec/aph-0.1.md");
  std::fs::read_to_string(&path).unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e))
}

/// One section's body: every line after `heading`, up to the next line that
/// opens a heading of any level.
///
/// Anchored on the heading text rather than a line number, so an edit
/// elsewhere in the document cannot silently re-point these tests at a
/// different table. If the heading is renumbered the lookup panics, which is
/// the correct outcome: someone must decide where the vocabulary now lives.
fn spec_section(spec: &str, heading: &str) -> String {
  let start = spec
    .lines()
    .position(|line| line.starts_with(heading))
    .unwrap_or_else(|| std::panic!("the spec has no section opening `{}`", heading));
  spec
    .lines()
    .skip(start + 1)
    .take_while(|line| !line.starts_with('#'))
    .collect::<std::vec::Vec<&str>>()
    .join("\n")
}

/// The field-definition table row for `field` within `section`.
fn table_row(section: &str, field: &str) -> String {
  let opener = std::format!("| `{}` |", field);
  section
    .lines()
    .find(|line| line.starts_with(opener.as_str()))
    .map(String::from)
    .unwrap_or_else(|| std::panic!("no table row defines `{}` in this section", field))
}

/// The backticked members of the comma-separated run that begins at `marker`.
///
/// The run is delimited deliberately rather than by taking every backticked
/// token in the row: only `, ` may separate two members, and only whitespace
/// may sit between the marker and the first one. Prose resumes where that
/// pattern breaks, and prose after the list is where the ERRATA live —
/// §7.1.5's erratum quotes the retired `googleChat` spelling in backticks, so
/// a looser reader would enrol a value the wire has never carried.
fn enumerated_labels(row: &str, marker: &str) -> std::vec::Vec<String> {
  let start = row
    .find(marker)
    .unwrap_or_else(|| std::panic!("the row no longer contains `{}`:\n{}", marker, row))
    + marker.len();
  let mut rest = &row[start..];
  let mut labels: std::vec::Vec<String> = std::vec::Vec::new();

  loop {
    let open = match rest.find('`') {
      std::option::Option::Some(index) => index,
      std::option::Option::None => break,
    };
    let gap = &rest[..open];
    let run_ended = if labels.is_empty() {
      !gap.trim().is_empty()
    } else {
      gap != ", "
    };
    if run_ended {
      break;
    }
    let after_open = &rest[open + 1..];
    let close = after_open
      .find('`')
      .unwrap_or_else(|| std::panic!("unterminated backtick after `{}`:\n{}", marker, row));
    labels.push(String::from(&after_open[..close]));
    rest = &after_open[close + 1..];
  }

  std::assert!(
    !labels.is_empty(),
    "no enumerated members follow `{}`; the row has been rewritten:\n{}",
    marker,
    row
  );
  labels
}

/// One place the specification writes a closed vocabulary out in full.
struct Restatement {
  /// Opening text of the heading whose section holds the row.
  heading: &'static str,
  /// The row's field, in its wire spelling.
  field: &'static str,
  /// The text immediately preceding the first member.
  marker: &'static str,
  /// How this site is named when an assertion fails.
  cite: &'static str,
}

impl Restatement {
  fn labels(&self, spec: &str) -> std::vec::Vec<String> {
    let section = spec_section(spec, self.heading);
    let row = table_row(&section, self.field);
    enumerated_labels(&row, self.marker)
  }
}

/// Both places the spec enumerates the channel kinds. §7.1.5 is the
/// definition; §6.2 restates it for the notarization request.
const CHANNEL_KIND_SITES: [Restatement; 2] = [
  Restatement {
    heading: "#### 7.1.5 ",
    field: "kind",
    marker: "enum values:",
    cite: "§7.1.5 `ChannelDescriptor.kind`",
  },
  Restatement {
    heading: "### 6.2 ",
    field: "channelKind",
    marker: "Channel kind (",
    cite: "§6.2 `CommunicationMandate.channelKind`",
  },
];

/// Both places the spec enumerates the content classes.
const CONTENT_CLASS_SITES: [Restatement; 2] = [
  Restatement {
    heading: "#### 7.1.6 ",
    field: "contentClass",
    marker: "Closed enum:",
    cite: "§7.1.6 `CommunicationDescriptor.contentClass`",
  },
  Restatement {
    heading: "### 6.2 ",
    field: "contentClass",
    marker: "(§7.1.6):",
    cite: "§6.2 `CommunicationMandate.contentClass`",
  },
];

/// Both places the spec enumerates the policy decisions. §7.1.7 defines;
/// §6.2 restates for the communication mandate. This vocabulary joined the
/// welds late — an audit found the reference validating it nowhere while
/// the spec and the independent implementation both closed it — so it gets
/// the same two-site membership check its older siblings have.
const POLICY_DECISION_SITES: [Restatement; 2] = [
  Restatement {
    heading: "#### 7.1.7 ",
    field: "decision",
    marker: "Closed enum:",
    cite: "§7.1.7 `PolicyDescriptor.decision`",
  },
  Restatement {
    heading: "### 6.2 ",
    field: "policyDecision",
    marker: "produced this mandate:",
    cite: "§6.2 `CommunicationMandate.policyDecision`",
  },
];

/// Both places the spec enumerates the recipient classes (RFC 0005): §7.1.5
/// defines the axis on the channel block; §6.1 restates it as the mandate
/// constraint. Welded from the day the vocabulary was born.
const RECIPIENT_CLASS_SITES: [Restatement; 2] = [
  Restatement {
    heading: "#### 7.1.5 ",
    field: "recipientClass",
    marker: "the closed set ",
    cite: "§7.1.5 `ChannelDescriptor.recipientClass`",
  },
  Restatement {
    heading: "### 6.1 ",
    field: "allowedRecipientClasses",
    marker: "the closed set ",
    cite: "§6.1 `DelegationMandate.allowedRecipientClasses`",
  },
];

/// Compares one restatement's members against the reference type's, in both
/// directions, and reports each direction as the distinct defect it is.
fn assert_membership_matches(site: &Restatement, spec: &str, reference: &[&'static str]) {
  let listed = site.labels(spec);

  let missing_from_spec: std::vec::Vec<&str> = reference
    .iter()
    .copied()
    .filter(|label| !listed.iter().any(|written| written == label))
    .collect();
  std::assert!(
    missing_from_spec.is_empty(),
    "{} does not list values the reference type declares: {:?}\n\
     A verifier accepts these and the specification never published them. Widen \
     the table in the SAME change that widened the type.",
    site.cite,
    missing_from_spec
  );

  let unknown_to_the_reference: std::vec::Vec<&String> = listed
    .iter()
    .filter(|written| !reference.contains(&written.as_str()))
    .collect();
  std::assert!(
    unknown_to_the_reference.is_empty(),
    "{} lists values the reference type does not declare: {:?}\n\
     An implementer building from the specification would emit these and the \
     reference would refuse them at strict parse.",
    site.cite,
    unknown_to_the_reference
  );
}

#[test]
fn the_spec_and_the_reference_agree_on_the_channel_kind_vocabulary() {
  // WHY THIS EXISTS. `nlang_snapp_test.rs` welds the Rust type to the Snapp,
  // so those two populators of the closed channel-kind set cannot part
  // company. The THIRD populator is the specification itself, and nothing
  // read it — the seven values existed in the §7.1.5 table as prose, checked
  // by no one, in the document every independent implementation is written
  // from.
  //
  // WHAT IT PINS. Membership, in both directions, at every site where the
  // spec writes the set out: add a variant to `ChannelKind::ALL` without
  // widening §7.1.5 AND §6.2 and this goes red, and so does removing a value
  // from either table. The ordering matters here too — RFC 0002 proposes a
  // `service` kind, so the next widening is already drafted, and it must
  // move all three populators or move none.
  let spec = spec_markdown();
  let reference: std::vec::Vec<&'static str> = aph_core::ChannelKind::ALL
    .iter()
    .map(aph_core::ChannelKind::label)
    .collect();
  for site in CHANNEL_KIND_SITES.iter() {
    assert_membership_matches(site, &spec, &reference);
  }
}

#[test]
fn the_spec_and_the_reference_agree_on_the_content_class_vocabulary() {
  // The twin of the channel-kind pin above; see it for the full reasoning.
  // This set has the sharper history: the §6.2 row's own erratum records that
  // it once read "etc." while §7.1.6 was closed, which left a required,
  // SIGNED field open in one table and shut in the other. That is precisely
  // the failure this test now makes unconstructible, and it is why both
  // restatements are checked rather than only the defining one.
  let spec = spec_markdown();
  let reference: std::vec::Vec<&'static str> = aph_core::ContentClass::ALL
    .iter()
    .map(aph_core::ContentClass::label)
    .collect();
  for site in CONTENT_CLASS_SITES.iter() {
    assert_membership_matches(site, &spec, &reference);
  }
}

#[test]
fn the_reference_lists_channel_kinds_in_the_order_the_spec_writes_them() {
  // WHY THIS EXISTS. `ChannelKind::ALL` documents itself as "in §7.1.5
  // order" and as "the ONE enumerable other surfaces (docs, tests, bindings)
  // derive from". Surfaces that derive POSITION from it — the Snapp assigns
  // u8 discriminants, and those are wire-adjacent — inherit that order
  // whether or not the claim is still true. Membership alone cannot catch a
  // reorder, so the claim would otherwise be an unchecked comment.
  //
  // WHAT IT PINS. Reorder the §7.1.5 table without reordering `ALL`, or the
  // reverse, and this goes red. Only the DEFINING site is order-normative:
  // §6.2 restates the set and claims nothing about sequence, so it is
  // deliberately left to the membership test above.
  let spec = spec_markdown();
  let listed = CHANNEL_KIND_SITES[0].labels(&spec);
  let reference: std::vec::Vec<&'static str> = aph_core::ChannelKind::ALL
    .iter()
    .map(aph_core::ChannelKind::label)
    .collect();
  std::assert_eq!(
    listed, reference,
    "`ChannelKind::ALL` documents itself as being in §7.1.5 order; it is not"
  );
}

#[test]
fn the_reference_lists_content_classes_in_the_order_the_spec_writes_them() {
  // The twin of the order pin above. `ContentClass::ALL` carries the same
  // "in §7.1.6 order" claim, and the same positional consumers derive from
  // it, so the same reorder would go unnoticed by a membership check alone.
  let spec = spec_markdown();
  let listed = CONTENT_CLASS_SITES[0].labels(&spec);
  let reference: std::vec::Vec<&'static str> = aph_core::ContentClass::ALL
    .iter()
    .map(aph_core::ContentClass::label)
    .collect();
  std::assert_eq!(
    listed, reference,
    "`ContentClass::ALL` documents itself as being in §7.1.6 order; it is not"
  );
}

#[test]
fn the_spec_and_the_reference_agree_on_the_policy_decision_vocabulary() {
  // Same membership weld as its siblings, both spec sites, both directions.
  let spec = spec_markdown();
  let reference: std::vec::Vec<&'static str> = aph_core::PolicyDecision::ALL
    .iter()
    .map(aph_core::PolicyDecision::label)
    .collect();
  for site in &POLICY_DECISION_SITES {
    assert_membership_matches(site, &spec, &reference);
  }
}

#[test]
fn the_spec_and_the_reference_agree_on_the_recipient_classes() {
  // Same two-site membership weld as every closed vocabulary above; this
  // one was born welded (RFC 0005) instead of joining late after an audit.
  let spec = spec_markdown();
  let reference: std::vec::Vec<&'static str> = aph_core::RecipientClass::ALL
    .iter()
    .map(aph_core::RecipientClass::label)
    .collect();
  for site in &RECIPIENT_CLASS_SITES {
    assert_membership_matches(site, &spec, &reference);
  }
}
