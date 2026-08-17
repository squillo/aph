//! WHY THIS FILE EXISTS: RFC 8785 §3.2.2.3 does not define number
//! serialization — it defers to ECMAScript `Number::toString`. That makes the
//! bytes an APH signature covers a function of the ECMAScript implementation
//! the canonicalizer runs on, and a suite that exercises one implementation
//! cannot tell a correct canonicalizer from one that has inherited a
//! host-specific assumption. This file runs the SAME COMPILED JavaScript the
//! node suite runs, over the SAME expectation table, under an independently
//! written engine — which is the only place that class of defect shows up
//! before a stranger's browser finds it.
//!
//! WHAT IT PINS: that every row of
//! `interpreters/typescript/testkit/jcs_vectors.json` produces byte-identical
//! canonical text under the second engine, including the float-formatting edge
//! set the table carries for this purpose (integer-valued doubles, both zeroes,
//! both exponent boundaries, and the 2^53 neighbourhood); and that every
//! non-finite row is REFUSED rather than coerced, under the second engine too.
//!
//! HOW A FAILURE READS: a divergence is collected, not thrown on sight, so one
//! run reports every disagreeing row with both outputs side by side. An engine
//! delta is a conformance finding about the TypeScript — an accidental
//! host-ism — and is never to be papered over with a per-engine branch. If the
//! pinned engine is itself provably nonconformant on a row, skip that row with
//! a citation to the engine's own issue; never silently.

/// Renders one row's disagreement with everything a reader needs to act on it.
fn divergence(
  row_name: &str,
  pins: &str,
  input: &str,
  expected: &str,
  actual: &str,
) -> std::string::String {
  std::format!(
    "  row: {row_name}\n    pins:         {pins}\n    input JSON:   {input}\n\
     \x20   table says:   {expected}\n    engine gives: {actual}\n"
  )
}

#[test]
fn the_shared_table_is_populated_and_every_row_is_distinct() {
  // Guards against a vacuous run two ways. A table that failed to load would
  // iterate zero rows in the tests below and pass while proving nothing; and
  // two rows sharing a name would let a regression hide behind its twin, since
  // results are matched back to rows by name.
  let (table, _text) = aph_js_harness::shared_jcs_table();
  std::assert!(
    !table.canonicalize.is_empty(),
    "the canonicalize section of the shared table is empty"
  );
  std::assert!(
    !table.refuse.is_empty(),
    "the refuse section of the shared table is empty"
  );

  let mut names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
  let mut total = 0usize;
  for name in table
    .canonicalize
    .iter()
    .map(|row| row.name.as_str())
    .chain(table.refuse.iter().map(|row| row.name.as_str()))
  {
    names.insert(name);
    total += 1;
  }
  std::assert_eq!(
    names.len(),
    total,
    "two rows in the shared table share a name"
  );
}

#[test]
fn every_shared_vector_canonicalizes_identically_under_the_second_engine() {
  let (table, text) = aph_js_harness::shared_jcs_table();
  let mut engine = aph_js_harness::Engine::boot();
  // The table's own TEXT crosses, unmodified. Re-encoding it here would make
  // this test assert something about a table neither suite reads.
  let results: std::vec::Vec<aph_js_harness::CaseResult> =
    engine.call_json("canonicalizeCases", &text);

  std::assert_eq!(
    results.len(),
    table.canonicalize.len(),
    "the second engine answered for a different number of rows than the table holds"
  );

  let mut divergences: std::vec::Vec<std::string::String> = std::vec::Vec::new();
  for (row, result) in table.canonicalize.iter().zip(results.iter()) {
    // Matched by NAME rather than trusted by position: a driver that dropped a
    // row would otherwise shift every later comparison onto the wrong
    // expectation and report a wall of failures with no real one among them.
    std::assert_eq!(
      result.name, row.name,
      "the second engine's answers came back out of order"
    );

    match (&result.canonical, &result.threw) {
      (std::option::Option::Some(actual), _) if *actual == row.canonical => {}
      (std::option::Option::Some(actual), _) => {
        divergences.push(divergence(&row.name, &row.pins, &row.json, &row.canonical, actual));
      }
      (std::option::Option::None, std::option::Option::Some(threw)) => {
        divergences.push(divergence(
          &row.name,
          &row.pins,
          &row.json,
          &row.canonical,
          &std::format!("REFUSED with {}: {}", threw.name, threw.message),
        ));
      }
      (std::option::Option::None, std::option::Option::None) => {
        divergences.push(divergence(
          &row.name,
          &row.pins,
          &row.json,
          &row.canonical,
          "nothing — the driver returned neither a result nor a refusal",
        ));
      }
    }
  }

  std::assert!(
    divergences.is_empty(),
    "\nTWO ENGINES DISAGREE about RFC 8785 canonical bytes.\n\n\
     Each row below is asserted under the node suite and produced a different answer here, \
     over the SAME compiled JavaScript. Treat it as a conformance finding about the \
     canonicalizer — an assumption it inherited from one host — unless the pinned engine is \
     provably nonconformant, in which case skip the row with a citation to that engine's \
     issue. Do NOT branch on the engine.\n\n{}",
    divergences.join("")
  );
}

#[test]
fn every_non_finite_row_is_refused_under_the_second_engine() {
  let (table, text) = aph_js_harness::shared_jcs_table();
  let mut engine = aph_js_harness::Engine::boot();
  let results: std::vec::Vec<aph_js_harness::CaseResult> = engine.call_json("refuseCases", &text);

  std::assert_eq!(
    results.len(),
    table.refuse.len(),
    "the second engine answered for a different number of refusal rows than the table holds"
  );

  let mut divergences: std::vec::Vec<std::string::String> = std::vec::Vec::new();
  for (row, result) in table.refuse.iter().zip(results.iter()) {
    std::assert_eq!(
      result.name, row.name,
      "the second engine's refusal answers came back out of order"
    );
    // A tag the driver does not know is a table/driver mismatch, not a finding
    // about the implementation — so it fails loudly on its own rather than
    // being counted as a divergence.
    std::assert!(
      result.unknown_tag.is_none(),
      "the shared table names a non-finite tag the driver does not map: {:?}",
      result.unknown_tag
    );

    match &result.threw {
      std::option::Option::Some(threw) if threw.name == row.error_name => {}
      std::option::Option::Some(threw) => {
        divergences.push(divergence(
          &row.name,
          &row.pins,
          &row.non_finite,
          &std::format!("refusal named {}", row.error_name),
          &std::format!("refusal named {}: {}", threw.name, threw.message),
        ));
      }
      std::option::Option::None => {
        // The dangerous direction, and the reason the row exists at all:
        // `JSON.stringify` turns a non-finite number into `null`, which changes
        // the bytes a signature covers without anything reporting it.
        divergences.push(divergence(
          &row.name,
          &row.pins,
          &row.non_finite,
          &std::format!("refusal named {}", row.error_name),
          &std::format!(
            "NO refusal — it serialized to {:?}",
            result
              .canonical
              .as_deref()
              .unwrap_or("<neither a result nor a refusal>")
          ),
        ));
      }
    }
  }

  std::assert!(
    divergences.is_empty(),
    "\nTWO ENGINES DISAGREE about refusing a non-finite number.\n\n{}",
    divergences.join("")
  );
}
