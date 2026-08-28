//! `aph` — a small CLI for exercising the APH interpreter without writing
//! Rust. Subcommands:
//!
//! - `aph validate [--json] <file|->` — strict-parse an envelope; exit 0/1.
//! - `aph inspect <file|->` — parse and print a human-readable summary.
//! - `aph golden [index]` — list conformance fixtures, or print one raw.
//! - `aph help` — usage, plus the `--json` verdict contract.
//!
//! `validate` reads stdin as `-`, which is what makes it usable as a gate on
//! envelopes minted by an implementation in any language: pipe the bytes in
//! and read the exit code. `--json` adds a machine-readable rendering of the
//! SAME verdict for a build that wants to say WHY it failed — see the
//! `report` module, which also states the shape's stability commitment. Without
//! `--json` every byte this tool writes is what it has always written.

mod report;

const USAGE: &str = "usage: aph <command>

commands:
  validate <file|-> [--json]   strict-parse a NotarizationEnvelope from a file or stdin
  inspect  <file|->            parse an envelope and print a human summary
  golden [index]               list conformance fixtures, or print fixture <index> (1-based) raw
  help                         show this message";

/// The `--json` verdict contract, printed by `aph help` and by nothing else.
///
/// It lives with `aph help` rather than in `USAGE` because `USAGE` is also
/// what a usage error prints, and a wall of contract text is the wrong answer
/// to a mistyped argument. It is in the binary at all because the shape is
/// public surface: a consumer who has the tool must be able to read what they
/// may depend on without finding the repository first — which is exactly the
/// step three downstream implementations did not take.
///
/// `{ALLOWED}` is filled in from `ChannelKind::ALL` by
/// `json_contract` rather than typed out here. Help text that hand-copies a
/// closed vocabulary teaches an implementer the wrong set the moment the set
/// widens — and this one widened while this text was being written.
const JSON_CONTRACT: &str = r#"
validate --json
  Writes ONE JSON object to stdout and nothing to stderr. Exit codes are
  unchanged -- 0 valid, 1 invalid, 2 usage -- so a gate may read the code, the
  object, or both, and they cannot disagree.

    {"ok":true,"id":"urn:uuid:...","issuer":"did:web:..."}
    {"ok":false,"layer":"parse","reason":"closed_set","message":"...",
     "field":"credentialSubject.channel.kind","value":"...",
     "allowed":[{ALLOWED}]}
    {"ok":false,"layer":"parse","reason":"malformed","message":"..."}
    {"ok":false,"layer":"io","reason":"unreadable","message":"..."}

  (One line each; wrapped here to fit.)

  reason=closed_set means one of the spec's closed vocabularies (§7.1) was
  handed a value it does not define. `value` is that value and `allowed` is
  the whole set, so a consumer can report it without hard-coding the
  vocabulary. There is deliberately no error code: this refusal happens at
  strict parse, §8.3 step 1, BELOW the closed APH_E error set, so `layer`
  names the layer that refused instead.

  `message` is byte-for-byte the line the same run prints to stderr when
  --json is not given. Exit 2 is a usage error, not a verdict about an
  envelope, and prints usage on stderr as always.

  Stability: the fields above keep their names and their meanings. New fields
  and new `reason` values may be added, so branch on `ok` first and treat an
  unrecognized `reason` as a refusal, never as a pass."#;

/// The contract text with the real channel-kind vocabulary spliced in.
///
/// A `replace` rather than a `format!` because the template is mostly JSON
/// and every brace in it would otherwise have to be doubled — thirty lines of
/// escaping in which one missed brace is a silent formatting bug.
fn json_contract() -> std::string::String {
  let allowed = aph_core::envelope::ChannelKind::ALL
    .iter()
    .map(|kind| std::format!("\"{}\"", kind.label()))
    .collect::<std::vec::Vec<std::string::String>>()
    .join(",");
  JSON_CONTRACT.replace("{ALLOWED}", &allowed)
}

fn main() {
  let args: std::vec::Vec<String> = std::env::args().skip(1).collect();
  let code = match args.first().map(String::as_str) {
    std::option::Option::Some("validate") => cmd_validate(&args[1..]),
    std::option::Option::Some("inspect") => cmd_inspect(args.get(1).map(String::as_str)),
    std::option::Option::Some("golden") => cmd_golden(args.get(1).map(String::as_str)),
    std::option::Option::Some("help") | std::option::Option::Some("--help") | std::option::Option::Some("-h") => {
      outln(USAGE);
      outln(&json_contract());
      0
    }
    _ => {
      eprintln!("{}", USAGE);
      2
    }
  };
  std::process::exit(code);
}

/// Print a line to stdout, ignoring broken-pipe errors (`aph golden | head`
/// must exit cleanly, not panic with exit 101 when the reader hangs up).
fn outln(line: &str) {
  let mut stdout = std::io::stdout();
  let _ = std::io::Write::write_all(&mut stdout, line.as_bytes());
  let _ = std::io::Write::write_all(&mut stdout, b"\n");
}

/// Read the whole input: `-` means stdin, anything else is a file path.
fn read_input(source: &str) -> std::io::Result<String> {
  if source == "-" {
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
    std::io::Result::Ok(buf)
  } else {
    std::fs::read_to_string(source)
  }
}

/// What reading and strict-parsing one input produced, as DATA.
///
/// The verdict is decided HERE, once, and rendered twice — as the stderr line
/// this tool has always printed, or as the `--json` object. Two renderings of
/// one decision cannot drift; two decisions could, and a machine gate that
/// disagreed with the human message would be worse than no gate at all.
enum Parsed {
  /// Strict parse succeeded. Boxed because the envelope dwarfs every other
  /// variant, and an enum sized to its largest arm would move ~half a
  /// kilobyte through a function whose other two arms carry a short string.
  Accepted(std::boxed::Box<aph_core::envelope::NotarizationEnvelope>),
  /// No input argument was given. A usage error is not a verdict about an
  /// envelope, so it has no JSON rendering — see `JSON_CONTRACT`.
  Usage,
  /// Refused, with the exact stderr line and the classification the report
  /// branches on.
  Refused {
    message: std::string::String,
    refusal: report::Refusal,
  },
}

fn classify(source: std::option::Option<&str>) -> Parsed {
  let source = match source {
    std::option::Option::Some(s) => s,
    std::option::Option::None => return Parsed::Usage,
  };
  let raw = match read_input(source) {
    std::result::Result::Ok(raw) => raw,
    std::result::Result::Err(e) => {
      return Parsed::Refused {
        message: std::format!("invalid envelope: cannot read {}: {}", source, e),
        refusal: report::Refusal::Unreadable,
      };
    }
  };
  match serde_json::from_str::<aph_core::envelope::NotarizationEnvelope>(&raw) {
    std::result::Result::Ok(env) => Parsed::Accepted(std::boxed::Box::new(env)),
    std::result::Result::Err(e) => Parsed::Refused {
      message: std::format!("invalid envelope: {}", e),
      refusal: report::Refusal::classify(&raw),
    },
  }
}

fn parse_arg(source: std::option::Option<&str>) -> std::result::Result<aph_core::envelope::NotarizationEnvelope, i32> {
  match classify(source) {
    Parsed::Accepted(env) => std::result::Result::Ok(*env),
    Parsed::Usage => {
      eprintln!("{}", USAGE);
      std::result::Result::Err(2)
    }
    Parsed::Refused { message, .. } => {
      eprintln!("{}", message);
      std::result::Result::Err(1)
    }
  }
}

/// Split `validate`'s arguments into "was `--json` asked for" and the input
/// source.
///
/// `--json` is accepted in either position, because `validate --json -` and
/// `validate - --json` are both what somebody will type. Everything after the
/// FIRST non-flag argument is ignored, which is exactly what the previous
/// `args.get(1)` did — a flag must not turn a previously-working invocation
/// into a usage error.
fn split_validate_args(args: &[String]) -> (bool, std::option::Option<&str>) {
  let mut json = false;
  let mut source: std::option::Option<&str> = std::option::Option::None;
  for arg in args {
    if arg == "--json" {
      json = true;
    } else if source.is_none() {
      source = std::option::Option::Some(arg.as_str());
    }
  }
  (json, source)
}

fn cmd_validate(args: &[String]) -> i32 {
  let (json, source) = split_validate_args(args);
  if json {
    cmd_validate_json(source)
  } else {
    cmd_validate_human(source)
  }
}

fn cmd_validate_human(source: std::option::Option<&str>) -> i32 {
  match parse_arg(source) {
    std::result::Result::Ok(env) => {
      outln(&format!("valid: {} ({})", env.id, env.issuer));
      0
    }
    std::result::Result::Err(code) => code,
  }
}

/// The same verdict, rendered for a build instead of for a person: one JSON
/// object on stdout, nothing on stderr, the same exit code.
fn cmd_validate_json(source: std::option::Option<&str>) -> i32 {
  match classify(source) {
    Parsed::Accepted(env) => {
      outln(&report::ValidateReport::accepted(&env.id, &env.issuer).render());
      0
    }
    // Usage is the one case that stays on stderr under `--json`: nothing was
    // read, so there is no envelope to report a verdict about, and printing
    // `{"ok":false}` for a typo would tell a gate an envelope was refused.
    Parsed::Usage => {
      eprintln!("{}", USAGE);
      2
    }
    Parsed::Refused { message, refusal } => {
      outln(&report::ValidateReport::refused(&message, refusal).render());
      1
    }
  }
}

fn cmd_inspect(source: std::option::Option<&str>) -> i32 {
  let env = match parse_arg(source) {
    std::result::Result::Ok(env) => env,
    std::result::Result::Err(code) => return code,
  };
  let subject = &env.credential_subject;
  outln(&format!("id:                  {}", env.id));
  outln(&format!("issuer:              {}", env.issuer));
  outln(&format!("validFrom:           {}", env.valid_from));
  outln(&format!("validUntil:          {}", env.valid_until));
  outln(&format!("channel kind:        {}", subject.channel.kind));
  outln(&format!("contentClass:        {}", subject.communication.content_class));
  outln(&format!("policy decision:     {}", subject.policy.decision));
  outln(&format!("matchedScope:        {}", subject.policy.matched_scope));
  outln(&format!(
    "delegationMandateId: {}",
    subject.policy.delegation_mandate_id.as_deref().unwrap_or("(none)")
  ));
  // Security-relevant optional claims are surfaced explicitly: an auditor
  // must never miss a vault mutation or payment cross-link because the
  // summary collapsed the whole linkedMandate to "present".
  match &env.linked_mandate {
    std::option::Option::Some(lm) => {
      outln("linkedMandate:       present");
      outln(&format!(
        "  ap2IntentMandateUri:  {}",
        lm.ap2_intent_mandate_uri.as_deref().unwrap_or("(none)")
      ));
      outln(&format!(
        "  ap2SignedPayloadB64:  {}",
        if lm.ap2_signed_payload_b64.is_some() { "present" } else { "(none)" }
      ));
      match &lm.vault_mutation {
        std::option::Option::Some(vm) => {
          outln(&format!("  vaultMutation:        present (grant_scope_id: {})", vm.grant_scope_id.as_str()));
        }
        std::option::Option::None => outln("  vaultMutation:        (none)"),
      }
    }
    std::option::Option::None => outln("linkedMandate:       absent"),
  }
  outln(&format!(
    "appleAurAcceptance:  {}",
    if subject.apple_aur_acceptance.is_some() { "present" } else { "absent" }
  ));
  // `attestationMode` decides what the credential CLAIMS: PrincipalSigned
  // means the human's own key signed, NotaryAttested means a notary asserts
  // they authorized it. Absent means NotaryAttested (spec §7.1.7), so the
  // resolved value is printed rather than the raw field — an operator must
  // never read a blank line as "the strong one".
  outln(&format!(
    "attestationMode:     {}{}",
    subject.policy.effective_attestation_mode(),
    if subject.policy.attestation_mode.is_none() { " (absent; defaulted)" } else { "" }
  ));
  outln(&format!(
    "delegationMandate:   {}",
    if subject.policy.delegation_mandate.is_some() { "embedded" } else { "(none)" }
  ));
  let proofs = env.proof.all();
  outln(&format!(
    "proof:               {} ({} proof{})",
    if env.proof.is_chain() { "chain" } else { "single" },
    proofs.len(),
    if proofs.len() == 1 { "" } else { "s" }
  ));
  for (position, proof) in proofs.iter().enumerate() {
    outln(&format!(
      "  [{}] {} / {} / {}",
      position + 1,
      proof.r#type,
      proof.cryptosuite.as_deref().unwrap_or("(none)"),
      proof.proof_purpose
    ));
  }
  // The structural rules of §7.1.11 — reported, not enforced, because
  // `inspect` describes an envelope rather than accepting it. `validate` is
  // the subcommand whose exit code is a verdict.
  match aph_core::verification::verify_proof_structure(&env) {
    std::result::Result::Ok(mode) => {
      outln(&format!("proof structure:     ok ({})", mode))
    }
    std::result::Result::Err(e) => {
      outln(&format!("proof structure:     REJECTED [{}] {}", e.code(), e))
    }
  }
  0
}

fn cmd_golden(index: std::option::Option<&str>) -> i32 {
  let fixtures = aph_conformance::golden_envelopes();
  match index {
    std::option::Option::None => {
      let mut corrupt = 0;
      for (i, raw) in fixtures.iter().enumerate() {
        match serde_json::from_str::<aph_core::envelope::NotarizationEnvelope>(raw) {
          std::result::Result::Ok(env) => outln(&format!(
            "{:>3}  {}  channel={}",
            i + 1,
            env.id,
            env.credential_subject.channel.kind
          )),
          std::result::Result::Err(e) => {
            eprintln!("{:>3}  UNPARSEABLE FIXTURE: {}", i + 1, e);
            corrupt += 1;
          }
        }
      }
      // A corrupted conformance corpus must be loud, not exit 0.
      if corrupt > 0 { 1 } else { 0 }
    }
    std::option::Option::Some(arg) => {
      let n: usize = match arg.parse() {
        std::result::Result::Ok(n) if n >= 1 && n <= fixtures.len() => n,
        _ => {
          eprintln!(
            "golden: index must be a number between 1 and {}",
            fixtures.len()
          );
          return 2;
        }
      };
      outln(fixtures[n - 1]);
      0
    }
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn all_golden_fixtures_strict_parse() {
    // The CLI is the plugin's entry point, so it must agree with the
    // conformance corpus: if `aph validate` rejected a golden fixture,
    // the tool would be telling users valid envelopes are invalid. The
    // non-empty assertion also guards against a vacuous pass.
    let fixtures = aph_conformance::golden_envelopes();
    std::assert!(!fixtures.is_empty(), "conformance corpus must not be empty");
    for (i, raw) in fixtures.iter().enumerate() {
      let env: aph_core::envelope::NotarizationEnvelope = serde_json::from_str(raw)
        .unwrap_or_else(|e| std::panic!("fixture {} failed strict parse: {}", i + 1, e));
      std::assert!(!env.id.is_empty(), "fixture {} has empty id", i + 1);
      std::assert!(!env.issuer.is_empty(), "fixture {} has empty issuer", i + 1);
    }
  }

  #[test]
  fn golden_fixtures_round_trip() {
    // Exercises the same parse path `inspect` uses, through the CLI crate,
    // so a dependency mismatch between the binary and aph-core surfaces
    // here rather than in a user's terminal.
    for raw in aph_conformance::golden_envelopes() {
      let env: aph_core::envelope::NotarizationEnvelope = serde_json::from_str(raw).unwrap();
      let re = serde_json::to_string(&env).unwrap();
      let env2: aph_core::envelope::NotarizationEnvelope = serde_json::from_str(&re).unwrap();
      std::assert_eq!(env, env2);
    }
  }

  #[test]
  fn truncated_fixture_is_rejected() {
    // Negative control for `validate`: a damaged envelope must fail, not
    // partially parse. Without this the suite would only ever prove the
    // happy path, leaving "validate accepts everything" undetectable.
    let raw = aph_conformance::golden_envelopes()[0];
    let truncated = &raw[..raw.len() / 2];
    let r: std::result::Result<aph_core::envelope::NotarizationEnvelope, _> =
      serde_json::from_str(truncated);
    std::assert!(r.is_err(), "truncated JSON must fail strict parse");
  }

  /// Build the argument vector `validate` would receive from the shell.
  fn argv(args: &[&str]) -> std::vec::Vec<std::string::String> {
    args.iter().map(|arg| arg.to_string()).collect()
  }

  #[test]
  fn json_flag_is_accepted_on_either_side_of_the_source() {
    // `aph validate --json -` and `aph validate - --json` are both what
    // somebody will type, and a gate that silently ran in human mode because
    // the flag came last would print a line no `jq` can read while still
    // exiting 0. Pinned in both orders because a positional-only parser
    // passes one of them by accident.
    std::assert_eq!(
      super::split_validate_args(&argv(&["--json", "-"])),
      (true, std::option::Option::Some("-"))
    );
    std::assert_eq!(
      super::split_validate_args(&argv(&["-", "--json"])),
      (true, std::option::Option::Some("-"))
    );
  }

  #[test]
  fn absent_flag_leaves_the_previous_argument_handling_exactly_as_it_was() {
    // The compatibility half of the same function, and the reason it ignores
    // trailing arguments instead of refusing them: before `--json` existed
    // `validate` read `args[1]` and never looked further, so `aph validate a
    // b` validated `a`. Turning that into a usage error would be a behaviour
    // change on the path this lane promised not to touch.
    std::assert_eq!(
      super::split_validate_args(&argv(&["envelope.json"])),
      (false, std::option::Option::Some("envelope.json"))
    );
    std::assert_eq!(
      super::split_validate_args(&argv(&["a", "b"])),
      (false, std::option::Option::Some("a"))
    );
    std::assert_eq!(
      super::split_validate_args(&argv(&[])),
      (false, std::option::Option::None)
    );
  }

  #[test]
  fn a_missing_source_is_a_usage_error_and_not_an_envelope_verdict() {
    // `--json` must never report `{"ok":false}` for a mistyped command line:
    // a gate reading that object would log "the envelope was refused" when no
    // envelope was ever read. `Parsed::Usage` is the type-level statement of
    // that, and this pins that no input argument still lands there.
    std::assert!(std::matches!(
      super::classify(std::option::Option::None),
      super::Parsed::Usage
    ));
  }

  #[test]
  fn the_json_message_is_the_line_the_plain_run_prints() {
    // The contract that lets the two renderings be trusted as one verdict:
    // the object's `message` is the stderr line verbatim, prefix included.
    // If these ever diverge, a consumer's log and a maintainer's terminal
    // describe the same refusal in different words — which is how the
    // original reports got written in the first place.
    //
    // The input is this crate's own manifest: a file that certainly exists,
    // certainly is not an envelope, and needs no fixture written to disk to
    // drive the read-then-strict-parse path end to end.
    let path = std::concat!(std::env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let raw = std::fs::read_to_string(path).unwrap();
    let expected = std::format!(
      "invalid envelope: {}",
      serde_json::from_str::<aph_core::envelope::NotarizationEnvelope>(&raw).unwrap_err()
    );
    match super::classify(std::option::Option::Some(path)) {
      super::Parsed::Refused { message, refusal } => {
        std::assert_eq!(message, expected);
        // Not JSON at all, so nothing may be claimed about a vocabulary.
        std::assert!(std::matches!(refusal, crate::report::Refusal::Malformed));
      }
      _ => std::panic!("a manifest is not an envelope and must be refused"),
    }
  }

  #[test]
  fn an_unreadable_source_is_refused_at_the_io_layer() {
    // A path that does not exist still exits 1 today, and must keep doing so
    // — but it is not a statement about any bytes. This pins that the
    // classification says so, and that the human line is unchanged.
    let parsed = super::classify(std::option::Option::Some(
      "/nonexistent/aph-cli/no-such-envelope.json",
    ));
    match parsed {
      super::Parsed::Refused { message, refusal } => {
        std::assert!(
          std::matches!(refusal, crate::report::Refusal::Unreadable),
          "a missing file is an I/O refusal"
        );
        std::assert!(
          message.starts_with("invalid envelope: cannot read "),
          "unchanged human line: {}",
          message
        );
      }
      _ => std::panic!("a missing file must be refused"),
    }
  }
}
