//! `aph` — a small CLI for exercising the APH interpreter without writing
//! Rust. Subcommands:
//!
//! - `aph validate <file|->` — strict-parse an envelope; exit 0/1.
//! - `aph inspect <file|->` — parse and print a human-readable summary.
//! - `aph golden [index]` — list conformance fixtures, or print one raw.
//! - `aph help` — usage.

const USAGE: &str = "usage: aph <command>

commands:
  validate <file|->   strict-parse a NotarizationEnvelope from a file or stdin
  inspect  <file|->   parse an envelope and print a human summary
  golden [index]      list conformance fixtures, or print fixture <index> (1-based) raw
  help                show this message";

fn main() {
  let args: std::vec::Vec<String> = std::env::args().skip(1).collect();
  let code = match args.first().map(String::as_str) {
    std::option::Option::Some("validate") => cmd_validate(args.get(1).map(String::as_str)),
    std::option::Option::Some("inspect") => cmd_inspect(args.get(1).map(String::as_str)),
    std::option::Option::Some("golden") => cmd_golden(args.get(1).map(String::as_str)),
    std::option::Option::Some("help") | std::option::Option::Some("--help") | std::option::Option::Some("-h") => {
      outln(USAGE);
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

fn parse_arg(source: std::option::Option<&str>) -> std::result::Result<aph_core::envelope::NotarizationEnvelope, i32> {
  let source = match source {
    std::option::Option::Some(s) => s,
    std::option::Option::None => {
      eprintln!("{}", USAGE);
      return std::result::Result::Err(2);
    }
  };
  let raw = match read_input(source) {
    std::result::Result::Ok(raw) => raw,
    std::result::Result::Err(e) => {
      eprintln!("invalid envelope: cannot read {}: {}", source, e);
      return std::result::Result::Err(1);
    }
  };
  match serde_json::from_str::<aph_core::envelope::NotarizationEnvelope>(&raw) {
    std::result::Result::Ok(env) => std::result::Result::Ok(env),
    std::result::Result::Err(e) => {
      eprintln!("invalid envelope: {}", e);
      std::result::Result::Err(1)
    }
  }
}

fn cmd_validate(source: std::option::Option<&str>) -> i32 {
  match parse_arg(source) {
    std::result::Result::Ok(env) => {
      outln(&format!("valid: {} ({})", env.id, env.issuer));
      0
    }
    std::result::Result::Err(code) => code,
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
  outln(&format!("proof:               present ({})", env.proof.r#type));
  outln(&format!(
    "proof cryptosuite:   {}",
    env.proof.cryptosuite.as_deref().unwrap_or("(none)")
  ));
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
}
