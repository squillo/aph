//! `aph attest-rotation` — the ONE verb in this binary that holds a private
//! key, kept out of `publish` because that module's preamble promises public
//! material only, and a promise with an exception folded into it is not one.
//!
//! THE SEED ARRIVES ON STDIN AND NOWHERE ELSE. An argv is readable in `ps`
//! by every process on the host; an environment is inherited by every child;
//! a path names a file something else can read later. A pipe from the
//! owner's own shell is consumed once, here, and is never echoed, logged, or
//! written — no error message carries any part of it, only its LENGTH class.
//! Everything this verb WRITES is public: the signed statement is exactly
//! what the DID document publishes (spec/aph-0.2.md §5, RFC 0001 §3.1).
//!
//! ONE SIGNER, ALWAYS. The statement is built as `aph_core::rotation` defines
//! it and signed by its `sign_rotation_attestation`; the same module's
//! verifier is run over the result BEFORE it is printed, under the public key
//! derived from the seed — so an operator is never handed a statement the
//! reference would refuse. Rendering it into the document is `render-did
//! --attestation`'s job, which verifies it AGAIN under the PUBLISHED key.

/// `attest-rotation <did:web> <predecessor-kid> <successor did:key>
/// <successor-kid> --id ID --created T --not-before T --not-after T`, with
/// the predecessor's 64-hex Ed25519 seed on `seed_source` (stdin in `main`).
///
/// Prints the signed statement, canonical JSON, to stdout. The predecessor's
/// PUBLIC key goes to stderr as a `did:key`, so a ceremony can confirm the
/// statement was signed by the key the live document publishes.
pub fn cmd_attest_rotation(args: &[std::string::String], seed_source: &mut dyn std::io::Read) -> i32 {
  match attest_rotation(args, seed_source) {
    std::result::Result::Ok((statement, predecessor_public)) => {
      eprintln!("predecessor public key: {}", predecessor_public);
      println!("{}", statement);
      0
    }
    std::result::Result::Err((code, message)) => {
      eprintln!("attest-rotation: {}", message);
      code
    }
  }
}

const USAGE: &str = "usage: attest-rotation <did:web> <predecessor-kid> <successor did:key> \
<successor-kid> --id ID --created T --not-before T --not-after T  (seed: 64 hex on stdin)";

/// The verb's body, kept free of process I/O so it can be exercised in tests
/// with a reader and a captured string. Exit code 2 is a usage error, 1 a
/// refusal; the message never contains seed material.
fn attest_rotation(
  args: &[std::string::String],
  seed_source: &mut dyn std::io::Read,
) -> std::result::Result<(std::string::String, std::string::String), (i32, std::string::String)> {
  let mut positional: std::vec::Vec<&str> = std::vec::Vec::with_capacity(4);
  let mut id: std::option::Option<&str> = std::option::Option::None;
  let mut created: std::option::Option<&str> = std::option::Option::None;
  let mut not_before: std::option::Option<&str> = std::option::Option::None;
  let mut not_after: std::option::Option<&str> = std::option::Option::None;

  let mut index = 0;
  while index < args.len() {
    let flag = args[index].as_str();
    let value = args.get(index + 1).map(std::string::String::as_str);
    match flag {
      "--id" | "--created" | "--not-before" | "--not-after" => {
        let value = match value {
          std::option::Option::Some(v) => v,
          std::option::Option::None => {
            return std::result::Result::Err((2, std::format!("{flag} needs a value\n{USAGE}")));
          }
        };
        match flag {
          "--id" => id = std::option::Option::Some(value),
          "--created" => created = std::option::Option::Some(value),
          "--not-before" => not_before = std::option::Option::Some(value),
          _ => not_after = std::option::Option::Some(value),
        }
        index += 2;
      }
      other => {
        positional.push(other);
        index += 1;
      }
    }
  }

  let [subject, predecessor_kid, successor_did, successor_kid] = positional.as_slice() else {
    return std::result::Result::Err((2, USAGE.to_string()));
  };
  if !subject.starts_with("did:web:") {
    return std::result::Result::Err((2, std::format!("subject `{subject}` is not a did:web identifier")));
  }
  let (id, created, not_before, not_after) = match (id, created, not_before, not_after) {
    (
      std::option::Option::Some(i),
      std::option::Option::Some(c),
      std::option::Option::Some(b),
      std::option::Option::Some(a),
    ) => (i, c, b, a),
    _ => {
      return std::result::Result::Err((
        2,
        "--id, --created, --not-before and --not-after are all required (RFC 3339 \
         timestamps; the ceremony supplies them so this binary needs no clock)"
          .to_string(),
      ));
    }
  };

  // The successor is PUBLIC material: a did:key, decoded by the same codec
  // `render-did` publishes with, which also fixes the §8.1 JWS spelling of
  // its algorithm (spec §5: `EdDSA`/`ES256`, never the TXT spelling).
  let alg = match aph_core::decode_did_key(successor_did) {
    std::result::Result::Ok(aph_core::DecodedDidKey::Ed25519(_)) => "EdDSA",
    std::result::Result::Ok(aph_core::DecodedDidKey::P256(_)) => "ES256",
    std::result::Result::Err(e) => {
      return std::result::Result::Err((
        1,
        std::format!("`{successor_did}` is not a decodable did:key: {e}"),
      ));
    }
  };
  // The decode above succeeded only with the prefix present.
  let public_key_multibase = successor_did.trim_start_matches("did:key:").to_string();

  // The seed: read once, validated by LENGTH and alphabet only, never echoed.
  let mut raw = std::string::String::new();
  if let std::result::Result::Err(e) = seed_source.read_to_string(&mut raw) {
    return std::result::Result::Err((1, std::format!("could not read the seed from stdin: {e}")));
  }
  let seed = match super::publish::hex_decode32(raw.trim()) {
    std::option::Option::Some(s) => s,
    std::option::Option::None => {
      return std::result::Result::Err((
        1,
        std::format!(
          "stdin must carry exactly 64 hex characters (a 32-byte Ed25519 seed); got {} \
           characters after trimming — nothing signed, value not echoed",
          raw.trim().len()
        ),
      ));
    }
  };
  let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
  let verifying_key = signing_key.verifying_key();
  let predecessor_public = aph_core::did_key_from_ed25519(&verifying_key);

  let predecessor = std::format!("{subject}#{predecessor_kid}");
  let mut attestation = aph_core::RotationAttestation {
    aph_version: std::string::String::from("0.2"),
    r#type: std::string::String::from(aph_core::ROTATION_ATTESTATION_TYPE),
    id: id.to_string(),
    subject: subject.to_string(),
    predecessor: predecessor.clone(),
    successor: aph_core::RotationSuccessor {
      kid: successor_kid.to_string(),
      alg: alg.to_string(),
      public_key_multibase,
      not_before: not_before.to_string(),
      not_after: not_after.to_string(),
    },
    created: created.to_string(),
    proof: aph_core::envelope::EnvelopeProof {
      r#type: std::string::String::from("DataIntegrityProof"),
      cryptosuite: std::option::Option::Some(std::string::String::from("eddsa-jcs-2022")),
      verification_method: predecessor,
      created: created.to_string(),
      proof_purpose: std::string::String::from("assertionMethod"),
      proof_value: std::string::String::new(),
      id: std::option::Option::None,
      previous_proof: std::option::Option::None,
    },
  };

  if let std::result::Result::Err(e) = aph_core::sign_rotation_attestation(&mut attestation, &signing_key) {
    return std::result::Result::Err((1, std::format!("signing refused: {e}")));
  }
  // The reference's own verifier, under the key the seed derives: a
  // statement it refuses is never printed, whatever the reason.
  if let std::result::Result::Err(e) = aph_core::verify_rotation_attestation(&attestation, &verifying_key) {
    return std::result::Result::Err((
      1,
      std::format!("the signed statement does not verify under its own key, so it was not printed: {e}"),
    ));
  }

  let value = serde_json::to_value(&attestation)
    .map_err(|e| (1, std::format!("the statement does not serialize: {e}")))?;
  std::result::Result::Ok((aph_core::crypto::jcs::canonicalize_rfc8785(&value), predecessor_public))
}

#[cfg(test)]
mod tests {
  //! These pin that the verb builds the statement the reference defines and
  //! refuses to print one the reference would refuse — and that the only
  //! private input is handled by length class alone. Keys are published test
  //! vectors (RFC 8032 §7.1 TEST 1 as predecessor, TEST 2 as successor) and
  //! authorize nothing.

  const RFC8032_TEST1_SEED_HEX: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  const RFC8032_TEST1_PUBLIC_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  const RFC8032_TEST2_PUBLIC_HEX: &str =
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
  const SUBJECT: &str = "did:web:notary.example.com";

  fn verifying(hex: &str) -> ed25519_dalek::VerifyingKey {
    ed25519_dalek::VerifyingKey::from_bytes(&super::super::publish::hex_decode32(hex).expect("hex"))
      .expect("curve point")
  }

  fn args(successor_did: &str) -> std::vec::Vec<std::string::String> {
    [
      SUBJECT, "k1", successor_did, "k2",
      "--id", "urn:uuid:00000000-0000-4000-8000-000000000001",
      "--created", "2026-11-06T22:00:00Z",
      "--not-before", "2026-11-06T22:00:00Z",
      "--not-after", "2028-11-06T22:00:00Z",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
  }

  fn published(hex: &str, kid: &str) -> aph_core::discovery::NotaryPublicKey {
    aph_core::discovery::NotaryPublicKey {
      algorithm: aph_core::discovery::KeyAlgorithm::Ed25519,
      key_bytes: verifying(hex).to_bytes().to_vec(),
      kid: std::option::Option::Some(kid.to_string()),
    }
  }

  /// WHY: an operator runs this verb once, offline, and publishes what it
  /// prints; the only acceptable output is one the reference verifies and the
  /// renderer embeds. PINS: the output strict-parses as a RotationAttestation;
  /// it verifies under the predecessor's PUBLIC key; the predecessor named is
  /// `subject#k1` and the proof names the same; the successor carries the
  /// JWS spelling `EdDSA` and the successor did:key's multibase payload; the
  /// stderr line is the predecessor's did:key; and `render-did`'s renderer
  /// accepts the statement with k1 and k2 published, surfacing it under the
  /// full-URI property.
  #[test]
  fn signs_a_statement_the_reference_verifies_and_the_renderer_embeds() {
    let successor_did = aph_core::did_key_from_ed25519(&verifying(RFC8032_TEST2_PUBLIC_HEX));
    let mut seed = std::io::Cursor::new(std::format!("{RFC8032_TEST1_SEED_HEX}\n"));
    let (statement, predecessor_public) =
      super::attest_rotation(&args(&successor_did), &mut seed).expect("signs");

    std::assert_eq!(predecessor_public, aph_core::did_key_from_ed25519(&verifying(RFC8032_TEST1_PUBLIC_HEX)));
    let parsed: aph_core::RotationAttestation = serde_json::from_str(&statement).expect("strict parse");
    aph_core::verify_rotation_attestation(&parsed, &verifying(RFC8032_TEST1_PUBLIC_HEX))
      .expect("verifies under the predecessor's public key");
    std::assert_eq!(parsed.predecessor, std::format!("{SUBJECT}#k1"));
    std::assert_eq!(parsed.proof.verification_method, parsed.predecessor);
    std::assert_eq!(parsed.successor.alg, "EdDSA");
    std::assert_eq!(parsed.successor.kid, "k2");
    std::assert_eq!(std::format!("did:key:{}", parsed.successor.public_key_multibase), successor_did);

    let keys = [published(RFC8032_TEST1_PUBLIC_HEX, "k1"), published(RFC8032_TEST2_PUBLIC_HEX, "k2")];
    let document = aph_core::discovery::publish::render_did_document_with_rotation(SUBJECT, &keys, &parsed)
      .expect("the renderer embeds a statement it can verify under the published #k1");
    let document: serde_json::Value = serde_json::from_str(&document).expect("json");
    let embedded: aph_core::RotationAttestation =
      serde_json::from_value(document[aph_core::DID_DOC_ROTATION_PROPERTY].clone())
        .expect("the statement rides the document under the full-URI property");
    std::assert_eq!(embedded, parsed);
  }

  /// WHY: the seed is the only private input and the failure messages are
  /// what an operator sees in a terminal; they must say WHAT is wrong without
  /// ever carrying the value. PINS: a 63-hex seed and a non-hex seed are
  /// refused (exit 1) and the message names only a character count; a
  /// missing required flag is a usage error (exit 2) before the seed is even
  /// read; no statement is produced in any of these.
  #[test]
  fn refuses_a_malformed_seed_and_incomplete_arguments_without_echoing() {
    let successor_did = aph_core::did_key_from_ed25519(&verifying(RFC8032_TEST2_PUBLIC_HEX));

    let short = &RFC8032_TEST1_SEED_HEX[..63];
    let (code, message) =
      super::attest_rotation(&args(&successor_did), &mut std::io::Cursor::new(short)).expect_err("short seed");
    std::assert_eq!(code, 1);
    std::assert!(message.contains("63 characters"), "{message}");
    std::assert!(!message.contains(short), "the seed must not be echoed: {message}");

    let not_hex = "zz".repeat(32);
    let (code, _) =
      super::attest_rotation(&args(&successor_did), &mut std::io::Cursor::new(not_hex)).expect_err("non-hex");
    std::assert_eq!(code, 1);

    let mut missing_flag = args(&successor_did);
    missing_flag.truncate(missing_flag.len() - 2); // drop `--not-after T`
    let mut untouched = std::io::Cursor::new(RFC8032_TEST1_SEED_HEX);
    let (code, _) = super::attest_rotation(&missing_flag, &mut untouched).expect_err("usage");
    std::assert_eq!(code, 2);
    std::assert_eq!(untouched.position(), 0, "a usage error must not consume the seed");
  }
}
