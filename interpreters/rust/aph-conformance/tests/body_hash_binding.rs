//! §8.3 step 8 — the BODY-HASH BINDING, exercised against a real published
//! body for the first time.
//!
//! ## Why this file exists
//!
//! Every check in §8.3 had a vector except the one that binds an envelope to
//! the bytes it describes. All the shape-only fixtures pair
//! `bodySha256` = SHA-256 of the empty string with a fictional `bodySize`,
//! and until this file landed even the signed golden did — an implementer
//! could pass every published test while never hashing a body at all, which
//! is precisely the coverage gap the README's honesty list called out.
//!
//! `examples/principal_signed_body.txt` is now the published body of the
//! signed golden: the envelope's `bodySha256`/`bodySize` are the SHA-256 and
//! exact byte length of that committed file, and the golden's four
//! signatures cover those values.
//!
//! ## Why the hash check lives HERE and not in aph-core
//!
//! §8.3 step 8 belongs to the RECIPIENT: the crate never sees message bodies
//! (it parses envelopes and verifies signatures; bodies travel on the
//! channel, not in the credential). aph-core therefore deliberately exposes
//! no body-hash checker — this test performs the comparison the way any
//! recipient must, with its own SHA-256 over the bytes it received, and
//! constructs the same typed `APH_E009` a recipient reports on mismatch.

mod generator_support;

/// The recipient-side check, written once the way operations-grade recipient
/// code performs it: hash what arrived, compare against what was attested,
/// and refuse with the typed `APH_E009` on any difference. Pure — bytes in,
/// verdict out — so both the positive and negative tests below share it.
fn check_body_binding(
  received_body: &[u8],
  envelope: &aph_core::NotarizationEnvelope,
) -> std::result::Result<(), aph_core::AphError> {
  use sha2::Digest as _;
  let mut hasher = sha2::Sha256::new();
  hasher.update(received_body);
  let actual = hasher
    .finalize()
    .iter()
    .map(|b| std::format!("{b:02x}"))
    .collect::<std::string::String>();
  let expected = &envelope.credential_subject.communication.body_sha256;
  if &actual != expected {
    return std::result::Result::Err(aph_core::AphError::envelope_body_hash_mismatch(
      expected, &actual,
    ));
  }
  std::result::Result::Ok(())
}

/// WHY THIS TEST EXISTS: §8.3 step 8 was exercised by nothing in this
/// repository (all fixtures carried the empty-string digest beside a
/// non-zero size).
/// WHAT IT PINS: the committed body file hashes to exactly the golden's
/// `bodySha256`, its byte length equals `bodySize`, its first line equals
/// the envelope's one-line preview (§7.3 consistency), and the envelope
/// holding those values still passes the full structural check — so the
/// binding is covered by the same four signatures the end-to-end test
/// verifies, not asserted beside them.
#[test]
fn the_published_body_hashes_to_what_the_golden_attests() {
  let body = std::fs::read(generator_support::example_path("principal_signed_body.txt"))
    .expect("the published body file must exist beside the envelope it binds");
  let envelope =
    generator_support::parse_published(&generator_support::example_path(
      "principal_signed_envelope.json",
    ));

  check_body_binding(&body, &envelope)
    .expect("the committed body must hash to the attested bodySha256");

  std::assert_eq!(
    body.len() as u64,
    envelope.credential_subject.communication.body_size,
    "bodySize must be the exact byte length of the published body"
  );

  // §7.3: the preview is the leading lines of the body. previewLines is 1
  // here, so the preview must equal the body's first line exactly — a
  // preview that drifted from the body would be attested UI text describing
  // bytes the hash no longer covers.
  let text = std::str::from_utf8(&body).expect("the published body is UTF-8");
  std::assert_eq!(
    envelope.credential_subject.communication.preview_lines,
    1,
    "this vector publishes a one-line preview"
  );
  std::assert_eq!(
    text.lines().next().expect("the body has a first line"),
    envelope.credential_subject.communication.preview,
    "the preview must be the body's first line, per its previewLines"
  );

  // The values above are only meaningful if the envelope carrying them still
  // verifies structurally — a broken golden with a correct hash would prove
  // nothing. The full four-signature verify stays pinned by the golden's own
  // end-to-end test; structure is re-checked here so THIS file fails loudly
  // too if the regeneration went wrong.
  aph_core::verify_proof_structure(&envelope)
    .expect("the golden that attests this body must remain structurally valid");
}

/// WHY THIS TEST EXISTS: a positive-only vector cannot prove anyone checks —
/// a recipient that skips step 8 passes it. The refusal is the test.
/// WHAT IT PINS: a single flipped byte in the received body yields exactly
/// `APH_E009` — the specific §11 code — never a pass and never some other
/// error, and the refusal names both digests so an operator can see WHICH
/// bytes were attested versus received.
#[test]
fn a_one_byte_different_body_is_refused_with_aph_e009() {
  let mut body = std::fs::read(generator_support::example_path("principal_signed_body.txt"))
    .expect("the published body file must exist");
  let envelope =
    generator_support::parse_published(&generator_support::example_path(
      "principal_signed_envelope.json",
    ));

  // Flip one byte in the middle — the smallest tamper a transit path can
  // make, and the exact case §2.2 of the security considerations names.
  let middle = body.len() / 2;
  body[middle] ^= 0x01;

  let error = check_body_binding(&body, &envelope)
    .expect_err("a tampered body must not hash to the attested digest");
  std::assert_eq!(
    error.code(),
    "APH_E009",
    "the body-hash mismatch must surface as the specific §11 code"
  );
}
