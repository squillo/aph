//! (<-) CROSS-VERIFICATION: the reference implementation verifies an envelope
//! the independent TypeScript implementation MINTED.
//!
//! WHY THIS FILE EXISTS. Every other signature check in this suite verifies
//! bytes this codebase produced. That proves the reference is self-consistent
//! and proves nothing about interoperability — a canonicalization or
//! signing-base mistake made once is made identically on both sides of a
//! self-check. `examples/ts_minted_envelope.json` was built by
//! `interpreters/typescript`, which shares no code with this crate: its own
//! RFC 8785 canonicalizer, its own §7.2.1 bases, its own base58btc, signatures
//! through the WebCrypto runtime rather than through `ed25519-dalek`. Two
//! implementations that each MINT what the other ADMITS is what interop means;
//! `interpreters/typescript/test/verify_golden.test.ts` is the other half, and
//! it admits `examples/principal_signed_envelope.json` — minted here.
//!
//! WHAT IT PINS. Strict deserialization, §7.1.11 proof structure, §7.2.1
//! issuance order, §7.1.7.1 mandate-to-envelope bindings, and all FOUR
//! signatures: both envelope proofs over their per-role §7.2.1 bases, and both
//! §6.1 mandate signatures. Plus the negative that gives the positives
//! meaning — a one-byte edit is refused.
//!
//! SCOPE, stated rather than implied. The committed artifact is Ed25519 only.
//! Ed25519 is deterministic in both stacks (RFC 8032 derives the nonce from
//! the key and the message), so the TypeScript side can byte-pin what it
//! mints. WebCrypto's ECDSA is randomized and exposes no RFC 6979 mode, so an
//! ES256 artifact minted there could not be committed at all; that path is
//! covered in the other direction (TypeScript verifies this repository's
//! `ecdsa-jcs-2019` vector) plus a mint-then-verify self-test inside one
//! TypeScript run.
//!
//! NO TOOLCHAIN COUPLING. This test never runs Node, and the TypeScript suite
//! never runs cargo. Both read committed bytes. A gate that shelled out to the
//! other stack would be testing a build pipeline rather than a protocol.

/// Where the TypeScript mint script writes its artifact. Three levels up from
/// this crate is the repository root: `interpreters/rust/aph-conformance`.
const TS_MINTED_PATH: &str =
  concat!(env!("CARGO_MANIFEST_DIR"), "/../../../examples/ts_minted_envelope.json");

/// Read the artifact, or fail with instructions rather than an opaque io error.
///
/// The file is GENERATED and committed, so a missing one means the mint step
/// has not run in this tree. `unwrap()` on the read would report
/// "No such file or directory" and send the reader looking for a path bug.
fn read_ts_minted() -> String {
  match std::fs::read_to_string(TS_MINTED_PATH) {
    std::result::Result::Ok(text) => text,
    std::result::Result::Err(error) => panic!(
      "MISSING ARTIFACT: examples/ts_minted_envelope.json is not present ({error}).\n\
       It is minted by the independent TypeScript implementation and committed:\n\
       \x20   cd interpreters/typescript && npm install && npm run build && npm run mint\n\
       This test is the (<-) half of the cross-verification bar and cannot run without it."
    ),
  }
}

/// Strict-parses the artifact. `NotarizationEnvelope` denies unknown fields, so
/// this is §8.3 step 1 and not merely a convenience.
fn parse_ts_minted() -> aph_core::NotarizationEnvelope {
  let text = read_ts_minted();
  match serde_json::from_str::<aph_core::NotarizationEnvelope>(&text) {
    std::result::Result::Ok(envelope) => envelope,
    std::result::Result::Err(error) => panic!(
      "the TypeScript-minted envelope did not survive STRICT deserialization: {error}.\n\
       That is a wire-shape disagreement between the two implementations, which is exactly \
       what this test exists to surface."
    ),
  }
}

/// The `did:key` a verification method names, with its `#fragment` removed.
///
/// `aph_core::decode_did_key` decodes an identifier, not a DID URL, and a
/// fragment would be fed to the base58 decoder as key material.
fn did_of(verification_method: &str) -> &str {
  match verification_method.split_once('#') {
    std::option::Option::Some((did, _fragment)) => did,
    std::option::Option::None => verification_method,
  }
}

fn ed25519_key_of(verification_method: &str) -> ed25519_dalek::VerifyingKey {
  match aph_core::decode_did_key(did_of(verification_method)) {
    std::result::Result::Ok(aph_core::DecodedDidKey::Ed25519(key)) => *key,
    std::result::Result::Ok(_) => panic!(
      "{verification_method} decodes to a non-Ed25519 key; the committed cross-artifact is \
       Ed25519 by design (WebCrypto ECDSA is randomized and cannot be byte-pinned)"
    ),
    std::result::Result::Err(error) => {
      panic!("{verification_method} is not a decodable did:key: {error:?}")
    }
  }
}

#[test]
fn ts_minted_envelope_parses_strictly_and_declares_the_structure_it_carries() {
  let envelope = parse_ts_minted();

  // §7.1.11: the mode is PROVED by the two-element chain whose head resolves
  // to `credentialSubject.humanPrincipal.id`, not read off the label.
  let mode = aph_core::verify_proof_structure(&envelope)
    .expect("the TypeScript-minted envelope must satisfy §7.1.11 proof structure");
  assert_eq!(mode, aph_core::AttestationMode::PrincipalSigned);

  // §8.3.1 step 1a from the other side: a verifier demanding the stronger mode
  // must be satisfied by this artifact.
  aph_core::require_mode(&envelope, aph_core::AttestationMode::PrincipalSigned)
    .expect("a PrincipalSigned policy must admit this artifact");

  // §7.2.1: the notary decided, the human signed what it prepared, the notary
  // countersigned what the human signed. The TypeScript minter enforces this
  // ordering by construction; this checks it landed in the bytes.
  aph_core::verify_timestamp_order(&envelope)
    .expect("the TypeScript-minted chain must ascend: decision, principal, countersignature");
}

#[test]
fn ts_minted_envelope_both_proof_signatures_verify_under_their_own_did_keys() {
  let envelope = parse_ts_minted();

  let principal = envelope
    .proof
    .principal()
    .expect("a PrincipalSigned artifact carries a principal proof");
  let notary = envelope
    .proof
    .notary()
    .expect("a PrincipalSigned artifact carries a notary countersignature");

  // Both parties are `did:key` in this artifact — deliberately, and unlike the
  // `did:web` notary of `principal_signed_envelope.json`. No key is supplied
  // from outside, so the whole check is offline and reproducible by anyone.
  let principal_key = ed25519_key_of(&principal.verification_method);
  let notary_key = ed25519_key_of(&notary.verification_method);

  // §7.2.1 principal base: `proof` as a ONE-ELEMENT ARRAY with this proof's
  // own `proofValue` emptied. The single likeliest place for two
  // implementations to disagree, and the reason this assertion is the point of
  // the file.
  aph_core::verify_proof(&envelope, aph_core::ProofRole::Principal, &principal_key)
    .expect("the TypeScript principal proof must verify over its §7.2.1 one-element-array base");

  // §7.2.1 notary base: both proofs present, the principal's `proofValue`
  // complete, its own emptied.
  aph_core::verify_proof(&envelope, aph_core::ProofRole::Notary, &notary_key)
    .expect("the TypeScript notary countersignature must verify over the two-proof base");

  // The chain head must be the HUMAN's key, or the label means nothing.
  assert_eq!(
    did_of(&principal.verification_method),
    envelope.credential_subject.human_principal.id,
    "the chain head must resolve to credentialSubject.humanPrincipal.id (§7.1.11)"
  );
}

#[test]
fn ts_minted_envelope_both_mandate_signatures_verify_over_the_ss6_1_bases() {
  use ed25519_dalek::Verifier;

  let envelope = parse_ts_minted();
  let mandate = envelope
    .credential_subject
    .policy
    .delegation_mandate
    .as_ref()
    .expect("the artifact embeds its parent §6.1 grant so the human's authority is offline-checkable");

  // §7.1.7.1 step 3: the three equalities that make the embedded mandate THIS
  // envelope's parent rather than some validly-signed mandate stapled on.
  aph_core::verify_embedded_mandate_binding(&envelope)
    .expect("the embedded mandate must bind to this envelope");

  let notary = envelope.proof.notary().expect("a countersigned chain has a notary proof");
  let principal_key = ed25519_key_of(&mandate.human_principal_did);
  let notary_key = ed25519_key_of(&notary.verification_method);

  // Signatures 3 and 4 of 4. The TypeScript side had to resolve a genuine
  // ambiguity to produce these: §6.1's field table says a mandate signature
  // covers the form MINUS the signature members, while §7.2.1 closes with a
  // sentence about EMPTYING them. These assertions are what proves both
  // implementations landed on the same reading — the removal one.
  let principal_base =
    aph_core::mandate_signing_base(mandate, aph_core::ProofRole::Principal).expect("principal base");
  let principal_signature = signature_of(&mandate.principal_signature, "principalSignature");
  principal_key
    .verify(principal_base.as_bytes(), &principal_signature)
    .expect("the TypeScript mandate principalSignature must verify over the §6.1 principal base");

  let notary_base =
    aph_core::mandate_signing_base(mandate, aph_core::ProofRole::Notary).expect("notary base");
  let notary_signature = signature_of(&mandate.notary_signature, "notarySignature");
  notary_key
    .verify(notary_base.as_bytes(), &notary_signature)
    .expect("the TypeScript mandate notarySignature must verify over the §6.1 notary base");
}

/// Decodes a multibase §6.1 mandate signature into a `dalek` signature.
fn signature_of(multibase: &str, field: &str) -> ed25519_dalek::Signature {
  let bytes = aph_core::crypto::multibase::base58btc_decode(multibase)
    .unwrap_or_else(|error| panic!("{field} is not multibase base58btc: {error:?}"));
  let array: [u8; 64] = match bytes.as_slice().try_into() {
    std::result::Result::Ok(array) => array,
    std::result::Result::Err(_) => {
      panic!("{field} decoded to {} bytes, not the 64 an Ed25519 signature has", bytes.len())
    }
  };
  ed25519_dalek::Signature::from_bytes(&array)
}

#[test]
fn ts_minted_envelope_refuses_a_one_byte_edit() {
  // Without this the positive checks would be compatible with a verifier that
  // admits everything. The edit targets `preview`, which is inside the bytes
  // BOTH envelope proofs cover, so the principal proof must fail first —
  // §8.3.1 forbids a countersignature from rescuing an unauthorized envelope.
  let mut envelope = parse_ts_minted();
  envelope.credential_subject.communication.preview.push('!');

  let principal = envelope.proof.principal().expect("principal proof").clone();
  let principal_key = ed25519_key_of(&principal.verification_method);
  assert!(
    aph_core::verify_proof(&envelope, aph_core::ProofRole::Principal, &principal_key).is_err(),
    "a tampered envelope must not verify under the principal's key"
  );
}

#[test]
fn ts_minted_envelope_is_a_distinct_credential_from_the_rust_golden() {
  // The two cross-verification artifacts must not collide: same ids would make
  // one a re-mint of the other and this test a duplicate of the golden's.
  let ts_minted = parse_ts_minted();
  let golden_text = std::fs::read_to_string(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/principal_signed_envelope.json"
  ))
  .expect("the Rust-minted golden is committed");
  let golden: aph_core::NotarizationEnvelope =
    serde_json::from_str(&golden_text).expect("the golden parses strictly");

  assert_ne!(ts_minted.id, golden.id, "the two artifacts must be different credentials");
  assert_ne!(
    ts_minted.credential_subject.notarization.notary_service.id,
    golden.credential_subject.notarization.notary_service.id,
    "the TypeScript artifact names a did:key notary so it needs no supplied key; the golden's \
     is did:web and does"
  );
  // Same HUMAN, though: both derive the principal from RFC 8032 §7.1 TEST 2,
  // so a reader can check one DID against the other and against the RFC.
  assert_eq!(
    ts_minted.credential_subject.human_principal.id,
    golden.credential_subject.human_principal.id,
    "both artifacts name the same published test principal"
  );
}
