//! `examples/es256_signed_envelope.json` — the `ecdsa-jcs-2019` signed vector.
//!
//! §8.1 makes TWO algorithms MUST-support and, until this file, only one of
//! them had a published byte string anywhere: an implementer writing an ES256
//! verifier had nothing to check it against, and the reference implementation
//! could declare `ecdsa-jcs-2019` in a fixture's `cryptosuite` field while
//! being unable to verify a single envelope under it.
//!
//! This is that vector. A `PrincipalSigned` envelope — the human's own proof,
//! then the notary's countersignature — with both proofs made under
//! `ecdsa-jcs-2019` through `aph-core`'s own signing path.
//!
//! # Why byte comparison is valid for an ECDSA vector
//!
//! Most ECDSA is randomized: sign the same message twice and you get two
//! different signatures, both valid. A published ECDSA vector would then
//! differ from every regeneration for no protocol reason at all. `p256`
//! implements **RFC 6979 deterministic ECDSA** — the nonce is derived from the
//! key and the message — so the same key over the same base yields
//! byte-identical signatures forever. That is the ONLY reason this file can be
//! a byte-comparable golden, it is pinned by
//! `signing_is_deterministic_so_a_vector_can_be_byte_compared` inside
//! `aph-core`, and an implementer who does not know it will read the byte
//! comparison below as a bug.
//!
//! # What this vector proves, and what it does not
//!
//! It proves RFC 8785 canonicalization, the three §7.2.1 per-proof bases, the
//! §7.1.11 chain linkage, and the §8.2 `proofValue` encoding for this suite —
//! **P1363 `r‖s`, multibase base58btc, never DER**. It deliberately embeds no
//! Delegation Mandate: the Ed25519 golden already publishes the §6.1 mandate
//! signatures, and repeating them here on a second curve would add a fourth
//! and fifth signature to check without adding a rule to learn.
//!
//! # Keys
//!
//! Both are PUBLISHED test scalars — a P-256 key cannot be a repeated-byte
//! fake the way an Ed25519 seed can, because the scalar must lie in `1..n`, so
//! each cites the document it comes from and is checked against something that
//! document prints. They authorize nothing.
//!
//! ZERO `#[ignore]`. ZERO `use` statements.

mod generator_support;

/// The HUMAN PRINCIPAL's key: the RFC 6979 Appendix A.2.5 sample private key
/// for curve P-256 with SHA-256. `aph-core`'s own suite tests use the same
/// scalar in the same role, so "the principal" means one key across the
/// repository.
const PRINCIPAL_SCALAR: [u8; 32] = [
  0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
  0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
];

/// The RFC 6979 Appendix A.2.5 signature over the ASCII message `sample`, as
/// the RFC publishes it (`r || s`). Reproducing it is what proves
/// [`PRINCIPAL_SCALAR`] is the RFC's key and not a stray scalar — and it is
/// only reproducible because RFC 6979 removes the nonce.
const RFC_6979_SAMPLE_SIGNATURE: [u8; 64] = [
  0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
  0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16,
  0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
  0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8,
];

/// The NOTARY's key: the `d` value of the ES256 example JWK in RFC 7515
/// Appendix A.3.1. A different published vector, because a notary must not
/// hold the principal's key — a vector that used one key for both roles could
/// not tell a countersignature from an authorization.
const NOTARY_SCALAR: [u8; 32] = [
  0x8e, 0x9b, 0x10, 0x9e, 0x71, 0x90, 0x98, 0xbf, 0x98, 0x04, 0x87, 0xdf, 0x1f, 0x5d, 0x77, 0xe9,
  0xcb, 0x29, 0x60, 0x6e, 0xbe, 0xd2, 0x26, 0x3b, 0x5f, 0x57, 0xc2, 0x13, 0xdf, 0x84, 0xf4, 0xb2,
];

/// The uncompressed SEC1 form of the RFC 7515 Appendix A.3.1 public key —
/// `0x04 || x || y`, with `x` and `y` the JWK's own base64url members decoded.
/// Deriving it proves [`NOTARY_SCALAR`] is that JWK's `d`.
const RFC_7515_PUBLIC_POINT: [u8; 65] = [
  0x04, 0x7f, 0xcd, 0xce, 0x27, 0x70, 0xf6, 0xc4, 0x5d, 0x41, 0x83, 0xcb, 0xee, 0x6f, 0xdb, 0x4b,
  0x7b, 0x58, 0x07, 0x33, 0x35, 0x7b, 0xe9, 0xef, 0x13, 0xba, 0xcf, 0x6e, 0x3c, 0x7b, 0xd1, 0x54,
  0x45, 0xc7, 0xf1, 0x44, 0xcd, 0x1b, 0xbd, 0x9b, 0x7e, 0x87, 0x2c, 0xdf, 0xed, 0xb9, 0xee, 0xb9,
  0xf4, 0xb3, 0x69, 0x5d, 0x6e, 0xa9, 0x0b, 0x24, 0xad, 0x8a, 0x46, 0x23, 0x28, 0x85, 0x88, 0xe5,
  0xad,
];

/// Published file name.
const EXAMPLE_FILE: &str = "es256_signed_envelope.json";

/// Envelope id. The `…00e{1,2,3}` range is this vector's own. The rest of the
/// published register, so the next vector does not have to rediscover it:
/// `…000{1..8}` the channel examples, `…0009` the detached-JWS vector,
/// `…00c{1,2,3}` + `…00d2` the TypeScript-minted artifact, `…00d1` +
/// `…00f{1,2,3}` the Ed25519 golden. Reusing any of them would publish two
/// different objects under one identifier.
const ENVELOPE_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000e3";
/// Principal proof id — named by the notary proof's `previousProof`.
const PRINCIPAL_PROOF_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000e1";
/// Notary proof id.
const NOTARY_PROOF_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000e2";

/// The notary's verification method, matching the rest of the corpus: the
/// notary is a `did:web` service, and its ES256 public key is re-derivable
/// from RFC 7515 A.3.1 by anyone.
const NOTARY_VERIFICATION_METHOD: &str = "did:web:notary.squillo.com#key-1";

fn principal_signing_key() -> p256::ecdsa::SigningKey {
  p256::ecdsa::SigningKey::from_slice(&PRINCIPAL_SCALAR)
    .expect("the RFC 6979 A.2.5 scalar is in 1..n")
}

fn notary_signing_key() -> p256::ecdsa::SigningKey {
  p256::ecdsa::SigningKey::from_slice(&NOTARY_SCALAR)
    .expect("the RFC 7515 A.3.1 scalar is in 1..n")
}

/// The principal's `did:key`, DERIVED rather than transcribed.
///
/// A P-256 `did:key` is base58btc over a multicodec-prefixed COMPRESSED point,
/// which no human transcribes correctly; deriving it also welds the identifier
/// in the published file to the key that signs it, so the two cannot drift.
fn principal_did() -> std::string::String {
  aph_core::crypto::did_key::encode_p256(principal_signing_key().verifying_key())
}

/// An unsigned chain proof template. `type` and `cryptosuite` carry their
/// final values here so the template reads as the proof it becomes; the signer
/// writes both again before building the base, because both are inside the
/// signed bytes (§7.2.1).
fn proof_template() -> aph_core::EnvelopeProof {
  aph_core::EnvelopeProof {
    r#type: std::string::String::from("DataIntegrityProof"),
    cryptosuite: std::option::Option::Some(std::string::String::from(
      aph_core::crypto::ecdsa_jcs::CRYPTOSUITE,
    )),
    verification_method: std::string::String::new(),
    created: std::string::String::new(),
    proof_purpose: std::string::String::new(),
    proof_value: std::string::String::new(),
    id: std::option::Option::None,
    previous_proof: std::option::Option::None,
  }
}

/// Rebuilds and re-signs the whole vector from the constants above, in the
/// §7.2.1 issuance order: the notary prepares the envelope, the principal
/// signs it, the notary countersigns.
fn build_signed_envelope() -> aph_core::NotarizationEnvelope {
  let principal = principal_did();

  let mut principal_proof = proof_template();
  principal_proof.verification_method = std::format!(
    "{did}#{fragment}",
    did = principal,
    fragment = principal.trim_start_matches("did:key:")
  );
  principal_proof.created = std::string::String::from("2026-05-21T00:00:01Z");
  principal_proof.proof_purpose = std::string::String::from("assertionMethod");
  principal_proof.id = std::option::Option::Some(std::string::String::from(PRINCIPAL_PROOF_ID));

  let mut notary_proof = proof_template();
  notary_proof.verification_method =
    std::string::String::from(NOTARY_VERIFICATION_METHOD);
  notary_proof.created = std::string::String::from("2026-05-21T00:00:02Z");
  notary_proof.proof_purpose = std::string::String::from("authentication");
  notary_proof.id = std::option::Option::Some(std::string::String::from(NOTARY_PROOF_ID));
  notary_proof.previous_proof =
    std::option::Option::Some(std::string::String::from(PRINCIPAL_PROOF_ID));

  let mut envelope = aph_core::NotarizationEnvelope {
    aph_version: std::string::String::from("0.1"),
    context: std::vec![
      std::string::String::from("https://www.w3.org/ns/credentials/v2"),
      std::string::String::from("https://w3id.org/aph/v1"),
    ],
    r#type: std::vec![
      std::string::String::from("VerifiableCredential"),
      std::string::String::from("AgentSendAuthorizationCredential"),
    ],
    id: std::string::String::from(ENVELOPE_ID),
    // In PrincipalSigned mode the ISSUER is the human (§7.1.7): the human is
    // the issuing authority in substance, the notary a witness.
    issuer: principal.clone(),
    valid_from: std::string::String::from("2026-05-21T00:00:00Z"),
    valid_until: std::string::String::from("2026-05-21T00:10:00Z"),
    credential_subject: aph_core::CredentialSubject {
      human_principal: aph_core::HumanPrincipalRef {
        id: principal,
        display_name: std::string::String::from("Scott Wyatt"),
      },
      agent: aph_core::AgentRef {
        id: std::string::String::from("did:web:agent.squillo.com"),
        agent_card_uri: std::option::Option::Some(std::string::String::from(
          "https://agent.squillo.com/.well-known/agent-card.json",
        )),
        display_name: std::string::String::from("Squillo Concierge"),
        version: std::string::String::from("1.0"),
      },
      channel: aph_core::ChannelDescriptor {
        kind: aph_core::ChannelKind::Slack,
        // Keys in sorted order: serde_json objects are BTreeMaps, so the
        // serializer emits them sorted and the published file must match.
        recipient_addressing: serde_json::json!({
          "channelId": "C01234567",
          "parentTs": "1716249600.000100",
          "teamId": "T01234567"
        }),
        recipient_class: std::option::Option::None,
      },
      communication: aph_core::CommunicationDescriptor {
        content_class: aph_core::ContentClass::Reply,
        // The SHA-256 of the empty string, as every shape-only example in the
        // corpus carries. This vector is about the SUITE, not about §8.3's
        // body-hash binding, and claiming otherwise would overstate it.
        body_sha256: std::string::String::from(
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        body_size: 1842,
        preview_lines: 1,
        preview: std::string::String::from("prod rollout finished at 14:02 UTC"),
      },
      policy: aph_core::PolicyDescriptor {
        decision: aph_core::PolicyDecision::AlwaysAllow,
        matched_scope: std::string::String::from("per-channel"),
        // No mandate, embedded or referenced: see the file docs. §7.1.7.1's
        // binding rule is exercised by the Ed25519 golden.
        delegation_mandate_id: std::option::Option::None,
        act_chain: std::vec::Vec::new(),
        attestation_mode: std::option::Option::Some(aph_core::AttestationMode::PrincipalSigned),
        delegation_mandate: std::option::Option::None,
      },
      notarization: aph_core::NotarizationMetadata {
        notary_service: aph_core::NotaryServiceRef {
          id: std::string::String::from("did:web:notary.squillo.com"),
          name: std::string::String::from("Squillo Notary Service"),
          version: std::string::String::from("0.1.0"),
          attested_digest: std::option::Option::None,
          attestation_uri: std::option::Option::None,
        },
        decision_timestamp: std::string::String::from("2026-05-21T00:00:00Z"),
        decision_latency_ms: 12,
      },
      apple_aur_acceptance: std::option::Option::None,
      audience: std::option::Option::None,
      sealed_payload: std::option::Option::None,
      act_classification: std::option::Option::None,
    },
    linked_mandate: std::option::Option::None,
    credential_status: std::option::Option::None,
    proof: aph_core::EnvelopeProofs::Chain(std::vec![principal_proof, notary_proof]),
  };

  aph_core::crypto::ecdsa_jcs::sign_as_principal(&mut envelope, &principal_signing_key())
    .expect("the principal signs the prepared envelope");
  aph_core::crypto::ecdsa_jcs::countersign_as_notary(&mut envelope, &notary_signing_key())
    .expect("the notary countersigns the principal's proof");
  envelope
}

#[test]
fn the_scalars_are_the_published_vectors_their_documents_print() {
  // Pins the "published test key" property itself. If either scalar were
  // swapped for unpublished key material, this vector would silently depend on
  // a secret — the one thing a public test fixture must never do. Each is
  // checked against something its own RFC prints, so neither can be replaced
  // by a plausible-looking 32 bytes.
  let sample: p256::ecdsa::Signature =
    p256::ecdsa::signature::Signer::sign(&principal_signing_key(), b"sample");
  std::assert_eq!(
    sample.to_bytes().as_slice(),
    RFC_6979_SAMPLE_SIGNATURE.as_slice(),
    "the principal scalar must be the RFC 6979 A.2.5 sample key"
  );
  std::assert_eq!(
    notary_signing_key()
      .verifying_key()
      .to_encoded_point(false)
      .as_bytes(),
    RFC_7515_PUBLIC_POINT.as_slice(),
    "the notary scalar must be the `d` of the RFC 7515 A.3.1 ES256 JWK"
  );
}

#[test]
fn the_principal_did_is_a_compressed_p256_did_key() {
  // The identifier in the published file is DERIVED from the key that signs
  // it, so this cannot check a transcription. What it can check is the
  // encoding: the `0x1200` multicodec over a COMPRESSED point always yields
  // `did:key:zDn…`, and the uncompressed form would produce a different
  // identifier for the same key that no other implementation would resolve.
  let did = principal_did();
  std::assert!(did.starts_with("did:key:zDn"), "got {}", did);
  std::assert!(
    std::matches!(
      aph_core::decode_did_key(&did).expect("the derived DID decodes"),
      aph_core::DecodedDidKey::P256(_)
    ),
    "the principal DID must decode as a P-256 key"
  );
}

#[test]
fn the_published_vector_is_byte_identical_to_what_the_signing_code_mints() {
  // The golden-that-cannot-drift gate, and the file's materializer: the
  // committed bytes and the signing code describe the same credential ONLY
  // while this holds. Byte comparison is legitimate here because `p256` is
  // RFC 6979 deterministic — see this file's docs; under a randomized signer
  // this test would fail on every run and mean nothing.
  generator_support::assert_matches_published(
    &generator_support::example_path(EXAMPLE_FILE),
    &generator_support::published_form(&build_signed_envelope()),
  );
}

#[test]
fn the_published_vector_verifies_end_to_end() {
  // What an implementer in another language must be able to reproduce, run
  // FROM THE PUBLISHED BYTES rather than from the in-memory envelope: the
  // §7.1.11 structure, the mode, both ES256 proofs under their own keys, and
  // the §7.2.1 issuance order. If this failed, the repository would be handing
  // implementers a vector its own reference implementation refuses.
  let envelope = generator_support::parse_published(&generator_support::example_path(EXAMPLE_FILE));
  let principal_vk = *principal_signing_key().verifying_key();
  let notary_vk = *notary_signing_key().verifying_key();

  std::assert_eq!(
    aph_core::verify_proof_structure(&envelope)
      .expect("the vector must satisfy the §7.1.11 structural rules"),
    aph_core::AttestationMode::PrincipalSigned
  );
  aph_core::crypto::ecdsa_jcs::verify_proof(
    &envelope,
    aph_core::ProofRole::Principal,
    &principal_vk,
  )
  .expect("the principal proof must verify under the principal's key");
  aph_core::crypto::ecdsa_jcs::verify_proof(
    &envelope,
    aph_core::ProofRole::Notary,
    &notary_vk,
  )
  .expect("the notary countersignature must verify under the notary's key");
  aph_core::verify_timestamp_order(&envelope)
    .expect("decisionTimestamp <= principal.created <= notary.created must hold");
}

#[test]
fn every_proof_declares_the_suite_and_carries_p1363_bytes_not_der() {
  // §8.2's encoding for this suite, asserted on the SHIPPED bytes rather than
  // in prose: P1363 `r‖s` is exactly 64 bytes, while the DER form this same
  // crate uses for Delegation Mandates and inside a detached JWS is 70–72 and
  // variable. A vector that shipped DER would round-trip the reference
  // implementation and interoperate with nothing.
  let envelope = generator_support::parse_published(&generator_support::example_path(EXAMPLE_FILE));
  for proof in envelope.proof.all() {
    std::assert_eq!(proof.r#type, "DataIntegrityProof");
    std::assert_eq!(
      proof.cryptosuite.as_deref(),
      std::option::Option::Some("ecdsa-jcs-2019")
    );
    let raw = aph_core::crypto::multibase::base58btc_decode(&proof.proof_value)
      .expect("a proofValue is multibase base58btc");
    std::assert_eq!(
      raw.len(),
      64,
      "an ecdsa-jcs-2019 proofValue is P1363 r||s, not DER"
    );
  }
}

#[test]
fn the_ed25519_verifier_refuses_this_vector_by_name() {
  // The downgrade guard the two suites exist to give each other, exercised
  // across published files: the default `eddsa-jcs-2022` verifier must refuse
  // this envelope as an UNSUPPORTED ALGORITHM (APH_E010) rather than decoding
  // 64 P-256 bytes as an Ed25519 signature and reporting a bad signature. An
  // operator reading APH_E001 would go looking for a key problem.
  let envelope = generator_support::parse_published(&generator_support::example_path(EXAMPLE_FILE));
  let unrelated = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
  std::assert_eq!(
    aph_core::verify_proof(&envelope, aph_core::ProofRole::Notary, &unrelated)
      .expect_err("an ES256 proof is not an Ed25519 proof")
      .code(),
    "APH_E010"
  );
}

#[test]
fn tampering_with_the_published_bytes_breaks_both_proofs() {
  // The property the whole protocol rests on, checked on the second curve and
  // in both chain positions: a credential must not authorize a message it did
  // not cover. Editing the body hash is the smallest edit an attacker would
  // want, and it must invalidate the human's proof — not merely the notary's.
  let mut envelope =
    generator_support::parse_published(&generator_support::example_path(EXAMPLE_FILE));
  envelope.credential_subject.communication.body_sha256 = "0".repeat(64);
  let principal_vk = *principal_signing_key().verifying_key();
  let notary_vk = *notary_signing_key().verifying_key();
  std::assert_eq!(
    aph_core::crypto::ecdsa_jcs::verify_proof(
      &envelope,
      aph_core::ProofRole::Principal,
      &principal_vk
    )
    .expect_err("the principal never signed the edited bytes")
    .code(),
    "APH_E011"
  );
  std::assert_eq!(
    aph_core::crypto::ecdsa_jcs::verify_proof(
      &envelope,
      aph_core::ProofRole::Notary,
      &notary_vk
    )
    .expect_err("the notary never signed the edited bytes")
    .code(),
    "APH_E001"
  );
}
