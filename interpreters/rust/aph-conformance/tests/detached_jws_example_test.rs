//! `examples/detached_jws_envelope.json` — the `JsonWebSignature2020` vector.
//!
//! §8.2 gives APH two proof-block formats. Data Integrity puts multibase
//! signature bytes in `proofValue`; this one puts a **compact detached JWS**
//! there instead, over the SAME §7.2.1 canonicalization base. Until this file
//! there was no published byte string for the second format anywhere — the
//! type name appeared in serde and in one parse test, and nothing dispatched
//! envelope verification to the JWS primitive at all.
//!
//! # It verifies with no network at all
//!
//! `issuer` is the notary's own `did:key`, so a stranger holding nothing but
//! this file can decode the P-256 point out of the identifier and check the
//! signature (§8.4.6's first mechanism). That path is exercised below through
//! `verify_envelope_did_key`, which had to learn to route a P-256 issuer for
//! this vector to exist.
//!
//! # ⛔ Two deployed quirks are PRESERVED, not fixed
//!
//! The vector is whatever `aph_core::verify_detached_jws` accepts, because
//! that function is the deployed AP2-interop wire and "cleaning it up" would
//! fork it. Both quirks are visible in these bytes and both are pinned below:
//!
//! - the protected header declares `"b64":false` with `"crit":["b64"]`
//!   (RFC 7797 unencoded payload) while the payload is nevertheless
//!   base64url-encoded into the signing input;
//! - the ES256 signature inside the JWS is **DER**, not the raw `r‖s` RFC 7518
//!   specifies — even though the very same crate encodes an `ecdsa-jcs-2019`
//!   `proofValue` as `r‖s`. The encoding follows the CARRIAGE, not the
//!   algorithm.
//!
//! An implementer who writes a standards-pure RFC 7518 signer will produce a
//! token this vector's verifier rejects. That is a real interoperability cost
//! and it is stated rather than hidden.
//!
//! # Determinism
//!
//! `p256` is RFC 6979 deterministic — the nonce comes from the key and the
//! message, not from an RNG — so the header, the empty payload section and the
//! signature are all byte-stable and this file can be a byte-comparable
//! golden. Most ECDSA is randomized; without RFC 6979 the byte comparison
//! below would fail on every run.
//!
//! ZERO `#[ignore]`. ZERO `use` statements.

mod generator_support;

/// The NOTARY's key: the `d` value of the ES256 example JWK in RFC 7515
/// Appendix A.3.1 — a published test vector that authorizes nothing, and the
/// same scalar `examples/es256_signed_envelope.json` gives the notary, so
/// "the notary" means one key across the published corpus.
///
/// ⛔ A P-256 scalar cannot be a repeated-byte fake the way an Ed25519 seed
/// can: it must lie in `1..n`. That is why this cites a document.
const NOTARY_SCALAR: [u8; 32] = [
  0x8e, 0x9b, 0x10, 0x9e, 0x71, 0x90, 0x98, 0xbf, 0x98, 0x04, 0x87, 0xdf, 0x1f, 0x5d, 0x77, 0xe9,
  0xcb, 0x29, 0x60, 0x6e, 0xbe, 0xd2, 0x26, 0x3b, 0x5f, 0x57, 0xc2, 0x13, 0xdf, 0x84, 0xf4, 0xb2,
];

/// The uncompressed SEC1 form of the RFC 7515 Appendix A.3.1 public key —
/// `0x04 || x || y`, with `x` and `y` the JWK's own base64url members decoded.
/// Deriving it proves [`NOTARY_SCALAR`] is that JWK's `d` and not a stray
/// scalar.
const RFC_7515_PUBLIC_POINT: [u8; 65] = [
  0x04, 0x7f, 0xcd, 0xce, 0x27, 0x70, 0xf6, 0xc4, 0x5d, 0x41, 0x83, 0xcb, 0xee, 0x6f, 0xdb, 0x4b,
  0x7b, 0x58, 0x07, 0x33, 0x35, 0x7b, 0xe9, 0xef, 0x13, 0xba, 0xcf, 0x6e, 0x3c, 0x7b, 0xd1, 0x54,
  0x45, 0xc7, 0xf1, 0x44, 0xcd, 0x1b, 0xbd, 0x9b, 0x7e, 0x87, 0x2c, 0xdf, 0xed, 0xb9, 0xee, 0xb9,
  0xf4, 0xb3, 0x69, 0x5d, 0x6e, 0xa9, 0x0b, 0x24, 0xad, 0x8a, 0x46, 0x23, 0x28, 0x85, 0x88, 0xe5,
  0xad,
];

/// Published file name.
const EXAMPLE_FILE: &str = "detached_jws_envelope.json";

/// Envelope id. The `…0009` slot is this vector's own — it continues the plain
/// numeric run rather than taking a letter block, because every letter block in
/// the published corpus is already spoken for: `…000{1..8}` the channel
/// examples, `…00c{1,2,3}` + `…00d2` the TypeScript-minted artifact, `…00d1` +
/// `…00f{1,2,3}` the Ed25519 golden, `…00e{1,2,3}` the ES256 chain.
///
/// ⛔ This vector first claimed `…00c1`, which the TypeScript artifact was
/// concurrently using for its principal proof. One `urn:uuid` naming two
/// published objects makes the identifier useless as a reference, which is the
/// whole reason the corpus partitions the space at all.
const ENVELOPE_ID: &str = "urn:uuid:00000000-0000-4000-8000-000000000009";

/// The human this credential is about. A `did:key` from the corpus's own
/// sample set; nothing in this vector is signed by the human — a lone proof is
/// a NOTARY proof (§7.1.11), and that is exactly the claim being published.
const HUMAN_PRINCIPAL_DID: &str = "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy";

fn notary_signing_key() -> p256::ecdsa::SigningKey {
  p256::ecdsa::SigningKey::from_slice(&NOTARY_SCALAR)
    .expect("the RFC 7515 A.3.1 scalar is in 1..n")
}

/// The notary's `did:key`, DERIVED rather than transcribed — a P-256
/// identifier is base58btc over a multicodec-prefixed compressed point, which
/// no human transcribes correctly, and deriving it welds the identifier in the
/// published file to the key that signs it.
fn notary_did() -> std::string::String {
  aph_core::crypto::did_key::encode_p256(notary_signing_key().verifying_key())
}

/// Rebuilds and re-signs the vector from the constants above.
///
/// The proof carries no `id` and no `previousProof`, and its purpose is
/// `assertionMethod`: §7.1.11 requires all three of a single-object proof,
/// because a lone proof links to nothing and chain vocabulary on it is a claim
/// about a chain that does not exist.
fn build_signed_envelope() -> aph_core::NotarizationEnvelope {
  let issuer = notary_did();

  let proof = aph_core::EnvelopeProof {
    // Both labels are rewritten by the signer before the base is built
    // (§7.2.1 puts them inside the signed bytes); they carry their final
    // values here so the template reads as the proof it becomes.
    r#type: std::string::String::from(aph_core::crypto::jws_envelope::PROOF_TYPE),
    // §7.1.11: `cryptosuite` is omitted for `JsonWebSignature2020`.
    cryptosuite: std::option::Option::None,
    verification_method: std::format!(
      "{did}#{fragment}",
      did = issuer,
      fragment = issuer.trim_start_matches("did:key:")
    ),
    created: std::string::String::from("2026-05-21T00:00:01Z"),
    proof_purpose: std::string::String::from("assertionMethod"),
    proof_value: std::string::String::new(),
    id: std::option::Option::None,
    previous_proof: std::option::Option::None,
  };

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
    // NotaryAttested (§7.1.7): the NOTARY is the issuer, and the issuer DID is
    // what a verifier resolves the signing key from.
    issuer,
    valid_from: std::string::String::from("2026-05-21T00:00:00Z"),
    valid_until: std::string::String::from("2026-05-22T00:00:00Z"),
    credential_subject: aph_core::CredentialSubject {
      human_principal: aph_core::HumanPrincipalRef {
        id: std::string::String::from(HUMAN_PRINCIPAL_DID),
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
        kind: aph_core::ChannelKind::Email,
        // Keys in sorted order: serde_json objects are BTreeMaps, so the
        // serializer emits them sorted and the published file must match.
        recipient_addressing: serde_json::json!({
          "inReplyTo": "<CA+abc123@mail.example.com>",
          "subject": "Re: Q3 rollout timeline",
          "to": ["ops@example.com"]
        }),
      },
      communication: aph_core::CommunicationDescriptor {
        content_class: aph_core::ContentClass::Reply,
        // The SHA-256 of the empty string, as every shape-only example in the
        // corpus carries. This vector is about the §8.2 CARRIAGE, not about
        // §8.3's body-hash binding, and claiming otherwise would overstate it.
        body_sha256: std::string::String::from(
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        body_size: 947,
        preview_lines: 1,
        preview: std::string::String::from("Confirming the Thursday freeze window."),
      },
      policy: aph_core::PolicyDescriptor {
        decision: std::string::String::from("AlwaysAllow"),
        matched_scope: std::string::String::from("per-channel"),
        delegation_mandate_id: std::option::Option::None,
        act_chain: std::vec::Vec::new(),
        // Absent means NotaryAttested (§7.1.7), and §7.1.11 forbids a
        // single-object proof from claiming anything stronger.
        attestation_mode: std::option::Option::None,
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
        decision_latency_ms: 31,
      },
      apple_aur_acceptance: std::option::Option::None,
    },
    linked_mandate: std::option::Option::None,
    credential_status: std::option::Option::None,
    proof: aph_core::EnvelopeProofs::Single(proof),
  };

  aph_core::crypto::jws_envelope::sign_envelope(&mut envelope, &notary_signing_key())
    .expect("the notary signs its lone proof as a detached JWS");
  envelope
}

/// The lone proof of the published vector.
fn published_proof() -> aph_core::EnvelopeProof {
  generator_support::parse_published(&generator_support::example_path(EXAMPLE_FILE))
    .proof
    .notary()
    .expect("a NotaryAttested vector carries a lone notary proof")
    .clone()
}

#[test]
fn the_scalar_is_the_published_vector_its_document_prints() {
  // Pins the "published test key" property itself: if this scalar were ever
  // swapped for unpublished key material, the vector would silently depend on
  // a secret — the one thing a public test fixture must never do — and every
  // other test in this file would still pass.
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
fn the_published_vector_is_byte_identical_to_what_the_signing_code_mints() {
  // The golden-that-cannot-drift gate, and the file's materializer. Byte
  // comparison is legitimate here only because `p256` is RFC 6979
  // deterministic — see this file's docs; a randomized signer would fail this
  // on every run while nothing was actually wrong.
  generator_support::assert_matches_published(
    &generator_support::example_path(EXAMPLE_FILE),
    &generator_support::published_form(&build_signed_envelope()),
  );
}

#[test]
fn the_published_vector_verifies_offline_from_its_issuer_alone() {
  // The whole point of the file, run FROM THE PUBLISHED BYTES: a stranger with
  // this JSON and no network decodes the P-256 point out of `issuer` and
  // checks the signature. Before the ES256 carriages existed, a P-256 `did:key`
  // issuer was refused outright here, so this is also the regression guard on
  // that dispatch.
  let envelope = generator_support::parse_published(&generator_support::example_path(EXAMPLE_FILE));
  std::assert_eq!(
    aph_core::verify_proof_structure(&envelope)
      .expect("the vector must satisfy the §7.1.11 structural rules"),
    aph_core::AttestationMode::NotaryAttested
  );
  aph_core::verify_envelope_did_key(&envelope)
    .expect("a detached-JWS envelope from a P-256 did:key issuer verifies with no network");
}

#[test]
fn the_proof_value_is_the_vendored_primitive_over_the_shared_signing_base() {
  // §8.2's claim in one assertion: the JWS covers the SAME §7.2.1 base a Data
  // Integrity proof would, and the envelope carriage adds nothing to the
  // vendored primitive but a protected header. Checked by handing the
  // published `proofValue` and the recomputed base straight to
  // `verify_detached_jws` — if the envelope layer ever derived its own base,
  // this passes nowhere.
  let envelope = generator_support::parse_published(&generator_support::example_path(EXAMPLE_FILE));
  let base = aph_core::signing_base(&envelope, aph_core::ProofRole::Notary)
    .expect("a lone notary base is always constructible");
  let key = *notary_signing_key().verifying_key();
  std::assert!(
    aph_core::verify_detached_jws(
      &envelope.proof.notary().expect("lone proof").proof_value,
      base.as_bytes(),
      &key
    ),
    "the published proofValue must verify as a detached JWS over the §7.2.1 base"
  );
}

#[test]
fn the_token_is_detached_and_its_header_carries_every_member_section_8_2_requires() {
  // "Detached" is the property §8.2 chose this format for: the payload travels
  // as the envelope itself and the middle section is empty, so a regression
  // that embedded the base would put a full copy of the envelope inside the
  // envelope. The six header members are §8.3 step 7's material — a verifier
  // that never read them has no answer to `alg: none` — and `kid` is pinned to
  // the proof's own `verificationMethod` so a bare token resolves to the same
  // key the envelope names.
  let proof = published_proof();
  let sections: std::vec::Vec<&str> = proof.proof_value.split('.').collect();
  std::assert_eq!(sections.len(), 3, "compact serialization has three sections");
  std::assert!(sections[1].is_empty(), "the payload section must be empty");

  let decoded = decode_base64url(sections[0]);
  let header: serde_json::Value =
    serde_json::from_slice(&decoded).expect("the protected header is a JSON object");
  std::assert_eq!(
    header,
    serde_json::json!({
      "alg": "ES256",
      "b64": false,
      "crit": ["b64"],
      "cty": "vc+ld+json",
      "kid": proof.verification_method,
      "typ": "aph+jws",
    })
  );
}

#[test]
fn the_published_proof_omits_cryptosuite_rather_than_nulling_it() {
  // ⛔ §7.1.11's proof table says `cryptosuite` is "Omitted for
  // `JsonWebSignature2020`", and `"cryptosuite": null` is not omitted. It is
  // also not free: the member sits inside the §7.2.1 canonicalization base, so
  // an implementer who follows the table and builds a base without it computes
  // different bytes and cannot verify this vector at all. Every other §8.1
  // path is unaffected — only a JWS proof has an absent `cryptosuite` — which
  // is why nothing caught this until a JWS envelope was first minted.
  //
  // `EnvelopeProof::cryptosuite` carries `skip_serializing_if` for exactly
  // that reason, and states it at the field; this test is the tripwire on the
  // PUBLISHED bytes, so removing the attribute fails here rather than only in
  // a unit test of the type.
  //
  // Asserted on the RAW JSON rather than through the typed model, because the
  // model cannot tell absent from null — which is the whole bug.
  let path = generator_support::example_path(EXAMPLE_FILE);
  let json = match generator_support::published_bytes(&path) {
    std::option::Option::Some(json) => json,
    std::option::Option::None => std::panic!(
      "{:?} has not been materialized yet; run this file's byte-identity test",
      path
    ),
  };
  let value: serde_json::Value =
    serde_json::from_str(&json).unwrap_or_else(|e| std::panic!("{:?} is not JSON: {}", path, e));
  let proof = value
    .get("proof")
    .and_then(serde_json::Value::as_object)
    .expect("a NotaryAttested vector carries a single-object `proof`");
  std::assert!(
    !proof.contains_key("cryptosuite"),
    "§7.1.11 omits `cryptosuite` for JsonWebSignature2020; the published proof carries it as {:?}",
    proof.get("cryptosuite")
  );
}

#[test]
fn the_signature_inside_the_token_is_der_and_that_is_the_deployed_quirk() {
  // ⛔ The interoperability cost, asserted rather than described: RFC 7518
  // specifies raw `r‖s` (64 bytes) for ES256 inside a JWS, and this dialect
  // carries DER (70–72, variable). The SAME crate emits `r‖s` for an
  // `ecdsa-jcs-2019` `proofValue`, so the encoding follows the carriage rather
  // than the algorithm. A "consistency" cleanup in either direction forks a
  // deployed wire, and only a test that pins the difference stops it.
  let proof = published_proof();
  let signature = decode_base64url(
    proof
      .proof_value
      .rsplit('.')
      .next()
      .expect("a compact JWS ends with its signature section"),
  );
  std::assert_ne!(
    signature.len(),
    64,
    "the JWS signature section carries DER, not RFC 7518 r||s"
  );
  std::assert_eq!(
    signature.first(),
    std::option::Option::Some(&0x30u8),
    "a DER SEQUENCE starts with 0x30"
  );
}

#[test]
fn tampering_with_the_published_bytes_breaks_the_signature() {
  // The property the whole protocol rests on, through the second carriage: a
  // credential must not authorize a message it did not cover. APH_E001 rather
  // than a generic failure, because a lone proof is a notary proof and the
  // code a verifier reports must not depend on which format failed.
  let mut envelope =
    generator_support::parse_published(&generator_support::example_path(EXAMPLE_FILE));
  envelope.credential_subject.communication.body_sha256 = "0".repeat(64);
  std::assert_eq!(
    aph_core::verify_envelope_did_key(&envelope)
      .expect_err("the notary never signed the edited bytes")
      .code(),
    "APH_E001"
  );
}

#[test]
fn the_data_integrity_verifier_refuses_this_vector_by_name() {
  // Cross-carriage dispatch guard, exercised across published files: the
  // default `eddsa-jcs-2022` verifier must refuse a `JsonWebSignature2020`
  // proof as an UNSUPPORTED ALGORITHM (APH_E010) rather than feeding a JWS
  // string to the base58 decoder and reporting a bad Ed25519 signature. An
  // operator reading APH_E001 would go looking for a key problem.
  let envelope = generator_support::parse_published(&generator_support::example_path(EXAMPLE_FILE));
  let unrelated = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
  std::assert_eq!(
    aph_core::verify_envelope(&envelope, &unrelated)
      .expect_err("a detached JWS is not an eddsa-jcs-2022 proofValue")
      .code(),
    "APH_E010"
  );
}

/// Base64url (RFC 4648 §5, unpadded) — the JWS section encoding.
///
/// Decoded through the `base64` crate rather than through `aph-core`, whose
/// helper is crate-private on purpose: a published vector that could only be
/// read with the reference implementation's internals would not be much of a
/// vector, and this is the same decode a third-party implementer writes.
fn decode_base64url(section: &str) -> std::vec::Vec<u8> {
  base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, section)
    .unwrap_or_else(|e| std::panic!("{:?} is not unpadded base64url: {}", section, e))
}
