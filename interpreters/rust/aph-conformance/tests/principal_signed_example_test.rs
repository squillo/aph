//! The first signed `PrincipalSigned` golden — spec §7.3.1, made real.
//!
//! `examples/principal_signed_envelope.json` is the §7.3.1 worked example
//! with every placeholder signature replaced by a REAL Ed25519 signature:
//! the human principal signs the envelope the notary prepared, the notary
//! countersigns the result, and the embedded Delegation Mandate carries both
//! of its §6.1 signatures. The ids and timestamps are the worked example's
//! own values, so the spec's prose and the published bytes describe the same
//! credential.
//!
//! Every key is derived from a FIXED, PUBLIC test seed — RFC 8032 §7.1
//! TEST 2 (the principal) and TEST 3 (the notary). These are the RFC's own
//! published vectors: they authorize nothing, and using them means anyone
//! can re-derive every byte of the golden with no secret material at all.
//!
//! The golden cannot drift from the signing code: this suite REBUILDS the
//! envelope from constants, re-signs it through `aph-core`'s own signing
//! path, and byte-compares the result with the committed file. On mismatch
//! the failure message prints the complete regenerated content so the file
//! can be corrected in one step.
//!
//! ZERO `#[ignore]`. ZERO `use` statements.

/// RFC 8032 §7.1 TEST 2 secret seed — the HUMAN PRINCIPAL's key. A public
/// test vector, never a production key.
const PRINCIPAL_SEED: [u8; 32] = [
  0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
  0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];

/// RFC 8032 §7.1 TEST 2 public key, as the RFC states it — pins that
/// `PRINCIPAL_SEED` really is the published vector and not a stray key.
const PRINCIPAL_PUBLIC_KEY: [u8; 32] = [
  0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
  0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];

/// RFC 8032 §7.1 TEST 3 secret seed — the NOTARY's key. A public test
/// vector, never a production key.
const NOTARY_SEED: [u8; 32] = [
  0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
  0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
];

/// RFC 8032 §7.1 TEST 3 public key, as the RFC states it.
const NOTARY_PUBLIC_KEY: [u8; 32] = [
  0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
  0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
];

/// The principal's `did:key`, derived from `PRINCIPAL_PUBLIC_KEY`. In
/// `PrincipalSigned` mode this DID is the `issuer`, the `humanPrincipal.id`,
/// and the DID of the principal proof's `verificationMethod` — §7.1.11 makes
/// a verifier check all three agree.
const PRINCIPAL_DID: &str = "did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT";

/// Envelope id — the §7.3.1 worked example's own value.
const ENVELOPE_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000f3";
/// Embedded Delegation Mandate id — the §7.3.1 worked example's own value.
const MANDATE_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000d1";
/// Principal proof id — the §7.3.1 worked example's own value.
const PRINCIPAL_PROOF_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000f1";
/// Notary proof id — the §7.3.1 worked example's own value.
const NOTARY_PROOF_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000f2";

/// Absolute path of the published golden.
fn example_path() -> std::path::PathBuf {
  std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("../../../examples/principal_signed_envelope.json")
}

/// The principal's signing key, from the fixed public seed.
fn principal_signing_key() -> ed25519_dalek::SigningKey {
  ed25519_dalek::SigningKey::from_bytes(&PRINCIPAL_SEED)
}

/// The notary's signing key, from the fixed public seed.
fn notary_signing_key() -> ed25519_dalek::SigningKey {
  ed25519_dalek::SigningKey::from_bytes(&NOTARY_SEED)
}

/// Parses the committed golden file.
fn published_envelope() -> aph_core::NotarizationEnvelope {
  let path = example_path();
  let json = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
  serde_json::from_str(&json)
    .unwrap_or_else(|e| std::panic!("{:?} failed strict parse: {}", path, e))
}

/// Signs one mandate role over its §7.2.1 base and multibase-encodes it —
/// the same construction `aph_core::mandate_signing_base` documents, applied
/// with Ed25519 because every proof in this golden is `eddsa-jcs-2022`.
fn sign_mandate_role(
  mandate: &aph_core::DelegationMandate,
  role: aph_core::ProofRole,
  key: &ed25519_dalek::SigningKey,
) -> String {
  let base = aph_core::mandate_signing_base(mandate, role)
    .expect("a serializable mandate always has a signing base");
  let signature: ed25519_dalek::Signature = ed25519_dalek::Signer::sign(key, base.as_bytes());
  aph_core::crypto::multibase::base58btc_encode(&signature.to_bytes())
}

/// Verifies one mandate signature against its §7.2.1 base.
fn mandate_role_verifies(
  mandate: &aph_core::DelegationMandate,
  role: aph_core::ProofRole,
  key: &ed25519_dalek::VerifyingKey,
) -> bool {
  let base = aph_core::mandate_signing_base(mandate, role)
    .expect("a serializable mandate always has a signing base");
  let encoded = match role {
    aph_core::ProofRole::Principal => &mandate.principal_signature,
    aph_core::ProofRole::Notary => &mandate.notary_signature,
  };
  let raw = match aph_core::crypto::multibase::base58btc_decode(encoded) {
    std::result::Result::Ok(bytes) => bytes,
    std::result::Result::Err(_) => return false,
  };
  let bytes: [u8; 64] = match std::convert::TryInto::try_into(raw.as_slice()) {
    std::result::Result::Ok(b) => b,
    std::result::Result::Err(_) => return false,
  };
  let signature = ed25519_dalek::Signature::from_bytes(&bytes);
  ed25519_dalek::Verifier::verify(key, base.as_bytes(), &signature).is_ok()
}

/// The embedded Delegation Mandate of §7.3.1, with BOTH §6.1 signatures
/// computed for real: the principal signs the form minus both signature
/// members, then the notary countersigns with `principalSignature` present.
fn signed_mandate() -> aph_core::DelegationMandate {
  let mut mandate = aph_core::DelegationMandate {
    id: std::string::String::from(MANDATE_ID),
    human_principal_did: std::string::String::from(PRINCIPAL_DID),
    agent_did: std::string::String::from("did:web:agent.squillo.com"),
    allowed_channels: std::vec![std::string::String::from("slack")],
    rate_limit_per_hour: std::option::Option::Some(20),
    valid_from: std::string::String::from("2026-05-20T00:00:00Z"),
    valid_until: std::string::String::from("2026-05-22T00:00:00Z"),
    // Both bases REMOVE their members (§7.2.1), so these placeholders never
    // reach the signed bytes.
    principal_signature: std::string::String::new(),
    notary_signature: std::string::String::new(),
  };
  mandate.principal_signature =
    sign_mandate_role(&mandate, aph_core::ProofRole::Principal, &principal_signing_key());
  mandate.notary_signature =
    sign_mandate_role(&mandate, aph_core::ProofRole::Notary, &notary_signing_key());
  mandate
}

/// An unsigned chain proof template shared by both positions.
fn proof_template() -> aph_core::EnvelopeProof {
  aph_core::EnvelopeProof {
    r#type: std::string::String::from("DataIntegrityProof"),
    cryptosuite: std::option::Option::Some(std::string::String::from("eddsa-jcs-2022")),
    verification_method: std::string::String::new(),
    created: std::string::String::new(),
    proof_purpose: std::string::String::new(),
    proof_value: std::string::String::new(),
    id: std::option::Option::None,
    previous_proof: std::option::Option::None,
  }
}

/// Rebuilds and re-signs the entire golden from constants, through the same
/// `aph-core` code path a real notary deployment uses: the notary prepares
/// the complete envelope, the principal signs it, the notary countersigns
/// (§7.2.1 issuance order).
fn build_signed_envelope() -> aph_core::NotarizationEnvelope {
  let mut principal = proof_template();
  principal.verification_method = std::format!(
    "{did}#{fragment}",
    did = PRINCIPAL_DID,
    fragment = PRINCIPAL_DID.trim_start_matches("did:key:")
  );
  principal.created = std::string::String::from("2026-05-21T00:00:01Z");
  principal.proof_purpose = std::string::String::from("assertionMethod");
  principal.id = std::option::Option::Some(std::string::String::from(PRINCIPAL_PROOF_ID));

  let mut notary = proof_template();
  notary.verification_method = std::string::String::from("did:web:notary.squillo.com#key-1");
  notary.created = std::string::String::from("2026-05-21T00:00:02Z");
  notary.proof_purpose = std::string::String::from("authentication");
  notary.id = std::option::Option::Some(std::string::String::from(NOTARY_PROOF_ID));
  notary.previous_proof = std::option::Option::Some(std::string::String::from(PRINCIPAL_PROOF_ID));

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
    issuer: std::string::String::from(PRINCIPAL_DID),
    valid_from: std::string::String::from("2026-05-21T00:00:00Z"),
    valid_until: std::string::String::from("2026-05-22T00:00:00Z"),
    credential_subject: aph_core::CredentialSubject {
      human_principal: aph_core::HumanPrincipalRef {
        id: std::string::String::from(PRINCIPAL_DID),
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
        kind: std::string::String::from("slack"),
        // Keys in sorted order: serde_json objects are BTreeMaps, so the
        // serializer emits them sorted and the golden must match.
        recipient_addressing: serde_json::json!({
          "channelId": "C01234567",
          "parentTs": "1716249600.000100",
          "teamId": "T01234567"
        }),
      },
      communication: aph_core::CommunicationDescriptor {
        content_class: std::string::String::from("Reply"),
        // The ONE published envelope whose body-hash binding is real: these
        // two values are the SHA-256 and exact byte length of the committed
        // `examples/principal_signed_body.txt`, so §8.3 step 8 finally has a
        // vector (every other fixture pairs the empty-string digest with a
        // fictional size and is shape-only by design). The pairing is pinned
        // by the body-hash binding test, which re-hashes the committed file —
        // change the body and BOTH constants here must move with it, which
        // regenerates all four signatures via this generator.
        body_sha256: std::string::String::from(
          "dae0b23f649c05222b955ff4752507c6d85a51e00566da4fea1867e50b3b60cb",
        ),
        body_size: 427,
        preview_lines: 1,
        preview: std::string::String::from("prod rollout finished at 14:02 UTC"),
      },
      policy: aph_core::PolicyDescriptor {
        decision: std::string::String::from("AlwaysAllow"),
        matched_scope: std::string::String::from("per-channel"),
        delegation_mandate_id: std::option::Option::Some(std::string::String::from(MANDATE_ID)),
        act_chain: std::vec::Vec::new(),
        attestation_mode: std::option::Option::Some(
          aph_core::AttestationMode::PrincipalSigned,
        ),
        delegation_mandate: std::option::Option::Some(signed_mandate()),
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
    },
    linked_mandate: std::option::Option::None,
    // Pattern A (§7.1.1): absent here means NO `credentialStatus` key on
    // the wire, which is what keeps this fixture byte-identical to the
    // pre-revocation shape its signatures were made over.
    credential_status: std::option::Option::None,
    proof: aph_core::EnvelopeProofs::Chain(std::vec![principal, notary]),
  };

  aph_core::sign_as_principal(&mut envelope, &principal_signing_key())
    .expect("the principal signs the prepared envelope");
  aph_core::countersign_as_notary(&mut envelope, &notary_signing_key())
    .expect("the notary countersigns the principal's proof");
  envelope
}

#[test]
fn the_seeds_are_the_rfc_8032_public_vectors_and_derive_the_golden_dids() {
  // Pins the "fixed public test seeds" property itself. If either seed
  // constant were ever swapped for unpublished key material, the derived
  // public keys would stop matching the RFC's stated vectors and the golden
  // would silently depend on a secret — the exact thing a public test
  // fixture must never do. Also welds seed → did:key: the DID inside the
  // golden must be DERIVED from the seed, not transcribed prose.
  let principal_vk = principal_signing_key().verifying_key();
  std::assert_eq!(
    principal_vk.to_bytes(),
    PRINCIPAL_PUBLIC_KEY,
    "the principal seed must derive the RFC 8032 TEST 2 public key"
  );
  std::assert_eq!(
    aph_core::did_key_from_ed25519(&principal_vk),
    PRINCIPAL_DID,
    "the golden's principal DID must be derived from the TEST 2 key"
  );
  let notary_vk = notary_signing_key().verifying_key();
  std::assert_eq!(
    notary_vk.to_bytes(),
    NOTARY_PUBLIC_KEY,
    "the notary seed must derive the RFC 8032 TEST 3 public key"
  );
}

#[test]
fn the_published_golden_is_byte_identical_to_what_the_signing_code_mints() {
  // The golden-that-cannot-drift gate. The committed file and the signing
  // code describe the same credential ONLY while this byte comparison
  // holds: a change to canonicalization, serde attributes, field order, or
  // the signing bases would mint different bytes here and fail loudly,
  // instead of leaving a published example no implementation can verify.
  let regenerated = std::format!(
    "{}\n",
    serde_json::to_string_pretty(&build_signed_envelope())
      .expect("the signed envelope serializes")
  );
  let path = example_path();
  let published = std::fs::read_to_string(&path)
    .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
  if published != regenerated {
    std::panic!(
      "examples/principal_signed_envelope.json has drifted from the bytes the \
       signing code mints.\nTo fix in ONE step, overwrite that file with EXACTLY \
       the content between the cut lines (the final newline is part of the \
       content):\n----8<----\n{}----8<----",
      regenerated
    );
  }
}

#[test]
fn the_published_golden_verifies_end_to_end() {
  // The first PrincipalSigned envelope anywhere in the ecosystem must pass
  // every §8.3.1 check a verifier runs, FROM THE PUBLISHED BYTES: structure
  // (§7.1.11), both envelope proofs, issuance order (§7.2.1), the embedded
  // mandate binding (§7.1.7.1), and both §6.1 mandate signatures. If any of
  // these failed, the repository would be teaching implementers a shape its
  // own reference implementation refuses.
  let envelope = published_envelope();
  let principal_vk = principal_signing_key().verifying_key();
  let notary_vk = notary_signing_key().verifying_key();

  let mode = aph_core::verify_proof_structure(&envelope)
    .expect("the golden must satisfy the §7.1.11 structural rules");
  std::assert_eq!(
    mode,
    aph_core::AttestationMode::PrincipalSigned,
    "the golden must verify as PrincipalSigned"
  );
  aph_core::require_mode(&envelope, aph_core::AttestationMode::PrincipalSigned)
    .expect("the golden must satisfy a PrincipalSigned-only policy");

  aph_core::verify_proof(&envelope, aph_core::ProofRole::Principal, &principal_vk)
    .expect("the principal proof must verify under the principal's key");
  aph_core::verify_proof(&envelope, aph_core::ProofRole::Notary, &notary_vk)
    .expect("the notary countersignature must verify under the notary's key");

  aph_core::verify_timestamp_order(&envelope)
    .expect("decisionTimestamp <= principal.created <= notary.created must hold");
  aph_core::verify_embedded_mandate_binding(&envelope)
    .expect("the embedded mandate must bind to THIS envelope");

  let mandate = envelope
    .credential_subject
    .policy
    .delegation_mandate
    .as_ref()
    .expect("the golden embeds its parent mandate");
  std::assert!(
    mandate_role_verifies(mandate, aph_core::ProofRole::Principal, &principal_vk),
    "the mandate's principalSignature must verify under the principal's key"
  );
  std::assert!(
    mandate_role_verifies(mandate, aph_core::ProofRole::Notary, &notary_vk),
    "the mandate's notarySignature must verify under the notary's key"
  );
}

#[test]
fn stripping_the_notary_countersignature_must_not_verify() {
  // The negative twin, run against the PUBLISHED bytes: §7.2.1's stated
  // attack is an intermediary stripping the countersignature from a
  // PrincipalSigned envelope and re-presenting the remainder. The one-element
  // ARRAY base is what defeats it, and this test proves that on the shipped
  // golden rather than on an in-memory fixture. All three re-presentations
  // an attacker can attempt must fail.
  let signed = published_envelope();
  let principal_vk = principal_signing_key().verifying_key();
  let notary_vk = notary_signing_key().verifying_key();
  let principal_proof = signed
    .proof
    .principal()
    .expect("the golden carries a two-element chain")
    .clone();

  // (1) Stripped but still an array: a one-element chain, rejected
  // structurally before any cryptography runs.
  let mut stripped_chain = signed.clone();
  stripped_chain.proof =
    aph_core::EnvelopeProofs::Chain(std::vec![principal_proof.clone()]);
  let err = aph_core::verify_proof_structure(&stripped_chain)
    .expect_err("a one-element chain must be rejected");
  std::assert_eq!(err.code(), "APH_E013");

  // (2) Collapsed to the single-object form with its chain vocabulary
  // intact: rejected structurally (a lone proof carries neither `id` nor
  // `previousProof`), and rejected cryptographically either way.
  let mut collapsed = signed.clone();
  collapsed.proof = aph_core::EnvelopeProofs::Single(principal_proof.clone());
  std::assert!(
    aph_core::verify_proof_structure(&collapsed).is_err(),
    "a lone proof carrying a chain id must be rejected"
  );
  std::assert!(
    aph_core::verify_proof(&collapsed, aph_core::ProofRole::Notary, &principal_vk).is_err(),
    "the object-form base is different bytes, so the signature must not verify"
  );

  // (3) The full rewrite: scrub the chain vocabulary and the label so the
  // structure reads as an ordinary NotaryAttested envelope. The structure
  // check passes — but the principal signed the ARRAY form with the
  // PrincipalSigned label inside the covered bytes, so NO key verifies the
  // rewritten envelope. This is the array-form domain separation doing its
  // job on the published bytes.
  let mut rewritten = signed;
  let mut lone = principal_proof;
  lone.id = std::option::Option::None;
  lone.previous_proof = std::option::Option::None;
  rewritten.proof = aph_core::EnvelopeProofs::Single(lone);
  rewritten.credential_subject.policy.attestation_mode = std::option::Option::None;
  let mode = aph_core::verify_proof_structure(&rewritten)
    .expect("the scrubbed rewrite is structurally a plain notary envelope");
  std::assert_eq!(
    mode,
    aph_core::AttestationMode::NotaryAttested,
    "the rewrite can only ever claim the weaker mode"
  );
  std::assert!(
    aph_core::verify_proof(&rewritten, aph_core::ProofRole::Notary, &principal_vk).is_err(),
    "the human's signature must not verify over the rewritten bytes"
  );
  std::assert!(
    aph_core::verify_proof(&rewritten, aph_core::ProofRole::Notary, &notary_vk).is_err(),
    "the notary's key never signed the rewritten bytes either"
  );
}
