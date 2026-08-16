//! Revocation status transport vectors, run against `aph_core` (spec §6.3.3).
//!
//! Why this file exists: a security mechanism specified in prose and shipped
//! without vectors is not implementable by a non-Rust adopter without
//! reverse-engineering this crate — and worse, an adopter who guesses wrong
//! about the same-origin rule or the bit order builds something that LOOKS
//! conformant. The vectors live in `aph_conformance`'s public surface so an
//! adopter can consume them directly, beside `spec/schemas/*.schema.json`;
//! this file is the proof that the reference implementation actually agrees
//! with them, which is the part a checked-in JSON corpus cannot prove on its
//! own.
//!
//! What it pins, mechanism by mechanism:
//!
//! - every ACCEPT vector parses AND binds same-origin against the endpoint
//!   §6.3.3.2 derives from the notary DID;
//! - every REFUSE-AT-BINDING vector parses and then fails the binding, so a
//!   verifier would never fetch the URL it names;
//! - every REFUSE-AT-PARSE vector fails to deserialize at all, which is
//!   where §6.3.3.1/§6.3.3.5 route malformed wire;
//! - the two status documents are validated against their notary and their
//!   evaluation instant, and every refusal vector is refused.

/// The endpoint every vector is bound against, recomputed HERE from the DID
/// rather than read from the constant, so the test proves the derivation
/// agrees with the vectors instead of assuming it.
fn derived_endpoint() -> std::string::String {
  aph_core::DidUrl::parse(aph_conformance::STATUS_VECTOR_NOTARY_DID)
    .web_status_url()
    .expect("the vector notary is a did:web and derives a status endpoint")
}

#[test]
fn the_derivation_matches_the_published_vector_endpoint() {
  // Pins §6.3.3.2 step 2 against the value the vectors were authored for. If
  // the derivation ever drifts — a different leaf, a lost `.well-known` —
  // every accept vector would start failing its binding, and this test says
  // WHY in one line instead of leaving eleven others to fail obscurely.
  std::assert_eq!(
    derived_endpoint(),
    aph_conformance::STATUS_VECTOR_DERIVED_ENDPOINT
  );
}

#[test]
fn every_accept_vector_parses_and_binds_same_origin() {
  // The positive control for the whole file. Without it a suite in which
  // everything is refused would pass even against an implementation that
  // refused unconditionally — which would be perfectly "secure" and
  // completely useless.
  let derived = derived_endpoint();
  let vectors = aph_conformance::status_entry_vectors_accept();
  std::assert_eq!(vectors.len(), 4, "the accept set is four vectors");
  for (why, json) in vectors {
    let entry: aph_core::CredentialStatusEntry = serde_json::from_str(json)
      .unwrap_or_else(|e| std::panic!("accept vector must parse ({why}): {e}"));
    entry
      .index()
      .unwrap_or_else(|e| std::panic!("accept vector must have a readable index ({why}): {e}"));
    std::assert!(
      aph_core::same_origin(&derived, &entry.status_list_credential),
      "accept vector must bind same-origin ({why})"
    );
  }
}

#[test]
fn the_large_index_vector_survives_a_value_that_a_double_would_round() {
  // §6.3.3.6 in its concrete form. 2^53 + 1 is the smallest integer an
  // IEEE-754 double cannot hold: a runtime that parsed the index as a number
  // would read 9007199254740992 — one bit off, belonging to a different
  // mandate — and would raise no error doing it. The vector exists so an
  // adopter can catch that in their own runtime, and this assertion proves
  // the reference implementation does not have the bug it warns about.
  let (_, json) = aph_conformance::status_entry_vectors_accept()[3];
  let entry: aph_core::CredentialStatusEntry =
    serde_json::from_str(json).expect("the large-index vector parses");
  std::assert_eq!(entry.index().unwrap(), 9_007_199_254_740_993u64);
}

#[test]
fn every_binding_refusal_vector_parses_and_then_fails_the_origin_check() {
  // The security core of §6.3.3.2. Each of these is well-formed APH wire —
  // it MUST parse — and is refused only because the origin it names is not
  // the one derived from the notary's own DID. Asserting the parse succeeds
  // is not padding: if a future change made these fail at parse instead, the
  // binding rule would stop being exercised by anything and could rot
  // silently.
  let derived = derived_endpoint();
  let vectors = aph_conformance::status_entry_vectors_refuse_at_binding();
  std::assert_eq!(vectors.len(), 3, "the binding-refusal set is three vectors");
  for (why, json) in vectors {
    let entry: aph_core::CredentialStatusEntry = serde_json::from_str(json)
      .unwrap_or_else(|e| std::panic!("binding-refusal vector must still parse ({why}): {e}"));
    std::assert!(
      !aph_core::same_origin(&derived, &entry.status_list_credential),
      "must NOT bind same-origin ({why})"
    );
  }
}

#[test]
fn every_parse_refusal_vector_fails_to_deserialize() {
  // §6.3.3.1 and §6.3.3.5 route these to §8.3 step 1, and the routing is the
  // security property: a closed value set that a verifier merely "handles
  // later" is an opt-out, because a producer can disable the check by
  // writing a word that verifier has never seen.
  let vectors = aph_conformance::status_entry_vectors_refuse_at_parse();
  std::assert_eq!(vectors.len(), 4, "the parse-refusal set is four vectors");
  for (why, json) in vectors {
    std::assert!(
      serde_json::from_str::<aph_core::CredentialStatusEntry>(json).is_err(),
      "must NOT deserialize ({why})"
    );
  }
}

#[test]
fn the_fresh_documents_validate_against_their_notary_and_instant() {
  // The document half's positive control, and the pairing that makes the
  // refusal vectors meaningful: these two differ from the refusals only in
  // the field each refusal breaks.
  for document in [
    aph_conformance::STATUS_DOCUMENT_FRESH_NOT_REVOKED,
    aph_conformance::STATUS_DOCUMENT_FRESH_REVOKED_AT_INDEX_2,
  ] {
    let credential = aph_core::parse_status_list_credential(document)
      .expect("a fresh status document parses");
    credential
      .validate(
        aph_conformance::STATUS_VECTOR_NOTARY_DID,
        aph_conformance::STATUS_VECTOR_EVALUATION_INSTANT,
      )
      .expect("a fresh status document validates");
    // The encoded list must be a real GZIP stream, not a placeholder: the
    // vectors are only worth shipping if an adopter with a gzip library can
    // run the mechanism end to end against them.
    let compressed = aph_core::decode_encoded_list(&credential.credential_subject.encoded_list)
      .expect("encodedList is multibase base64url over a GZIP stream");
    std::assert_eq!(&compressed[..2], &[0x1f, 0x8b]);
  }
}

#[test]
fn every_document_refusal_vector_is_aph_e008() {
  // §6.3.3.4 case 2's single-code rule: fetch, TLS, parse, proof, issuer,
  // purpose and freshness failures all surface APH_E008, because the
  // verifier's action and the operator's remediation are identical for all
  // of them. A taxonomy that split them would make consumers split them too,
  // for a distinction nobody acts on.
  let vectors = aph_conformance::status_document_vectors_refuse();
  std::assert_eq!(vectors.len(), 5, "the document-refusal set is five vectors");
  for (why, json) in vectors {
    let outcome = aph_core::parse_status_list_credential(json).and_then(|credential| {
      credential.validate(
        aph_conformance::STATUS_VECTOR_NOTARY_DID,
        aph_conformance::STATUS_VECTOR_EVALUATION_INSTANT,
      )
    });
    let error = outcome.expect_err(why);
    std::assert_eq!(error.code(), "APH_E008", "{why}");
  }
}

#[test]
fn the_published_schemas_agree_with_the_rust_types() {
  // A schema that drifts from the code is worse than no schema: an adopter
  // builds against it, passes their own validation, and is refused on the
  // wire by the implementation the schema claimed to describe. This welds
  // the two together at the only place both are visible — the `required`
  // list and the closed values that carry the security argument.
  //
  // Path from this file:
  //   interpreters/rust/aph-conformance/tests/ -> ../../../../spec/schemas/
  let entry_schema: serde_json::Value = serde_json::from_str(std::include_str!(
    "../../../../spec/schemas/credential-status-entry.schema.json"
  ))
  .expect("the entry schema is valid JSON");
  let required = entry_schema["required"]
    .as_array()
    .expect("the entry schema states a required list");
  let required: std::vec::Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
  std::assert_eq!(
    required,
    std::vec!["type", "statusPurpose", "statusListIndex", "statusListCredential"],
    "the schema's required members must match the non-Option fields of CredentialStatusEntry"
  );
  // `id` is the one optional member, and it is Pattern A on the Rust side.
  std::assert!(
    entry_schema["properties"]["id"].is_object(),
    "the optional `id` member must still be described"
  );
  std::assert_eq!(
    entry_schema["additionalProperties"],
    serde_json::Value::Bool(false),
    "the entry is inside a strictly-parsed envelope, so its schema is closed too"
  );
  std::assert_eq!(entry_schema["properties"]["type"]["const"], "BitstringStatusListEntry");
  std::assert_eq!(entry_schema["properties"]["statusPurpose"]["const"], "revocation");
  std::assert_eq!(
    entry_schema["properties"]["statusListIndex"]["type"], "string",
    "the f64 hazard of §6.3.3.6 is only closed if the schema says string too"
  );

  let document_schema: serde_json::Value = serde_json::from_str(std::include_str!(
    "../../../../spec/schemas/bitstring-status-list-credential.schema.json"
  ))
  .expect("the document schema is valid JSON");
  std::assert!(
    document_schema.get("additionalProperties").is_none(),
    "the fetched document is a general W3C artifact and its schema must stay OPEN"
  );
  std::assert_eq!(
    document_schema["properties"]["credentialSubject"]["properties"]["statusPurpose"]["const"],
    "revocation"
  );
}
