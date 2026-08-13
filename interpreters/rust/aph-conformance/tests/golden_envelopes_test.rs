//! Golden envelope round-trip tests for the 7 in-source APH fixtures.
//!
//! Iterates over `aph_conformance::golden_envelopes()` and asserts each JSON
//! fixture parses cleanly into `aph_core::NotarizationEnvelope`,
//! reserializes, and reparses to the SAME value (byte-stable round-trip per
//! `Eq` equality of the canonical struct).
//!
//! ZERO `#[ignore]`. ZERO `use` statements.

#[test]
fn all_seven_golden_envelopes_round_trip() {
  // Corpus-wide gate: every frozen fixture must survive parse → serialize
  // → reparse. Because these fixtures represent envelopes already signed
  // in the field, a failure here means the implementation can no longer
  // read credentials it previously issued.
  let envelopes = aph_conformance::golden_envelopes();
  std::assert_eq!(
    envelopes.len(),
    7,
    "expected exactly 7 golden envelopes, got {}",
    envelopes.len()
  );
  for (idx, json) in envelopes.iter().enumerate() {
    let parsed: aph_core::NotarizationEnvelope = serde_json::from_str(json)
      .unwrap_or_else(|e| std::panic!("envelope #{} failed to parse: {}", idx + 1, e));
    let reserialized = serde_json::to_string(&parsed)
      .unwrap_or_else(|e| std::panic!("envelope #{} failed to serialize: {}", idx + 1, e));
    let reparsed: aph_core::NotarizationEnvelope =
      serde_json::from_str(&reserialized).unwrap_or_else(|e| {
        std::panic!(
          "envelope #{} reserialize failed to round-trip: {}",
          idx + 1,
          e
        )
      });
    std::assert_eq!(
      parsed,
      reparsed,
      "envelope #{} byte round-trip mismatch",
      idx + 1
    );
  }
}

#[test]
fn first_envelope_is_minimal_email_shape() {
  // The floor case: an envelope with every optional field omitted. Pins
  // that the minimum legal credential still parses, so optional fields
  // cannot quietly become required.
  let envelopes = aph_conformance::golden_envelopes();
  let parsed: aph_core::NotarizationEnvelope =
    serde_json::from_str(envelopes[0]).expect("minimal email envelope parses");
  std::assert_eq!(parsed.aph_version, "0.1");
  std::assert_eq!(parsed.credential_subject.channel.kind, "email");
  std::assert!(
    parsed.linked_mandate.is_none(),
    "envelope #1 must have no linkedMandate"
  );
  std::assert!(
    parsed.credential_subject.policy.act_chain.is_empty(),
    "envelope #1 act_chain must default to empty"
  );
}

#[test]
fn second_envelope_carries_linked_ap2_mandate() {
  // Covers the AP2 cross-link: the only fixture where linkedMandate is
  // populated, so it is what proves payment-authorization linkage
  // survives parsing rather than being dropped as an unknown branch.
  let envelopes = aph_conformance::golden_envelopes();
  let parsed: aph_core::NotarizationEnvelope =
    serde_json::from_str(envelopes[1]).expect("slack+ap2 envelope parses");
  std::assert_eq!(parsed.credential_subject.channel.kind, "slack");
  let linked = parsed
    .linked_mandate
    .as_ref()
    .expect("envelope #2 must carry linkedMandate");
  std::assert!(
    linked.ap2_intent_mandate_uri.is_some(),
    "envelope #2 linkedMandate must carry ap2IntentMandateUri"
  );
}

#[test]
fn third_envelope_is_foreign_did_web_issuer_es256() {
  // The interop fixture: a FOREIGN issuer using did:web and the ES256
  // cryptosuite instead of the local did:key/EdDSA default. This is the
  // cross-vendor case the whole protocol exists for, so it must never
  // regress into only understanding self-issued envelopes.
  let envelopes = aph_conformance::golden_envelopes();
  let parsed: aph_core::NotarizationEnvelope =
    serde_json::from_str(envelopes[2]).expect("inbound-verify envelope parses");
  std::assert!(
    parsed.issuer.starts_with("did:web:"),
    "envelope #3 must be issued by a did:web foreign notary, got: {}",
    parsed.issuer
  );
  let notary_proof = parsed
    .proof
    .notary()
    .expect("envelope #3 must carry a notary proof");
  std::assert_eq!(
    notary_proof.cryptosuite.as_deref(),
    std::option::Option::Some("ecdsa-jcs-2019"),
    "envelope #3 must be pinned to the ES256 cryptosuite"
  );
}

#[test]
fn fourth_envelope_carries_delegation_and_act_chain() {
  // The delegated (human-not-present) case with a multi-hop actChain —
  // the evidence trail proving which principal acted for whom. Losing it
  // would erase accountability for autonomous sends.
  let envelopes = aph_conformance::golden_envelopes();
  let parsed: aph_core::NotarizationEnvelope =
    serde_json::from_str(envelopes[3]).expect("delegation envelope parses");
  std::assert!(
    parsed
      .credential_subject
      .policy
      .delegation_mandate_id
      .is_some(),
    "envelope #4 must carry policy.delegationMandateId"
  );
  std::assert_eq!(
    parsed.credential_subject.policy.act_chain.len(),
    2,
    "envelope #4 must carry a 2-hop act_chain"
  );
}

#[test]
fn fifth_envelope_recipient_addressing_carries_multi_recipient_array() {
  // Opaque-addressing stress case #1: arrays (to/cc/bcc). Confirms the
  // untyped addressing blob preserves list structure rather than
  // collapsing it to a scalar.
  let envelopes = aph_conformance::golden_envelopes();
  let parsed: aph_core::NotarizationEnvelope =
    serde_json::from_str(envelopes[4]).expect("multi-recipient envelope parses");
  let addressing = &parsed.credential_subject.channel.recipient_addressing;
  let to_arr = addressing
    .get("to")
    .and_then(serde_json::Value::as_array)
    .expect("envelope #5 recipientAddressing.to must be an array");
  std::assert_eq!(
    to_arr.len(),
    3,
    "envelope #5 must carry exactly 3 primary recipients"
  );
}

#[test]
fn sixth_envelope_recipient_addressing_carries_attachment_metadata() {
  // Opaque-addressing stress case #2: arrays of objects (attachments).
  // Proves nested structure inside the addressing blob round-trips, which
  // is what lets new channels ship without changing these types.
  let envelopes = aph_conformance::golden_envelopes();
  let parsed: aph_core::NotarizationEnvelope =
    serde_json::from_str(envelopes[5]).expect("discord+attachment envelope parses");
  std::assert_eq!(parsed.credential_subject.channel.kind, "discord");
  std::assert!(
    parsed
      .credential_subject
      .channel
      .recipient_addressing
      .get("attachments")
      .and_then(serde_json::Value::as_array)
      .is_some(),
    "envelope #6 must carry an attachments array in recipientAddressing"
  );
}

#[test]
fn seventh_envelope_recipient_addressing_carries_retention_policy() {
  // Opaque-addressing stress case #3: a nested policy object. Retention
  // terms are compliance-relevant, so silently dropping them would
  // misrepresent what the human authorized.
  let envelopes = aph_conformance::golden_envelopes();
  let parsed: aph_core::NotarizationEnvelope =
    serde_json::from_str(envelopes[6]).expect("imessage+retention envelope parses");
  std::assert_eq!(parsed.credential_subject.channel.kind, "imessage");
  std::assert!(
    parsed
      .credential_subject
      .channel
      .recipient_addressing
      .get("retention")
      .and_then(serde_json::Value::as_object)
      .is_some(),
    "envelope #7 must carry a retention object in recipientAddressing"
  );
}

#[test]
fn every_envelope_is_w3c_vc_2_shaped() {
  // Standards-conformance sweep: @context order, both required type
  // entries, assertionMethod proof purpose, aphVersion. These are what
  // make an APH envelope a valid W3C Verifiable Credential 2.0 — break
  // any one and generic VC tooling stops accepting our credentials.
  let envelopes = aph_conformance::golden_envelopes();
  for (idx, json) in envelopes.iter().enumerate() {
    let parsed: aph_core::NotarizationEnvelope = serde_json::from_str(json)
      .unwrap_or_else(|e| std::panic!("envelope #{} failed to parse: {}", idx + 1, e));
    std::assert_eq!(
      parsed.aph_version,
      "0.1",
      "envelope #{} must pin aphVersion=0.1",
      idx + 1
    );
    std::assert!(
      parsed
        .context
        .iter()
        .any(|c| c == "https://www.w3.org/ns/credentials/v2"),
      "envelope #{} @context must include W3C VC 2.0 context",
      idx + 1
    );
    std::assert!(
      parsed.r#type.iter().any(|t| t == "VerifiableCredential"),
      "envelope #{} type must include VerifiableCredential",
      idx + 1
    );
    std::assert!(
      parsed
        .r#type
        .iter()
        .any(|t| t == "AgentSendAuthorizationCredential"),
      "envelope #{} type must include AgentSendAuthorizationCredential",
      idx + 1
    );
    let notary_proof = parsed
      .proof
      .notary()
      .unwrap_or_else(|| std::panic!("envelope #{} must carry a notary proof", idx + 1));
    std::assert_eq!(
      notary_proof.proof_purpose,
      "assertionMethod",
      "envelope #{} proof.proofPurpose must be assertionMethod",
      idx + 1
    );
  }
}

#[test]
fn every_golden_envelope_is_a_single_proof_notary_attested_credential() {
  // The whole frozen corpus predates `attestationMode` and the §7.1.11 proof
  // chain: every fixture carries ONE proof object and no mode field. Two
  // things must hold for those envelopes to keep meaning what they meant.
  // The untagged `proof` union must still read a JSON object as the single
  // form — if it ever parsed as a chain, or failed, the corpus would stop
  // loading. And the absent label must resolve to the WEAKER claim: these
  // fixtures were signed by a notary alone, so reporting them as
  // `PrincipalSigned` would assert a human signature that does not exist.
  for (idx, json) in aph_conformance::golden_envelopes().iter().enumerate() {
    let parsed: aph_core::NotarizationEnvelope = serde_json::from_str(json)
      .unwrap_or_else(|e| std::panic!("envelope #{} failed to parse: {}", idx + 1, e));
    std::assert!(
      !parsed.proof.is_chain(),
      "envelope #{} must carry the single-object proof form",
      idx + 1
    );
    let mode = aph_core::verification::verify_proof_structure(&parsed)
      .unwrap_or_else(|e| std::panic!("envelope #{} failed §7.1.11: {}", idx + 1, e));
    std::assert_eq!(
      mode,
      aph_core::envelope::AttestationMode::NotaryAttested,
      "envelope #{} must verify as NotaryAttested",
      idx + 1
    );
  }
}
