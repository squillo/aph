---
section: "APH Specification"
name: "APH Type Surface Tests"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH — Type Surface Tests

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.


Run with `nlang test`. Each test constructs an instance of a declared block
and reads one prop back.

## Why one assertion per test

This is forced by the toolchain, not a style preference.

**A test's result reflects only its FINAL assertion.** An earlier failing
assertion is discarded if a later one passes. Minimal repro:

```nlang,ignore
#[test]
fn fail_then_pass() -> () {
  assert_eq!(1, 2)   // fails
  assert_eq!(1, 1)   // passes
}                    // -> reported as ok
```

`pass_then_fail` and `fail_then_fail` both report correctly, so only the
masking case is affected. A five-assertion test therefore really only
checks the fifth. Splitting each check into its own test makes every
assertion the last one, and so gives every assertion teeth — verified by
mutating four independent assertions, each of which failed exactly one
test.

## What these prove

Each prop is addressable by its declared name and carries the value written
to it. A misspelled or absent path reads as `None`, which fails the
assertion.

## What they do not prove

That a construction conforms to its block. The compiler does not
structurally validate a typed ledger binding: unknown props, missing
required props, and wrong-typed values are all accepted. Conformance
between the declared types and the published examples is covered outside
N Lang by the round-trip suite at
`interpreters/rust/aph-conformance/tests/nlang_snapp_test.rs`.

Values come from the published example envelopes, so drift in the canonical
examples shows up here.

```nlang
mod * {
  // Envelope identity and window — what a verifier reads first.
  #[test]
  fn envelope_aph_version() -> () {
    let e: NotarizationEnvelope = { aph_version: "0.1", id: "urn:uuid:00000000-0000-4000-8000-000000000001", issuer: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV", valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z" }
    assert_eq!(e.aph_version, "0.1")
  }

  #[test]
  fn envelope_id() -> () {
    let e: NotarizationEnvelope = { aph_version: "0.1", id: "urn:uuid:00000000-0000-4000-8000-000000000001", issuer: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV", valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z" }
    assert_eq!(e.id, "urn:uuid:00000000-0000-4000-8000-000000000001")
  }

  #[test]
  fn envelope_issuer() -> () {
    let e: NotarizationEnvelope = { aph_version: "0.1", id: "urn:uuid:00000000-0000-4000-8000-000000000001", issuer: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV", valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z" }
    assert_eq!(e.issuer, "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV")
  }

  #[test]
  fn envelope_valid_from() -> () {
    let e: NotarizationEnvelope = { aph_version: "0.1", id: "urn:uuid:00000000-0000-4000-8000-000000000001", issuer: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV", valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z" }
    assert_eq!(e.valid_from, "2026-05-21T00:00:00Z")
  }

  #[test]
  fn envelope_valid_until() -> () {
    let e: NotarizationEnvelope = { aph_version: "0.1", id: "urn:uuid:00000000-0000-4000-8000-000000000001", issuer: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV", valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z" }
    assert_eq!(e.valid_until, "2026-05-22T00:00:00Z")
  }

  // The two identities a recipient checks: who authorized, and who acted.
  #[test]
  fn human_principal_id() -> () {
    let h: HumanPrincipalRef = { id: "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy", display_name: "Scott Wyatt" }
    assert_eq!(h.id, "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy")
  }

  #[test]
  fn human_principal_display_name() -> () {
    let h: HumanPrincipalRef = { id: "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy", display_name: "Scott Wyatt" }
    assert_eq!(h.display_name, "Scott Wyatt")
  }

  #[test]
  fn agent_id() -> () {
    let a: AgentRef = { id: "did:web:agent.squillo.io", agent_card_uri: "https://agent.squillo.io/.well-known/agent-card.json", display_name: "Squillo Concierge", version: "1.0" }
    assert_eq!(a.id, "did:web:agent.squillo.io")
  }

  #[test]
  fn agent_card_uri_optional_prop_is_readable() -> () {
    let a: AgentRef = { id: "did:web:agent.squillo.io", agent_card_uri: "https://agent.squillo.io/.well-known/agent-card.json", display_name: "Squillo Concierge", version: "1.0" }
    assert_eq!(a.agent_card_uri, "https://agent.squillo.io/.well-known/agent-card.json")
  }

  #[test]
  fn agent_display_name() -> () {
    let a: AgentRef = { id: "did:web:agent.squillo.io", agent_card_uri: "https://agent.squillo.io/.well-known/agent-card.json", display_name: "Squillo Concierge", version: "1.0" }
    assert_eq!(a.display_name, "Squillo Concierge")
  }

  #[test]
  fn agent_version() -> () {
    let a: AgentRef = { id: "did:web:agent.squillo.io", agent_card_uri: "https://agent.squillo.io/.well-known/agent-card.json", display_name: "Squillo Concierge", version: "1.0" }
    assert_eq!(a.version, "1.0")
  }

  // body_sha256 binds the credential to one specific message body.
  #[test]
  fn communication_content_class() -> () {
    let c: CommunicationDescriptor = { content_class: "Reply", body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", body_size: 1842, preview_lines: 3, preview: "Hey team" }
    assert_eq!(c.content_class, "Reply")
  }

  #[test]
  fn communication_body_sha256() -> () {
    let c: CommunicationDescriptor = { content_class: "Reply", body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", body_size: 1842, preview_lines: 3, preview: "Hey team" }
    assert_eq!(c.body_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  }

  #[test]
  fn communication_body_size() -> () {
    let c: CommunicationDescriptor = { content_class: "Reply", body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", body_size: 1842, preview_lines: 3, preview: "Hey team" }
    assert_eq!(c.body_size, 1842)
  }

  #[test]
  fn communication_preview_lines() -> () {
    let c: CommunicationDescriptor = { content_class: "Reply", body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", body_size: 1842, preview_lines: 3, preview: "Hey team" }
    assert_eq!(c.preview_lines, 3)
  }

  // The authorization decision and the scope that produced it.
  #[test]
  fn policy_decision() -> () {
    let p: PolicyDescriptor = { decision: "AskEveryTime", matched_scope: "per-channel" }
    assert_eq!(p.decision, "AskEveryTime")
  }

  #[test]
  fn policy_matched_scope() -> () {
    let p: PolicyDescriptor = { decision: "AskEveryTime", matched_scope: "per-channel" }
    assert_eq!(p.matched_scope, "per-channel")
  }

  // `type` is spelled as it appears on the wire, which N Lang permits
  // where Rust needs an escape — reading it back confirms that works.
  #[test]
  fn proof_type_uses_the_wire_spelling() -> () {
    let pr: EnvelopeProof = { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", verification_method: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#k1", created: "2026-05-21T00:00:01Z", proof_purpose: "assertionMethod", proof_value: "z3WgvA9JHkbV" }
    assert_eq!(pr.type, "DataIntegrityProof")
  }

  #[test]
  fn proof_cryptosuite() -> () {
    let pr: EnvelopeProof = { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", verification_method: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#k1", created: "2026-05-21T00:00:01Z", proof_purpose: "assertionMethod", proof_value: "z3WgvA9JHkbV" }
    assert_eq!(pr.cryptosuite, "eddsa-jcs-2022")
  }

  #[test]
  fn proof_purpose() -> () {
    let pr: EnvelopeProof = { type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", verification_method: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#k1", created: "2026-05-21T00:00:01Z", proof_purpose: "assertionMethod", proof_value: "z3WgvA9JHkbV" }
    assert_eq!(pr.proof_purpose, "assertionMethod")
  }

  // Standing authority; rate_limit_per_hour is optional and readable.
  #[test]
  fn delegation_human_principal_did() -> () {
    let d: DelegationMandate = { id: "urn:uuid:00000000-0000-4000-8000-0000000000a1", human_principal_did: "did:key:zAlice", agent_did: "did:web:agent.example", rate_limit_per_hour: 12, valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z", principal_signature: "z-illustrative-human", notary_signature: "z-illustrative" }
    assert_eq!(d.human_principal_did, "did:key:zAlice")
  }

  #[test]
  fn delegation_agent_did() -> () {
    let d: DelegationMandate = { id: "urn:uuid:00000000-0000-4000-8000-0000000000a1", human_principal_did: "did:key:zAlice", agent_did: "did:web:agent.example", rate_limit_per_hour: 12, valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z", principal_signature: "z-illustrative-human", notary_signature: "z-illustrative" }
    assert_eq!(d.agent_did, "did:web:agent.example")
  }

  #[test]
  fn delegation_rate_limit_per_hour() -> () {
    let d: DelegationMandate = { id: "urn:uuid:00000000-0000-4000-8000-0000000000a1", human_principal_did: "did:key:zAlice", agent_did: "did:web:agent.example", rate_limit_per_hour: 12, valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z", principal_signature: "z-illustrative-human", notary_signature: "z-illustrative" }
    assert_eq!(d.rate_limit_per_hour, 12)
  }

  #[test]
  fn delegation_valid_until() -> () {
    let d: DelegationMandate = { id: "urn:uuid:00000000-0000-4000-8000-0000000000a1", human_principal_did: "did:key:zAlice", agent_did: "did:web:agent.example", rate_limit_per_hour: 12, valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z", principal_signature: "z-illustrative-human", notary_signature: "z-illustrative" }
    assert_eq!(d.valid_until, "2026-05-22T00:00:00Z")
  }

  // Single-use authority, bound to one body and short-lived.
  #[test]
  fn communication_mandate_channel_kind() -> () {
    let m: CommunicationMandate = { id: "urn:uuid:00000000-0000-4000-8000-000000000002", human_principal_did: "did:key:zAlice", agent_did: "did:web:agent.example", channel_kind: "slack", content_class: "Reply", body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", body_size: 1842, policy_decision: "AskEveryTime", issued_at: "2026-05-21T00:00:00Z", expires_at: "2026-05-21T00:05:00Z", notary_signature: "z-illustrative" }
    assert_eq!(m.channel_kind, "slack")
  }

  #[test]
  fn communication_mandate_policy_decision() -> () {
    let m: CommunicationMandate = { id: "urn:uuid:00000000-0000-4000-8000-000000000002", human_principal_did: "did:key:zAlice", agent_did: "did:web:agent.example", channel_kind: "slack", content_class: "Reply", body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", body_size: 1842, policy_decision: "AskEveryTime", issued_at: "2026-05-21T00:00:00Z", expires_at: "2026-05-21T00:05:00Z", notary_signature: "z-illustrative" }
    assert_eq!(m.policy_decision, "AskEveryTime")
  }

  #[test]
  fn communication_mandate_body_sha256() -> () {
    let m: CommunicationMandate = { id: "urn:uuid:00000000-0000-4000-8000-000000000002", human_principal_did: "did:key:zAlice", agent_did: "did:web:agent.example", channel_kind: "slack", content_class: "Reply", body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", body_size: 1842, policy_decision: "AskEveryTime", issued_at: "2026-05-21T00:00:00Z", expires_at: "2026-05-21T00:05:00Z", notary_signature: "z-illustrative" }
    assert_eq!(m.body_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  }

  #[test]
  fn communication_mandate_expires_at() -> () {
    let m: CommunicationMandate = { id: "urn:uuid:00000000-0000-4000-8000-000000000002", human_principal_did: "did:key:zAlice", agent_did: "did:web:agent.example", channel_kind: "slack", content_class: "Reply", body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", body_size: 1842, policy_decision: "AskEveryTime", issued_at: "2026-05-21T00:00:00Z", expires_at: "2026-05-21T00:05:00Z", notary_signature: "z-illustrative" }
    assert_eq!(m.expires_at, "2026-05-21T00:05:00Z")
  }

  // DNS TXT tag names are a wire contract (spec §8.4.5).
  #[test]
  fn txt_record_version_tag() -> () {
    let t: AphTxtKeyRecord = { version: "APHv1", alg: "ed25519", k: "2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw", kid: "k1", not_before: "2026-05-21T00:00:00Z", not_after: "2027-05-21T00:00:00Z" }
    assert_eq!(t.version, "APHv1")
  }

  #[test]
  fn txt_record_alg_tag() -> () {
    let t: AphTxtKeyRecord = { version: "APHv1", alg: "ed25519", k: "2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw", kid: "k1", not_before: "2026-05-21T00:00:00Z", not_after: "2027-05-21T00:00:00Z" }
    assert_eq!(t.alg, "ed25519")
  }

  #[test]
  fn txt_record_k_tag() -> () {
    let t: AphTxtKeyRecord = { version: "APHv1", alg: "ed25519", k: "2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw", kid: "k1", not_before: "2026-05-21T00:00:00Z", not_after: "2027-05-21T00:00:00Z" }
    assert_eq!(t.k, "2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw")
  }

  #[test]
  fn txt_record_kid_tag() -> () {
    let t: AphTxtKeyRecord = { version: "APHv1", alg: "ed25519", k: "2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw", kid: "k1", not_before: "2026-05-21T00:00:00Z", not_after: "2027-05-21T00:00:00Z" }
    assert_eq!(t.kid, "k1")
  }

  #[test]
  fn txt_record_not_after_tag() -> () {
    let t: AphTxtKeyRecord = { version: "APHv1", alg: "ed25519", k: "2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw", kid: "k1", not_before: "2026-05-21T00:00:00Z", not_after: "2027-05-21T00:00:00Z" }
    assert_eq!(t.not_after, "2027-05-21T00:00:00Z")
  }

  // Who proved the authorization (spec §7.1.7). The value is the wire's
  // bare string, not a tagged enum object, so it reads back as written.
  #[test]
  fn policy_attestation_mode() -> () {
    let p: PolicyDescriptor = { decision: "AlwaysAllow", matched_scope: "per-channel", attestation_mode: "PrincipalSigned", delegation_mandate_id: "urn:uuid:00000000-0000-4000-8000-0000000000d1" }
    assert_eq!(p.attestation_mode, "PrincipalSigned")
  }

  #[test]
  fn policy_delegation_mandate_id() -> () {
    let p: PolicyDescriptor = { decision: "AlwaysAllow", matched_scope: "per-channel", attestation_mode: "PrincipalSigned", delegation_mandate_id: "urn:uuid:00000000-0000-4000-8000-0000000000d1" }
    assert_eq!(p.delegation_mandate_id, "urn:uuid:00000000-0000-4000-8000-0000000000d1")
  }

  // The human's own signature on the standing grant (spec §6.1) — the root
  // of every credential issued under it, and required, not optional.
  #[test]
  fn delegation_principal_signature() -> () {
    let d: DelegationMandate = { id: "urn:uuid:00000000-0000-4000-8000-0000000000a1", human_principal_did: "did:key:zAlice", agent_did: "did:web:agent.example", rate_limit_per_hour: 12, valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z", principal_signature: "z-illustrative-human", notary_signature: "z-illustrative" }
    assert_eq!(d.principal_signature, "z-illustrative-human")
  }

  #[test]
  fn delegation_notary_signature_countersigns() -> () {
    let d: DelegationMandate = { id: "urn:uuid:00000000-0000-4000-8000-0000000000a1", human_principal_did: "did:key:zAlice", agent_did: "did:web:agent.example", rate_limit_per_hour: 12, valid_from: "2026-05-21T00:00:00Z", valid_until: "2026-05-22T00:00:00Z", principal_signature: "z-illustrative-human", notary_signature: "z-illustrative" }
    assert_eq!(d.notary_signature, "z-illustrative")
  }

  // Chain linkage (spec §7.1.11): the notary proof names the principal
  // proof's id, which is the binding a verifier checks — array order is not.
  #[test]
  fn chained_proof_id() -> () {
    let pr: EnvelopeProof = { id: "urn:uuid:00000000-0000-4000-8000-0000000000f2", type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", verification_method: "did:web:notary.squillo.io#key-1", created: "2026-05-21T00:00:01Z", proof_purpose: "authentication", previous_proof: "urn:uuid:00000000-0000-4000-8000-0000000000f1", proof_value: "z3WgvA9JHkbV" }
    assert_eq!(pr.id, "urn:uuid:00000000-0000-4000-8000-0000000000f2")
  }

  #[test]
  fn chained_proof_previous_proof() -> () {
    let pr: EnvelopeProof = { id: "urn:uuid:00000000-0000-4000-8000-0000000000f2", type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", verification_method: "did:web:notary.squillo.io#key-1", created: "2026-05-21T00:00:01Z", proof_purpose: "authentication", previous_proof: "urn:uuid:00000000-0000-4000-8000-0000000000f1", proof_value: "z3WgvA9JHkbV" }
    assert_eq!(pr.previous_proof, "urn:uuid:00000000-0000-4000-8000-0000000000f1")
  }

  #[test]
  fn notary_countersignature_uses_the_authentication_purpose() -> () {
    let pr: EnvelopeProof = { id: "urn:uuid:00000000-0000-4000-8000-0000000000f2", type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", verification_method: "did:web:notary.squillo.io#key-1", created: "2026-05-21T00:00:01Z", proof_purpose: "authentication", previous_proof: "urn:uuid:00000000-0000-4000-8000-0000000000f1", proof_value: "z3WgvA9JHkbV" }
    assert_eq!(pr.proof_purpose, "authentication")
  }

  // The guard that makes every assertion above meaningful: a misspelled or
  // absent path reads as None and therefore is not equal to a real value.
  #[test]
  fn absent_prop_is_not_equal_to_a_present_value() -> () {
    let h: HumanPrincipalRef = { id: "did:key:zAlice", display_name: "Alice" }
    assert_ne!(h.no_such_prop, "Alice")
  }
}
```
