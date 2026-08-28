//! `CredentialAccessNotarizationEnvelope` — APH envelope variant for
//! agent-credential-access authorization.
//!
//! Sibling to [`crate::envelope::NotarizationEnvelope`]: shares the W3C
//! VC 2.0 + JSON-LD wire shape, but the credential subject describes a
//! CREDENTIAL ACCESS request (agent reading a credential) instead of a
//! MESSAGE SEND request.
//!
//! Reuses shared types from [`crate::envelope`]: `HumanPrincipalRef`,
//! `AgentRef`, `PolicyDescriptor`, `NotarizationMetadata`, `LinkedMandate`,
//! `EnvelopeProof`. This envelope type is additive — it does NOT touch the
//! existing `NotarizationEnvelope` shape.
//!
//! The two access-specific field types — `CredentialRef` (opaque
//! identifier for the credential being accessed) and `AccessIntent`
//! (OneShot / Session(ttl) / Persistent(mandate_id)) — are vendored
//! into this module; their serde output must match the originating
//! implementation exactly.

/// Opaque identifier for the credential being accessed. The shape is a
/// newtype around `String` (serializes as a bare JSON string).
#[derive(
  ::std::clone::Clone,
  ::std::fmt::Debug,
  ::std::cmp::PartialEq,
  ::std::cmp::Eq,
  ::std::hash::Hash,
  ::serde::Serialize,
  ::serde::Deserialize,
)]
pub struct CredentialRef(::std::string::String);

impl CredentialRef {
  /// Wraps an existing credential reference string.
  pub fn new(s: ::std::string::String) -> Self {
    Self(s)
  }

  /// Borrows the reference as it appears on the wire (a bare string).
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

/// Duration / shape of the access the agent is requesting.
///
/// `OneShot` — single read, grant expires after first fetch.
/// `Session { ttl_seconds }` — multi-read over a time-bounded window.
/// `Persistent { mandate_id }` — long-lived, governed by an external
/// AP2 IntentMandate that the user has signed; the engine consults the
/// mandate on each fetch.
#[derive(
  ::std::clone::Clone,
  ::std::fmt::Debug,
  ::std::cmp::PartialEq,
  ::std::cmp::Eq,
  ::serde::Serialize,
  ::serde::Deserialize,
)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccessIntent {
  /// Single read; the grant expires after the first fetch.
  OneShot,
  /// Multi-read over a time-bounded window.
  Session {
    /// Lifetime of the session grant, in seconds.
    ttl_seconds: u64,
  },
  /// Long-lived access governed by an external signed mandate.
  Persistent {
    /// Identifier of the governing AP2 IntentMandate.
    mandate_id: ::std::string::String,
  },
}

/// Top-level envelope for agent-credential-access authorization. Mirrors
/// the JSON-LD + W3C VC 2.0 shape of [`crate::envelope::NotarizationEnvelope`]
/// but with a credential-access subject in place of the message-send
/// subject.
///
/// The `type` array MUST include `"VerifiableCredential"` and
/// `"AgentCredentialAccessAuthorization"`.
#[derive(
  ::std::fmt::Debug,
  ::std::clone::Clone,
  ::std::cmp::PartialEq,
  ::std::cmp::Eq,
  ::serde::Serialize,
  ::serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialAccessNotarizationEnvelope {
  /// APH version pin (`"0.1"`).
  pub aph_version: ::std::string::String,
  /// JSON-LD `@context` array. Always begins with W3C VC 2.0 context.
  #[serde(rename = "@context")]
  pub context: ::std::vec::Vec<::std::string::String>,
  /// JSON-LD `type` array; MUST include `"VerifiableCredential"` and
  /// `"AgentCredentialAccessAuthorization"`.
  #[serde(rename = "type")]
  pub r#type: ::std::vec::Vec<::std::string::String>,
  /// `urn:uuid:...` envelope identifier.
  pub id: ::std::string::String,
  /// DID of the notary service.
  pub issuer: ::std::string::String,
  /// RFC 3339 issuance timestamp.
  pub valid_from: ::std::string::String,
  /// RFC 3339 expiry timestamp.
  pub valid_until: ::std::string::String,
  /// Inner credential-access subject (the notarized claim).
  pub credential_access_subject: CredentialAccessSubject,
  /// Optional link to an AP2 IntentMandate (for cross-protocol mandates).
  #[serde(default)]
  pub linked_mandate: ::std::option::Option<crate::envelope::LinkedMandate>,
  /// Cryptographic proof block (reuses the canonical APH proof shape).
  ///
  /// Deliberately a SINGLE [`crate::envelope::EnvelopeProof`], not the
  /// [`crate::envelope::EnvelopeProofs`] object-or-array union: §7.1.11's
  /// proof-chain rules govern `NotarizationEnvelope` only, and this variant
  /// is a spec v0.2 candidate. Widening it here would invent wire shapes no
  /// normative text defines.
  pub proof: crate::envelope::EnvelopeProof,
}

/// The credential subject for an agent-credential-access envelope.
///
/// Reuses `HumanPrincipalRef` (delegator) + `AgentRef` (subject) +
/// `PolicyDescriptor` (governing policy) + `NotarizationMetadata`
/// (decision metadata) from the message-send envelope. Adds two NEW
/// access-specific fields: `credential_ref` (which credential) and
/// `access_intent` (how the agent intends to use it).
#[derive(
  ::std::fmt::Debug,
  ::std::clone::Clone,
  ::std::cmp::PartialEq,
  ::std::cmp::Eq,
  ::serde::Serialize,
  ::serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialAccessSubject {
  /// The human principal who delegates access (= the user signing the
  /// consent).
  pub human_principal: crate::envelope::HumanPrincipalRef,
  /// The agent requesting access.
  pub agent: crate::envelope::AgentRef,
  /// Opaque identifier for the credential being accessed
  /// (vendored [`CredentialRef`] above).
  pub credential_ref: CredentialRef,
  /// Intent / duration of the access grant (OneShot / Session(ttl) /
  /// Persistent(mandate_id)) — vendored [`AccessIntent`] above.
  pub access_intent: AccessIntent,
  /// Governing policy descriptor.
  pub policy: crate::envelope::PolicyDescriptor,
  /// Notarization decision metadata.
  pub notarization: crate::envelope::NotarizationMetadata,
}

#[cfg(test)]
mod tests {
  // Pure-fn round-trip tests. No async runtime needed.

  // Test fixture — single source of envelope construction used by all 3
  // round-trip tests below. Keeps the cross-test shape identical so a
  // breaking change to any reused type surfaces consistently.
  fn make_envelope() -> super::CredentialAccessNotarizationEnvelope {
    super::CredentialAccessNotarizationEnvelope {
      aph_version: ::std::string::String::from("0.1"),
      context: ::std::vec![::std::string::String::from(
        "https://www.w3.org/ns/credentials/v2",
      )],
      r#type: ::std::vec![
        ::std::string::String::from("VerifiableCredential"),
        ::std::string::String::from("AgentCredentialAccessAuthorization"),
      ],
      id: ::std::string::String::from("urn:uuid:00000000-0000-4000-8000-000000000000"),
      issuer: ::std::string::String::from("did:web:notary.example"),
      valid_from: ::std::string::String::from("2026-05-29T00:00:00Z"),
      valid_until: ::std::string::String::from("2026-05-29T01:00:00Z"),
      credential_access_subject: super::CredentialAccessSubject {
        human_principal: crate::envelope::HumanPrincipalRef {
          id: ::std::string::String::from("did:key:zUser"),
          display_name: ::std::string::String::from("Scott"),
        },
        agent: crate::envelope::AgentRef {
          id: ::std::string::String::from("did:web:agent.example"),
          agent_card_uri: ::std::option::Option::None,
          display_name: ::std::string::String::from("TestAgent"),
          version: ::std::string::String::from("0.1.0"),
        },
        credential_ref: super::CredentialRef::new(
          ::std::string::String::from("cred-id-1"),
        ),
        access_intent: super::AccessIntent::OneShot,
        policy: crate::envelope::PolicyDescriptor {
          decision: crate::envelope::PolicyDecision::AlwaysAllow,
          matched_scope: ::std::string::String::from("per-credential"),
          delegation_mandate_id: ::std::option::Option::None,
          act_chain: ::std::vec::Vec::new(),
          attestation_mode: ::std::option::Option::None,
          delegation_mandate: ::std::option::Option::None,
        },
        notarization: crate::envelope::NotarizationMetadata {
          notary_service: crate::envelope::NotaryServiceRef {
            id: ::std::string::String::from("did:web:notary.example"),
            name: ::std::string::String::from("Squillo Notary Service"),
            version: ::std::string::String::from("0.1.0"),
            attested_digest: ::std::option::Option::None,
            attestation_uri: ::std::option::Option::None,
          },
          decision_timestamp: ::std::string::String::from("2026-05-29T00:00:00Z"),
          decision_latency_ms: 0,
        },
      },
      linked_mandate: ::std::option::Option::None,
      proof: crate::envelope::EnvelopeProof {
        r#type: ::std::string::String::from("DataIntegrityProof"),
        cryptosuite: ::std::option::Option::Some(::std::string::String::from(
          "eddsa-jcs-2022",
        )),
        verification_method: ::std::string::String::from("did:key:zNotary#zNotary"),
        created: ::std::string::String::from("2026-05-29T00:00:00Z"),
        proof_purpose: ::std::string::String::from("assertionMethod"),
        proof_value: ::std::string::String::from("placeholder"),
        id: ::std::option::Option::None,
        previous_proof: ::std::option::Option::None,
      },
    }
  }

  #[test]
  fn type_array_contains_credential_access_marker() {
    // The type array is how a verifier tells a credential-access envelope
    // from an ordinary send authorization. Losing the marker would let a
    // credential-access grant be processed as a plain message envelope.
    let env = make_envelope();
    assert_eq!(env.r#type.len(), 2);
    assert!(env
      .r#type
      .iter()
      .any(|t| t == "AgentCredentialAccessAuthorization"));
  }

  #[test]
  fn envelope_round_trip_json_serde() {
    // Round-trips the variant end to end, including the vendored
    // CredentialRef and AccessIntent types — their serde shapes must match
    // the originals byte-for-byte or cross-system grants stop parsing.
    let env = make_envelope();
    let s = ::serde_json::to_string(&env).expect("serialize");
    let env2: super::CredentialAccessNotarizationEnvelope =
      ::serde_json::from_str(&s).expect("deserialize");
    assert_eq!(env, env2);

    // Confirm wire shape carries the required JSON-LD + VC 2.0 markers.
    assert!(s.contains("@context"));
    assert!(s.contains("VerifiableCredential"));
    assert!(s.contains("AgentCredentialAccessAuthorization"));
    // The credential_access_subject MUST carry the camelCase wire form.
    assert!(s.contains("credentialAccessSubject"));
    // CredentialRef + AccessIntent (vendored types) MUST be serialized
    // inline as part of the subject — verify both surface.
    assert!(s.contains("credentialRef"));
    assert!(s.contains("accessIntent"));
  }

  #[test]
  fn envelope_rejects_unknown_fields() {
    // `deny_unknown_fields` on the struct attribute must reject extra
    // JSON fields. This is a wire-stability gate: if a peer ships a
    // newer envelope with extra fields we want a hard deserialize error
    // rather than silent drop.
    let env = make_envelope();
    let mut value = ::serde_json::to_value(&env).expect("serialize");
    if let ::serde_json::Value::Object(map) = &mut value {
      map.insert(
        ::std::string::String::from("bogusFieldNotInSchema"),
        ::serde_json::Value::String(::std::string::String::from("should-fail")),
      );
    } else {
      panic!("envelope serializes to a JSON object");
    }
    let s = ::serde_json::to_string(&value).expect("re-serialize");
    let result: ::std::result::Result<
      super::CredentialAccessNotarizationEnvelope,
      ::serde_json::Error,
    > = ::serde_json::from_str(&s);
    assert!(
      result.is_err(),
      "deny_unknown_fields MUST reject bogus extra field"
    );
  }

  #[test]
  fn cross_crate_credential_ref_in_envelope_round_trips() {
    // Verify the vendored CredentialRef + AccessIntent types embedded
    // inside the credential_access_subject round-trip correctly through
    // the envelope's serde implementation. This is the vendored-type
    // wire-stability gate.
    let env = make_envelope();
    let s = ::serde_json::to_string(&env).expect("serialize");
    let env2: super::CredentialAccessNotarizationEnvelope =
      ::serde_json::from_str(&s).expect("deserialize");
    assert_eq!(
      env.credential_access_subject.credential_ref,
      env2.credential_access_subject.credential_ref,
    );
    assert_eq!(
      env.credential_access_subject.access_intent,
      env2.credential_access_subject.access_intent,
    );
  }
}
