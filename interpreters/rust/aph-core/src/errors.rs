//! APH error taxonomy.
//!
//! Codes APH_E001 .. APH_E024 (E021-E024 declared by the v0.2 delta). Each variant carries a `code() -> &'static str`
//! and `suggestion() -> &'static str`.

/// APH protocol error with structured codes and suggestions.
#[derive(std::fmt::Debug, std::clone::Clone, std::cmp::PartialEq, std::cmp::Eq, thiserror::Error)]
pub enum AphError {
  /// `APH_E001` — the envelope's `proof.proofValue` did not verify against
  /// the notary's public key over the canonical form.
  #[error("APH_E001: invalid envelope signature")]
  InvalidEnvelopeSignature,

  /// `APH_E002` — a notarization flow was driven along an edge the state
  /// machine does not define.
  #[error("APH_E002: invalid flow transition from `{from}` to `{to}`")]
  InvalidFlowTransition {
    /// State the flow was in.
    from: String,
    /// State the caller attempted to move to.
    to: String,
  },

  /// `APH_E003` — the referenced mandate is outside its validity window.
  #[error("APH_E003: mandate expired: {mandate_id}")]
  MandateExpired {
    /// Identifier of the expired mandate.
    mandate_id: String,
  },

  /// `APH_E004` — a party attempted an operation its role does not permit
  /// under the §5 permission matrix.
  #[error("APH_E004: role `{role}` cannot perform `{operation}`")]
  RoleViolation {
    /// Role of the party that made the attempt.
    role: String,
    /// Operation that was attempted.
    operation: String,
  },

  /// `APH_E005` — the channel is not listed in the delegation mandate's
  /// `allowedChannels`.
  #[error("APH_E005: channel `{channel}` not allowed by delegation mandate")]
  ChannelNotAllowed {
    /// Channel kind that fell outside the granted scope.
    channel: String,
  },

  /// `APH_E006` — a mandate's `notarySignature` did not verify (distinct
  /// from `APH_E001`, which covers the envelope-level proof).
  #[error("APH_E006: notary service signature invalid")]
  NotarySignatureInvalid,

  /// `APH_E007` — the operation requires a human decision that has not
  /// been obtained.
  #[error("APH_E007: human authentication required")]
  HumanAuthenticationRequired,

  /// `APH_E008` — a protocol-mandated fetch from a notary-hosted surface
  /// did not succeed, so no decision could be made either way: the service
  /// itself could not be reached, or a document it is contracted to serve
  /// could not be reached, parsed, or validated — a DID Document (spec
  /// §8.4.4) or a revocation status list credential (spec §6.3.3.4 case 2,
  /// which folds TLS, parse, proof, issuer, purpose and freshness failures
  /// into this one code because the verifier's action and the operator's
  /// remedy are identical in all of them; log the specific cause, do not
  /// mint a code for it). Distinct from `APH_E014`, which means the
  /// surface ANSWERED and published nothing.
  #[error("APH_E008: notary service unreachable")]
  NotaryServiceUnreachable,

  /// `APH_E009` — the delivered body does not hash to the value the
  /// envelope attests, indicating tampering or a mismatched payload.
  #[error("APH_E009: envelope body hash mismatch (expected `{expected}`, got `{actual}`)")]
  EnvelopeBodyHashMismatch {
    /// Hash recorded in `communication.bodySha256`.
    expected: String,
    /// Hash recomputed over the received body.
    actual: String,
  },

  /// `APH_E010` — the declared algorithm is outside the allow-list
  /// (`ES256`, `EdDSA`); `alg: none` is always rejected here.
  #[error("APH_E010: unsupported signature algorithm: {alg}")]
  UnsupportedAlgorithm {
    /// The rejected algorithm identifier.
    alg: String,
  },

  /// `APH_E011` — a signature made by the HUMAN's key did not verify:
  /// the principal proof of a chain, or an embedded delegation mandate's
  /// `principalSignature`. Deliberately distinct from `APH_E001` and
  /// `APH_E006`, which are both NOTARY signatures — conflating them would
  /// report a forged authorization as a notary misconfiguration.
  #[error("APH_E011: principal signature invalid")]
  PrincipalSignatureInvalid,

  /// `APH_E012` — the verifier requires `PrincipalSigned` and the envelope
  /// is `NotaryAttested`. Not a defect in the envelope: a refusal to accept
  /// the weaker claim, which the spec forbids doing silently.
  #[error("APH_E012: attestation mode refused: required `{required}`, envelope is `{actual}`")]
  AttestationModeRefused {
    /// The mode the verifier's policy demands.
    required: String,
    /// The mode the envelope actually declares.
    actual: String,
  },

  /// `APH_E013` — the proof chain is malformed: wrong length, wrong
  /// `proofPurpose` for a position, or a `previousProof` that is missing,
  /// dangling, duplicated, or cyclic.
  #[error("APH_E013: proof chain invalid: {reason}")]
  ProofChainInvalid {
    /// What specifically is wrong with the chain.
    reason: String,
  },

  /// `APH_E014` — no notary key is published at the queried discovery
  /// surface: the DNS TXT name carries no APH record (or none matching the
  /// named `kid`), or a fetched DID Document names no key under the queried
  /// fragment. Deliberately distinct from `APH_E008`, which means the
  /// surface could not be REACHED: §8.4.6's no-downgrade rule turns on
  /// exactly this distinction — absence advances the fallback sequence,
  /// failure must stop it — and a taxonomy that flattens the two forces
  /// every consumer's error surface to flatten them again.
  #[error("APH_E014: notary key not published: {surface}")]
  NotaryKeyNotPublished {
    /// Which discovery surface answered "nothing is published here".
    surface: String,
  },

  /// `APH_E015` — the parent delegation mandate's bit is SET in the
  /// revocation status list its issuing notary publishes (spec §6.3.3):
  /// the human withdrew the standing authority this envelope was issued
  /// under. The signatures are still valid — this is a WITHDRAWN
  /// authorization, not a forged one, so reporting it as a signature
  /// failure would send an operator to inspect key material when the
  /// answer is a human decision. Deliberately distinct from `APH_E003`,
  /// which is authority that ran out on schedule rather than authority
  /// that was pulled.
  ///
  /// Carries the mandate id alone, mirroring `APH_E003`: the revocation
  /// timestamp lives in the notary's status state, not in the refusal.
  #[error("APH_E015: delegation mandate revoked: {mandate_id}")]
  MandateRevoked {
    /// Identifier of the revoked delegation mandate.
    mandate_id: String,
  },

  /// `APH_E016` — a human-not-present notarization (§9.2) was attempted with
  /// no matching, unexpired delegation mandate: nothing authorized this act.
  /// Held distinct from THREE neighbours because the remedies differ
  /// completely — `APH_E007` is *nobody was asked* (reach the human),
  /// `APH_E011` is *the authorization presented is invalid* (inspect it),
  /// `APH_E015` is *the authorization was withdrawn* (obtain a new one).
  /// Reporting an ABSENT mandate under any of those conflates absence with
  /// failure — the distinction this crate makes structural everywhere else
  /// (`discovery::DiscoveryOutcome`). Added 2026-08-23 from an implementer
  /// field report: the first production consumer had to misuse an
  /// invalid-mandate code for exactly this case.
  #[error("APH_E016: no delegation mandate authorizes this act (agent `{agent_did}`, channel `{channel_kind}`)")]
  MandateRequired {
    /// DID of the agent that attempted the act.
    agent_did: String,
    /// Channel kind the act targeted.
    channel_kind: String,
  },

  /// `APH_E017` — the envelope names an audience that is not this verifier:
  /// its `audience.id` differs from the verifier's own identity, or a
  /// present `channelBinding` member differs from the delivery coordinates
  /// of the act being performed.
  ///
  /// REGISTERED AHEAD OF ITS RFC. The `audience` field is RFC 0003 (Draft)
  /// and no type in this crate carries it yet — the code exists now, per the
  /// specification's additive-codes rule, so an implementation exercising
  /// the draft ahead of ratification emits a stable code instead of minting
  /// a private one. That is the same reasoning that added `APH_E016` from a
  /// field report: the first consumer to need a code should not have to
  /// misuse a neighbour. An envelope with no `audience` member never
  /// produces this code — absence is the producer's decision to issue a
  /// bearer credential, and RFC 0003 is explicit that a verifier that cannot
  /// determine its OWN identity rejects rather than skips.
  #[error("APH_E017: audience mismatch: envelope names `{audience_id}`, this verifier is `{verifier_id}`")]
  AudienceMismatch {
    /// The audience the envelope names (`credentialSubject.audience.id`).
    audience_id: String,
    /// The verifier's own identity, as it knows itself.
    verifier_id: String,
  },

  /// `APH_E018` — this envelope was already accepted once. RFC 0003's
  /// single-use step: a verifier records `id` at the moment it commits to
  /// the act (acceptance in the RFC 5321 §6.1 sense) and refuses every
  /// later presentation of the same `id`. The record is the RECIPIENT'S
  /// ledger obligation — two independent verifiers each accept once, which
  /// is why audience binding (`APH_E017`) and single-use are load-bearing
  /// together and neither is sufficient alone.
  #[error("APH_E018: envelope already spent: `{envelope_id}` was accepted before")]
  EnvelopeAlreadySpent {
    /// The `id` that was presented again after acceptance.
    envelope_id: String,
  },

  /// `APH_E019` — the envelope's OWN validity window fails against the
  /// verifier's clock: `validFrom` is in the future or `validUntil` is in
  /// the past. Deliberately distinct from `APH_E003`, which is a *mandate*
  /// consulted past its expiry; before this code existed an implementer
  /// refusing an expired envelope had to invent a refusal or miscite
  /// `APH_E003`, and this crate's own tests nearly did.
  #[error("APH_E019: envelope window invalid: [{valid_from} .. {valid_until}] judged at {observed_at}")]
  EnvelopeWindowInvalid {
    /// The envelope's `validFrom`, verbatim.
    valid_from: String,
    /// The envelope's `validUntil`, verbatim.
    valid_until: String,
    /// The instant the verifier judged the window at, RFC 3339.
    observed_at: String,
  },

  /// `APH_E020` — the mandate constrains WHO may consume (RFC 0005's
  /// `allowedRecipientClasses`) and this envelope either declares a class
  /// outside the grant or declares none at all. The second half is
  /// deliberate: a constraint the envelope lets nobody check would be
  /// escapable by omission, and the threat here is one's own
  /// honest-but-over-broad agent — exactly the party the refusal teaches.
  /// Deliberately distinct from `APH_E005`, which is the MEDIUM being out
  /// of scope; this is the CONSUMER being out of scope on an allowed
  /// medium.
  #[error("APH_E020: recipient class not allowed: envelope declares `{declared}`, mandate `{mandate_id}` allows {{{allowed}}}")]
  RecipientClassNotAllowed {
    /// What the envelope's channel declared — or the literal word
    /// `nothing`, when it declared no class at all.
    declared: String,
    /// The constraining mandate's `id`.
    mandate_id: String,
    /// The granted classes, comma-joined, so the refusal teaches the fix.
    allowed: String,
  },

  /// `APH_E021` — a sealed payload addressed to THIS verifier did not
  /// open: wrong key, tampered ciphertext, or a seal staged under a
  /// different context (envelope, reader, or suite relabeled) — the four
  /// cases AEAD makes indistinguishable by design. Per RFC 0008 §4 this
  /// refuses the ENVELOPE, never the seal alone: an unopenable seal
  /// addressed to you is evidence, not an inconvenience.
  ///
  /// DECLARED BY spec/aph-0.2.md, absent from v0.1.0's closed
  /// twenty; emitted only on wires that declare `sealedPayload`.
  #[error("APH_E021: sealed payload addressed to this verifier did not open (envelope `{envelope_id}`)")]
  SealUnopenable {
    /// The envelope whose seal refused.
    envelope_id: String,
  },

  /// `APH_E022` — the sealed payload names a ciphersuite this verifier
  /// does not compile. One suite per draft, no negotiation; refused by
  /// name before any key material is touched. Declared by
  /// spec/aph-0.2.md.
  #[error("APH_E022: sealed payload suite `{suite}` is not supported (this build seals only `{supported}`)")]
  SealSuiteUnknown {
    /// The suite the payload claimed.
    suite: String,
    /// The one suite this build compiles.
    supported: String,
  },

  /// `APH_E023` — the seal's reader key could not be discovered: the
  /// reader's DID document publishes no matching `keyAgreement` entry for
  /// the named `kid`. Held distinct from `APH_E014` exactly as E014 is
  /// held distinct from E008: WHICH surface came up empty is the repair.
  /// Declared by spec/aph-0.2.md.
  #[error("APH_E023: no `keyAgreement` key `{kid}` published for reader `{reader_id}`")]
  SealReaderKeyUnpublished {
    /// The reader DID whose document was consulted.
    reader_id: String,
    /// The kid the sealed payload named.
    kid: String,
  },

  /// `APH_E024` — a rotation attestation (RFC 0001, v0.2) failed a
  /// structural rule or its predecessor signature. The message carries the
  /// SPECIFIC defect — which rule, which value — because "invalid" with no
  /// reason teaches an operator nothing about a statement whose entire job
  /// is auditability.
  #[error("APH_E024: rotation attestation invalid: {reason}")]
  RotationAttestationInvalid {
    /// The specific rule that refused, with the offending values.
    reason: String,
  },
}

impl AphError {
  // ── Code + suggestion ──────────────────────────────────────────────

  /// Returns the APH error code string (e.g., `"APH_E001"`).
  pub fn code(&self) -> &'static str {
    match self {
      Self::InvalidEnvelopeSignature => "APH_E001",
      Self::InvalidFlowTransition { .. } => "APH_E002",
      Self::MandateExpired { .. } => "APH_E003",
      Self::RoleViolation { .. } => "APH_E004",
      Self::ChannelNotAllowed { .. } => "APH_E005",
      Self::NotarySignatureInvalid => "APH_E006",
      Self::HumanAuthenticationRequired => "APH_E007",
      Self::NotaryServiceUnreachable => "APH_E008",
      Self::EnvelopeBodyHashMismatch { .. } => "APH_E009",
      Self::UnsupportedAlgorithm { .. } => "APH_E010",
      Self::PrincipalSignatureInvalid => "APH_E011",
      Self::AttestationModeRefused { .. } => "APH_E012",
      Self::ProofChainInvalid { .. } => "APH_E013",
      Self::NotaryKeyNotPublished { .. } => "APH_E014",
      Self::MandateRevoked { .. } => "APH_E015",
      Self::MandateRequired { .. } => "APH_E016",
      Self::AudienceMismatch { .. } => "APH_E017",
      Self::EnvelopeAlreadySpent { .. } => "APH_E018",
      Self::EnvelopeWindowInvalid { .. } => "APH_E019",
      Self::RecipientClassNotAllowed { .. } => "APH_E020",
      Self::SealUnopenable { .. } => "APH_E021",
      Self::SealSuiteUnknown { .. } => "APH_E022",
      Self::SealReaderKeyUnpublished { .. } => "APH_E023",
      Self::RotationAttestationInvalid { .. } => "APH_E024",
    }
  }

  /// Returns a human-readable suggestion for resolving this error.
  pub fn suggestion(&self) -> &'static str {
    match self {
      Self::InvalidEnvelopeSignature => "Verify the notary signing key and re-sign",
      Self::InvalidFlowTransition { .. } => "Check the APH notarization flow state machine",
      Self::MandateExpired { .. } => "Issue a fresh mandate with a future `validUntil`",
      Self::RoleViolation { .. } => "Ensure the party holds the correct AphPartyRole",
      Self::ChannelNotAllowed { .. } => "Grant the channel scope on the delegation mandate",
      Self::NotarySignatureInvalid => "Verify the notary's JWK matches `verificationMethod`",
      Self::HumanAuthenticationRequired => "Prompt the human for AskEveryTime confirmation",
      Self::NotaryServiceUnreachable => "Check notary endpoint health + retry with backoff",
      Self::EnvelopeBodyHashMismatch { .. } => "Re-hash the body and compare against `bodySha256`",
      Self::UnsupportedAlgorithm { .. } => "Use one of `ES256` or `EdDSA`; reject `alg: none`",
      Self::PrincipalSignatureInvalid => "Re-sign with the human's key; check it matches `humanPrincipalDid`",
      Self::AttestationModeRefused { .. } => "Re-issue in `PrincipalSigned` mode, or relax the policy deliberately",
      Self::ProofChainInvalid { .. } => "Emit principal proof then notary proof, linked by `previousProof`",
      Self::NotaryKeyNotPublished { .. } => "Publish the key at this surface (§8.4.4/§8.4.5), or query one the notary publishes to",
      Self::MandateRevoked { .. } => "Obtain a fresh delegation mandate from the human principal; a revoked mandate cannot be re-activated (§6.3.2)",
      Self::MandateRequired { .. } => "Issue a delegation mandate covering this channel and scope, or route the act through the human-present flow (§9.1)",
      Self::AudienceMismatch { .. } => "Deliver the envelope to the endpoint it names, or re-issue naming the intended recipient",
      Self::EnvelopeAlreadySpent { .. } => "Mint a fresh envelope for a new act; acceptance consumes an envelope and a replayed one is refused by design",
      Self::EnvelopeWindowInvalid { .. } => "Mint a fresh envelope with a current window; single-act windows should be minutes, not hours",
      Self::RecipientClassNotAllowed { .. } => "Declare the recipient class the act actually has, or ask the principal for a grant that covers it",
      Self::SealUnopenable { .. } => "Refuse the envelope and tell the sender: re-seal to the current keyAgreement key under this envelope's own context",
      Self::SealSuiteUnknown { .. } => "Re-seal with the one supported suite; suite agility arrives by amendment, not negotiation",
      Self::SealReaderKeyUnpublished { .. } => "Publish a keyAgreement entry under that kid, or seal to a key the reader actually publishes",
      Self::RotationAttestationInvalid { .. } => "Re-mint the attestation with the predecessor key it names, over the lone-proof base, with an ordered window",
    }
  }

  // ── Constructors ────────────────────────────────────────────────────

  /// Builds an `APH_E002` naming the illegal edge that was attempted.
  pub fn invalid_flow_transition(
    from: impl std::convert::Into<String>,
    to: impl std::convert::Into<String>,
  ) -> Self {
    Self::InvalidFlowTransition {
      from: from.into(),
      to: to.into(),
    }
  }

  /// Builds an `APH_E003` naming the expired mandate.
  pub fn mandate_expired(mandate_id: impl std::convert::Into<String>) -> Self {
    Self::MandateExpired {
      mandate_id: mandate_id.into(),
    }
  }

  /// Builds an `APH_E014` naming the surface that published nothing.
  pub fn notary_key_not_published(surface: impl std::convert::Into<String>) -> Self {
    Self::NotaryKeyNotPublished {
      surface: surface.into(),
    }
  }

  /// Builds an `APH_E004` naming the role and the denied operation.
  pub fn role_violation(
    role: impl std::convert::Into<String>,
    operation: impl std::convert::Into<String>,
  ) -> Self {
    Self::RoleViolation {
      role: role.into(),
      operation: operation.into(),
    }
  }

  /// Builds an `APH_E005` naming the out-of-scope channel.
  pub fn channel_not_allowed(channel: impl std::convert::Into<String>) -> Self {
    Self::ChannelNotAllowed {
      channel: channel.into(),
    }
  }

  /// Builds an `APH_E009` carrying both the attested and the recomputed
  /// hash so an investigator can tell which side diverged.
  pub fn envelope_body_hash_mismatch(
    expected: impl std::convert::Into<String>,
    actual: impl std::convert::Into<String>,
  ) -> Self {
    Self::EnvelopeBodyHashMismatch {
      expected: expected.into(),
      actual: actual.into(),
    }
  }

  /// Builds an `APH_E010` naming the rejected algorithm.
  pub fn unsupported_algorithm(alg: impl std::convert::Into<String>) -> Self {
    Self::UnsupportedAlgorithm { alg: alg.into() }
  }

  /// Builds an `APH_E012` recording both modes, so an operator can see what
  /// was demanded and what arrived without re-parsing the envelope.
  pub fn attestation_mode_refused(
    required: impl std::convert::Into<String>,
    actual: impl std::convert::Into<String>,
  ) -> Self {
    Self::AttestationModeRefused {
      required: required.into(),
      actual: actual.into(),
    }
  }

  /// Builds an `APH_E013` naming what is wrong with the chain.
  pub fn proof_chain_invalid(reason: impl std::convert::Into<String>) -> Self {
    Self::ProofChainInvalid {
      reason: reason.into(),
    }
  }

  /// Builds an `APH_E015` naming the revoked delegation mandate.
  pub fn mandate_revoked(mandate_id: impl std::convert::Into<String>) -> Self {
    Self::MandateRevoked {
      mandate_id: mandate_id.into(),
    }
  }

  /// Builds an `APH_E016` naming the agent and channel nothing authorized,
  /// so the operator's first question — WHO tried WHAT — is answered by the
  /// error itself rather than by log correlation.
  pub fn mandate_required(
    agent_did: impl std::convert::Into<String>,
    channel_kind: impl std::convert::Into<String>,
  ) -> Self {
    Self::MandateRequired {
      agent_did: agent_did.into(),
      channel_kind: channel_kind.into(),
    }
  }

  /// Builds an `APH_E017` naming both identities, so the operator's first
  /// question — for WHOM was this envelope, and who am I — is answered by
  /// the error itself.
  pub fn audience_mismatch(
    audience_id: impl std::convert::Into<String>,
    verifier_id: impl std::convert::Into<String>,
  ) -> Self {
    Self::AudienceMismatch {
      audience_id: audience_id.into(),
      verifier_id: verifier_id.into(),
    }
  }

  /// Builds an `APH_E018` naming the id whose second presentation was
  /// refused, so an operator can find the first acceptance in their ledger.
  pub fn envelope_already_spent(envelope_id: impl std::convert::Into<String>) -> Self {
    Self::EnvelopeAlreadySpent { envelope_id: envelope_id.into() }
  }

  /// Builds an `APH_E019` carrying the window verbatim and the instant it
  /// was judged at; without all three, "expired" is unactionable.
  pub fn envelope_window_invalid(
    valid_from: impl std::convert::Into<String>,
    valid_until: impl std::convert::Into<String>,
    observed_at: impl std::convert::Into<String>,
  ) -> Self {
    Self::EnvelopeWindowInvalid {
      valid_from: valid_from.into(),
      valid_until: valid_until.into(),
      observed_at: observed_at.into(),
    }
  }

  /// Builds an `APH_E020` naming what was declared (or `nothing`), which
  /// mandate constrained it, and what that mandate allows.
  pub fn recipient_class_not_allowed(
    declared: impl std::convert::Into<String>,
    mandate_id: impl std::convert::Into<String>,
    allowed: impl std::convert::Into<String>,
  ) -> Self {
    Self::RecipientClassNotAllowed {
      declared: declared.into(),
      mandate_id: mandate_id.into(),
      allowed: allowed.into(),
    }
  }

  /// Builds an `APH_E021` naming the envelope whose seal refused.
  pub fn seal_unopenable(envelope_id: impl std::convert::Into<String>) -> Self {
    Self::SealUnopenable { envelope_id: envelope_id.into() }
  }

  /// Builds an `APH_E022` naming both the claimed and the supported suite.
  pub fn seal_suite_unknown(
    suite: impl std::convert::Into<String>,
    supported: impl std::convert::Into<String>,
  ) -> Self {
    Self::SealSuiteUnknown { suite: suite.into(), supported: supported.into() }
  }

  /// Builds an `APH_E023` naming the reader and the missing kid.
  pub fn seal_reader_key_unpublished(
    reader_id: impl std::convert::Into<String>,
    kid: impl std::convert::Into<String>,
  ) -> Self {
    Self::SealReaderKeyUnpublished { reader_id: reader_id.into(), kid: kid.into() }
  }

  /// Builds an `APH_E024` carrying the specific rule that refused.
  pub fn rotation_attestation_invalid(reason: impl std::convert::Into<String>) -> Self {
    Self::RotationAttestationInvalid { reason: reason.into() }
  }
}

#[cfg(test)]
mod tests {
  fn all_variants() -> std::vec::Vec<super::AphError> {
    std::vec![
      super::AphError::InvalidEnvelopeSignature,
      super::AphError::invalid_flow_transition("Drafted", "Delivered"),
      super::AphError::mandate_expired("urn:uuid:00000000-0000-4000-8000-000000000001"),
      super::AphError::role_violation("AgentSender", "Notarize"),
      super::AphError::channel_not_allowed("slack"),
      super::AphError::NotarySignatureInvalid,
      super::AphError::HumanAuthenticationRequired,
      super::AphError::NotaryServiceUnreachable,
      super::AphError::envelope_body_hash_mismatch("abc", "def"),
      super::AphError::unsupported_algorithm("HS256"),
      super::AphError::PrincipalSignatureInvalid,
      super::AphError::attestation_mode_refused("PrincipalSigned", "NotaryAttested"),
      super::AphError::proof_chain_invalid("previousProof does not name a proof in this chain"),
      super::AphError::notary_key_not_published("_aph._notary.example.com"),
      super::AphError::mandate_revoked("urn:uuid:00000000-0000-4000-8000-000000000002"),
      super::AphError::mandate_required("did:key:zTestAgent", "slack"),
      super::AphError::audience_mismatch("did:web:other.example.com", "did:web:this.example.com"),
      super::AphError::envelope_already_spent("urn:uuid:00000000-0000-4000-8000-000000000003"),
      super::AphError::envelope_window_invalid(
        "2026-05-21T12:00:00Z",
        "2026-05-21T12:10:00Z",
        "2026-05-21T13:00:00Z",
      ),
      super::AphError::recipient_class_not_allowed(
        "agent",
        "urn:uuid:00000000-0000-4000-8000-000000000004",
        "human",
      ),
      super::AphError::seal_unopenable("urn:uuid:00000000-0000-4000-8000-000000000005"),
      super::AphError::seal_suite_unknown("APH-SEAL-99", "APH-SEAL-1"),
      super::AphError::seal_reader_key_unpublished("did:web:reader.example.com", "enc-1"),
      super::AphError::rotation_attestation_invalid("illustrative census entry"),
    ]
  }

  #[test]
  fn every_code_in_the_closed_set_is_unique() {
    // v0.1.0's §11 fixes a CLOSED set of exactly twenty codes, and
    // the v0.2 delta declares four more (E021-E024) — so this
    // build's enum holds twenty-four, and
    // other implementations branch on them. A duplicate would make two
    // distinct failures indistinguishable to a remote verifier. The count
    // is pinned so that adding a code without amending §11 fails here.
    //
    // The guarantee in that last sentence had already failed once: this
    // list omitted `NotaryKeyNotPublished` from the day APH_E014 landed,
    // so the count stayed at thirteen against a §11 that said fourteen and
    // E014 was swept by NONE of the three all_variants() tests below. Both
    // missing entries are restored here alongside APH_E015 — the sweep is
    // only worth its comment if the list it walks is the whole enum. And it
    // failed a SECOND time the very day APH_E016 landed: the new variant's
    // own pin test passed while this list still held fifteen, because a
    // hand-maintained census cannot fail on what it does not contain. The
    // count-free test name is deliberate (the old name carried the number
    // and rotted); the pinned count below is the tripwire, kept in exactly
    // one place.
    let errors = all_variants();
    std::assert_eq!(errors.len(), 24);
    let codes: std::vec::Vec<&str> = errors.iter().map(|e| e.code()).collect();
    let mut unique = codes.clone();
    unique.sort();
    unique.dedup();
    std::assert_eq!(codes.len(), unique.len(), "error codes must be unique");
  }

  #[test]
  fn the_three_signature_failures_have_three_distinct_codes() {
    // A verifier reports WHY a credential failed, and the three signature
    // failures mean entirely different things: APH_E001 is the notary's
    // envelope proof, APH_E006 the notary's mandate signature, APH_E011 the
    // HUMAN's own signature. Only the last means the authorization itself
    // is forged or corrupt. Collapsing them would report a forged
    // authorization as a notary misconfiguration, which is the wrong alarm.
    std::assert_eq!(super::AphError::InvalidEnvelopeSignature.code(), "APH_E001");
    std::assert_eq!(super::AphError::NotarySignatureInvalid.code(), "APH_E006");
    std::assert_eq!(super::AphError::PrincipalSignatureInvalid.code(), "APH_E011");
  }

  #[test]
  fn attestation_mode_refusal_names_both_modes() {
    // Refusing a downgrade is a policy decision, not a malformed envelope,
    // so the error has to say what was demanded AND what arrived — an
    // operator reading a log must be able to tell a misconfigured verifier
    // from a sender that never signed.
    let err = super::AphError::attestation_mode_refused("PrincipalSigned", "NotaryAttested");
    let text = std::string::ToString::to_string(&err);
    std::assert!(text.contains("PrincipalSigned"), "missing required mode: {}", text);
    std::assert!(text.contains("NotaryAttested"), "missing actual mode: {}", text);
  }

  #[test]
  fn proof_chain_invalid_carries_the_reason() {
    // A chain can be malformed in several distinct ways (length, purpose,
    // dangling previousProof). One opaque code per family would leave an
    // implementer guessing, so the reason travels with the error.
    let err = super::AphError::proof_chain_invalid("previousProof is dangling");
    std::assert_eq!(err.code(), "APH_E013");
    std::assert!(std::string::ToString::to_string(&err).contains("dangling"));
  }

  #[test]
  fn codes_follow_aph_e_nnn_format() {
    // Code strings are a cross-implementation contract; consumers pattern
    // match on the APH_Ennn shape, so a stray format would not merely look
    // wrong, it would fail their matchers.
    for err in all_variants() {
      let code = err.code();
      std::assert!(
        code.starts_with("APH_E"),
        "code `{}` lacks APH_E prefix",
        code
      );
      std::assert_eq!(code.len(), 8, "code `{}` is not 8 chars", code);
    }
  }

  #[test]
  fn every_variant_has_non_empty_suggestion() {
    // The spec says implementations SHOULD surface a suggested resolution;
    // an empty one leaves an operator staring at a bare code with no path
    // forward. Easy to forget when adding a variant, hence the sweep.
    for err in all_variants() {
      std::assert!(
        !err.suggestion().is_empty(),
        "{} has empty suggestion",
        err.code()
      );
    }
  }

  #[test]
  fn display_includes_code_for_every_variant() {
    // Logs usually capture only the Display string, so the code must be
    // embedded in it — otherwise a failure in production cannot be mapped
    // back to its spec-defined cause.
    for err in all_variants() {
      let msg = format!("{err}");
      std::assert!(
        msg.contains(err.code()),
        "Display `{}` does not include code `{}`",
        msg,
        err.code()
      );
    }
  }

  #[test]
  fn invalid_flow_transition_constructor_preserves_strings() {
    // Constructors take context arguments that only reach an operator via
    // the message; if from/to were dropped, an APH_E002 would say a
    // transition was illegal without saying which one.
    let err = super::AphError::invalid_flow_transition("Drafted", "EnvelopeIssued");
    let msg = format!("{err}");
    std::assert!(msg.contains("Drafted"));
    std::assert!(msg.contains("EnvelopeIssued"));
    std::assert_eq!(err.code(), "APH_E002");
  }

  #[test]
  fn mandate_expired_constructor_preserves_id() {
    // The mandate id is what lets an operator find and re-issue the
    // expired delegation; losing it makes APH_E003 unactionable.
    let err = super::AphError::mandate_expired("urn:uuid:abc");
    let msg = format!("{err}");
    std::assert!(msg.contains("urn:uuid:abc"));
    std::assert_eq!(err.code(), "APH_E003");
  }

  #[test]
  fn role_violation_constructor_preserves_role_and_op() {
    // A permission-matrix denial is a security event: both the role and
    // the attempted operation must survive into the message, or the audit
    // trail cannot say who tried to do what.
    let err = super::AphError::role_violation("AgentSender", "Notarize");
    let msg = format!("{err}");
    std::assert!(msg.contains("AgentSender"));
    std::assert!(msg.contains("Notarize"));
    std::assert_eq!(err.code(), "APH_E004");
  }

  #[test]
  fn channel_not_allowed_constructor_preserves_channel() {
    // Names the channel that fell outside the delegation's scope — the
    // detail a human needs to decide whether to widen the mandate.
    let err = super::AphError::channel_not_allowed("discord");
    let msg = format!("{err}");
    std::assert!(msg.contains("discord"));
    std::assert_eq!(err.code(), "APH_E005");
  }

  #[test]
  fn envelope_body_hash_mismatch_constructor_preserves_hashes() {
    // APH_E009 means the delivered body does not match what was notarized
    // — possible tampering. BOTH hashes must appear so an investigator can
    // tell which side changed rather than just that something did.
    let err = super::AphError::envelope_body_hash_mismatch("sha256:aaa", "sha256:bbb");
    let msg = format!("{err}");
    std::assert!(msg.contains("sha256:aaa"));
    std::assert!(msg.contains("sha256:bbb"));
    std::assert_eq!(err.code(), "APH_E009");
  }

  #[test]
  fn revoked_is_not_expired_and_names_the_mandate() {
    // Expiry and revocation are the two ways standing authority ends, and
    // they call for opposite responses: an expired mandate is routine
    // housekeeping, a revoked one is a human who changed their mind and
    // whose decision must not be re-granted by reflex. Collapsing them
    // into one code would hide that, and the mandate id is what lets an
    // operator find WHICH grant was pulled — APH_E015 is unactionable
    // without it, exactly as APH_E003 is.
    let revoked = super::AphError::mandate_revoked("urn:uuid:def");
    let expired = super::AphError::mandate_expired("urn:uuid:def");
    std::assert_eq!(revoked.code(), "APH_E015");
    std::assert_eq!(expired.code(), "APH_E003");
    std::assert_ne!(revoked, expired);
    std::assert!(std::string::ToString::to_string(&revoked).contains("urn:uuid:def"));
  }

  /// WHY THIS TEST EXISTS: the first production consumer of the human-not-
  /// present flow had to reuse an invalid-mandate code for the no-mandate
  /// case, because §11 had no code for unrooted authority — absence reported
  /// as failure, the conflation this crate exists to keep structural.
  /// WHAT IT PINS: `APH_E016` is its own code, distinct from its neighbours
  /// (absent ≠ invalid ≠ revoked ≠ human-unreachable), and the message names
  /// the agent and channel so the refusal is actionable without log
  /// correlation.
  #[test]
  fn an_absent_mandate_is_its_own_refusal_not_an_invalid_one() {
    let required =
      super::AphError::mandate_required("did:key:zAgent", "slack");
    std::assert_eq!(required.code(), "APH_E016");
    std::assert_ne!(required.code(), super::AphError::mandate_revoked("x").code());
    let msg = std::string::ToString::to_string(&required);
    std::assert!(msg.contains("did:key:zAgent"));
    std::assert!(msg.contains("slack"));
    std::assert!(
      required.suggestion().contains("§9.1"),
      "the remedy must point at the human-present flow, not at mandate repair"
    );
  }

  #[test]
  fn unsupported_algorithm_constructor_preserves_alg() {
    // Uses "none" deliberately: alg:none is the classic JWS downgrade
    // attack, and the spec requires rejecting it with APH_E010. The
    // rejected algorithm name must reach the log to make the attempt
    // visible rather than silently dropped.
    let err = super::AphError::unsupported_algorithm("none");
    let msg = format!("{err}");
    std::assert!(msg.contains("none"));
    std::assert_eq!(err.code(), "APH_E010");
  }
}
