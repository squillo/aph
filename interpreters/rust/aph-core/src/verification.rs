//! Structural verification of an envelope's proof block — spec §7.1.11,
//! §7.1.7.1, §7.2.1 and §8.3.1 steps 1a, 1d, 1e.
//!
//! This module answers one question: *is this envelope's proof structure
//! well formed, and does it say what it is?* It is deliberately PURE — no
//! cryptography, no key resolution, no network, no clock. Signature checking
//! belongs to [`crate::crypto`]; key discovery belongs to
//! [`crate::discovery`]; deciding *which* mode a deployment demands belongs
//! to the caller.
//!
//! The reason these checks are separated out and made mandatory is stated
//! in §7.1.11: without them `attestationMode` is a **self-asserted string**.
//! A holder of a notary key could write `PrincipalSigned` above a single
//! notary proof whose `proofPurpose` is `assertionMethod` — indistinguishable
//! from a principal proof by purpose alone — and a verifier that trusted the
//! label would report a forged authorization as the human's own signature.
//! Every rule below exists to make the label unforgeable by a notary.
//!
//! Order of use, mirroring §8.3.1:
//!
//! 1. [`require_mode`] — step 1a. Refuse an envelope weaker than policy
//!    demands BEFORE doing any work on unauthenticated input.
//! 2. [`verify_proof_structure`] — steps 1a (label/structure agreement) and
//!    1e (chain linkage). Returns the mode the envelope is actually in.
//! 3. [`verify_embedded_mandate_binding`] — step 1d, the non-cryptographic
//!    half: is the embedded mandate THIS envelope's parent?
//! 4. [`verify_timestamp_order`] — the issuance order §7.2.1 makes normative.
//!
//! Timestamps are compared by parsing them with `chrono`, which is what
//! [`crate::delegation_mandate::DelegationMandate::is_valid_at`] and
//! [`crate::discovery::dns_txt`] already do, and every comparison fails
//! CLOSED on an unparseable value. No date library is introduced: `chrono`
//! is already a dependency of this crate for exactly this purpose.

/// `proofPurpose` of a principal proof, and of a lone notary proof kept for
/// wire compatibility (§7.1.11).
const ASSERTION_METHOD: &str = "assertionMethod";

/// `proofPurpose` of a notary countersignature — the value that distinguishes
/// the second proof of a chain from the first (§7.1.11).
const AUTHENTICATION: &str = "authentication";

/// Verifies the structural rules of §7.1.11 and returns the mode the
/// envelope is actually in.
///
/// This is the check that makes `attestationMode` mean something. It
/// enforces, each with its own `APH_E013` reason string:
///
/// - a chain carries EXACTLY two proofs;
/// - position 1 has `proofPurpose == "assertionMethod"`, position 2
///   `"authentication"`;
/// - both chain proofs carry an `id`, and the two ids differ;
/// - the notary proof's `previousProof` equals the principal proof's `id` —
///   array position is a hint, this linkage is the binding (§7.1.11);
/// - the principal proof carries NO `previousProof`; it is the chain head;
/// - label and structure agree in BOTH directions: a chain MUST be labelled
///   `PrincipalSigned`, and `PrincipalSigned` MUST be a chain. A mismatch is
///   a rejection, never a silent coercion;
/// - the principal proof's `verificationMethod` is a DID URL under
///   `credentialSubject.humanPrincipal.id`. This is the rule that closes the
///   forgery §7.1.11 describes, because the notary does not hold that key.
///
/// A single-object `proof` is a notary proof and yields `NotaryAttested` —
/// the shape all eight published example envelopes carry.
///
/// A successful return says the structure is sound; it says NOTHING about
/// whether either signature verifies. A caller that reports "the human
/// signed this" on the strength of this function alone is reporting a claim
/// no key has backed.
pub fn verify_proof_structure(
  envelope: &crate::envelope::NotarizationEnvelope,
) -> std::result::Result<crate::envelope::AttestationMode, crate::errors::AphError> {
  let declared = envelope.credential_subject.policy.attestation_mode;

  // ── The single-object form ────────────────────────────────────────────
  if !envelope.proof.is_chain() {
    if declared
      == std::option::Option::Some(crate::envelope::AttestationMode::PrincipalSigned)
    {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "`attestationMode` is `PrincipalSigned` but `proof` is a single object; \
         the label MUST accompany a two-element chain (§7.1.11)",
      ));
    }
    // A lone proof links to nothing, so chain members on it are not merely
    // redundant — they are a claim about a chain that does not exist. §7.1.11
    // says `id` is "omitted for a single-object `proof`" and a
    // `previousProof` here is dangling by construction. Accepting either
    // would let a stripped chain keep the vocabulary of one, and a verifier
    // reading loosely could conclude a principal proof had been present.
    let lone = match envelope.proof.notary() {
      std::option::Option::Some(proof) => proof,
      // A non-chain always has exactly one proof; refuse rather than index.
      std::option::Option::None => {
        return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
          "`proof` is neither a chain nor a single proof",
        ));
      }
    };
    if lone.id.is_some() || lone.previous_proof.is_some() {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "a single-object `proof` MUST carry neither `id` nor `previousProof`; \
         both belong to a chain, and a lone proof links to nothing (§7.1.11)",
      ));
    }
    // §7.1.11: a lone proof "uses `assertionMethod` for wire compatibility".
    // `authentication` is the countersignature purpose and means a chain was
    // intended, so a lone proof carrying it is a chain missing its head.
    if lone.proof_purpose != ASSERTION_METHOD {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        std::format!(
          "a single-object `proof` MUST use `proofPurpose` `{}`; found `{}` (§7.1.11)",
          ASSERTION_METHOD, lone.proof_purpose
        ),
      ));
    }
    return std::result::Result::Ok(crate::envelope::AttestationMode::NotaryAttested);
  }

  // ── The array form ────────────────────────────────────────────────────
  let proofs = envelope.proof.all();
  if proofs.len() != 2 {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      std::format!(
        "a proof chain MUST carry exactly two proofs (principal, then notary); found {}",
        proofs.len()
      ),
    ));
  }

  // Label/structure agreement, the other direction: an array MUST be
  // labelled `PrincipalSigned`. Left unenforced, an intermediary could
  // present a chain as a notary attestation and the human's own proof would
  // be read as the notary's.
  match declared {
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "`proof` is a chain but `attestationMode` is absent; absent means \
         `NotaryAttested`, and a chain MUST declare `PrincipalSigned` (§7.1.11)",
      ));
    }
    std::option::Option::Some(crate::envelope::AttestationMode::NotaryAttested) => {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "`proof` is a chain but `attestationMode` is `NotaryAttested`; \
         a chain MUST declare `PrincipalSigned` (§7.1.11)",
      ));
    }
    std::option::Option::Some(crate::envelope::AttestationMode::PrincipalSigned) => {}
  }

  let (principal, notary) = match (envelope.proof.principal(), envelope.proof.notary()) {
    (std::option::Option::Some(p), std::option::Option::Some(n)) => (p, n),
    // Unreachable while the accessors key off the same length just checked.
    // Written as a refusal rather than an `unwrap` so that a future change
    // to `EnvelopeProofs` fails closed instead of panicking on hostile input.
    _ => {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "`proof` is not a well-formed two-element chain",
      ));
    }
  };

  // ── Proof purposes, per position (§7.1.11) ────────────────────────────
  if principal.proof_purpose != ASSERTION_METHOD {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      std::format!(
        "chain position 1 (principal proof) MUST have `proofPurpose` \
         `assertionMethod`; found `{}`",
        principal.proof_purpose
      ),
    ));
  }
  if notary.proof_purpose != AUTHENTICATION {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      std::format!(
        "chain position 2 (notary proof) MUST have `proofPurpose` \
         `authentication`; found `{}`",
        notary.proof_purpose
      ),
    ));
  }

  // ── Proof ids ─────────────────────────────────────────────────────────
  let principal_id = match principal.id.as_deref() {
    std::option::Option::Some(id) => id,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "chain position 1 (principal proof) MUST carry an `id`; \
         without one the notary proof has nothing to name (§7.1.11)",
      ));
    }
  };
  let notary_id = match notary.id.as_deref() {
    std::option::Option::Some(id) => id,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "chain position 2 (notary proof) MUST carry an `id`; \
         every proof in a chain is identified (§7.1.11)",
      ));
    }
  };
  if principal_id == notary_id {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      std::format!(
        "the two proofs in a chain MUST carry distinct `id`s; both are `{}`",
        principal_id
      ),
    ));
  }

  // ── Chain linkage (§8.3.1 step 1e) ────────────────────────────────────
  // Array position is a hint. `previousProof` is the binding, because a
  // verifier that trusted order alone would accept a chain an intermediary
  // reordered.
  if principal.previous_proof.is_some() {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      "the principal proof is the HEAD of the chain and MUST NOT carry \
       `previousProof` (§7.1.11)",
    ));
  }
  let previous = match notary.previous_proof.as_deref() {
    std::option::Option::Some(previous) => previous,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "the notary proof MUST carry `previousProof` naming the principal \
         proof's `id`; a chain without linkage is only an ordered array",
      ));
    }
  };
  if previous == notary_id {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      std::format!(
        "`previousProof` is self-referential: the notary proof names its own \
         `id` `{}`",
        notary_id
      ),
    ));
  }
  if previous != principal_id {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      std::format!(
        "`previousProof` `{}` is dangling: it does not name a proof in this \
         chain (the principal proof's `id` is `{}`)",
        previous, principal_id
      ),
    ));
  }

  // ── The binding that makes the label unforgeable (§7.1.11) ────────────
  // A DID URL is `<did>#<fragment>`. The principal proof MUST be made under
  // the human principal's own DID; a proof made by any other key is not the
  // principal's proof, whatever its `proofPurpose` says (§8.3.1 step 1c).
  // Only this check stops a notary — who does not hold the human's key —
  // from writing `PrincipalSigned` above a proof of its own.
  let human_did = envelope.credential_subject.human_principal.id.as_str();
  let principal_did = match principal.verification_method.split_once('#') {
    std::option::Option::Some((did, _fragment)) => did,
    std::option::Option::None => principal.verification_method.as_str(),
  };
  if principal_did != human_did {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      std::format!(
        "the principal proof's `verificationMethod` `{}` is not a DID URL under \
         the human principal `{}`; a proof made by any other key is not the \
         principal's proof (§7.1.11)",
        principal.verification_method, human_did
      ),
    ));
  }

  std::result::Result::Ok(crate::envelope::AttestationMode::PrincipalSigned)
}

/// Refuses an envelope weaker than the caller's policy demands (§8.3.1 1a).
///
/// `PrincipalSigned` required against a `NotaryAttested` envelope is
/// `APH_E012`. The reverse is fine: a stronger envelope satisfies a weaker
/// policy. There is no silent downgrade, for the same reason §8.4.6 forbids
/// downgrading key discovery — an attacker who can defeat the weak path will
/// always present the weak path.
///
/// This reads the DECLARED label, and deliberately so: §8.3.1 puts it at
/// step 1a precisely so a verifier refuses a too-weak claim *before* doing
/// work on unauthenticated input. The label is not evidence on its own, so a
/// caller MUST also call [`verify_proof_structure`], which is what rejects a
/// `PrincipalSigned` label written above a structure that does not support
/// it. Calling this function alone accepts a forged label.
pub fn require_mode(
  envelope: &crate::envelope::NotarizationEnvelope,
  required: crate::envelope::AttestationMode,
) -> std::result::Result<(), crate::errors::AphError> {
  let actual = envelope
    .credential_subject
    .policy
    .effective_attestation_mode();
  match (required, actual) {
    (
      crate::envelope::AttestationMode::PrincipalSigned,
      crate::envelope::AttestationMode::NotaryAttested,
    ) => std::result::Result::Err(crate::errors::AphError::attestation_mode_refused(
      required.label(),
      actual.label(),
    )),
    _ => std::result::Result::Ok(()),
  }
}

/// Binds an embedded Delegation Mandate to the envelope carrying it
/// (§7.1.7.1 steps 3-4, §8.3.1 step 1d). Signature checking is NOT here.
///
/// **Why this exists.** `policy.delegationMandateId` names the parent
/// mandate by id only, and an id is not verifiable. Embedding the whole
/// mandate lets a recipient check the human's `principalSignature` offline —
/// but a valid signature over *some* grant proves nothing about *this*
/// message. Without the equalities below, an attacker could staple any
/// validly-signed mandate to any envelope and the notary's word would again
/// be the only thing linking the human to the send. Closing that hole is the
/// entire purpose of §7.1.7.1.
///
/// Checks, in order:
///
/// - `mandate.humanPrincipalDid == credentialSubject.humanPrincipal.id`
/// - `mandate.agentDid == credentialSubject.agent.id`
/// - `mandate.id == policy.delegationMandateId`, when that field is present
/// - `channel.kind` is in `mandate.allowedChannels` (else `APH_E005`)
/// - the envelope's `validFrom` AND `validUntil` fall inside the mandate's
///   window (else `APH_E003`)
///
/// The three identity equalities report `APH_E011`: the embedded mandate
/// carries a principal signature that does not authorize THIS envelope, so
/// no valid signature by this human covers this authorization. §11 scopes
/// `APH_E011` to step 1d, and the two codes §8.3.1 names explicitly for that
/// step (`APH_E005`, `APH_E003`) cover only the scope and window failures.
///
/// A `None` embedded mandate is `Ok(())`. Absence is not a structural
/// defect: §7.1.7.1 makes embedding SHOULD, not MUST, because an embedded
/// mandate discloses the human's entire standing grant to every recipient.
/// What absence means is that the human's authorization is NOT verifiable by
/// this recipient, who should then treat the credential as the notary's
/// assertion alone — a policy decision, and the caller's to make.
///
/// **Bounds.** The embedded mandate parses under the same
/// `deny_unknown_fields` rule as the envelope (§7.1.7.1), so a mandate
/// carrying an unknown field never reaches this function. Rejecting an
/// oversized envelope before canonicalizing it remains the caller's job.
pub fn verify_embedded_mandate_binding(
  envelope: &crate::envelope::NotarizationEnvelope,
) -> std::result::Result<(), crate::errors::AphError> {
  let subject = &envelope.credential_subject;
  let mandate = match subject.policy.delegation_mandate.as_ref() {
    std::option::Option::Some(mandate) => mandate,
    std::option::Option::None => return std::result::Result::Ok(()),
  };

  if mandate.human_principal_did != subject.human_principal.id {
    return std::result::Result::Err(crate::errors::AphError::PrincipalSignatureInvalid);
  }
  if mandate.agent_did != subject.agent.id {
    return std::result::Result::Err(crate::errors::AphError::PrincipalSignatureInvalid);
  }
  if let std::option::Option::Some(declared_id) = subject.policy.delegation_mandate_id.as_deref() {
    if mandate.id != declared_id {
      return std::result::Result::Err(crate::errors::AphError::PrincipalSignatureInvalid);
    }
  }

  // §7.1.7.1 is explicit that a Delegation Mandate constrains channel, rate
  // and time and NOTHING else — it cannot express a recipient allow-list or
  // a content class, so this is a channel-and-window check and must not be
  // described as more.
  if !mandate.allows_channel(subject.channel.kind) {
    return std::result::Result::Err(crate::errors::AphError::channel_not_allowed(
      subject.channel.kind.label(),
    ));
  }

  // `is_valid_at` is the crate's existing RFC 3339 window comparison: it
  // parses with `chrono` and returns false on anything unparseable, so a
  // garbage timestamp denies rather than defaulting to valid. Both endpoints
  // are checked because §8.3.1 step 1d requires the envelope's WINDOW to
  // fall inside the mandate's, not merely its start.
  if !mandate.is_valid_at(&envelope.valid_from) || !mandate.is_valid_at(&envelope.valid_until) {
    return std::result::Result::Err(crate::errors::AphError::mandate_expired(
      mandate.id.as_str(),
    ));
  }

  std::result::Result::Ok(())
}

/// Pins the issuance order §7.2.1 makes normative:
/// `decisionTimestamp <= principal.created <= notary.created`.
///
/// The order is not stylistic. The notary prepares the complete envelope
/// (including its own `notarization` metadata), THEN the principal signs
/// what was prepared, THEN the notary countersigns the result. Reverse the
/// first two and the principal would have to sign notary-produced fields
/// that do not yet exist — the circularity the §7.2.1 canonicalization bases
/// are written to avoid. §7.2.1 states outright that a verifier MUST NOT
/// accept a chain whose notary proof is dated before the principal proof it
/// claims to have observed.
///
/// Out-of-order is `APH_E013`. Applies only to a chain: a single proof has
/// nothing to order, so a single-proof envelope returns `Ok(())`.
///
/// Timestamps are parsed with `chrono`, matching
/// [`crate::delegation_mandate::DelegationMandate::is_valid_at`] rather than
/// comparing strings, so an offset written as `+00:00` orders correctly
/// against the same instant written as `Z`. An unparseable timestamp is
/// `APH_E013`: this fails CLOSED, because an unordered chain and an
/// unreadable one are equally unacceptable as evidence.
pub fn verify_timestamp_order(
  envelope: &crate::envelope::NotarizationEnvelope,
) -> std::result::Result<(), crate::errors::AphError> {
  if !envelope.proof.is_chain() {
    return std::result::Result::Ok(());
  }
  let (principal, notary) = match (envelope.proof.principal(), envelope.proof.notary()) {
    (std::option::Option::Some(p), std::option::Option::Some(n)) => (p, n),
    _ => {
      return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
        "cannot check issuance order: `proof` is not a well-formed two-element chain",
      ));
    }
  };

  let decision = parse_rfc3339(
    &envelope.credential_subject.notarization.decision_timestamp,
    "credentialSubject.notarization.decisionTimestamp",
  )?;
  let principal_created = parse_rfc3339(&principal.created, "the principal proof's `created`")?;
  let notary_created = parse_rfc3339(&notary.created, "the notary proof's `created`")?;

  if principal_created < decision {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      std::format!(
        "the principal proof's `created` `{}` precedes \
         `notarization.decisionTimestamp` `{}`; the principal signs the \
         envelope the notary has already prepared (§7.2.1)",
        principal.created, envelope.credential_subject.notarization.decision_timestamp
      ),
    ));
  }
  if notary_created < principal_created {
    return std::result::Result::Err(crate::errors::AphError::proof_chain_invalid(
      std::format!(
        "the notary proof's `created` `{}` precedes the principal proof's \
         `created` `{}`; a countersignature cannot predate the proof it \
         claims to have observed (§7.2.1)",
        notary.created, principal.created
      ),
    ));
  }

  std::result::Result::Ok(())
}

/// Parses an RFC 3339 timestamp, reporting `APH_E013` and naming the field
/// when it cannot be read. Fails closed: an unreadable timestamp is never
/// treated as satisfying an ordering constraint.
fn parse_rfc3339(
  value: &str,
  field: &str,
) -> std::result::Result<
  chrono::DateTime<chrono::FixedOffset>,
  crate::errors::AphError,
> {
  chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
    crate::errors::AphError::proof_chain_invalid(std::format!(
      "{} `{}` is not a parseable RFC 3339 timestamp, so issuance order \
       cannot be checked",
      field, value
    ))
  })
}

#[cfg(test)]
mod tests {
  // ── Fixtures ──────────────────────────────────────────────────────────
  //
  // The human principal's DID appears in three places that MUST agree —
  // `humanPrincipal.id`, the principal proof's `verificationMethod`, and an
  // embedded mandate's `humanPrincipalDid` — so it is named once here. A
  // test that needs them to disagree changes one copy explicitly, which is
  // what makes the disagreement visible in the test body.
  const HUMAN_DID: &str = "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy";
  const NOTARY_DID: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV";
  const AGENT_DID: &str = "did:web:agent.squillo.com";
  const PRINCIPAL_PROOF_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000a1";
  const NOTARY_PROOF_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000b1";
  const MANDATE_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000c1";

  fn notary_proof() -> crate::envelope::EnvelopeProof {
    crate::envelope::EnvelopeProof {
      r#type: std::string::String::from("DataIntegrityProof"),
      cryptosuite: std::option::Option::Some(std::string::String::from("eddsa-jcs-2022")),
      verification_method: std::format!("{}#{}", NOTARY_DID, "z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"),
      created: std::string::String::from("2026-05-21T00:00:01Z"),
      proof_purpose: std::string::String::from("assertionMethod"),
      proof_value: std::string::String::from("z-illustrative-lone-notary-proof"),
      id: std::option::Option::None,
      previous_proof: std::option::Option::None,
    }
  }

  fn principal_proof() -> crate::envelope::EnvelopeProof {
    crate::envelope::EnvelopeProof {
      r#type: std::string::String::from("DataIntegrityProof"),
      cryptosuite: std::option::Option::Some(std::string::String::from("eddsa-jcs-2022")),
      verification_method: std::format!("{}#{}", HUMAN_DID, "z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy"),
      created: std::string::String::from("2026-05-21T00:00:02Z"),
      proof_purpose: std::string::String::from("assertionMethod"),
      proof_value: std::string::String::from("z-illustrative-principal-proof"),
      id: std::option::Option::Some(std::string::String::from(PRINCIPAL_PROOF_ID)),
      previous_proof: std::option::Option::None,
    }
  }

  fn countersignature() -> crate::envelope::EnvelopeProof {
    crate::envelope::EnvelopeProof {
      r#type: std::string::String::from("DataIntegrityProof"),
      cryptosuite: std::option::Option::Some(std::string::String::from("eddsa-jcs-2022")),
      verification_method: std::format!("{}#{}", NOTARY_DID, "z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"),
      created: std::string::String::from("2026-05-21T00:00:03Z"),
      proof_purpose: std::string::String::from("authentication"),
      proof_value: std::string::String::from("z-illustrative-countersignature"),
      id: std::option::Option::Some(std::string::String::from(NOTARY_PROOF_ID)),
      previous_proof: std::option::Option::Some(std::string::String::from(PRINCIPAL_PROOF_ID)),
    }
  }

  fn mandate() -> crate::delegation_mandate::DelegationMandate {
    crate::delegation_mandate::DelegationMandate {
      id: std::string::String::from(MANDATE_ID),
      human_principal_did: std::string::String::from(HUMAN_DID),
      agent_did: std::string::String::from(AGENT_DID),
      allowed_channels: std::vec![crate::envelope::ChannelKind::Slack, crate::envelope::ChannelKind::Email],
      rate_limit_per_hour: std::option::Option::Some(12),
      valid_from: std::string::String::from("2026-05-01T00:00:00Z"),
      valid_until: std::string::String::from("2026-06-01T00:00:00Z"),
      principal_signature: std::string::String::from("z-illustrative-principal-signature"),
      notary_signature: std::string::String::from("z-illustrative-notary-signature"),
    }
  }

  /// A `NotaryAttested` envelope in exactly the shape all eight published
  /// examples carry: one proof object, no `attestationMode`.
  fn single_proof_envelope() -> crate::envelope::NotarizationEnvelope {
    crate::envelope::NotarizationEnvelope {
      aph_version: std::string::String::from("0.1"),
      context: std::vec![
        std::string::String::from("https://www.w3.org/ns/credentials/v2"),
        std::string::String::from("https://w3id.org/aph/v1"),
      ],
      r#type: std::vec![
        std::string::String::from("VerifiableCredential"),
        std::string::String::from("AgentSendAuthorizationCredential"),
      ],
      id: std::string::String::from("urn:uuid:00000000-0000-4000-8000-000000000001"),
      issuer: std::string::String::from(NOTARY_DID),
      valid_from: std::string::String::from("2026-05-21T00:00:00Z"),
      valid_until: std::string::String::from("2026-05-22T00:00:00Z"),
      credential_subject: crate::envelope::CredentialSubject {
        human_principal: crate::envelope::HumanPrincipalRef {
          id: std::string::String::from(HUMAN_DID),
          display_name: std::string::String::from("Scott Wyatt"),
        },
        agent: crate::envelope::AgentRef {
          id: std::string::String::from(AGENT_DID),
          agent_card_uri: std::option::Option::None,
          display_name: std::string::String::from("Squillo Concierge"),
          version: std::string::String::from("1.0"),
        },
        channel: crate::envelope::ChannelDescriptor {
          kind: crate::envelope::ChannelKind::Slack,
          recipient_addressing: serde_json::json!({"teamId": "T01234567"}),
        },
        communication: crate::envelope::CommunicationDescriptor {
          content_class: crate::envelope::ContentClass::Reply,
          body_sha256: std::string::String::from(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          ),
          body_size: 1842,
          preview_lines: 3,
          preview: std::string::String::from("hello world"),
        },
        policy: crate::envelope::PolicyDescriptor {
          decision: crate::envelope::PolicyDecision::AskEveryTime,
          matched_scope: std::string::String::from("per-channel"),
          delegation_mandate_id: std::option::Option::None,
          act_chain: std::vec::Vec::new(),
          attestation_mode: std::option::Option::None,
          delegation_mandate: std::option::Option::None,
        },
        notarization: crate::envelope::NotarizationMetadata {
          notary_service: crate::envelope::NotaryServiceRef {
            id: std::string::String::from("did:web:notary.squillo.com"),
            name: std::string::String::from("Squillo Notary Service"),
            version: std::string::String::from("0.1.0"),
            attested_digest: std::option::Option::None,
            attestation_uri: std::option::Option::None,
          },
          decision_timestamp: std::string::String::from("2026-05-21T00:00:01Z"),
          decision_latency_ms: 1834,
        },
        apple_aur_acceptance: std::option::Option::None,
        act_classification: std::option::Option::None,
      },
      linked_mandate: std::option::Option::None,
      // Pattern A (§7.1.1): absent here means NO `credentialStatus` key on
      // the wire, which is what keeps this fixture byte-identical to the
      // pre-revocation shape its signatures were made over.
      credential_status: std::option::Option::None,
      proof: crate::envelope::EnvelopeProofs::Single(notary_proof()),
    }
  }

  /// A well-formed `PrincipalSigned` envelope: two linked proofs, the label
  /// that matches, and the principal proof made under the human's own DID.
  fn chain_envelope() -> crate::envelope::NotarizationEnvelope {
    let mut envelope = single_proof_envelope();
    envelope.credential_subject.policy.attestation_mode =
      std::option::Option::Some(crate::envelope::AttestationMode::PrincipalSigned);
    envelope.proof =
      crate::envelope::EnvelopeProofs::Chain(std::vec![principal_proof(), countersignature()]);
    envelope
  }

  /// Builds a chain envelope after letting the caller mutate either proof —
  /// the shape every rejection test below needs.
  fn chain_envelope_with(
    mutate: impl std::ops::FnOnce(
      &mut crate::envelope::EnvelopeProof,
      &mut crate::envelope::EnvelopeProof,
    ),
  ) -> crate::envelope::NotarizationEnvelope {
    let mut principal = principal_proof();
    let mut notary = countersignature();
    mutate(&mut principal, &mut notary);
    let mut envelope = chain_envelope();
    envelope.proof = crate::envelope::EnvelopeProofs::Chain(std::vec![principal, notary]);
    envelope
  }

  // ── verify_proof_structure: positive cases ────────────────────────────

  #[test]
  fn single_proof_without_a_label_verifies_as_notary_attested() {
    // This is the shape of ALL EIGHT published example envelopes and every
    // envelope any notary signed before `attestationMode` existed. If it
    // failed, or resolved to `PrincipalSigned`, the implementation would
    // either reject the entire deployed corpus or silently promote it to a
    // claim no human ever made.
    let mode = super::verify_proof_structure(&single_proof_envelope())
      .expect("a lone notary proof is a well-formed NotaryAttested envelope");
    std::assert_eq!(mode, crate::envelope::AttestationMode::NotaryAttested);
  }

  #[test]
  fn a_lone_proof_carrying_chain_members_is_rejected() {
    // `id` and `previousProof` are chain vocabulary. On a lone proof they
    // describe a chain that is not there, which is exactly what a stripped
    // chain looks like: an attacker removes the countersignature and the
    // remainder still speaks as though a principal proof were present. A
    // verifier reading loosely could conclude the human had signed.
    let mut envelope = single_proof_envelope();
    if let crate::envelope::EnvelopeProofs::Single(proof) = &mut envelope.proof {
      proof.previous_proof =
        std::option::Option::Some(std::string::String::from("urn:uuid:00000000-0000-4000-8000-0000000000f1"));
    }
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a lone proof naming a previous proof is not well formed");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn a_lone_proof_using_the_countersignature_purpose_is_rejected() {
    // `authentication` is the purpose of the SECOND proof of a chain. A lone
    // proof carrying it is a chain missing its head — the principal proof
    // that was the entire authorization. Accepting it would admit an
    // envelope whose own proof block says a countersignature is all that
    // remains.
    let mut envelope = single_proof_envelope();
    if let crate::envelope::EnvelopeProofs::Single(proof) = &mut envelope.proof {
      proof.proof_purpose = std::string::String::from("authentication");
    }
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a lone proof may not use the countersignature purpose");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn single_proof_labelled_notary_attested_verifies() {
    // A producer MAY state the weaker mode explicitly rather than relying on
    // absence. Rejecting the explicit spelling would punish the more honest
    // producer and push everyone toward the ambiguous form.
    let mut envelope = single_proof_envelope();
    envelope.credential_subject.policy.attestation_mode =
      std::option::Option::Some(crate::envelope::AttestationMode::NotaryAttested);
    let mode = super::verify_proof_structure(&envelope)
      .expect("an explicitly-labelled NotaryAttested envelope is well formed");
    std::assert_eq!(mode, crate::envelope::AttestationMode::NotaryAttested);
  }

  #[test]
  fn well_formed_chain_verifies_as_principal_signed() {
    // The positive control for the whole §7.1.11 rule set. Every rejection
    // test below mutates exactly one field of this envelope, so if this case
    // failed they would all pass for the wrong reason and the suite would
    // prove nothing.
    let mode = super::verify_proof_structure(&chain_envelope())
      .expect("a correctly linked and labelled chain must verify");
    std::assert_eq!(mode, crate::envelope::AttestationMode::PrincipalSigned);
  }

  #[test]
  fn principal_verification_method_without_a_fragment_is_accepted() {
    // A DID URL is `<did>#<fragment>`, but the fragment is what selects a
    // key, not what identifies the principal. A bare DID equal to
    // `humanPrincipal.id` still binds the proof to the right human, so
    // rejecting it would refuse a conformant producer on a formatting
    // preference rather than a security property.
    let envelope = chain_envelope_with(|principal, _notary| {
      principal.verification_method = std::string::String::from(HUMAN_DID);
    });
    std::assert!(super::verify_proof_structure(&envelope).is_ok());
  }

  // ── verify_proof_structure: chain length ──────────────────────────────

  #[test]
  fn a_one_element_chain_is_rejected() {
    // §7.2.1's stripped-proof attack lands here. An intermediary that
    // removes the notary proof from a PrincipalSigned envelope leaves a
    // one-element ARRAY, and because the principal's signature covers the
    // array form it would still verify. Rejecting length 1 is what stops the
    // human's own proof being re-presented as a notary attestation.
    let mut envelope = chain_envelope();
    envelope.proof = crate::envelope::EnvelopeProofs::Chain(std::vec![principal_proof()]);
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a one-element chain must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn a_three_element_chain_is_rejected() {
    // §7.1.11 constrains the chain to exactly two ROLES. A third proof has
    // no defined role, no canonicalization base (§7.2.1 defines two), and no
    // verification order — accepting it would mean verifying a signature
    // whose covered bytes are undefined.
    let mut envelope = chain_envelope();
    envelope.proof = crate::envelope::EnvelopeProofs::Chain(std::vec![
      principal_proof(),
      countersignature(),
      countersignature(),
    ]);
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a three-element chain must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn an_empty_chain_is_rejected() {
    // An empty array is a `proof` member that proves nothing while still
    // satisfying "the proof field is present". Without this rule an envelope
    // with no signatures at all would reach the signature-verification step
    // and pass it vacuously, having verified zero proofs.
    let mut envelope = chain_envelope();
    envelope.proof = crate::envelope::EnvelopeProofs::Chain(std::vec::Vec::new());
    let err =
      super::verify_proof_structure(&envelope).expect_err("an empty chain must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  // ── verify_proof_structure: label/structure agreement ─────────────────

  #[test]
  fn a_chain_with_no_attestation_mode_is_rejected() {
    // Absence means `NotaryAttested` (§7.1.7), and a NotaryAttested envelope
    // has no principal proof. An unlabelled chain therefore contradicts
    // itself, and §7.1.11 requires rejection rather than inferring the
    // stronger mode from the structure — the label must be asserted, so that
    // its absence can never be read as a claim.
    let mut envelope = chain_envelope();
    envelope.credential_subject.policy.attestation_mode = std::option::Option::None;
    let err = super::verify_proof_structure(&envelope)
      .expect_err("an unlabelled chain must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn a_chain_labelled_notary_attested_is_rejected() {
    // The mismatch must be a rejection, never a silent coercion to the
    // weaker mode: an envelope carrying the human's own proof but read as
    // the notary's assertion would understate the evidence, and a verifier
    // that quietly rewrote the label would hide a producer bug that could
    // just as easily have gone the other way.
    let mut envelope = chain_envelope();
    envelope.credential_subject.policy.attestation_mode =
      std::option::Option::Some(crate::envelope::AttestationMode::NotaryAttested);
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a chain labelled NotaryAttested must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn a_single_proof_labelled_principal_signed_is_rejected() {
    // THE attack §7.1.11 names outright. A holder of a notary key can write
    // `PrincipalSigned` above a single notary proof whose `proofPurpose` is
    // `assertionMethod` — indistinguishable from a principal proof by purpose
    // alone. A verifier that trusted the label would report a forged
    // authorization as the human's own signature.
    let mut envelope = single_proof_envelope();
    envelope.credential_subject.policy.attestation_mode =
      std::option::Option::Some(crate::envelope::AttestationMode::PrincipalSigned);
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a PrincipalSigned label over a single proof must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  // ── verify_proof_structure: proof purposes ────────────────────────────

  #[test]
  fn a_principal_proof_with_the_wrong_purpose_is_rejected() {
    // Position 1 asserts the authorization, so its purpose is
    // `assertionMethod` (§7.1.11). A head proof carrying `authentication`
    // describes a countersignature, and a chain of two countersignatures
    // contains no authorization at all.
    let envelope = chain_envelope_with(|principal, _notary| {
      principal.proof_purpose = std::string::String::from("authentication");
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("principal proof must carry assertionMethod");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn a_notary_proof_with_the_wrong_purpose_is_rejected() {
    // Position 2 is a COUNTERSIGNATURE — `authentication`, not
    // `assertionMethod`. A notary proof claiming `assertionMethod` claims to
    // be making the assertion rather than witnessing it, which is precisely
    // the substitution the chain exists to prevent.
    let envelope = chain_envelope_with(|_principal, notary| {
      notary.proof_purpose = std::string::String::from("assertionMethod");
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("notary proof must carry authentication");
    std::assert_eq!(err.code(), "APH_E013");
  }

  // ── verify_proof_structure: proof ids ─────────────────────────────────

  #[test]
  fn a_principal_proof_without_an_id_is_rejected() {
    // The `id` is what `previousProof` names. Without it the chain can only
    // be read positionally, and §7.1.11 says a verifier that trusted order
    // alone would accept a chain an intermediary reordered.
    let envelope = chain_envelope_with(|principal, notary| {
      principal.id = std::option::Option::None;
      notary.previous_proof = std::option::Option::None;
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a chain proof without an id must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn a_notary_proof_without_an_id_is_rejected() {
    // §7.1.11 requires an `id` on EVERY proof in a chain, not only on the
    // one that is named. Enforcing it on the head alone would leave the
    // requirement half-implemented and let a producer ship a chain no other
    // implementation accepts.
    let envelope = chain_envelope_with(|_principal, notary| {
      notary.id = std::option::Option::None;
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("the notary proof must carry an id");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn two_proofs_sharing_one_id_are_rejected() {
    // Duplicate ids make `previousProof` ambiguous: the link would resolve
    // to either proof, so a self-reference and a real countersignature
    // become indistinguishable and the linkage stops carrying information.
    let envelope = chain_envelope_with(|_principal, notary| {
      notary.id = std::option::Option::Some(std::string::String::from(PRINCIPAL_PROOF_ID));
      notary.previous_proof = std::option::Option::Some(std::string::String::from(PRINCIPAL_PROOF_ID));
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("duplicate proof ids must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  // ── verify_proof_structure: linkage ───────────────────────────────────

  #[test]
  fn a_notary_proof_without_previous_proof_is_rejected() {
    // Array position is a HINT; `previousProof` is the binding (§8.3.1 1e).
    // An unlinked pair of proofs is just two signatures that happen to share
    // an envelope — nothing states that the notary observed THIS principal
    // proof, which is the one thing the countersignature is for.
    let envelope = chain_envelope_with(|_principal, notary| {
      notary.previous_proof = std::option::Option::None;
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("missing previousProof must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
    std::assert!(
      std::string::ToString::to_string(&err).contains("previousProof"),
      "the reason must name the missing member: {}",
      err
    );
  }

  #[test]
  fn a_dangling_previous_proof_is_rejected() {
    // §7.1.11: a verifier MUST reject a chain whose `previousProof` does not
    // resolve to a proof present in the same chain. A link pointing outside
    // this envelope could name a proof from a DIFFERENT envelope, which is
    // how a countersignature would get detached and reattached.
    let envelope = chain_envelope_with(|_principal, notary| {
      notary.previous_proof =
        std::option::Option::Some(std::string::String::from("urn:uuid:not-in-this-chain"));
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a dangling previousProof must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
    std::assert!(
      std::string::ToString::to_string(&err).contains("dangling"),
      "the reason must distinguish dangling from missing: {}",
      err
    );
  }

  #[test]
  fn a_self_referential_previous_proof_is_rejected() {
    // A proof that countersigns itself is a cycle: it claims to cover bytes
    // that include its own signature, which is unconstructible. Reported
    // distinctly from "dangling" so an implementer sees which mistake they
    // made rather than hunting for a proof id that was never missing.
    let envelope = chain_envelope_with(|_principal, notary| {
      notary.previous_proof = std::option::Option::Some(std::string::String::from(NOTARY_PROOF_ID));
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a self-referential previousProof must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
    std::assert!(
      std::string::ToString::to_string(&err).contains("self-referential"),
      "the reason must distinguish a cycle from a dangling link: {}",
      err
    );
  }

  #[test]
  fn a_principal_proof_carrying_previous_proof_is_rejected() {
    // The principal proof is the HEAD of the chain and countersigns nothing
    // (§7.1.11). A `previousProof` on it either names a proof outside this
    // envelope or forms a cycle with the notary proof; both make the chain's
    // direction — and therefore the verification order — undefined.
    let envelope = chain_envelope_with(|principal, _notary| {
      principal.previous_proof = std::option::Option::Some(std::string::String::from(NOTARY_PROOF_ID));
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("the chain head must not carry previousProof");
    std::assert_eq!(err.code(), "APH_E013");
  }

  // ── verify_proof_structure: the principal-key binding ─────────────────

  #[test]
  fn a_principal_proof_made_by_another_key_is_rejected() {
    // The check that makes `PrincipalSigned` unforgeable by a notary. Here
    // the chain is perfectly formed and correctly labelled, but the head
    // proof is made under the NOTARY's DID — so the "principal proof" is the
    // notary signing twice. §7.1.11 says a proof made by any other key is
    // not the principal's proof, whatever its `proofPurpose` says, and the
    // notary does not hold the human's key.
    let envelope = chain_envelope_with(|principal, _notary| {
      principal.verification_method = std::format!("{}#key-1", NOTARY_DID);
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a principal proof under a foreign DID must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn a_principal_verification_method_that_only_prefixes_the_human_did_is_rejected() {
    // Prefix matching on the RAW string would accept
    // `did:key:zHuman-evil#k` for the principal `did:key:zHuman`. The rule
    // is equality of the DID part BEFORE the `#`, not string containment, or
    // an attacker could register a DID whose text extends the victim's.
    let envelope = chain_envelope_with(|principal, _notary| {
      principal.verification_method = std::format!("{}-attacker#key-1", HUMAN_DID);
    });
    let err = super::verify_proof_structure(&envelope)
      .expect_err("a DID that merely starts with the human's DID must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  // ── require_mode ──────────────────────────────────────────────────────

  #[test]
  fn require_principal_signed_refuses_a_notary_attested_envelope() {
    // §8.3.1 step 1a: there is no silent downgrade from a stronger
    // attestation to a weaker one, because an attacker who can defeat the
    // weak path will always present the weak path. APH_E012 specifically —
    // this is a policy refusal, not a malformed envelope, and an operator
    // reading a log must be able to tell those apart.
    let err = super::require_mode(
      &single_proof_envelope(),
      crate::envelope::AttestationMode::PrincipalSigned,
    )
    .expect_err("a NotaryAttested envelope must not satisfy a PrincipalSigned policy");
    std::assert_eq!(err.code(), "APH_E012");
  }

  #[test]
  fn require_notary_attested_accepts_a_principal_signed_envelope() {
    // A STRONGER envelope satisfies a weaker policy. Rejecting it would
    // punish the producer who did more work and give every deployment a
    // reason to stay on the weaker mode.
    std::assert!(
      super::require_mode(
        &chain_envelope(),
        crate::envelope::AttestationMode::NotaryAttested,
      )
      .is_ok()
    );
  }

  #[test]
  fn require_mode_accepts_an_exact_match() {
    // The ordinary case, pinned so a future rewrite of the comparison cannot
    // make the common path fail while the two interesting cases still pass.
    std::assert!(
      super::require_mode(
        &single_proof_envelope(),
        crate::envelope::AttestationMode::NotaryAttested,
      )
      .is_ok()
    );
  }

  #[test]
  fn require_mode_reads_absence_as_the_weaker_mode() {
    // The eight published envelopes carry no `attestationMode`, so a
    // deployment that demands `PrincipalSigned` must refuse them rather than
    // treat the missing field as unconstrained. §7.1.7 fixes absent as
    // `NotaryAttested`; this is that default doing security work.
    let mut envelope = single_proof_envelope();
    envelope.credential_subject.policy.attestation_mode = std::option::Option::None;
    let err = super::require_mode(&envelope, crate::envelope::AttestationMode::PrincipalSigned)
      .expect_err("an unlabelled envelope must not satisfy a PrincipalSigned policy");
    std::assert_eq!(err.code(), "APH_E012");
  }

  // ── verify_embedded_mandate_binding ───────────────────────────────────

  #[test]
  fn an_absent_embedded_mandate_is_not_a_structural_error() {
    // §7.1.7.1 makes embedding SHOULD, not MUST, because an embedded mandate
    // discloses the human's entire standing grant to every recipient.
    // Absence means the human's authorization is not VERIFIABLE here — a
    // policy conclusion for the caller, not a malformed envelope.
    std::assert!(super::verify_embedded_mandate_binding(&single_proof_envelope()).is_ok());
  }

  #[test]
  fn a_matching_embedded_mandate_binds() {
    // Positive control for all five bindings at once. Every rejection test
    // below changes exactly one field of this envelope, so if this failed
    // they would all pass without proving the specific rule they name.
    let mut envelope = single_proof_envelope();
    envelope.credential_subject.policy.delegation_mandate_id =
      std::option::Option::Some(std::string::String::from(MANDATE_ID));
    envelope.credential_subject.policy.delegation_mandate = std::option::Option::Some(mandate());
    std::assert!(super::verify_embedded_mandate_binding(&envelope).is_ok());
  }

  #[test]
  fn an_embedded_mandate_for_another_human_is_rejected() {
    // The staple attack §7.1.7.1 exists to close: a validly-signed mandate
    // belonging to a DIFFERENT human, attached to this envelope. Its
    // principalSignature verifies perfectly; it just does not authorize this
    // send. Without this equality the embedded mandate proves only that
    // SOME human granted SOME agent SOMETHING.
    let mut envelope = single_proof_envelope();
    let mut stapled = mandate();
    stapled.human_principal_did = std::string::String::from("did:key:z6MkSomeoneElse");
    envelope.credential_subject.policy.delegation_mandate = std::option::Option::Some(stapled);
    let err = super::verify_embedded_mandate_binding(&envelope)
      .expect_err("a mandate for another human must not bind");
    std::assert_eq!(err.code(), "APH_E011");
  }

  #[test]
  fn an_embedded_mandate_for_another_agent_is_rejected() {
    // Same staple, one hop over: the human is right but the grant was made
    // to a different agent. Accepting it would let any agent borrow another
    // agent's delegation from the same human, defeating the per-agent scope
    // the mandate exists to express.
    let mut envelope = single_proof_envelope();
    let mut stapled = mandate();
    stapled.agent_did = std::string::String::from("did:web:other-agent.example");
    envelope.credential_subject.policy.delegation_mandate = std::option::Option::Some(stapled);
    let err = super::verify_embedded_mandate_binding(&envelope)
      .expect_err("a mandate for another agent must not bind");
    std::assert_eq!(err.code(), "APH_E011");
  }

  #[test]
  fn an_embedded_mandate_disagreeing_with_the_declared_id_is_rejected() {
    // When `delegationMandateId` is present the envelope has NAMED its
    // parent. A different mandate in the `delegationMandate` member means
    // the notary's own record and the embedded evidence disagree, and a
    // verifier cannot know which one policy was actually evaluated against.
    let mut envelope = single_proof_envelope();
    envelope.credential_subject.policy.delegation_mandate_id =
      std::option::Option::Some(std::string::String::from("urn:uuid:some-other-mandate"));
    envelope.credential_subject.policy.delegation_mandate = std::option::Option::Some(mandate());
    let err = super::verify_embedded_mandate_binding(&envelope)
      .expect_err("an embedded mandate must be the one the envelope names");
    std::assert_eq!(err.code(), "APH_E011");
  }

  #[test]
  fn an_embedded_mandate_not_covering_the_channel_is_rejected() {
    // APH_E005 specifically, because this is the one §8.3.1 step 1d names
    // for it: the grant is genuine and belongs to this pair, but this send
    // is outside the channel scope the human approved. A verifier reporting
    // E011 here would tell an operator the signature was bad when the
    // signature was fine and the SCOPE was wrong.
    let mut envelope = single_proof_envelope();
    envelope.credential_subject.channel.kind = crate::envelope::ChannelKind::Discord;
    envelope.credential_subject.policy.delegation_mandate = std::option::Option::Some(mandate());
    let err = super::verify_embedded_mandate_binding(&envelope)
      .expect_err("a channel outside allowedChannels must not bind");
    std::assert_eq!(err.code(), "APH_E005");
  }

  #[test]
  fn an_envelope_outside_the_mandate_window_is_rejected() {
    // APH_E003, the other code §8.3.1 step 1d names. Expiry is the primary
    // revocation mechanism in v0.1 (§6.3.1 defers on-wire revocation), so an
    // envelope dated outside the mandate's window that still bound would
    // leave a human with no way to withdraw authority at all.
    let mut envelope = single_proof_envelope();
    envelope.valid_from = std::string::String::from("2026-07-01T00:00:00Z");
    envelope.valid_until = std::string::String::from("2026-07-02T00:00:00Z");
    envelope.credential_subject.policy.delegation_mandate = std::option::Option::Some(mandate());
    let err = super::verify_embedded_mandate_binding(&envelope)
      .expect_err("an envelope outside the mandate window must not bind");
    std::assert_eq!(err.code(), "APH_E003");
  }

  #[test]
  fn an_envelope_expiring_after_the_mandate_is_rejected() {
    // §8.3.1 step 1d requires the envelope's WINDOW to fall inside the
    // mandate's, not merely its start. Checking `validFrom` alone would let
    // a notary issue an envelope that starts inside the grant and stays
    // valid for a year after the human's authority ended.
    let mut envelope = single_proof_envelope();
    envelope.valid_from = std::string::String::from("2026-05-31T00:00:00Z");
    envelope.valid_until = std::string::String::from("2026-06-30T00:00:00Z");
    envelope.credential_subject.policy.delegation_mandate = std::option::Option::Some(mandate());
    let err = super::verify_embedded_mandate_binding(&envelope)
      .expect_err("an envelope outliving the mandate must not bind");
    std::assert_eq!(err.code(), "APH_E003");
  }

  #[test]
  fn an_unparseable_envelope_window_fails_closed() {
    // Hostile input must deny, never default to valid. `is_valid_at`
    // returns false on anything it cannot parse, and this pins that the
    // caller inherits that fail-closed behavior instead of a panic or a
    // silent pass.
    let mut envelope = single_proof_envelope();
    envelope.valid_from = std::string::String::from("not-a-timestamp");
    envelope.credential_subject.policy.delegation_mandate = std::option::Option::Some(mandate());
    let err = super::verify_embedded_mandate_binding(&envelope)
      .expect_err("an unparseable window must not bind");
    std::assert_eq!(err.code(), "APH_E003");
  }

  // ── verify_timestamp_order ────────────────────────────────────────────

  #[test]
  fn a_single_proof_envelope_has_nothing_to_order() {
    // §7.2.1's ordering constrains a CHAIN. A lone notary proof has no
    // principal proof to precede it, so the check must be vacuous rather
    // than inventing a constraint that would reject the published corpus.
    std::assert!(super::verify_timestamp_order(&single_proof_envelope()).is_ok());
  }

  #[test]
  fn issuance_order_decision_then_principal_then_notary_is_accepted() {
    // The order §7.2.1 makes normative: the notary prepares the envelope,
    // the principal signs what was prepared, the notary countersigns. This
    // is the positive control for the two rejections below.
    std::assert!(super::verify_timestamp_order(&chain_envelope()).is_ok());
  }

  #[test]
  fn equal_timestamps_are_accepted() {
    // The constraint is `<=`, not `<`. Three signatures produced inside the
    // same second are ordinary — the notary is typically co-located with the
    // principal (§4) — and a strict comparison would reject correct
    // envelopes for having a fast device.
    let mut envelope = chain_envelope_with(|principal, notary| {
      principal.created = std::string::String::from("2026-05-21T00:00:01Z");
      notary.created = std::string::String::from("2026-05-21T00:00:01Z");
    });
    envelope.credential_subject.notarization.decision_timestamp =
      std::string::String::from("2026-05-21T00:00:01Z");
    std::assert!(super::verify_timestamp_order(&envelope).is_ok());
  }

  #[test]
  fn a_principal_proof_predating_the_decision_is_rejected() {
    // Reverse §7.2.1 steps 1 and 2 and the principal would have to sign
    // notary-produced fields — the decision timestamp, the latency — that do
    // not exist yet. A proof dated before the decision it authorizes is
    // evidence that the envelope was assembled out of order, or that its
    // timestamps were written to tell a story.
    let envelope = chain_envelope_with(|principal, _notary| {
      principal.created = std::string::String::from("2026-05-21T00:00:00Z");
    });
    let err = super::verify_timestamp_order(&envelope)
      .expect_err("a principal proof predating the decision must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn a_countersignature_predating_the_principal_proof_is_rejected() {
    // §7.2.1 states it outright: a verifier MUST NOT accept a chain whose
    // notary proof is dated before the principal proof it claims to have
    // observed. The notary proof covers the principal's `proofValue`, so a
    // notary that signed first signed bytes that did not yet exist.
    let envelope = chain_envelope_with(|_principal, notary| {
      notary.created = std::string::String::from("2026-05-21T00:00:01Z");
    });
    let err = super::verify_timestamp_order(&envelope)
      .expect_err("a countersignature predating its principal proof must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn an_unparseable_proof_timestamp_is_rejected() {
    // Fail closed. An unreadable timestamp cannot be shown to satisfy the
    // ordering, and treating "cannot check" as "checked" would make the
    // whole rule optional for any producer willing to emit garbage.
    let envelope = chain_envelope_with(|principal, _notary| {
      principal.created = std::string::String::from("yesterday");
    });
    let err = super::verify_timestamp_order(&envelope)
      .expect_err("an unparseable timestamp must be rejected");
    std::assert_eq!(err.code(), "APH_E013");
  }

  #[test]
  fn timestamps_are_compared_as_instants_not_strings() {
    // `2026-05-21T00:00:03Z` and `2026-05-20T20:00:03-04:00` are the SAME
    // instant, but the second sorts earlier lexicographically. Comparing the
    // text would reject this correct chain, so the crate parses with
    // `chrono` — the same thing `DelegationMandate::is_valid_at` does.
    let envelope = chain_envelope_with(|_principal, notary| {
      notary.created = std::string::String::from("2026-05-20T20:00:03-04:00");
    });
    std::assert!(
      super::verify_timestamp_order(&envelope).is_ok(),
      "an equivalent instant written with an offset must order correctly"
    );
  }

  #[test]
  fn a_malformed_chain_cannot_have_its_order_checked() {
    // Fail closed on a structure this function cannot interpret. Returning
    // Ok would let a caller that runs the ordering check but skips
    // `verify_proof_structure` conclude a malformed chain was fine.
    let mut envelope = chain_envelope();
    envelope.proof = crate::envelope::EnvelopeProofs::Chain(std::vec![principal_proof()]);
    let err = super::verify_timestamp_order(&envelope)
      .expect_err("a one-element chain has no checkable order");
    std::assert_eq!(err.code(), "APH_E013");
  }
}

