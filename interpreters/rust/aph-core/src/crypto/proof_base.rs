//! Per-proof canonicalization bases — spec §7.2.1.
//!
//! A proof is a signature over *bytes*, and this module is the single place
//! that decides which bytes. Nothing else in the crate may derive a signing
//! base: signer and verifier must agree exactly, and two code paths that
//! agree today drift tomorrow.
//!
//! # Each proof covers what precedes it, and nothing after it
//!
//! These are W3C Data Integrity proof-chain semantics, and they are forced:
//! a signer cannot sign bytes that do not exist yet, so a base that included
//! a later proof would be unconstructible. Concretely (§7.2.1):
//!
//! | Role | `proof` member of the working copy |
//! |---|---|
//! | Lone notary proof | the proof object alone, its `proofValue` emptied |
//! | Principal proof of a chain | a **one-element array** holding the principal proof, its `proofValue` emptied — the notary proof is DISCARDED, not blanked |
//! | Notary countersignature | the two-element array, the principal's `proofValue` COMPLETE and the notary's emptied |
//!
//! # Why the principal's base keeps the array form
//!
//! `"proof": [{…}]` and `"proof": {…}` canonicalize to different bytes, and
//! that difference **domain-separates** a principal proof from a lone notary
//! proof. Were the object form used for a one-proof base, an intermediary
//! could strip the notary proof from a `PrincipalSigned` envelope and
//! re-present the remainder as a valid single-proof envelope: the signature
//! would still verify, and the recipient would read the human's own proof as
//! a mere notary attestation. With the array form the stripped envelope is a
//! one-element chain, which §7.1.11 rejects outright.
//!
//! This is not a redundant wrapper waiting to be simplified away. Removing
//! it is a security regression, and `stripping_the_notary_proof_...` in
//! [`crate::crypto::eddsa_jcs`] fails if anyone tries.
//!
//! # Empty, never absent
//!
//! In every envelope base the covered field is set to the EMPTY STRING, not
//! removed: JCS over an object with `proofValue` absent and JCS over the same
//! object with `proofValue` empty are different byte strings, so signer and
//! verifier must make the same choice. §7.2.1 settles it as the empty string.
//! Mandate bases are the documented exception — see [`mandate_signing_base`].

/// Which signature's base is being built (spec §7.2.1).
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::marker::Copy,
  std::cmp::PartialEq,
  std::cmp::Eq,
)]
pub enum ProofRole {
  /// The human principal's own proof — the head of a chain.
  Principal,
  /// The notary's proof: a lone proof, or the countersignature of a chain.
  Notary,
}

/// Builds the JCS-canonical signing base for one proof of an envelope.
///
/// The three bases are laid out in the module docs. Two properties matter to
/// callers:
///
/// - `ProofRole::Principal` requires a two-element chain (§7.1.11). Anything
///   else — a lone proof, a one-element array, a three-element array — is
///   [`crate::errors::AphError::ProofChainInvalid`] (`APH_E013`), never a
///   panic, because the shape is attacker-supplied.
/// - The principal base carries the principal proof in a ONE-ELEMENT ARRAY.
///   The array form is normative and load-bearing; see the module docs.
pub fn signing_base(
  envelope: &crate::envelope::NotarizationEnvelope,
  role: ProofRole,
) -> std::result::Result<std::string::String, crate::errors::AphError> {
  // Resolve the shape before cloning: a wrong-shaped envelope should cost an
  // error, not a full deep copy.
  let proofs = base_proofs(&envelope.proof, role)?;
  let mut working = envelope.clone();
  working.proof = proofs;
  canonicalize(&working)
}

/// The base a Delegation Mandate signature covers (spec §6.1, §7.2.1).
///
/// - `ProofRole::Principal` → the canonical form MINUS **both** signature
///   fields. This is the human's actual grant of authority.
/// - `ProofRole::Notary` → the canonical form MINUS `notarySignature` only,
///   with `principalSignature` present and complete. The notary countersigns
///   what the principal signed.
///
/// **The mandate bases REMOVE their members; the envelope bases EMPTY
/// theirs.** That asymmetry is deliberate, not an oversight: §6.1 and §7.2.1
/// both say a mandate signature covers the form *minus* the field, and the
/// only prior statement of this contract in the tree — the doc comment on
/// [`crate::delegation_mandate::DelegationMandate::notary_signature`] — says
/// "MINUS the `notary_signature` field" as well. No deployed code computed
/// this base before, so no field signature is invalidated by honoring the
/// normative wording here.
pub fn mandate_signing_base(
  mandate: &crate::delegation_mandate::DelegationMandate,
  role: ProofRole,
) -> std::result::Result<std::string::String, crate::errors::AphError> {
  let mut value = match serde_json::to_value(mandate) {
    std::result::Result::Ok(v) => v,
    // A mandate that cannot be serialized cannot be signed or checked.
    std::result::Result::Err(_) => {
      return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
    }
  };
  match value.as_object_mut() {
    std::option::Option::Some(object) => {
      object.remove("notarySignature");
      if role == ProofRole::Principal {
        object.remove("principalSignature");
      }
    }
    // A struct always serializes to a JSON object; refuse rather than panic
    // if that ever stops being true.
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature);
    }
  }
  std::result::Result::Ok(super::jcs::canonicalize_rfc8785(&value))
}

/// Mutable access to the proof a given role owns, so a signer can fill in
/// its `proofValue` after the base is built.
///
/// Shares one shape check with [`signing_base`]: the signer and the base
/// builder must never disagree about which proof is being signed.
pub(crate) fn proof_mut(
  envelope: &mut crate::envelope::NotarizationEnvelope,
  role: ProofRole,
) -> std::result::Result<&mut crate::envelope::EnvelopeProof, crate::errors::AphError> {
  // Read the shape while the borrow is still shared; both values are Copy,
  // so the borrow ends here and the mutable borrow below is legal.
  let count = envelope.proof.all().len();
  let is_chain = envelope.proof.is_chain();
  match &mut envelope.proof {
    crate::envelope::EnvelopeProofs::Single(proof) => match role {
      ProofRole::Notary => std::result::Result::Ok(proof),
      // A lone proof is a notary proof (§7.1.11); there is no principal
      // proof to fill in.
      ProofRole::Principal => {
        std::result::Result::Err(wrong_shape(role, is_chain, count))
      }
    },
    crate::envelope::EnvelopeProofs::Chain(proofs) => {
      if proofs.len() != CHAIN_LENGTH {
        return std::result::Result::Err(wrong_shape(role, is_chain, count));
      }
      let index = match role {
        ProofRole::Principal => 0,
        ProofRole::Notary => 1,
      };
      match proofs.get_mut(index) {
        std::option::Option::Some(proof) => std::result::Result::Ok(proof),
        // Unreachable after the length check; an error rather than an index
        // panic keeps a future edit from turning a bug into a crash.
        std::option::Option::None => {
          std::result::Result::Err(wrong_shape(role, is_chain, count))
        }
      }
    }
  }
}

/// The only chain length §7.1.11 permits: principal proof, notary proof.
const CHAIN_LENGTH: usize = 2;

/// Builds the `proof` member of the working copy for `role` (§7.2.1).
fn base_proofs(
  proofs: &crate::envelope::EnvelopeProofs,
  role: ProofRole,
) -> std::result::Result<crate::envelope::EnvelopeProofs, crate::errors::AphError> {
  let count = proofs.all().len();
  let is_chain = proofs.is_chain();
  match role {
    ProofRole::Principal => {
      let principal = match proofs.principal() {
        std::option::Option::Some(proof) => proof,
        std::option::Option::None => {
          return std::result::Result::Err(wrong_shape(role, is_chain, count));
        }
      };
      let mut head = principal.clone();
      head.proof_value = std::string::String::new();
      // A ONE-ELEMENT ARRAY, not an object: see the module docs. The notary
      // proof is discarded because it did not exist when the principal
      // signed.
      std::result::Result::Ok(crate::envelope::EnvelopeProofs::Chain(std::vec![head]))
    }
    ProofRole::Notary => match proofs {
      crate::envelope::EnvelopeProofs::Single(proof) => {
        let mut lone = proof.clone();
        lone.proof_value = std::string::String::new();
        std::result::Result::Ok(crate::envelope::EnvelopeProofs::Single(lone))
      }
      crate::envelope::EnvelopeProofs::Chain(_) => {
        let principal = match proofs.principal() {
          std::option::Option::Some(proof) => proof,
          std::option::Option::None => {
            return std::result::Result::Err(wrong_shape(role, is_chain, count));
          }
        };
        let notary = match proofs.notary() {
          std::option::Option::Some(proof) => proof,
          std::option::Option::None => {
            return std::result::Result::Err(wrong_shape(role, is_chain, count));
          }
        };
        let mut tail = notary.clone();
        tail.proof_value = std::string::String::new();
        // The principal's proofValue stays COMPLETE: that is what makes the
        // countersignature cover the principal's signature rather than an
        // empty placeholder.
        std::result::Result::Ok(crate::envelope::EnvelopeProofs::Chain(std::vec![
          principal.clone(),
          tail,
        ]))
      }
    },
  }
}

/// JCS-canonicalizes an envelope working copy.
fn canonicalize(
  envelope: &crate::envelope::NotarizationEnvelope,
) -> std::result::Result<std::string::String, crate::errors::AphError> {
  match serde_json::to_value(envelope) {
    std::result::Result::Ok(value) => {
      std::result::Result::Ok(super::jcs::canonicalize_rfc8785(&value))
    }
    // An envelope that cannot be serialized cannot be signed or checked.
    std::result::Result::Err(_) => {
      std::result::Result::Err(crate::errors::AphError::InvalidEnvelopeSignature)
    }
  }
}

/// Builds the `APH_E013` an envelope of the wrong proof shape earns, naming
/// what was found so an operator can fix the producer.
fn wrong_shape(role: ProofRole, is_chain: bool, count: usize) -> crate::errors::AphError {
  let form = if is_chain { "array" } else { "object" };
  let expected = match role {
    ProofRole::Principal => "a two-element proof chain",
    ProofRole::Notary => "a single proof or a two-element proof chain",
  };
  crate::errors::AphError::proof_chain_invalid(std::format!(
    "the {} canonicalization base (§7.2.1) requires {}; this envelope carries {} proof(s) in {} form",
    role_label(role),
    expected,
    count,
    form
  ))
}

/// Names a role for error messages.
fn role_label(role: ProofRole) -> &'static str {
  match role {
    ProofRole::Principal => "principal",
    ProofRole::Notary => "notary",
  }
}

/// Fixtures shared by this module's tests and [`crate::crypto::eddsa_jcs`]'s.
///
/// Both modules must exercise the SAME chain shape: a base built here and a
/// signature produced there that disagreed about the fixture would hide the
/// very mismatch these tests exist to catch.
#[cfg(test)]
pub(crate) mod test_support {
  /// The golden single-proof (lone notary) envelope every crypto test starts
  /// from.
  pub(crate) fn single_proof_envelope() -> crate::envelope::NotarizationEnvelope {
    let raw = include_str!("../../tests/golden/slack_reply_envelope.json");
    serde_json::from_str(raw).expect("golden fixture parses")
  }

  /// `urn:uuid` of the principal proof in [`chain_envelope`].
  pub(crate) const PRINCIPAL_PROOF_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000a1";
  /// `urn:uuid` of the notary proof in [`chain_envelope`].
  pub(crate) const NOTARY_PROOF_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000a2";

  /// A `PrincipalSigned` envelope whose two-element chain is structurally
  /// complete but UNSIGNED: both `proofValue`s are empty, ready for
  /// `sign_as_principal` then `countersign_as_notary` in that order (§7.2.1).
  ///
  /// The `verificationMethod`s are the fixture's own DIDs. Binding the
  /// principal proof's method to `credentialSubject.humanPrincipal.id` is the
  /// verifier's duty (§8.3.1 step 1c), not this layer's — the crypto layer is
  /// handed the key it must check against.
  pub(crate) fn chain_envelope() -> crate::envelope::NotarizationEnvelope {
    let mut envelope = single_proof_envelope();
    let template = envelope
      .proof
      .notary()
      .expect("the golden fixture carries a lone notary proof")
      .clone();

    let mut principal = template.clone();
    principal.id = std::option::Option::Some(std::string::String::from(PRINCIPAL_PROOF_ID));
    principal.previous_proof = std::option::Option::None;
    principal.proof_purpose = std::string::String::from("assertionMethod");
    principal.verification_method = std::format!(
      "{did}#{fragment}",
      did = envelope.credential_subject.human_principal.id,
      fragment = envelope
        .credential_subject
        .human_principal
        .id
        .trim_start_matches("did:key:")
    );
    principal.proof_value = std::string::String::new();

    let mut notary = template;
    notary.id = std::option::Option::Some(std::string::String::from(NOTARY_PROOF_ID));
    notary.previous_proof =
      std::option::Option::Some(std::string::String::from(PRINCIPAL_PROOF_ID));
    notary.proof_purpose = std::string::String::from("authentication");
    notary.proof_value = std::string::String::new();

    envelope.credential_subject.policy.attestation_mode =
      std::option::Option::Some(crate::envelope::AttestationMode::PrincipalSigned);
    envelope.proof = crate::envelope::EnvelopeProofs::Chain(std::vec![principal, notary]);
    envelope
  }
}

#[cfg(test)]
mod tests {
  fn single() -> crate::envelope::NotarizationEnvelope {
    super::test_support::single_proof_envelope()
  }

  fn chain() -> crate::envelope::NotarizationEnvelope {
    super::test_support::chain_envelope()
  }

  fn sample_mandate() -> crate::delegation_mandate::DelegationMandate {
    crate::delegation_mandate::DelegationMandate {
      id: std::string::String::from("urn:uuid:00000000-0000-4000-8000-000000000001"),
      human_principal_did: std::string::String::from("did:key:zHuman"),
      agent_did: std::string::String::from("did:web:agent.squillo.com"),
      allowed_channels: std::vec![std::string::String::from("slack")],
      rate_limit_per_hour: std::option::Option::Some(30),
      valid_from: std::string::String::from("2026-05-21T00:00:00Z"),
      valid_until: std::string::String::from("2026-06-21T00:00:00Z"),
      principal_signature: std::string::String::from("zPrincipalSignatureBytes"),
      notary_signature: std::string::String::from("zNotarySignatureBytes"),
    }
  }

  #[test]
  fn the_three_bases_are_pairwise_distinct() {
    // Domain separation is the whole point of §7.2.1. If any two bases ever
    // canonicalized identically, a signature made for one role would verify
    // in another and a proof would be transplantable between positions —
    // e.g. a lone notary proof re-presented as a human's authorization.
    let lone = super::signing_base(&single(), super::ProofRole::Notary)
      .expect("a lone notary base is always constructible");
    let chained = chain();
    let principal = super::signing_base(&chained, super::ProofRole::Principal)
      .expect("a two-element chain has a principal base");
    let notary = super::signing_base(&chained, super::ProofRole::Notary)
      .expect("a two-element chain has a notary base");

    std::assert_ne!(lone, principal);
    std::assert_ne!(lone, notary);
    std::assert_ne!(principal, notary);
  }

  #[test]
  fn principal_base_is_a_one_element_array_not_an_object() {
    // The array form is normative (§7.2.1) and is what stops an intermediary
    // stripping the notary proof and re-presenting the remainder as a valid
    // single-proof envelope. An implementation that "simplified" this to the
    // object form would still round-trip its own signatures, so only a byte
    // assertion catches it.
    let base = super::signing_base(&chain(), super::ProofRole::Principal)
      .expect("a two-element chain has a principal base");
    std::assert!(
      base.contains(r#""proof":[{"#),
      "principal base must carry a one-element ARRAY: {}",
      base
    );
  }

  #[test]
  fn principal_base_discards_the_notary_proof_entirely() {
    // "Discarded, not blanked" (§7.2.1): the notary proof did not exist when
    // the principal signed, so no trace of it — not even an emptied object —
    // may appear in the principal's base.
    let base = super::signing_base(&chain(), super::ProofRole::Principal)
      .expect("a two-element chain has a principal base");
    std::assert!(
      !base.contains(super::test_support::NOTARY_PROOF_ID),
      "principal base must not mention the notary proof: {}",
      base
    );
  }

  #[test]
  fn notary_base_keeps_both_proofs() {
    // The countersignature must cover the principal proof (§7.1.11) — that
    // is what stops a notary detaching a principal's signature and
    // re-attaching it to a different envelope.
    let base = super::signing_base(&chain(), super::ProofRole::Notary)
      .expect("a two-element chain has a notary base");
    std::assert!(
      base.contains(super::test_support::PRINCIPAL_PROOF_ID)
        && base.contains(super::test_support::NOTARY_PROOF_ID),
      "notary base must carry both proofs: {}",
      base
    );
  }

  #[test]
  fn every_envelope_base_empties_rather_than_removes_proof_value() {
    // JCS over an object with `proofValue` absent and JCS over the same
    // object with it empty are different bytes, so signer and verifier must
    // make the same choice. §7.2.1 fixes it as the empty string, for all
    // three bases — not just the lone-proof one the earlier code covered.
    let chained = chain();
    for (label, base) in [
      (
        "lone",
        super::signing_base(&single(), super::ProofRole::Notary).expect("lone base"),
      ),
      (
        "principal",
        super::signing_base(&chained, super::ProofRole::Principal).expect("principal base"),
      ),
      (
        "notary",
        super::signing_base(&chained, super::ProofRole::Notary).expect("notary base"),
      ),
    ] {
      std::assert!(
        base.contains(r#""proofValue":"""#),
        "{} base must keep proofValue present-but-empty: {}",
        label,
        base
      );
    }
  }

  #[test]
  fn principal_base_of_a_single_proof_envelope_is_aph_e013() {
    // A lone proof is a notary proof: there is no principal base to build.
    // The proof shape is attacker-supplied, so this must be a typed refusal
    // a verifier can report, never an index panic in a parser-adjacent path.
    let error = super::signing_base(&single(), super::ProofRole::Principal)
      .expect_err("a single proof has no principal base");
    std::assert_eq!(error.code(), "APH_E013");
  }

  #[test]
  fn principal_base_of_a_one_element_chain_is_aph_e013() {
    // The exact artifact §7.2.1 describes an attacker producing: a
    // `PrincipalSigned` envelope with the notary proof stripped. It must be
    // rejected as a malformed chain rather than treated as signable.
    let mut envelope = chain();
    let principal = envelope
      .proof
      .principal()
      .expect("the chain fixture has a principal proof")
      .clone();
    envelope.proof = crate::envelope::EnvelopeProofs::Chain(std::vec![principal]);
    let error = super::signing_base(&envelope, super::ProofRole::Principal)
      .expect_err("a one-element chain is not a chain");
    std::assert_eq!(error.code(), "APH_E013");
  }

  #[test]
  fn notary_base_of_a_three_element_chain_is_aph_e013() {
    // §7.1.11 fixes the chain at exactly two proofs. A longer chain has no
    // defined base, and guessing (say, "sign the last one") would let a
    // producer smuggle an extra proof under a real countersignature.
    let mut envelope = chain();
    let mut proofs = envelope.proof.all().to_vec();
    let extra = proofs
      .last()
      .expect("the chain fixture is non-empty")
      .clone();
    proofs.push(extra);
    envelope.proof = crate::envelope::EnvelopeProofs::Chain(proofs);
    let error = super::signing_base(&envelope, super::ProofRole::Notary)
      .expect_err("a three-element chain has no defined base");
    std::assert_eq!(error.code(), "APH_E013");
  }

  #[test]
  fn mandate_principal_base_removes_both_signature_fields() {
    // §6.1: `principalSignature` covers the form MINUS both signatures. If
    // either leaked into the base, the human could not sign the mandate
    // before the notary countersigned it — the required order.
    let base = super::mandate_signing_base(&sample_mandate(), super::ProofRole::Principal)
      .expect("a mandate always has a principal base");
    std::assert!(
      !base.contains("principalSignature") && !base.contains("notarySignature"),
      "principal mandate base must carry neither signature: {}",
      base
    );
  }

  #[test]
  fn mandate_notary_base_keeps_the_principal_signature() {
    // "The notary countersigns what the principal signed" (§6.1). The
    // principal's signature must be inside the notary's covered bytes, or a
    // notary signature could be moved onto a mandate the human never signed.
    let base = super::mandate_signing_base(&sample_mandate(), super::ProofRole::Notary)
      .expect("a mandate always has a notary base");
    std::assert!(
      base.contains("zPrincipalSignatureBytes") && !base.contains("notarySignature"),
      "notary mandate base must keep principalSignature and drop its own: {}",
      base
    );
  }

  #[test]
  fn the_two_mandate_bases_are_distinct() {
    // Same domain-separation argument as the envelope bases: if the human's
    // base equalled the notary's, one party's signature would verify as the
    // other's and the countersignature would prove nothing.
    let mandate = sample_mandate();
    let principal = super::mandate_signing_base(&mandate, super::ProofRole::Principal)
      .expect("principal mandate base");
    let notary =
      super::mandate_signing_base(&mandate, super::ProofRole::Notary).expect("notary mandate base");
    std::assert_ne!(principal, notary);
  }

  #[test]
  fn bases_are_deterministic() {
    // Every signature in the protocol is over these bytes, so the same input
    // must canonicalize identically on every call. A base that depended on
    // map iteration order would verify locally and fail across machines.
    let chained = chain();
    let once = super::signing_base(&chained, super::ProofRole::Notary).expect("notary base");
    let twice = super::signing_base(&chained, super::ProofRole::Notary).expect("notary base");
    std::assert_eq!(once, twice);
  }
}
