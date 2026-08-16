// Every public item in a protocol reference implementation is read by
// implementers, so undocumented surface is a defect.
#![warn(missing_docs)]

//! APH (Agent per Human) protocol v0.1 core types.
//!
//! **Trust model, stated up front.** The human principal signs; the notary
//! countersigns. An envelope is in one of two modes, and which one decides
//! what a successful verification actually proves:
//!
//! - `PrincipalSigned` — `proof` is a two-element chain whose head was made
//!   by the human's own key. Verifying it proves *this human authorized
//!   this*.
//! - `NotaryAttested` — a single notary proof, and what an ABSENT
//!   `attestationMode` means. Verifying it proves only *a notary asserts
//!   this human authorized this*, which is strictly weaker. The human's own
//!   authorization, if present at all, lives in the `principalSignature` of
//!   the Delegation Mandate embedded at `policy.delegation_mandate`.
//!
//! **Callers must never report the weaker claim as the stronger one.** Use
//! [`verification::require_mode`] to refuse a downgrade rather than
//! inspecting the shape by hand, and [`verification::verify_proof_structure`]
//! to learn which mode an envelope is really in — the declared label is
//! bound to the proof structure precisely so a notary key alone cannot
//! forge the stronger claim (spec §7.1.11).
//!
//! Standalone implementation of the APH protocol: party roles, mandate
//! types, notarization flow state machines, the W3C VC 2.0-shaped
//! `NotarizationEnvelope` on-wire credential, the agent-credential-access
//! envelope variant, the A2A extension descriptor, SD-JWT-VC profile
//! pinning, and the JCS / detached-JWS / ECDSA signing helpers used to
//! sign and verify envelopes.
//!
//! The normative protocol specification lives at `../../spec/aph-0.1.md`
//! in this repository.
//!
//! Wire compatibility is this crate's primary invariant: every serde
//! attribute on the wire types is load-bearing. Envelopes already signed
//! by existing notaries MUST keep parsing and re-canonicalizing
//! identically across releases.
//!
//! Registered optional extensions (spec §7.5): this implementation accepts
//! and can emit `credentialSubject.appleAurAcceptance` (§7.5.1),
//! `linkedMandate.ap2SignedPayloadB64` (§7.5.2), and
//! `linkedMandate.vaultMutation` (§7.5.3). All are omitted when absent, so
//! extension-free envelopes round-trip byte-identically. The
//! `CredentialAccessNotarizationEnvelope` variant remains a spec v0.2
//! candidate.
//!
//! Top-level `credentialStatus` (§6.3.3.1) is a CORE optional field rather
//! than a registered extension, and it follows the same omit-when-absent
//! rule for the same reason: an envelope with no status reference is
//! byte-identical to one written before revocation had a transport, so every
//! existing signature stays valid. [`credential_status`] holds the type, the
//! derived-endpoint and same-origin rules, and the §6.3.3.4 trichotomy a
//! recipient applies at §8.3 step 8a.

pub mod a2a_extension;
pub mod aph_config;
pub mod communication_mandate;
pub mod credential_access_envelope;
pub mod credential_status;
pub mod crypto;
pub mod delegation_mandate;
pub mod discovery;
pub mod envelope;
pub mod errors;
pub mod human_not_present_flow;
pub mod human_present_flow;
pub mod roles;
pub mod sd_jwt_profile;
pub mod vault_mutation;
pub mod verification;

#[cfg(test)]
mod prop_tests;

// Re-exports — public surface.
pub use a2a_extension::{APH_EXTENSION_URI, aph_a2a_extension};
pub use aph_config::{
  ALG_EDDSA, ALG_ES256, APH_CONTEXT_V1, APH_CREDENTIAL_TYPE, APH_DI_CRYPTOSUITE, APH_VERSION,
  DEFAULT_MANDATE_TTL_SECONDS, MAX_BODY_PREVIEW_BYTES, MAX_PREVIEW_LINES, W3C_VC_CONTEXT_V2,
};
pub use communication_mandate::CommunicationMandate;
pub use credential_status::{
  CredentialStatusEntry, StatusCheck, StatusEntryType, StatusListCredential, StatusListSubject,
  StatusPurpose, check_credential_status, check_envelope_status, decode_encoded_list,
  parse_status_list_credential, revocation_bit, status_list_signing_base,
};
pub use delegation_mandate::DelegationMandate;
pub use envelope::{
  AgentRef, AttestationMode, ChannelDescriptor, CommunicationDescriptor, CredentialSubject,
  EnvelopeProof, EnvelopeProofs, HumanPrincipalRef, LinkedMandate, NotarizationEnvelope,
  NotarizationMetadata, NotaryServiceRef, PolicyDescriptor,
};
pub use errors::AphError;
pub use human_not_present_flow::{
  HumanNotPresentNotarizationFlow, HumanNotPresentNotarizationState,
};
pub use human_present_flow::{HumanPresentNotarizationFlow, HumanPresentNotarizationState};
pub use roles::{AphOperation, AphPartyRole};
pub use sd_jwt_profile::{
  APH_SD_JWT_TYP, SD_JWT_BASE_DRAFT_PIN, SD_JWT_VC_DRAFT_PIN, SdJwtVcProfile, current_profile,
};
pub use vault_mutation::{VaultMutationKind, VaultMutationMandate};

// Crypto re-exports — JCS canonicalization, detached JWS, and ECDSA
// mandate signing/verification.
pub use crate::discovery::{DidUrl, KeyAlgorithm, NotaryPublicKey, https_origin, same_origin};
pub use crate::crypto::did_key::{DecodedDidKey, decode as decode_did_key, encode_ed25519 as did_key_from_ed25519};
pub use crate::crypto::eddsa_jcs::{
  countersign_as_notary, sign_as_principal, sign_envelope, signing_input, verify_envelope,
  verify_envelope_did_key, verify_proof,
};
pub use crate::crypto::jcs::canonicalize_rfc8785;
pub use crate::crypto::jws_detached::{create_detached_jws, verify_detached_jws};
pub use crate::crypto::signing::{sign_mandate, verify_mandate};
pub use crate::crypto::proof_base::{ProofRole, mandate_signing_base, signing_base};
pub use crate::verification::{
  require_mode, verify_embedded_mandate_binding, verify_proof_structure, verify_timestamp_order,
};
