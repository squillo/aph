//! Cryptographic helpers for APH envelopes.
//!
//! Two layers live here:
//!
//! - **Envelope signing** — one module per §8.1/§8.2 combination of algorithm
//!   and carriage, all three sharing [`proof_base`] so they cannot disagree
//!   about which bytes a proof covers:
//!
//!   | Module | `proof.type` | Algorithm | `proofValue` carries |
//!   |---|---|---|---|
//!   | [`eddsa_jcs`] | `DataIntegrityProof` (`eddsa-jcs-2022`) | Ed25519 | multibase base58btc, 64 raw bytes |
//!   | [`ecdsa_jcs`] | `DataIntegrityProof` (`ecdsa-jcs-2019`) | ES256 | multibase base58btc, P1363 `r‖s` |
//!   | [`jws_envelope`] | `JsonWebSignature2020` | ES256 | a compact DETACHED JWS |
//!
//!   `eddsa-jcs-2022` is the protocol's default and the suite the channel
//!   examples declare; the other two are §8.1 MUST-support and each now has a
//!   published vector under `examples/`. [`did_key`] and [`multibase`] let a
//!   verifier recover a `did:key` issuer's public key on either curve with no
//!   network access at all. [`proof_base`] owns the canonicalization base each
//!   proof covers (spec §7.2.1) — the one place that decides which bytes a
//!   signature is over, so signer and verifier cannot drift apart.
//! - **Shared primitives** — [`jcs`] canonicalization, [`jws_detached`], and
//!   ES256 [`signing`] are shared with the AP2 payment-mandate ecosystem and
//!   are vendored here so the APH crate stands alone with no external
//!   protocol dependencies.
//!
//! # ⛔ The signature encoding depends on the CARRIAGE, not on the algorithm
//!
//! The same ES256 key produces two different wire forms in this crate, and
//! both are correct:
//!
//! - an `ecdsa-jcs-2019` `proofValue` is P1363 `r‖s`, per the W3C suite
//!   definition ([`ecdsa_jcs`]);
//! - the signature inside a detached JWS is DER, and a Delegation Mandate
//!   signature is DER, because that is the deployed AP2-interop wire
//!   ([`jws_detached`], [`signing`]).
//!
//! Unifying them "for consistency" would fork one of the two wires. Both
//! sides are pinned by tests that assert they DIFFER.

pub mod did_key;
pub mod ecdsa_jcs;
pub mod eddsa_jcs;
pub mod jcs;
pub mod jws_detached;
pub mod jws_envelope;
pub mod multibase;
pub mod proof_base;
pub mod signing;

pub(crate) mod base64url;
