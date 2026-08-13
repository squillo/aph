//! Cryptographic helpers for APH envelopes.
//!
//! Two layers live here:
//!
//! - **Envelope signing** — [`eddsa_jcs`] implements `eddsa-jcs-2022`, the
//!   protocol's default cryptosuite and the one every published example
//!   declares, together with [`did_key`] and [`multibase`] so a verifier can
//!   recover a `did:key` issuer's public key and check a proof with no
//!   network access at all.
//! - **Shared primitives** — [`jcs`] canonicalization, [`jws_detached`], and
//!   ES256 [`signing`] are shared with the AP2 payment-mandate ecosystem and
//!   are vendored here so the APH crate stands alone with no external
//!   protocol dependencies.

pub mod did_key;
pub mod eddsa_jcs;
pub mod jcs;
pub mod jws_detached;
pub mod multibase;
pub mod signing;

pub(crate) mod base64url;
