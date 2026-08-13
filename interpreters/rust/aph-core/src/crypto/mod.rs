//! Cryptographic helpers for APH envelopes.
//!
//! These helpers (JCS canonicalization, detached JWS, ES256 signing) are
//! shared with the AP2 payment-mandate ecosystem and are vendored here so
//! the APH crate stands alone with no external protocol dependencies.

pub mod jcs;
pub mod jws_detached;
pub mod signing;

pub(crate) mod base64url;
