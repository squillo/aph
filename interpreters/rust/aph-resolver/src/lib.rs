// Every public item in a protocol reference implementation is read by
// implementers, so undocumented surface is a defect.
#![warn(missing_docs)]

//! Ready-made I/O adapters for APH notary-key discovery (spec §8.4).
//!
//! `aph-core` parses and never fetches. Two of §8.4's three publication
//! mechanisms are defined in terms of I/O — a DNS TXT query (§8.4.5) and an
//! HTTPS GET of a DID Document (§8.4.4) — and `aph-core` declares them as two
//! narrow one-method ports so the fetching lives outside it. This crate is one
//! implementation of those two ports, carrying the DNS and HTTP dependencies
//! that `aph-core` deliberately does not.
//!
//! # Who this is for
//!
//! **Adopters with no adapter layer of their own.** If you are writing a
//! verifier — a CLI, a service, a test harness — and you have no opinion
//! about how HTTP and DNS should be performed, [`resolve`] gets you a notary
//! key in one call and the guards below come with it.
//!
//! **It is explicitly not for a host that already has a transport stack.** An
//! OS or platform with its own HTTP client, its own DNS policy, its own
//! timeout and retry budget and its own audit log should implement
//! `aph_core::discovery::ports` over THAT stack, which is a few dozen lines,
//! and keep one place where outbound requests are made. That is exactly what
//! Squillo does, and it is why Squillo never links this crate: two HTTP
//! clients in one process means two timeout policies, two proxy
//! configurations and two answers to "what did this machine connect to".
//!
//! # What this crate does NOT decide
//!
//! Every parsing, selection and ordering rule stays in `aph-core`: tag-list
//! parsing and key selection (`discovery::dns_txt`), DID Document parsing and
//! verification-method lookup (`discovery::did_document`), and the §8.4.6
//! mechanism order with its no-downgrade rule (`discovery::composer`). This
//! crate contributes bytes and one classification — see below — and forms no
//! opinion about what those bytes mean. A second parser here would be a
//! second chance to disagree with the specification.
//!
//! The one judgement it does make is the ABSENCE/FAILURE split, and it is
//! made because only the adapter can see it. §8.4.6 advances the mechanism
//! sequence on absence and refuses on failure, so a DNS answer of NXDOMAIN
//! (or NOERROR with no TXT records) becomes
//! `Ok(aph_core::discovery::DiscoveryOutcome::Absent)` while a timeout,
//! SERVFAIL or REFUSED becomes `APH_E008`. That distinction is what keeps a
//! notary publishing only a DID Document verifiable, without letting whoever
//! can block DNS choose which anchor a verifier trusts.
//!
//! # Security posture — the five SSRF controls
//!
//! The host a verifier connects to is named by the envelope being verified,
//! which means it is chosen by an untrusted party. [`ReqwestDocumentFetch`]
//! therefore applies five controls: a deny table over EVERY resolved address
//! before any connect with the validated set pinned so the connect cannot
//! re-resolve; HTTPS only with no certificate-validation escape hatch;
//! redirects refused and the response origin re-checked; a 5 s budget and a
//! 64 KiB body cap enforced while streaming; and ONE opaque `APH_E008`
//! outward for every failure, so a verifier cannot be used as a network
//! probe by whoever chose the DID. The source states each control at the
//! line that implements it.
//!
//! # Example
//!
//! ```no_run
//! # async fn run() -> std::result::Result<(), std::boxed::Box<dyn std::error::Error>> {
//! // The DID URL comes from the envelope's `proof.verificationMethod`, and
//! // the instant comes from its `decisionTimestamp` — not the wall clock,
//! // so an envelope signed before a rotation keeps verifying.
//! let key = aph_resolver::resolve(
//!   "did:web:notary.example.com#k1",
//!   "2026-06-01T00:00:00Z",
//! )
//! .await?;
//! std::println!("{} byte key", key.key_bytes.len());
//! # std::result::Result::Ok(())
//! # }
//! ```

mod address;
mod dns;
mod web;

pub use crate::dns::HickoryTxtLookup;
pub use crate::web::ReqwestDocumentFetch;

/// Resolves the notary public key a DID URL names, building both adapters
/// for you (spec §8.4.6).
///
/// The no-host convenience path: a system-configured resolver and a guarded
/// HTTPS client are constructed here and handed to
/// `aph_core::discovery::composer::resolve` under
/// `MechanismSelection::NamedByDid`. An adopter who wants a pinned mechanism,
/// a shared resolver, or a client they configured should build
/// [`HickoryTxtLookup`] and [`ReqwestDocumentFetch`] themselves and call the
/// composer directly — this function is the default, not the only door.
///
/// # What the §8.4.6 order does
///
/// A `did:key` DID is decoded in-process and touches NO network at all: the
/// key bytes are the identifier, so this path works on an air-gapped
/// verifier. A `did:web` DID probes DNS TXT first and advances to the
/// document fetch only when nothing is published there — absence advances,
/// failure never does. A mechanism that was offered and then FAILED refuses
/// on the spot under its own code, because retrying a weaker anchor when a
/// stronger one breaks hands an attacker a free downgrade.
///
/// # `at_rfc3339`
///
/// Pass the envelope's `decisionTimestamp`, not the wall clock. Per §8.4.7 a
/// verifier accepts any envelope whose signing key was valid at the moment
/// the decision was made; using "now" instead would start rejecting
/// correctly-signed historical envelopes the day an old key's `notAfter`
/// passes.
///
/// # Errors
///
/// Whatever the chosen mechanism returns, unflattened — `APH_E008`
/// unreachable, `APH_E014` nothing published, `APH_E003` outside the key's
/// validity window, `APH_E010` unsupported method or algorithm. Also
/// `APH_E008` if the host's own resolver configuration cannot be read, which
/// is deliberately indistinguishable from a failed lookup.
pub async fn resolve(
  did_url: &str,
  at_rfc3339: &str,
) -> std::result::Result<aph_core::discovery::NotaryPublicKey, aph_core::errors::AphError> {
  let lookup = crate::dns::HickoryTxtLookup::from_system_conf()?;
  let fetch = crate::web::ReqwestDocumentFetch::new();
  aph_core::discovery::composer::resolve(
    aph_core::discovery::composer::MechanismSelection::NamedByDid,
    did_url,
    &lookup,
    &fetch,
    at_rfc3339,
  )
  .await
}

#[cfg(test)]
mod tests {
  /// The Ed25519 key published in every spec §8.4 example.
  const SPEC_MULTIBASE: &str = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV";

  #[tokio::test]
  async fn a_did_key_resolves_through_this_crate_with_no_network() {
    // The whole convenience path, on the one mechanism that needs no I/O.
    // It pins two things a signature alone does not: that `resolve` really
    // delegates to the §8.4.6 composer rather than reimplementing dispatch
    // (a reimplementation would have to decide what did:key means, and this
    // crate must never decide that), and that the did:key arm reaches an
    // answer without either adapter performing a lookup — which is what
    // makes an air-gapped verifier possible. Note it still constructs the
    // system resolver, so a machine with no resolver configuration would
    // report APH_E008 here; that is accepted, and it is the reason an
    // air-gapped caller should use `composer::resolve_did_key` directly.
    let did = std::format!("did:key:{}#{}", SPEC_MULTIBASE, SPEC_MULTIBASE);
    match super::resolve(&did, "2026-06-01T00:00:00Z").await {
      std::result::Result::Ok(key) => {
        std::assert_eq!(key.algorithm, aph_core::discovery::KeyAlgorithm::Ed25519);
        std::assert_eq!(key.key_bytes.len(), 32);
        std::assert_eq!(key.kid.as_deref(), std::option::Option::Some(SPEC_MULTIBASE));
      }
      // The only tolerated failure is the resolver-construction one, which
      // happens before any mechanism is chosen. Anything else means the
      // did:key path went to the network.
      std::result::Result::Err(error) => std::assert_eq!(
        error,
        aph_core::errors::AphError::NotaryServiceUnreachable,
        "did:key resolution failed for a reason other than resolver setup"
      ),
    }
  }

  #[tokio::test]
  async fn an_unknown_did_method_is_refused_before_any_adapter_runs() {
    // APH v0.1 defines exactly two DID methods. A third must be APH_E010
    // from `composer::named_by`, not a guess at a resolution strategy — and
    // certainly not an outbound request whose shape a stranger chose by
    // writing an unrecognised DID into an envelope.
    let error = super::resolve("did:example:notary", "2026-06-01T00:00:00Z")
      .await
      .unwrap_err();
    std::assert!(
      error.code() == "APH_E010" || error == aph_core::errors::AphError::NotaryServiceUnreachable,
      "unexpected error for an unknown DID method: {}",
      error
    );
  }
}
