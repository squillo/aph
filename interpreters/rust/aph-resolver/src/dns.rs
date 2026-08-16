//! The §8.4.5 DNS TXT adapter, over `hickory-resolver`.
//!
//! This module contributes I/O and nothing else. It does not know what an
//! APH tag-list looks like, which record wins a rotation, or what a validity
//! window is — all of that is `aph_core::discovery::dns_txt`, reached through
//! the composer. What lives here is the DNS query and ONE decision the parsing
//! half cannot make on its own: whether a failed query means *nothing is
//! published* or *the lookup broke*.
//!
//! That decision is load-bearing. Spec §8.4.6 advances to the next mechanism
//! on ABSENCE and refuses outright on FAILURE, so an adapter that reports
//! absence as failure takes every `did:web` notary offline the moment it stops
//! publishing TXT, and one that reports failure as absence hands an attacker
//! the downgrade §8.4.6 exists to forbid: block the DNS answer, and the
//! verifier volunteers to trust whatever the web origin serves. The port says
//! which is which in its return type — `aph_core::discovery::DiscoveryOutcome`
//! — so this module's job is only to decide which DNS answers land where.

/// Which side of the absence/failure line a resolver error falls on.
///
/// Named rather than a `bool` because the two outcomes are not degrees of
/// the same thing: one continues the §8.4.6 sequence and the other stops it.
///
/// Deliberately NOT `aph_core::discovery::DiscoveryOutcome`, which is the
/// protocol's word for the same line. This classifies an ERROR, so it can
/// never be `Found`; reusing the port's type here would give a pure two-
/// valued classifier a third variant it cannot produce, and would force it
/// to construct an `AphError` it has no business owning.
/// [`negative_answer`] is the one place the two vocabularies meet.
#[derive(std::fmt::Debug, std::clone::Clone, std::marker::Copy, std::cmp::PartialEq, std::cmp::Eq)]
pub(crate) enum LookupOutcome {
  /// Nothing is published at this name. The composer may advance.
  Absence,
  /// The lookup could not be completed. `APH_E008`; the composer must stop.
  Failure,
}

/// A [`aph_core::discovery::ports::TxtRecordLookup`] backed by a system-
/// configured hickory resolver.
///
/// `Send + Sync` follows from the resolver's own bounds, so one instance can
/// be shared across concurrent verifications without wrapping.
pub struct HickoryTxtLookup {
  resolver: hickory_resolver::TokioAsyncResolver,
}

impl HickoryTxtLookup {
  /// Builds a lookup from the host's own resolver configuration —
  /// `/etc/resolv.conf` on Unix, the registry on Windows.
  ///
  /// # Errors
  ///
  /// `APH_E008` if the system configuration cannot be read. The failure is
  /// reported in the same opaque form as a failed query on purpose: a caller
  /// that could distinguish "this verifier is misconfigured" from "that
  /// notary is unreachable" by reading an error string would be reporting
  /// its own posture to whoever chose the DID.
  pub fn from_system_conf() -> std::result::Result<Self, aph_core::errors::AphError> {
    match hickory_resolver::TokioAsyncResolver::tokio_from_system_conf() {
      std::result::Result::Ok(resolver) => std::result::Result::Ok(Self { resolver }),
      std::result::Result::Err(_) => {
        std::result::Result::Err(aph_core::errors::AphError::NotaryServiceUnreachable)
      }
    }
  }

  /// Builds a lookup over a resolver the caller configured.
  ///
  /// The injection point for an adopter who already runs a resolver — a
  /// pinned recursive server, DNS-over-TLS, a shorter timeout — without
  /// having to reimplement the absence/failure split, which is the only part
  /// of this adapter that is protocol knowledge rather than plumbing.
  pub fn with_resolver(resolver: hickory_resolver::TokioAsyncResolver) -> Self {
    Self { resolver }
  }
}

impl aph_core::discovery::ports::TxtRecordLookup for HickoryTxtLookup {
  /// Returns EVERY TXT string at `name`, unparsed and unfiltered.
  ///
  /// No pre-filtering, per the port contract: a domain legitimately holds
  /// unrelated TXT records at one name and a rotating notary holds several
  /// APH records side by side, so an adapter that dropped what it judged
  /// malformed would turn one typo in DNS into a total verification outage.
  ///
  /// `name` arrives already derived by `DidUrl::dns_txt_name`; this adapter
  /// does not re-derive it.
  fn lookup_txt<'a>(
    &'a self,
    name: &'a str,
  ) -> aph_core::discovery::ports::DiscoveryFuture<
    'a,
    aph_core::discovery::DiscoveryOutcome<std::vec::Vec<String>>,
  > {
    std::boxed::Box::pin(async move {
      match self.resolver.txt_lookup(name).await {
        std::result::Result::Ok(lookup) => {
          let mut records: std::vec::Vec<String> = std::vec::Vec::new();
          for txt in lookup.iter() {
            records.push(join_character_strings(
              txt.txt_data().iter().map(|part| &part[..]),
            ));
          }
          // hickory reports the ordinary no-records answer as a
          // `NoRecordsFound` ERROR, classified on the arm below. This guard
          // is for the other shape — a lookup that succeeded and yielded
          // nothing — so that the port can never answer `Found` with nothing
          // found. Downstream it makes no difference (an empty record set
          // selects to absence anyway); it makes the port's own answer
          // honest, which is the whole point of the type.
          if records.is_empty() {
            return std::result::Result::Ok(aph_core::discovery::DiscoveryOutcome::Absent);
          }
          std::result::Result::Ok(aph_core::discovery::DiscoveryOutcome::Found(records))
        }
        std::result::Result::Err(error) => negative_answer(classify_resolve_error(&error)),
      }
    })
  }
}

/// The classifier's verdict expressed as the port's own answer.
///
/// The one place this crate's absence/failure vocabulary meets the protocol's
/// (see [`LookupOutcome`]), split out as a pure function so the translation
/// is testable with no network — which matters, because getting it backwards
/// in either direction is a live outage or a silent downgrade, and neither is
/// visible in a unit test of the classifier alone.
fn negative_answer(
  outcome: LookupOutcome,
) -> std::result::Result<
  aph_core::discovery::DiscoveryOutcome<std::vec::Vec<String>>,
  aph_core::errors::AphError,
> {
  match outcome {
    LookupOutcome::Absence => {
      std::result::Result::Ok(aph_core::discovery::DiscoveryOutcome::Absent)
    }
    LookupOutcome::Failure => {
      std::result::Result::Err(aph_core::errors::AphError::NotaryServiceUnreachable)
    }
  }
}

/// Reassembles one TXT record's character-strings into the single value the
/// publisher wrote.
///
/// A TXT record's RDATA is a sequence of length-prefixed strings, each at
/// most 255 bytes, and a record longer than that arrives split. Concatenating
/// them is the same reassembly DKIM (RFC 6376 §3.6.2.2) and SPF perform, and
/// it is NOT the filtering the port forbids: nothing is dropped, and the
/// record count out equals the record count in. Handing the fragments back
/// separately would be the defect — two unparseable halves instead of one
/// valid tag-list.
///
/// Non-UTF-8 bytes are replaced rather than causing the record to be skipped.
/// Skipping would be filtering, and a garbled record must be allowed to fail
/// `select_key` on its own without denying a valid record beside it.
fn join_character_strings<'a>(parts: impl std::iter::Iterator<Item = &'a [u8]>) -> String {
  let mut joined: std::vec::Vec<u8> = std::vec::Vec::new();
  for part in parts {
    joined.extend_from_slice(part);
  }
  String::from_utf8_lossy(&joined).into_owned()
}

/// The absence/failure split, as a pure function of a resolver error.
///
/// Pure so it is testable with no network — which is the point, because this
/// is the rule a live run proved and a live run is exactly what a test suite
/// must not need. hickory 0.24 folds the negative answers into a single
/// `NoRecordsFound` kind and preserves the DNS response code beside it, so
/// the code is what has to be read: `NXDomain` and `NoError` are the server
/// answering "there is nothing here", while `ServFail`, `Refused` and every
/// other kind mean the question was never answered.
///
/// The `_` arm is required — `ResolveErrorKind` is `#[non_exhaustive]` — and
/// it fails CLOSED: a kind this build has never heard of is a failure, not
/// an absence, so a hickory upgrade cannot quietly widen what advances the
/// §8.4.6 sequence.
pub(crate) fn classify_resolve_error(
  error: &hickory_resolver::error::ResolveError,
) -> LookupOutcome {
  match error.kind() {
    hickory_resolver::error::ResolveErrorKind::NoRecordsFound { response_code, .. } => {
      classify_response_code(*response_code)
    }
    _ => LookupOutcome::Failure,
  }
}

/// The DNS response-code half of the split.
///
/// Separated from [`classify_resolve_error`] so the rule can be stated —
/// and tested — over the value that actually decides it, independent of how
/// any resolver release chooses to wrap it.
pub(crate) fn classify_response_code(
  response_code: hickory_resolver::proto::op::ResponseCode,
) -> LookupOutcome {
  match response_code {
    // The name does not exist. Live-proven absence: on 2026-08-14 real DNS
    // answered NXDOMAIN for a notary's `_aph._notary` name and the §8.4.6
    // composer correctly advanced to did:web, which then resolved.
    hickory_resolver::proto::op::ResponseCode::NXDomain => LookupOutcome::Absence,
    // The name exists but holds no TXT records — absence just as much as
    // NXDOMAIN, and the more common shape for a domain that publishes A
    // records and nothing else at that label.
    hickory_resolver::proto::op::ResponseCode::NoError => LookupOutcome::Absence,
    // SERVFAIL, REFUSED and the rest: the resolver did not answer the
    // question. Treating these as absence would let anyone who can break or
    // merely block DNS choose which anchor the verifier trusts.
    _ => LookupOutcome::Failure,
  }
}

#[cfg(test)]
mod tests {
  /// Builds the negative answer hickory reports for a given response code.
  ///
  /// `ResolveErrorKind` is `#[non_exhaustive]`, which forbids exhaustive
  /// MATCHING outside the crate but not construction of an individual
  /// variant, so the real error shape can be built here rather than
  /// approximated.
  fn no_records_found(
    response_code: hickory_resolver::proto::op::ResponseCode,
  ) -> hickory_resolver::error::ResolveError {
    std::convert::Into::into(hickory_resolver::error::ResolveErrorKind::NoRecordsFound {
      query: std::boxed::Box::new(hickory_resolver::proto::op::Query::new()),
      soa: std::option::Option::None,
      negative_ttl: std::option::Option::None,
      response_code,
      trusted: false,
    })
  }

  #[test]
  fn nxdomain_and_empty_noerror_are_absence() {
    // THE contract this adapter exists to get right, and the one the shipped
    // port doc got wrong until 2026-08-14: a notary that publishes only a
    // DID Document has no `_aph._notary` name at all, so NXDOMAIN is the
    // NORMAL answer on the §8.4.6 path — proven live, where the composer saw
    // NXDOMAIN, advanced, and resolved the key over did:web. Report either of
    // these as APH_E008 and every did:web-only notary becomes unverifiable.
    std::assert_eq!(
      super::classify_response_code(hickory_resolver::proto::op::ResponseCode::NXDomain),
      super::LookupOutcome::Absence
    );
    std::assert_eq!(
      super::classify_response_code(hickory_resolver::proto::op::ResponseCode::NoError),
      super::LookupOutcome::Absence
    );
  }

  #[test]
  fn servfail_and_refused_are_failure() {
    // The other half, and the security-critical one. SERVFAIL and REFUSED
    // mean the question was never answered — including when an on-path
    // attacker made sure of it. Classifying them as absence would advance
    // the §8.4.6 sequence past the anchor the notary actually publishes to,
    // which is precisely the downgrade that section forbids.
    std::assert_eq!(
      super::classify_response_code(hickory_resolver::proto::op::ResponseCode::ServFail),
      super::LookupOutcome::Failure
    );
    std::assert_eq!(
      super::classify_response_code(hickory_resolver::proto::op::ResponseCode::Refused),
      super::LookupOutcome::Failure
    );
    // A response code with no bearing on APH still stops the sequence:
    // fail-closed is the default, and only the two absence codes escape it.
    std::assert_eq!(
      super::classify_response_code(hickory_resolver::proto::op::ResponseCode::NotImp),
      super::LookupOutcome::Failure
    );
  }

  #[test]
  fn the_split_survives_the_real_resolver_error_shape() {
    // classify_response_code is the rule; classify_resolve_error is what the
    // adapter actually calls. Testing only the former would leave the
    // unwrapping untested, and an unwrapping that matched the wrong kind
    // would send every NXDOMAIN down the failure arm while every unit test
    // above still passed.
    std::assert_eq!(
      super::classify_resolve_error(&no_records_found(
        hickory_resolver::proto::op::ResponseCode::NXDomain
      )),
      super::LookupOutcome::Absence
    );
    std::assert_eq!(
      super::classify_resolve_error(&no_records_found(
        hickory_resolver::proto::op::ResponseCode::ServFail
      )),
      super::LookupOutcome::Failure
    );
  }

  #[test]
  fn a_timeout_is_never_absence() {
    // A timeout carries no response code at all, so it reaches the `_` arm.
    // That arm must fail closed: a verifier whose resolver is being starved
    // of answers is not a verifier that has learned a notary publishes
    // nothing, and the difference decides whether an attacker can pick the
    // trust anchor by dropping packets.
    std::assert_eq!(
      super::classify_resolve_error(&std::convert::Into::into(
        hickory_resolver::error::ResolveErrorKind::Timeout
      )),
      super::LookupOutcome::Failure
    );
    std::assert_eq!(
      super::classify_resolve_error(&std::convert::Into::into(
        hickory_resolver::error::ResolveErrorKind::NoConnections
      )),
      super::LookupOutcome::Failure
    );
  }

  #[test]
  fn the_verdict_becomes_a_typed_absent_answer_or_an_opaque_refusal() {
    // The classifier tests above pin which DNS answers are absence; this pins
    // what the PORT then says, which is the half a caller acts on. Both
    // directions are load-bearing and neither is observable from the
    // classifier alone: `Absent` is what lets the §8.4.6 sequence advance to
    // did:web, and `Err(APH_E008)` is what stops it. Swap the two arms and
    // every classifier test still passes while every did:web-only notary
    // becomes unverifiable — or, the other way, whoever can block DNS picks
    // the trust anchor.
    std::assert_eq!(
      super::negative_answer(super::LookupOutcome::Absence).unwrap(),
      aph_core::discovery::DiscoveryOutcome::Absent
    );
    std::assert_eq!(
      super::negative_answer(super::LookupOutcome::Failure).unwrap_err(),
      aph_core::errors::AphError::NotaryServiceUnreachable
    );
  }

  #[test]
  fn a_split_record_is_reassembled_not_returned_in_pieces() {
    // A TXT record longer than 255 bytes arrives as several character-
    // strings, and an APH tag-list with a P-256 key plus a `did` tag can
    // cross that line. Handing the halves back separately would give
    // `select_key` two unparseable fragments where the publisher wrote one
    // valid record — a filtering defect wearing the costume of fidelity.
    std::assert_eq!(
      super::join_character_strings(
        [&b"v=APHv1; alg=ed25519; "[..], &b"k=2Vc3Hpcg1XOoxCBT"[..]].into_iter()
      ),
      "v=APHv1; alg=ed25519; k=2Vc3Hpcg1XOoxCBT"
    );
  }

  #[test]
  fn a_non_utf8_record_survives_as_a_lossy_string() {
    // Dropping an undecodable record would be exactly the pre-filtering the
    // port forbids: one neighbour publishing binary junk at
    // `_aph._notary.<domain>` must not be able to deny the valid APH record
    // beside it. The garbled value reaches `select_key`, fails to parse
    // there, and is skipped by the selection rules that were written for it.
    let lossy = super::join_character_strings([&b"\xff\xfe"[..]].into_iter());
    std::assert!(!lossy.is_empty(), "a record was dropped rather than kept");
  }
}
