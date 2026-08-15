//! The two narrow fetch ports notary-key discovery needs.
//!
//! `aph-core` parses; it never fetches. Spec §8.4 defines two of its three
//! publication mechanisms in terms of I/O — a DNS query (§8.4.5) and an
//! HTTPS GET (§8.4.4) — and this module is the entire boundary across which
//! that I/O arrives. The adapters live outside this crate, so `aph-core`
//! keeps no HTTP client, no resolver, and no async runtime, and every rule
//! in [`crate::discovery`] stays testable against fixed strings.
//!
//! **Two traits, one method each, on purpose.** A bounded context declares
//! its OWN narrow port rather than depending on a wide shared one: reusing a
//! host-wide `HttpPort` would widen this crate's dependency surface and tie
//! its lifetime to the host's. One method means a test double is a struct
//! with a canned answer, which is why [`super::composer`] is exercised
//! end-to-end with no network at all.
//!
//! **No `async fn` in trait, deliberately.** Both methods return a boxed,
//! pinned future — the shape `#[async_trait]` generates — written by hand
//! because it is dyn-compatible and needs no dependency. `async fn` in a
//! trait (or a bare `-> impl Future`) would force every consumer of a port
//! to become generic over the adapter, which defeats the point of a port:
//! choosing the adapter at run time.

/// The future a discovery port returns: a boxed, pinned, `Send` future
/// resolving to `T` or to a [`crate::errors::AphError`].
///
/// Boxed rather than `impl Future` so `&dyn TxtRecordLookup` and
/// `std::sync::Arc<dyn DidDocumentFetch>` both work — see the module note.
/// One allocation per lookup is irrelevant beside the network round trip it
/// wraps.
pub type DiscoveryFuture<'a, T> = std::pin::Pin<
  std::boxed::Box<
    dyn std::future::Future<Output = std::result::Result<T, crate::errors::AphError>>
      + std::marker::Send
      + 'a,
  >,
>;

/// Fetches the TXT records published at a DNS name (spec §8.4.5).
///
/// `Send + Sync` so one adapter can be shared across concurrent
/// verifications without wrapping.
pub trait TxtRecordLookup: std::marker::Send + std::marker::Sync {
  /// Returns EVERY TXT string at `name`, unparsed and unfiltered.
  ///
  /// "Unfiltered" is a hard requirement, not a convenience. A domain
  /// legitimately holds unrelated TXT records at the same name (SPF, site
  /// verification tokens) and a rotating notary holds several APH records
  /// side by side. [`super::dns_txt::select_key`] is written so that a
  /// malformed record beside a valid one does not deny the valid one; an
  /// adapter that pre-filtered — dropping anything it judged malformed, or
  /// returning only the first record — would silently defeat that and turn
  /// one typo in DNS into a total verification outage.
  ///
  /// `name` is always a value derived by [`super::DidUrl::dns_txt_name`].
  /// An adapter MUST NOT re-derive it from the DID.
  ///
  /// # Errors
  ///
  /// `APH_E008` ([`crate::errors::AphError::NotaryServiceUnreachable`]) for
  /// a transport outcome that left the question UNANSWERED: timeout,
  /// SERVFAIL, refused.
  ///
  /// NXDOMAIN is NOT in that list, and neither is a NOERROR answer carrying
  /// no records. Both are ABSENCE — the server answered, and the answer is
  /// "nothing is published here" — so an adapter returns `Ok` with an empty
  /// `Vec` and the §8.4.6 composer advances to the next mechanism. This is
  /// live-proven, not a reading: real DNS reports NXDOMAIN for the
  /// `_aph._notary` name of a notary that publishes only a DID Document, and
  /// a verifier that reported that as `APH_E008` would refuse every such
  /// notary outright. The distinction is the same one
  /// [`crate::errors::AphError::NotaryKeyNotPublished`] exists for: absence
  /// advances the fallback sequence, failure must stop it.
  ///
  /// The error MUST NOT carry a status, an address, a resolver identity, or a
  /// timing. A verifier's result is disclosed to whoever sent the envelope,
  /// and an envelope names the DID that names the DNS name — so a port that
  /// leaked *how* a lookup failed would turn every verifier into a network
  /// scanner steerable by an attacker (PRD-700 §7 A2 control 5). "No key was
  /// obtained" is the whole of what a verifier may learn and report.
  fn lookup_txt<'a>(
    &'a self,
    name: &'a str,
  ) -> DiscoveryFuture<'a, std::vec::Vec<String>>;
}

/// Fetches a `did:web` DID Document (spec §8.4.4).
///
/// `Send + Sync` so one adapter can be shared across concurrent
/// verifications without wrapping.
pub trait DidDocumentFetch: std::marker::Send + std::marker::Sync {
  /// Returns the document body at `url` as a UTF-8 string, unparsed.
  ///
  /// Parsing is [`super::did_document::parse_did_document`]'s job, so an
  /// adapter hands back bytes and forms no opinion about them. It MUST
  /// fetch over TLS and MUST treat certificate validation failure as a
  /// fetch failure (§8.4.4 step 3); it MUST NOT follow a redirect to
  /// another origin, since the origin is the entire trust anchor here.
  ///
  /// `url` is always a value derived by
  /// [`super::DidUrl::web_document_url`], which encodes the percent-decode
  /// ordering that keeps a `%3A`-written port attached to the host instead
  /// of becoming a path segment. An adapter MUST NOT rebuild the URL.
  ///
  /// # Errors
  ///
  /// `APH_E008` ([`crate::errors::AphError::NotaryServiceUnreachable`]) for
  /// every transport outcome: DNS failure, TLS failure, connection refused,
  /// timeout, and any non-success HTTP status. As with
  /// [`TxtRecordLookup::lookup_txt`], the error MUST NOT disclose the
  /// status code, the resolved address, or how long the attempt took — that
  /// disclosure is what would make a verifier a probe for whoever chose the
  /// DID (PRD-700 §7 A2 control 5).
  fn fetch_did_document<'a>(
    &'a self,
    url: &'a str,
  ) -> DiscoveryFuture<'a, String>;
}

#[cfg(test)]
mod tests {
  /// A stub implementing BOTH ports, counting only work done *inside* the
  /// returned future so laziness is observable.
  #[derive(std::default::Default)]
  struct StubPorts {
    calls: std::sync::atomic::AtomicUsize,
  }

  impl super::TxtRecordLookup for StubPorts {
    fn lookup_txt<'a>(
      &'a self,
      _name: &'a str,
    ) -> super::DiscoveryFuture<'a, std::vec::Vec<String>> {
      std::boxed::Box::pin(async move {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // Annotated rather than left to inference: the async block's output
        // type is only pinned by the unsizing coercion to `dyn Future`, and
        // an empty `Vec` gives inference nothing to work from.
        let out: std::result::Result<std::vec::Vec<String>, crate::errors::AphError> =
          std::result::Result::Ok(std::vec::Vec::new());
        out
      })
    }
  }

  impl super::DidDocumentFetch for StubPorts {
    fn fetch_did_document<'a>(&'a self, _url: &'a str) -> super::DiscoveryFuture<'a, String> {
      std::boxed::Box::pin(async move {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let out: std::result::Result<String, crate::errors::AphError> =
          std::result::Result::Ok(String::new());
        out
      })
    }
  }

  #[test]
  fn both_ports_are_dyn_compatible() {
    // The load-bearing part of this test is that it COMPILES: a port exists
    // so the adapter can be chosen at run time (a DNS adapter here, a
    // fixture adapter in a conformance run, an offline one on an air-gapped
    // verifier). If a future refactor replaced the boxed future with
    // `async fn` in trait or `-> impl Future`, these coercions would stop
    // compiling and every consumer would be forced to become generic over
    // its adapter. That is a breaking change to the whole seam, not a local
    // style choice, so it must fail here rather than downstream.
    let stub = StubPorts::default();
    let lookup: &dyn super::TxtRecordLookup = &stub;
    let fetch: &dyn super::DidDocumentFetch = &stub;
    let shared: std::sync::Arc<dyn super::TxtRecordLookup> =
      std::sync::Arc::new(StubPorts::default());
    // A registry of adapters keyed at run time is the shape a host wiring
    // actually has, and it is exactly what an `async fn` in trait forbids.
    let lookups: std::vec::Vec<&dyn super::TxtRecordLookup> = std::vec![lookup, &*shared];
    let fetches: std::vec::Vec<&dyn super::DidDocumentFetch> = std::vec![fetch];
    std::assert_eq!(lookups.len() + fetches.len(), 3);
  }

  #[test]
  fn port_futures_can_cross_a_thread_boundary() {
    // Adapters run under a host executor that moves tasks between threads,
    // and `tokio::spawn` demands `Send`. Without the `+ Send` bound on
    // `DiscoveryFuture` these traits would still compile here, but no real
    // adapter could be spawned — and the breakage would surface in the host
    // crate, far from the decision that caused it. Handing the futures to a
    // scoped thread is the runtime form of that bound.
    let stub = StubPorts::default();
    let lookup = super::TxtRecordLookup::lookup_txt(&stub, "_aph._notary.example.com");
    let fetch = super::DidDocumentFetch::fetch_did_document(
      &stub,
      "https://example.com/.well-known/did.json",
    );
    let moved = std::thread::scope(|scope| {
      scope
        .spawn(move || {
          std::mem::drop(lookup);
          std::mem::drop(fetch);
        })
        .join()
    });
    std::assert!(moved.is_ok());
  }

  #[test]
  fn constructing_a_port_call_performs_no_io_until_awaited() {
    // This laziness is what lets a composer hold both ports and still
    // *prove* it never used one: an un-awaited future has touched nothing.
    // If an adapter did its work eagerly in the method body instead of
    // inside the returned future, merely deciding not to use a mechanism
    // would already have queried it — and the no-downgrade guarantee in
    // `super::composer` would become unobservable.
    let stub = StubPorts::default();
    let future = super::TxtRecordLookup::lookup_txt(&stub, "_aph._notary.example.com");
    std::mem::drop(future);
    std::assert_eq!(stub.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
  }
}
