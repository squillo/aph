//! The §8.4.4 `did:web` document fetch adapter, over `reqwest`.
//!
//! Like the DNS adapter beside it, this module contributes I/O only — parsing the
//! document and picking the key the proof names is
//! `aph_core::discovery::did_document`. What it does own is the guard, and
//! the guard is the reason this crate exists as more than a five-line
//! convenience.
//!
//! **The host being fetched is chosen by whoever wrote the envelope.** A
//! verifier reads `proof.verificationMethod`, derives a URL from it, and
//! connects. That is an outbound request an untrusted party specified, so
//! without controls a verifier is a request forger with a credential-shaped
//! excuse. All five SSRF controls are implemented here
//! in the order they must run:
//!
//! 1. **Address deny table over the FULL resolved set, before any connect**,
//!    then the validated set is PINNED into the client so the connect cannot
//!    re-resolve. Classifying and then letting the HTTP stack resolve again
//!    is the TOCTOU hole DNS rebinding walks through.
//! 2. **HTTPS only** — asserted on the parsed scheme AND enforced by the
//!    client. No `danger_accept_invalid_*` appears anywhere in this crate;
//!    §8.4.4 step 3 makes certificate validation failure a fetch failure,
//!    because the certificate chain IS the trust anchor for this mechanism.
//! 3. **No redirects, and an origin-equality re-check on the response.** A
//!    redirect that changed origin would move the trust anchor to a host the
//!    notary's certificate never covered.
//! 4. **Bounded** — 5 s connect, 5 s total, and a body cap enforced WHILE
//!    streaming. A real DID Document is under 2 KiB.
//! 5. **One opaque error outward.** Every distinguishable failure collapses
//!    to a bare `APH_E008`.
//!
//! Control 5 deserves its own sentence, because it is the one that looks like
//! bad ergonomics. A verifier's result is disclosed to whoever sent the
//! envelope, and that party chose the DID — so an error that said "connection
//! refused" where another said "certificate invalid", or that simply came
//! back faster, would turn every verifier into a network scanner steerable
//! from outside. "No key was obtained" is the whole of what a verifier may
//! learn and report.

/// Total time allowed for the whole request, connect included.
const TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Time allowed to establish the connection.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Hard ceiling on the response body.
///
/// Spec §8.4.4 documents are a handful of verification methods; the largest
/// real one this implementation has seen is under 2 KiB. 64 KiB leaves two
/// orders of magnitude of headroom and still means a hostile origin cannot
/// stream a verifier out of memory.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// The one failure this adapter ever reports.
///
/// A free function rather than an inline literal at each site so the promise
/// is checkable by reading one place: every arm below returns THIS, and the
/// variant carries no payload, so opacity is structural rather than a
/// discipline someone has to maintain.
fn refused() -> aph_core::errors::AphError {
  aph_core::errors::AphError::NotaryServiceUnreachable
}

/// A [`aph_core::discovery::ports::DidDocumentFetch`] over `reqwest`, with
/// all five SSRF controls applied.
#[derive(std::fmt::Debug, std::clone::Clone, std::marker::Copy, std::default::Default)]
pub struct ReqwestDocumentFetch {
  // A zero-sized struct on purpose: see `fetch_did_document` for why no
  // client is cached here.
  _private: (),
}

impl ReqwestDocumentFetch {
  /// Builds the guarded fetch adapter.
  pub fn new() -> Self {
    Self { _private: () }
  }
}

impl aph_core::discovery::ports::DidDocumentFetch for ReqwestDocumentFetch {
  /// Fetches `url` under the five controls and returns the body unparsed.
  ///
  /// `url` is taken AS DERIVED. `DidUrl::web_document_url` already encoded
  /// the colon-to-path-segment mapping, the `/.well-known/` special case and
  /// the percent-decode ordering that keeps a `%3A`-written port attached to
  /// its host; re-deriving here would get one of them wrong, and a wrong
  /// document that happens to parse yields a wrong key rather than an error.
  ///
  /// # Errors
  ///
  /// `APH_E008`, always the same bare value — see the module note on
  /// control 5.
  fn fetch_did_document<'a>(
    &'a self,
    url: &'a str,
  ) -> aph_core::discovery::ports::DiscoveryFuture<'a, String> {
    std::boxed::Box::pin(async move {
      // Annotated because the async block's output type is pinned only by
      // the unsizing coercion to `dyn Future`.
      let out: std::result::Result<String, aph_core::errors::AphError> = fetch_guarded(url).await;
      out
    })
  }
}

/// The guarded fetch, written as a free async fn so the control order reads
/// top to bottom.
async fn fetch_guarded(url: &str) -> std::result::Result<String, aph_core::errors::AphError> {
  let target = match reqwest::Url::parse(url) {
    std::result::Result::Ok(parsed) => parsed,
    std::result::Result::Err(_) => return std::result::Result::Err(refused()),
  };

  // ── Control 2: HTTPS only, asserted on the parsed scheme ──────────────
  // The client is also built with `https_only(true)`. Both, not either: the
  // explicit assertion refuses BEFORE any resolution work happens, so a
  // plaintext URL never even causes a DNS query, and the client setting
  // remains as the enforcement a future refactor cannot drop by accident.
  if target.scheme() != "https" {
    return std::result::Result::Err(refused());
  }

  let host = match target.host_str() {
    std::option::Option::Some(host) if !host.is_empty() => host,
    _ => return std::result::Result::Err(refused()),
  };
  let port = match target.port_or_known_default() {
    std::option::Option::Some(port) => port,
    std::option::Option::None => return std::result::Result::Err(refused()),
  };

  let mut builder = reqwest::Client::builder()
    .https_only(true)
    // ── Control 3: no redirects ────────────────────────────────────────
    // The origin is the entire trust anchor for §8.4.4, so following a
    // redirect would let the named host hand resolution to a host whose
    // certificate proves nothing about the notary.
    .redirect(reqwest::redirect::Policy::none())
    // ── Control 4: bounds ──────────────────────────────────────────────
    .timeout(TOTAL_TIMEOUT)
    .connect_timeout(CONNECT_TIMEOUT);

  // ── Control 1: address deny table, then pin ───────────────────────────
  // `host_str` brackets an IPv6 literal; strip them before parsing so a
  // literal host is recognised as one rather than falling through to a DNS
  // query for the text "[::1]".
  let bare_host = match host.strip_prefix('[') {
    std::option::Option::Some(rest) => rest.strip_suffix(']').unwrap_or(rest),
    std::option::Option::None => host,
  };
  match <std::net::IpAddr as std::str::FromStr>::from_str(bare_host) {
    std::result::Result::Ok(literal) => {
      // A literal needs no pin: there is no name, so there is nothing that
      // could resolve differently between this check and the connect.
      if crate::address::classify_ip(literal) == crate::address::AddressClass::Refused {
        return std::result::Result::Err(refused());
      }
    }
    std::result::Result::Err(_) => {
      let resolved: std::vec::Vec<std::net::SocketAddr> =
        match tokio::net::lookup_host((bare_host, port)).await {
          std::result::Result::Ok(addresses) => addresses.collect(),
          std::result::Result::Err(_) => return std::result::Result::Err(refused()),
        };
      // A name that resolves to nothing is not reachable; refusing here also
      // means `resolve_to_addrs` is never handed an empty set, which reqwest
      // would treat as "no override" and resolve normally.
      if resolved.is_empty() {
        return std::result::Result::Err(refused());
      }
      // EVERY address, not the first: a name that answers with one public
      // and one loopback address is a rebinding attempt, and connecting to
      // whichever the stack happened to try first is a coin flip an attacker
      // gets to re-toss.
      for address in &resolved {
        if crate::address::classify_ip(address.ip()) == crate::address::AddressClass::Refused {
          return std::result::Result::Err(refused());
        }
      }
      // The pin. Without it the classification above is advisory: the client
      // would resolve the name again at connect time, and a DNS answer with
      // a one-second TTL can be public for the check and loopback for the
      // connect. This is also why no `Client` is cached on the adapter — the
      // pin is per-URL, so a shared client could not carry it.
      builder = builder.resolve_to_addrs(bare_host, &resolved);
    }
  }

  let client = match builder.build() {
    std::result::Result::Ok(client) => client,
    std::result::Result::Err(_) => return std::result::Result::Err(refused()),
  };
  let response = match client.get(target.clone()).send().await {
    std::result::Result::Ok(response) => response,
    // Connect failure, TLS failure and timeout all land here, and all three
    // leave by the same door (control 5).
    std::result::Result::Err(_) => return std::result::Result::Err(refused()),
  };

  // ── Control 3, second half: the response really came from the origin ──
  // `Policy::none()` already refuses to follow a redirect, so this can only
  // fire if that policy stopped being applied. It is cheap, and the failure
  // it guards against — a body attributed to an origin that did not serve
  // it — is not detectable anywhere downstream.
  if !same_origin(&target, response.url()) {
    return std::result::Result::Err(refused());
  }

  // A non-success status is `APH_E008` per the shipped port contract, 404
  // included: `did:web` has no served-absence form in v0.1, so "the origin
  // answered 404" and "the origin answered 503" are the same fact to a
  // verifier — no key was obtained. Inventing an absence code from a status
  // would also make the status readable from outside, which is control 5's
  // whole concern.
  if !response.status().is_success() {
    return std::result::Result::Err(refused());
  }

  read_capped(response).await
}

/// Scheme, host and effective port all equal.
///
/// Compared field by field rather than by `Url::origin()` so the comparison
/// is visible at the call site and so a URL whose port is written explicitly
/// (`:443`) matches the same URL with it omitted.
fn same_origin(requested: &reqwest::Url, answered: &reqwest::Url) -> bool {
  requested.scheme() == answered.scheme()
    && requested.host_str() == answered.host_str()
    && requested.port_or_known_default() == answered.port_or_known_default()
}

/// Reads the body, aborting the moment it would exceed [`MAX_BODY_BYTES`].
///
/// Streaming rather than `Response::bytes().await` and then measuring: a
/// read-then-measure cap has already allocated whatever the origin sent by
/// the time it decides the body was too large, which makes the "cap" a
/// memory amplifier rather than a bound. `Content-Length` is no substitute
/// either — it is a claim by the same origin the cap exists to distrust.
async fn read_capped(
  response: reqwest::Response,
) -> std::result::Result<String, aph_core::errors::AphError> {
  let mut body: std::vec::Vec<u8> = std::vec::Vec::new();
  // `bytes_stream` is not `Unpin`; pinning to the stack is what lets
  // `StreamExt::next` take it by `&mut`.
  let mut stream = std::pin::pin!(response.bytes_stream());
  loop {
    match futures_util::StreamExt::next(&mut stream).await {
      std::option::Option::Some(std::result::Result::Ok(chunk)) => {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
          return std::result::Result::Err(refused());
        }
        body.extend_from_slice(&chunk);
      }
      std::option::Option::Some(std::result::Result::Err(_)) => {
        return std::result::Result::Err(refused());
      }
      std::option::Option::None => break,
    }
  }
  // The port hands back a UTF-8 string and forms no opinion about the JSON
  // inside it; bytes that are not UTF-8 at all are not a document.
  match String::from_utf8(body) {
    std::result::Result::Ok(text) => std::result::Result::Ok(text),
    std::result::Result::Err(_) => std::result::Result::Err(refused()),
  }
}

#[cfg(test)]
mod tests {
  /// The exact text a bare `APH_E008` renders as.
  ///
  /// Spelled out rather than derived from the error under test, so a change
  /// that started interpolating detail into the message fails here instead
  /// of comparing a leaky message against itself.
  const OPAQUE: &str = "APH_E008: notary service unreachable";

  #[tokio::test]
  async fn a_loopback_url_is_refused_before_any_socket_is_opened() {
    // No listener is started, and none is needed — that absence IS the
    // assertion. The refusal happens at address classification, which runs
    // on the parsed literal before a client is built or a connect attempted,
    // so this test would pass identically on a machine with something bound
    // to :443 and on one with nothing running at all. `did:web:127.0.0.1` is
    // a well-formed DID any envelope may name, and a verifier that fetched
    // it would be reading its own loopback services on a stranger's
    // instruction.
    let fetch = super::ReqwestDocumentFetch::new();
    let error = aph_core::discovery::ports::DidDocumentFetch::fetch_did_document(
      &fetch,
      "https://127.0.0.1/.well-known/did.json",
    )
    .await
    .unwrap_err();
    std::assert_eq!(error, aph_core::errors::AphError::NotaryServiceUnreachable);
  }

  #[tokio::test]
  async fn cloud_metadata_and_ipv6_loopback_are_refused_too() {
    // The two literals an SSRF attempt actually reaches for. Covered here as
    // well as in the classifier tests because these go through the whole
    // fetch path — a guard that classified correctly but ran AFTER the
    // client was built would still pass the pure tests.
    let fetch = super::ReqwestDocumentFetch::new();
    for url in [
      "https://169.254.169.254/.well-known/did.json",
      "https://[::1]/.well-known/did.json",
      "https://[::ffff:127.0.0.1]/.well-known/did.json",
    ] {
      let error = aph_core::discovery::ports::DidDocumentFetch::fetch_did_document(&fetch, url)
        .await
        .unwrap_err();
      std::assert_eq!(
        error,
        aph_core::errors::AphError::NotaryServiceUnreachable,
        "{} was not refused",
        url
      );
    }
  }

  #[tokio::test]
  async fn a_plaintext_url_is_refused_with_the_same_opaque_error() {
    // §8.4.4 step 3 anchors this mechanism in the TLS certificate chain, so
    // a plaintext fetch is not a weaker success — it proves nothing at all.
    // The host here is public and would resolve, which is the point: the
    // scheme assertion refuses before any DNS query is made, so this test
    // needs no network either. It refuses with the SAME error as the
    // loopback case, so nothing about which control fired is readable from
    // outside.
    let fetch = super::ReqwestDocumentFetch::new();
    let error = aph_core::discovery::ports::DidDocumentFetch::fetch_did_document(
      &fetch,
      "http://notary.example.com/.well-known/did.json",
    )
    .await
    .unwrap_err();
    std::assert_eq!(error, aph_core::errors::AphError::NotaryServiceUnreachable);
  }

  #[tokio::test]
  async fn a_malformed_url_is_refused_rather_than_panicking() {
    // The URL is derived from an attacker-chosen DID. `web_document_url`
    // builds it from percent-decoded segments and does not itself validate
    // the result, so a URL that will not parse must be an ordinary refusal
    // here rather than an unwrap on the parse.
    let fetch = super::ReqwestDocumentFetch::new();
    for url in ["not a url", "https://", "file:///etc/passwd", ""] {
      let error = aph_core::discovery::ports::DidDocumentFetch::fetch_did_document(&fetch, url)
        .await
        .unwrap_err();
      std::assert_eq!(
        error,
        aph_core::errors::AphError::NotaryServiceUnreachable,
        "{:?} was not refused",
        url
      );
    }
  }

  #[tokio::test]
  async fn the_refusal_message_discloses_nothing_about_what_was_refused() {
    // Control 5, pinned as text. The verifier's result reaches whoever chose
    // the DID, so a message naming the address, echoing the URL, or carrying
    // a status code would let that party probe an address space through this
    // process and read the answers. Comparing the two refusals to ONE
    // constant is the strong form of the claim: not merely "no detail
    // leaked" but "these two outcomes are indistinguishable".
    let fetch = super::ReqwestDocumentFetch::new();
    let loopback = aph_core::discovery::ports::DidDocumentFetch::fetch_did_document(
      &fetch,
      "https://127.0.0.1:8443/.well-known/did.json",
    )
    .await
    .unwrap_err();
    let plaintext = aph_core::discovery::ports::DidDocumentFetch::fetch_did_document(
      &fetch,
      "http://notary.example.com/.well-known/did.json",
    )
    .await
    .unwrap_err();
    let rendered = std::string::ToString::to_string(&loopback);
    std::assert_eq!(rendered, OPAQUE);
    std::assert_eq!(std::string::ToString::to_string(&plaintext), OPAQUE);
    for leak in ["127.0.0.1", "8443", "notary.example.com", "well-known", "http"] {
      std::assert!(
        !rendered.contains(leak),
        "refusal message leaked `{}`: {}",
        leak,
        rendered
      );
    }
  }

  #[test]
  fn origin_equality_rejects_a_moved_response() {
    // The check behind control 3. Same scheme and same path but a different
    // host is precisely what an open redirect produces, and it is the case
    // that must fail: the trust anchor for §8.4.4 is the certificate that
    // validated THIS origin, and a document served by another host carries
    // no claim about this notary. The implicit-port row pins the other
    // direction — `:443` written out must not be read as a different origin,
    // or every explicitly-ported URL would refuse its own answer.
    let requested = reqwest::Url::parse("https://notary.example.com/.well-known/did.json").unwrap();
    std::assert!(super::same_origin(
      &requested,
      &reqwest::Url::parse("https://notary.example.com:443/.well-known/did.json").unwrap()
    ));
    std::assert!(!super::same_origin(
      &requested,
      &reqwest::Url::parse("https://evil.example.net/.well-known/did.json").unwrap()
    ));
    std::assert!(!super::same_origin(
      &requested,
      &reqwest::Url::parse("https://notary.example.com:8443/.well-known/did.json").unwrap()
    ));
  }

  #[test]
  fn the_body_cap_is_a_bound_not_a_suggestion() {
    // A constant test looks trivial and is not: this number is the only
    // thing standing between a verifier and an origin that streams
    // indefinitely, and "it was 64 KiB when reviewed" is the claim worth
    // pinning. A real DID Document is under 2 KiB, so any change large
    // enough to matter is a change of posture rather than of tuning.
    std::assert_eq!(super::MAX_BODY_BYTES, 65536);
    std::assert_eq!(super::TOTAL_TIMEOUT, std::time::Duration::from_secs(5));
    std::assert_eq!(super::CONNECT_TIMEOUT, std::time::Duration::from_secs(5));
  }
}
