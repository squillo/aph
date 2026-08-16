//! Mechanism dispatch for notary key discovery (spec §8.4.6).
//!
//! Spec §8.4 gives a verifier three ways to recover a notary's public key,
//! and §8.4.6 states the order they are preferred in — `did:key` offline,
//! then DNS TXT, then `did:web` over HTTPS — followed by the rule that makes
//! the order safe:
//!
//! > A verifier MUST NOT silently fall back from a stronger anchor to a
//! > weaker one mid-resolution; failures escalate to envelope rejection.
//!
//! **That rule is the whole design of this module.** The SELECTION is fixed
//! before any I/O happens, and failure is always the answer — what advances
//! the §8.4.6 sequence is ABSENCE, never failure. There is no `or_else` on
//! an error path, because a verifier that retries a weaker anchor when a
//! stronger one FAILS hands an attacker a free downgrade: break (or merely
//! block) the mechanism the notary actually anchors its identity to, and the
//! verifier volunteers to trust whatever is published under the one it can
//! reach. A mechanism that was never published offered nothing to break, so
//! advancing past it concedes nothing — that distinction is the whole §8.4.6
//! order.
//!
//! Which mechanism a DID *names* is [`DiscoveryMechanism::named_by`]: a
//! `did:key` DID names the offline decode, a `did:web` DID names its DID
//! Document. DNS TXT is never named by a DID — §8.4.5 anchors it to the
//! domain of a `did:web` identifier — but a `did:web` DID still reaches it:
//! [`resolve`]'s `DidWeb` arm probes DNS TXT FIRST per §8.4.6's order,
//! advancing to the document fetch only when nothing is published there
//! (absence), and rejecting outright when TXT is published-and-broken.
//! [`MechanismSelection::Pinned`] narrows to exactly one mechanism — §8.4.6's
//! "A verifier MAY pin a preferred mechanism per notary (typically via
//! configuration or via prior successful resolution)" — for the operator who
//! wants no sequence at all.
//!
//! Nothing here does I/O. The two ports in [`super::ports`] supply it, the
//! `did:key` path needs none, and every parsing rule is delegated:
//! [`crate::crypto::did_key`] decodes multicodec key material,
//! [`super::dns_txt`] parses and selects TXT records, and
//! [`super::did_document`] parses DID Documents. This module adds no second
//! decoder and — importantly — no `map_err`: each mechanism's failure
//! distinctions (`APH_E008` unreachable, `APH_E003` outside its validity
//! window, `APH_E010` unsupported, `APH_E014` not published) reach the caller
//! unflattened, because "the notary is down" and "the notary rotated last
//! week" have different next steps for an operator.

/// One of the three publication mechanisms of spec §8.4.2.
#[derive(std::fmt::Debug, std::clone::Clone, std::marker::Copy, std::cmp::PartialEq, std::cmp::Eq)]
pub enum DiscoveryMechanism {
  /// §8.4.3 — the key bytes are embedded in the DID itself; decoded
  /// in-process with no network access of any kind.
  DidKey,
  /// §8.4.5 — a DKIM-style tag-list in TXT records at
  /// `_aph._notary.<domain>`, anchored in DNS.
  DnsTxt,
  /// §8.4.4 — a DID Document fetched over TLS from the notary's web
  /// origin, anchored in the certificate chain that validated it.
  DidWeb,
}

impl DiscoveryMechanism {
  /// Returns the mechanism a DID URL itself names (spec §8.4.6 steps 1
  /// and 3).
  ///
  /// `did:key` names [`Self::DidKey`]; `did:web` names [`Self::DidWeb`].
  /// [`Self::DnsTxt`] is never returned by THIS function because no DID
  /// method spells it — but a `did:web` DID still reaches it: [`resolve`]'s
  /// `DidWeb` arm probes DNS TXT first per §8.4.6's order, advancing to the
  /// document fetch only on ABSENCE (nothing published) and never on
  /// FAILURE. [`MechanismSelection::Pinned`] narrows to one mechanism when
  /// an operator wants no sequence at all.
  ///
  /// # Errors
  ///
  /// `APH_E010` for any other DID method. APH v0.1 defines exactly two, and
  /// guessing a resolution strategy for a third would mean verifying against
  /// key material obtained by an unspecified route.
  pub fn named_by(did_url: &str) -> std::result::Result<Self, crate::errors::AphError> {
    let did = super::DidUrl::parse(did_url).did;
    if did.starts_with("did:key:") {
      return std::result::Result::Ok(Self::DidKey);
    }
    if did.starts_with("did:web:") {
      return std::result::Result::Ok(Self::DidWeb);
    }
    std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(std::format!(
      "DID method of `{}` is not an APH v0.1 key discovery mechanism (§8.4.2)",
      did
    )))
  }
}

/// How [`resolve`] picks the single mechanism it will use.
#[derive(std::fmt::Debug, std::clone::Clone, std::marker::Copy, std::cmp::PartialEq, std::cmp::Eq)]
pub enum MechanismSelection {
  /// Use whatever the DID names ([`DiscoveryMechanism::named_by`]). The
  /// default for a verifier with no configuration for this notary.
  NamedByDid,
  /// Use exactly this mechanism and no other — §8.4.6's per-notary pin.
  ///
  /// A pin is a narrowing, never a widening: pinning a mechanism the DID
  /// cannot support fails rather than quietly resolving by another route,
  /// so an operator learns their configuration is wrong instead of getting
  /// a key from somewhere they did not choose.
  Pinned(DiscoveryMechanism),
}

/// Resolves the notary public key that `did_url` names, through §8.4.6's
/// order for the selected mechanism — and a FAILURE in one mechanism never
/// reaches another (spec §8.4.6).
///
/// Both ports are taken because the `DidWeb` sequence and the pinned
/// selections route between them; the `did:key` path uses neither. The
/// `match` below is the no-downgrade guarantee: every error propagates with
/// `?` or is returned, so [`super::DiscoveryOutcome::Absent`] is the only
/// thing that advances.
///
/// `at_rfc3339` is the instant the key must be valid at. Per §8.4.7 a
/// verifier "accept[s] any envelope where the signing key was valid at the
/// envelope's `decisionTimestamp`", so callers pass THAT timestamp, not the
/// wall clock — otherwise every envelope signed before a rotation would
/// start failing the day the old key's `notAfter` passes. It is consulted
/// only by the DNS TXT mechanism, which is the only one publishing a
/// validity window in v0.1.
///
/// # Errors
///
/// Whatever the chosen mechanism returns, unmodified — see the module note
/// on preserving failure distinctions.
pub async fn resolve(
  selection: MechanismSelection,
  did_url: &str,
  lookup: &dyn super::ports::TxtRecordLookup,
  fetch: &dyn super::ports::DidDocumentFetch,
  at_rfc3339: &str,
) -> std::result::Result<super::NotaryPublicKey, crate::errors::AphError> {
  let mechanism = match selection {
    MechanismSelection::NamedByDid => DiscoveryMechanism::named_by(did_url)?,
    MechanismSelection::Pinned(pinned) => pinned,
  };
  match mechanism {
    DiscoveryMechanism::DidKey => resolve_did_key(did_url),
    DiscoveryMechanism::DnsTxt => resolve_dns_txt(did_url, lookup, at_rfc3339).await,
    // §8.4.6 orders the network mechanisms DNS TXT then did:web, and the
    // sequence below is NOT the downgrade that section forbids: the `?` is
    // what makes it safe. Only `DiscoveryOutcome::Absent` can reach the
    // second arm, because every failure has already left through the `?` —
    // so a broken TXT record can never advance to the web origin, and no
    // future edit can make it without deleting that `?`.
    //
    // Forged absence (an on-path attacker answering with an empty record
    // set) buys nothing: it advances the verifier to did:web, which is
    // anchored in a TLS certificate for the same domain — a bar DNS forgery
    // does not clear.
    DiscoveryMechanism::DidWeb => {
      match probe_dns_txt(did_url, lookup, at_rfc3339).await? {
        super::DiscoveryOutcome::Found(key) => std::result::Result::Ok(key),
        super::DiscoveryOutcome::Absent => resolve_did_web(did_url, fetch).await,
      }
    }
  }
}

/// Resolves a `did:key` DID URL offline (spec §8.4.3).
///
/// Synchronous and port-free by design: the key bytes ARE the identifier, so
/// this path is usable on an air-gapped verifier that has no adapters at all.
/// The multicodec decode is pure delegation to
/// [`crate::crypto::did_key::decode`] — the same decoder `did:web`'s
/// `publicKeyMultibase` goes through — because two decoders for one encoding
/// is two chances to disagree about what a key is.
///
/// The DID URL's fragment becomes the returned
/// [`super::NotaryPublicKey::kid`], and is stripped before decoding: a
/// `did:key` URL conventionally repeats its multibase suffix after the `#`,
/// and feeding that whole string to the decoder would fail.
///
/// # Errors
///
/// `APH_E001` if the identifier is not a decodable `did:key`, `APH_E010` if
/// it carries a multicodec APH does not define.
pub fn resolve_did_key(
  did_url: &str,
) -> std::result::Result<super::NotaryPublicKey, crate::errors::AphError> {
  let parsed = super::DidUrl::parse(did_url);
  // Decoded into a binding first so the borrow of `parsed.did` is plainly
  // over before the arms move `parsed.fragment` out.
  let decoded = crate::crypto::did_key::decode(&parsed.did)?;
  match decoded {
    crate::crypto::did_key::DecodedDidKey::Ed25519(key) => {
      std::result::Result::Ok(super::NotaryPublicKey {
        algorithm: super::KeyAlgorithm::Ed25519,
        key_bytes: key.as_bytes().to_vec(),
        kid: parsed.fragment,
      })
    }
    crate::crypto::did_key::DecodedDidKey::P256(bytes) => {
      std::result::Result::Ok(super::NotaryPublicKey {
        algorithm: super::KeyAlgorithm::P256,
        key_bytes: bytes,
        kid: parsed.fragment,
      })
    }
  }
}

/// Resolves through the DNS TXT mechanism (spec §8.4.5).
///
/// The queried name comes from [`super::DidUrl::dns_txt_name`] and is never
/// assembled here: that function strips any port number (a port belongs in
/// an HTTPS URL but never in a DNS name), percent-decodes in the one order
/// that keeps a `%3A`-written port attached to its host, and prefixes
/// `_aph._notary.` — a re-derivation gets at least one of those wrong, and
/// this crate has already paid for that bug once.
///
/// Every record the port returns is handed to
/// [`super::dns_txt::select_key`] untouched, so a malformed or unrelated TXT
/// record sitting beside a valid one does not deny the valid one. The DID
/// URL's fragment is passed through as the requested `kid`; note the
/// consequence, which is an operator footgun worth stating: if the proof
/// names a fragment, only a TXT record carrying a matching `kid` tag will be
/// accepted, because an unlabelled record is not a substitute for a named
/// key (§8.4.5 step 3b, and rotation would be ambiguous otherwise).
///
/// # Errors
///
/// `APH_E010` if the DID has no DNS anchor — notably a `did:key` DID, for
/// which §8.4.5 step 1 says "this discovery path is not applicable". It
/// fails rather than decoding the `did:key` offline: a caller that pinned
/// DNS TXT asked for DNS TXT, and quietly answering from a different
/// mechanism is the substitution this module exists to prevent.
/// Otherwise whatever the port or `select_key` returns: `APH_E014` when
/// nothing resolvable is published at the TXT name, `APH_E003` when a
/// matching key's `notBefore`/`notAfter` window excludes `at_rfc3339`,
/// `APH_E008` when the lookup itself failed.
pub async fn resolve_dns_txt(
  did_url: &str,
  lookup: &dyn super::ports::TxtRecordLookup,
  at_rfc3339: &str,
) -> std::result::Result<super::NotaryPublicKey, crate::errors::AphError> {
  let parsed = super::DidUrl::parse(did_url);
  let name = match parsed.dns_txt_name() {
    std::option::Option::Some(name) => name,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
        std::format!(
          "DNS TXT discovery is not applicable to `{}` (§8.4.5 step 1)",
          parsed.did
        ),
      ));
    }
  };
  match dns_txt_step(&name, parsed.fragment.as_deref(), lookup, at_rfc3339).await? {
    super::DiscoveryOutcome::Found(key) => std::result::Result::Ok(key),
    // Terminal absence: this mechanism was explicitly chosen (named or
    // pinned), so there is no later mechanism to advance to — but absence
    // is still not failure, and E014 is where the boundary says which one
    // happened. A caller holding E014 knows nothing is published here; a
    // caller holding E008 knows the lookup broke. §8.4.6's no-downgrade
    // rule is only writable downstream because these are different codes.
    super::DiscoveryOutcome::Absent => std::result::Result::Err(
      crate::errors::AphError::notary_key_not_published(std::format!(
        "DNS TXT `{}` (terminal: this mechanism was explicitly selected)",
        name
      )),
    ),
  }
}

/// The DNS TXT mechanism as one step: query the name, then select.
///
/// ONE translation point from the port's answer to the mechanism's, shared by
/// the terminal [`resolve_dns_txt`] and the non-terminal [`probe_dns_txt`],
/// because the two differ only in what they do with absence and a second copy
/// is how they would come to differ in more than that. The two ways of
/// publishing nothing collapse here: an adapter answering `Absent` and an
/// adapter answering `Found` with a record set holding no APH record are the
/// same fact, and `select_key` reports the second as absence too.
async fn dns_txt_step(
  name: &str,
  kid: std::option::Option<&str>,
  lookup: &dyn super::ports::TxtRecordLookup,
  at_rfc3339: &str,
) -> std::result::Result<super::DiscoveryOutcome<super::NotaryPublicKey>, crate::errors::AphError> {
  match lookup.lookup_txt(name).await? {
    super::DiscoveryOutcome::Found(records) => {
      super::dns_txt::select_key(&records, kid, at_rfc3339)
    }
    super::DiscoveryOutcome::Absent => {
      std::result::Result::Ok(super::DiscoveryOutcome::Absent)
    }
  }
}

/// The non-terminal DNS TXT probe the §8.4.6 ordered sequence uses, where
/// `Absent` lets the caller advance and an error must stop it.
async fn probe_dns_txt(
  did_url: &str,
  lookup: &dyn super::ports::TxtRecordLookup,
  at_rfc3339: &str,
) -> std::result::Result<super::DiscoveryOutcome<super::NotaryPublicKey>, crate::errors::AphError> {
  let parsed = super::DidUrl::parse(did_url);
  let name = match parsed.dns_txt_name() {
    std::option::Option::Some(name) => name,
    // A DID with no derivable TXT name does not offer the mechanism at all.
    std::option::Option::None => {
      return std::result::Result::Ok(super::DiscoveryOutcome::Absent);
    }
  };
  dns_txt_step(&name, parsed.fragment.as_deref(), lookup, at_rfc3339).await
}

/// Resolves through the `did:web` DID Document mechanism (spec §8.4.4).
///
/// The document URL comes from [`super::DidUrl::web_document_url`] and is
/// never assembled here, for the same reason the DNS name is not: colon-to-
/// path-segment mapping, the `/.well-known/` special case, and percent-decode
/// ordering are all already encoded there.
///
/// The fetched body goes to [`super::did_document::parse_did_document`] and
/// then to [`super::did_document::DidDocument::resolve_key`] with the FULL
/// DID URL, fragment included, so the document cannot answer with a key the
/// proof did not name.
///
/// Note what is deliberately NOT enforced: membership in the document's
/// `assertionMethod` list. The correct proof purpose depends on the proof's
/// position in an envelope's chain — §7.1.11 gives a principal proof
/// `assertionMethod` but a notary countersignature `authentication` — so a
/// key-discovery function cannot know which list to demand without seeing
/// the proof. A caller enforcing proof purpose must parse the document
/// itself and consult
/// [`super::did_document::DidDocument::allows_assertion`].
///
/// # Errors
///
/// `APH_E010` if the identifier yields no document URL (e.g. an empty host)
/// or the named key is published only as `publicKeyJwk`; `APH_E008` if the
/// port could not fetch or the body will not parse; `APH_E014` if the
/// document was fetched but publishes no key under the named fragment —
/// the document exists, this key is simply not published in it, and the
/// requester already knows the host is reachable so the code leaks nothing
/// a transport-opaque `APH_E008` was protecting.
pub async fn resolve_did_web(
  did_url: &str,
  fetch: &dyn super::ports::DidDocumentFetch,
) -> std::result::Result<super::NotaryPublicKey, crate::errors::AphError> {
  let parsed = super::DidUrl::parse(did_url);
  let url = match parsed.web_document_url() {
    std::option::Option::Some(url) => url,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::unsupported_algorithm(
        std::format!(
          "`{}` yields no did:web document URL (§8.4.4 step 2)",
          parsed.did
        ),
      ));
    }
  };
  let body = fetch.fetch_did_document(&url).await?;
  super::did_document::parse_did_document(&body)?.resolve_key(did_url)
}

#[cfg(test)]
mod tests {
  /// The Ed25519 key published in every spec §8.4 example.
  const SPEC_MULTIBASE: &str = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV";
  /// The single-key TXT record printed in spec §8.4.5.
  const SPEC_TXT: &str =
    "v=APHv1; alg=ed25519; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw";
  /// The DID Document printed in spec §8.4.4.
  const SPEC_DOC: &str = r#"{
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:web:notary.example.com",
    "verificationMethod": [
      {
        "id": "did:web:notary.example.com#k1",
        "type": "Multikey",
        "controller": "did:web:notary.example.com",
        "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"
      }
    ],
    "assertionMethod": ["did:web:notary.example.com#k1"]
  }"#;
  /// An instant inside the spec's rotation-example window.
  const NOW: &str = "2026-06-01T00:00:00Z";

  /// Drives a future to completion on the calling thread.
  ///
  /// The poller itself now lives in
  /// [`crate::discovery::test_support::block_on`], because the §6.3.3 status
  /// arm needs the same twelve lines and two hand-written wakers in one
  /// crate is two sets of soundness assumptions. This local name is kept so
  /// the fifteen call sites below stay about §8.4.6 rather than about test
  /// scaffolding.
  fn block_on<F: std::future::Future>(future: F) -> F::Output {
    crate::discovery::test_support::block_on(future)
  }

  /// A DNS port with a canned answer that records the names it was asked for.
  ///
  /// The recorded names are what let a test assert a mechanism was NOT
  /// consulted, which is the only observable form of "did not downgrade".
  ///
  /// The canned answer is the port's whole return type rather than a bare
  /// record list, so a test can distinguish the three cases the §8.4.6 rule
  /// turns on — published, definitively-not-published, and the lookup broke —
  /// instead of spelling two of them with the same empty `Vec`.
  struct FakeTxt {
    answer: std::result::Result<
      crate::discovery::DiscoveryOutcome<std::vec::Vec<String>>,
      crate::errors::AphError,
    >,
    asked: std::sync::Mutex<std::vec::Vec<String>>,
  }

  impl FakeTxt {
    fn with(records: &[&str]) -> Self {
      Self::answering(std::result::Result::Ok(
        crate::discovery::DiscoveryOutcome::Found(
          records.iter().map(|r| String::from(*r)).collect(),
        ),
      ))
    }

    /// The name answered, and nothing is published there.
    fn absent() -> Self {
      Self::answering(std::result::Result::Ok(
        crate::discovery::DiscoveryOutcome::Absent,
      ))
    }

    fn failing(error: crate::errors::AphError) -> Self {
      Self::answering(std::result::Result::Err(error))
    }

    fn answering(
      answer: std::result::Result<
        crate::discovery::DiscoveryOutcome<std::vec::Vec<String>>,
        crate::errors::AphError,
      >,
    ) -> Self {
      Self {
        answer,
        asked: std::sync::Mutex::new(std::vec::Vec::new()),
      }
    }

    fn asked(&self) -> std::vec::Vec<String> {
      self.asked.lock().expect("test mutex poisoned").clone()
    }
  }

  impl crate::discovery::ports::TxtRecordLookup for FakeTxt {
    fn lookup_txt<'a>(
      &'a self,
      name: &'a str,
    ) -> crate::discovery::ports::DiscoveryFuture<
      'a,
      crate::discovery::DiscoveryOutcome<std::vec::Vec<String>>,
    > {
      std::boxed::Box::pin(async move {
        self
          .asked
          .lock()
          .expect("test mutex poisoned")
          .push(String::from(name));
        self.answer.clone()
      })
    }
  }

  /// A `did:web` port with a canned body that records the URLs it was given.
  struct FakeFetch {
    body: String,
    error: std::option::Option<crate::errors::AphError>,
    asked: std::sync::Mutex<std::vec::Vec<String>>,
  }

  impl FakeFetch {
    fn with(body: &str) -> Self {
      Self {
        body: String::from(body),
        error: None,
        asked: std::sync::Mutex::new(std::vec::Vec::new()),
      }
    }

    fn failing(error: crate::errors::AphError) -> Self {
      Self {
        body: String::new(),
        error: Some(error),
        asked: std::sync::Mutex::new(std::vec::Vec::new()),
      }
    }

    fn asked(&self) -> std::vec::Vec<String> {
      self.asked.lock().expect("test mutex poisoned").clone()
    }
  }

  impl crate::discovery::ports::DidDocumentFetch for FakeFetch {
    fn fetch_did_document<'a>(
      &'a self,
      url: &'a str,
    ) -> crate::discovery::ports::DiscoveryFuture<'a, String> {
      std::boxed::Box::pin(async move {
        self
          .asked
          .lock()
          .expect("test mutex poisoned")
          .push(String::from(url));
        let out: std::result::Result<String, crate::errors::AphError> = match &self.error {
          Some(error) => Err(error.clone()),
          None => Ok(self.body.clone()),
        };
        out
      })
    }
  }

  /// A port pair that panics on contact.
  ///
  /// Counting calls proves a port was not used *in this run*; panicking
  /// proves it cannot be used at all on the path under test, which is the
  /// stronger statement wanted for the offline `did:key` mechanism.
  struct Exploding;

  impl crate::discovery::ports::TxtRecordLookup for Exploding {
    fn lookup_txt<'a>(
      &'a self,
      _name: &'a str,
    ) -> crate::discovery::ports::DiscoveryFuture<
      'a,
      crate::discovery::DiscoveryOutcome<std::vec::Vec<String>>,
    > {
      std::panic!("did:key resolution must perform no DNS lookup");
    }
  }

  impl crate::discovery::ports::DidDocumentFetch for Exploding {
    fn fetch_did_document<'a>(
      &'a self,
      _url: &'a str,
    ) -> crate::discovery::ports::DiscoveryFuture<'a, String> {
      std::panic!("this path must perform no HTTPS fetch");
    }
  }

  #[test]
  fn did_key_resolves_with_both_ports_wired_to_explode() {
    // §8.4.3's entire value is that verification works offline — on an
    // air-gapped recipient, or when the notary's origin and DNS are both
    // unreachable. A port that panics on contact is the only way to PROVE
    // zero I/O rather than merely observe none: if a future refactor made
    // the did:key path "confirm" the key against DNS or the DID Document,
    // this test aborts instead of silently becoming a network dependency.
    let did = std::format!("did:key:{}#{}", SPEC_MULTIBASE, SPEC_MULTIBASE);
    let key = block_on(super::resolve(
      super::MechanismSelection::NamedByDid,
      &did,
      &Exploding,
      &Exploding,
      NOW,
    ))
    .unwrap();
    std::assert_eq!(key.algorithm, crate::discovery::KeyAlgorithm::Ed25519);
  }

  #[test]
  fn did_key_fragment_becomes_the_kid() {
    // A did:key URL repeats its multibase suffix after the '#'. The fragment
    // must survive as the kid (callers match it against
    // proof.verificationMethod) AND must be stripped before decoding — pass
    // the whole URL to the multicodec decoder and it fails.
    let did = std::format!("did:key:{}#{}", SPEC_MULTIBASE, SPEC_MULTIBASE);
    let key = super::resolve_did_key(&did).unwrap();
    std::assert_eq!(key.kid.as_deref(), Some(SPEC_MULTIBASE));
  }

  #[test]
  fn dns_txt_returns_the_valid_key_beside_a_malformed_one() {
    // A notary's domain holds TXT records this protocol knows nothing about
    // (SPF, site verification) and, mid-rotation, records that are simply
    // wrong. If one bad neighbour denied the valid key, a single typo in DNS
    // would take a notary offline for every verifier. The port therefore
    // hands back EVERY record and selection does the filtering.
    let lookup = FakeTxt::with(&["v=spf1 include:example.com ~all", "garbage", SPEC_TXT]);
    let key = block_on(super::resolve(
      super::MechanismSelection::Pinned(super::DiscoveryMechanism::DnsTxt),
      "did:web:notary.example.com",
      &lookup,
      &Exploding,
      NOW,
    ))
    .unwrap();
    std::assert_eq!(key.key_bytes.len(), 32);
  }

  #[test]
  fn the_queried_dns_name_comes_from_did_url_not_from_string_building() {
    // DidUrl::dns_txt_name strips any port number, percent-decodes in the one
    // order that keeps a %3A-written port attached to its host, prefixes
    // _aph._notary., and — as here — ignores the DID's path segments.
    // Re-deriving the name instead of calling it gets at least one of those
    // wrong; pinning the exact queried name is what stops that recurring.
    let lookup = FakeTxt::with(&[SPEC_TXT]);
    let _ = block_on(super::resolve_dns_txt(
      "did:web:example.com:notaries:alice",
      &lookup,
      NOW,
    ));
    std::assert_eq!(lookup.asked(), std::vec![String::from("_aph._notary.example.com")]);
  }

  #[test]
  fn did_web_resolves_through_the_fetch_port() {
    // The §8.4.4 path end to end: probe DNS TXT first per §8.4.6's order,
    // find NOTHING PUBLISHED (absence — the one outcome that may advance),
    // then derive the well-known URL, fetch through the port, parse, and
    // return the key the proof's fragment names. Asserting the kid pins
    // that the document answered for k1 rather than whatever it listed
    // first; the absent TXT fake pins that advancing required absence, not
    // an ignored error.
    let lookup = FakeTxt::absent();
    let fetch = FakeFetch::with(SPEC_DOC);
    let key = block_on(super::resolve(
      super::MechanismSelection::NamedByDid,
      "did:web:notary.example.com#k1",
      &lookup,
      &fetch,
      NOW,
    ))
    .unwrap();
    std::assert_eq!(key.kid.as_deref(), Some("k1"));
  }

  #[test]
  fn the_fetched_url_comes_from_did_url_not_from_string_building() {
    // Same reason as the DNS name: web_document_url encodes the colon-to-
    // path-segment mapping and the /.well-known special case. A composer
    // that rebuilt the URL would fetch the wrong document for any pathful
    // did:web — and a wrong document that happens to parse yields a wrong
    // key, not an error.
    let fetch = FakeFetch::with(SPEC_DOC);
    let _ = block_on(super::resolve_did_web("did:web:example.com:notaries:alice#k1", &fetch));
    std::assert_eq!(
      fetch.asked(),
      std::vec![String::from("https://example.com/notaries/alice/did.json")]
    );
  }

  #[test]
  fn a_broken_txt_record_never_advances_to_did_web() {
    // THE no-downgrade test, in the direction §8.4.6 makes sharp: DNS TXT
    // is PUBLISHED AND BROKEN (a key exists, its window has closed), and a
    // perfectly good did:web document sits one step further down the
    // chain. A composer that advanced would succeed here and look correct.
    // That success is the attack: whoever can expire or corrupt the TXT
    // record — the preferred anchor — gets to choose that the verifier
    // trusts the next one instead, and choosing the anchor is an identity
    // decision. The two assertions are one claim: the TXT failure was
    // reported AS the outcome, and the web port was never consulted.
    let expired = "v=APHv1; alg=ed25519; kid=k1; \
                   k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw; \
                   notAfter=2026-01-01T00:00:00Z";
    let lookup = FakeTxt::with(&[expired]);
    let fetch = FakeFetch::with(SPEC_DOC);
    let error = block_on(super::resolve(
      super::MechanismSelection::NamedByDid,
      "did:web:notary.example.com#k1",
      &lookup,
      &fetch,
      NOW,
    ))
    .unwrap_err();
    std::assert_eq!(error.code(), "APH_E003");
    std::assert!(
      fetch.asked().is_empty(),
      "did:web was consulted after a TXT failure: {:?}",
      fetch.asked()
    );
  }

  #[test]
  fn a_published_txt_key_preempts_the_did_web_fetch() {
    // The complementary pin: when TXT publishes a valid key, §8.4.6's
    // order means it IS the answer and the fetch never happens. This is
    // the resilience §8.4.6 ranks TXT above HTTPS for — an origin outage
    // does not take out verification for a notary that publishes both.
    // The record carries kid=k1 because the probe selects by the proof's
    // fragment; an unlabelled record beside a kid-bearing proof is ABSENCE
    // (see dns_txt::select_key), which would advance instead of preempting.
    let labelled =
      "v=APHv1; alg=ed25519; kid=k1; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw";
    let lookup = FakeTxt::with(&[labelled]);
    let fetch = FakeFetch::failing(crate::errors::AphError::NotaryServiceUnreachable);
    let key = block_on(super::resolve(
      super::MechanismSelection::NamedByDid,
      "did:web:notary.example.com#k1",
      &lookup,
      &fetch,
      NOW,
    ))
    .unwrap();
    std::assert_eq!(key.kid.as_deref(), Some("k1"));
    std::assert!(fetch.asked().is_empty(), "fetch ran despite a valid TXT key");
  }

  #[test]
  fn a_failed_dns_lookup_never_falls_back_to_did_web() {
    // The downgrade guard has to hold in BOTH directions. A verifier that
    // pinned DNS TXT for this notary (§8.4.6 per-notary pin) has decided the
    // DNS anchor is the one it trusts; reaching for the DID Document when
    // DNS fails would silently overrule that decision, and the operator who
    // set the pin would never know it stopped being honoured.
    let lookup = FakeTxt::failing(crate::errors::AphError::NotaryServiceUnreachable);
    let fetch = FakeFetch::with(SPEC_DOC);
    let error = block_on(super::resolve(
      super::MechanismSelection::Pinned(super::DiscoveryMechanism::DnsTxt),
      "did:web:notary.example.com#k1",
      &lookup,
      &fetch,
      NOW,
    ))
    .unwrap_err();
    std::assert_eq!(error.code(), "APH_E008");
    std::assert!(fetch.asked().is_empty(), "HTTPS was consulted: {:?}", fetch.asked());
  }

  #[test]
  fn pinning_dns_txt_on_a_did_key_refuses_rather_than_decoding_offline() {
    // §8.4.5 step 1: for did:key "this discovery path is not applicable".
    // The tempting shortcut — notice the DID is a did:key and just decode it
    // — is mechanism substitution: the caller asked for the DNS anchor and
    // would be handed a key from the self-describing identifier instead,
    // which is precisely the anchor a pin was set to avoid relying on.
    let did = std::format!("did:key:{}", SPEC_MULTIBASE);
    let error = block_on(super::resolve_dns_txt(&did, &Exploding, NOW)).unwrap_err();
    std::assert_eq!(error.code(), "APH_E010");
  }

  #[test]
  fn dns_txt_is_never_the_mechanism_a_did_names() {
    // If `named_by` returned DnsTxt for a did:web DID, DNS would become an
    // implicit extra attempt on the default path for every did:web notary,
    // and `resolve`'s single-mechanism guarantee would be worthless. DNS TXT
    // is reachable only through an explicit pin.
    std::assert_eq!(
      super::DiscoveryMechanism::named_by("did:web:notary.example.com#k1").unwrap(),
      super::DiscoveryMechanism::DidWeb
    );
    std::assert_eq!(
      super::DiscoveryMechanism::named_by(&std::format!("did:key:{}", SPEC_MULTIBASE)).unwrap(),
      super::DiscoveryMechanism::DidKey
    );
  }

  #[test]
  fn failure_classes_do_not_collapse_into_one_code() {
    // A verifier's error is what an operator acts on, and
    // these four demand four different actions — restore the service, wait
    // for or re-issue against the rotated key, publish a supported key form,
    // fix the DID method. A composer that map_err'd everything to one code
    // (an easy accident when threading errors through three mechanisms)
    // would leave every one of those questions unanswerable.
    let expired = "v=APHv1; alg=ed25519; k=2Vc3Hpcg1XOoxCBT0qZQYR8WlAlBpvW0nVwRyJI5Ouw; \
                   notAfter=2026-01-01T00:00:00Z";

    // APH_E010 — the DID method is not one APH v0.1 can resolve.
    std::assert_eq!(
      block_on(super::resolve(
        super::MechanismSelection::NamedByDid,
        "did:example:notary",
        &Exploding,
        &Exploding,
        NOW,
      ))
      .unwrap_err()
      .code(),
      "APH_E010"
    );

    // APH_E014 — a PIN is a narrowing (there is no later mechanism), so
    // absence at a pinned mechanism is terminal — but terminal absence is
    // still absence, and since E014 joined the taxonomy the code says so.
    // Pinning E014 (not E008) here is the point of the widening: a caller
    // can now tell "nothing is published" from "the lookup broke" without
    // parsing a message string.
    std::assert_eq!(
      block_on(super::resolve(
        super::MechanismSelection::Pinned(super::DiscoveryMechanism::DnsTxt),
        "did:web:notary.example.com",
        &FakeTxt::absent(),
        &Exploding,
        NOW,
      ))
      .unwrap_err()
      .code(),
      "APH_E014"
    );

    // APH_E003 — the key was found, but not valid at this instant.
    std::assert_eq!(
      block_on(super::resolve(
        super::MechanismSelection::Pinned(super::DiscoveryMechanism::DnsTxt),
        "did:web:notary.example.com",
        &FakeTxt::with(&[expired]),
        &Exploding,
        NOW,
      ))
      .unwrap_err()
      .code(),
      "APH_E003"
    );

    // APH_E014 — the anchor answered, but publishes no such key. The TXT
    // probe that precedes the fetch sees absence (nothing published) and
    // advances, per §8.4.6 — hence an absent fake here rather than the
    // exploding one used on the did:key row. The fetched document exists
    // and simply lacks `#k9`, which is "not published" (E014), not "the
    // envelope's signature is invalid" (the E001 this arm reported before
    // the taxonomy had a word for absence).
    std::assert_eq!(
      block_on(super::resolve(
        super::MechanismSelection::NamedByDid,
        "did:web:notary.example.com#k9",
        &FakeTxt::absent(),
        &FakeFetch::with(SPEC_DOC),
        NOW,
      ))
      .unwrap_err()
      .code(),
      "APH_E014"
    );
  }

  #[test]
  fn the_txt_ports_three_answers_advance_advance_and_refuse() {
    // The absence/failure rule now lives in a TYPE, so this pins that the
    // type is wired to the behaviour it names — all three answers the DNS
    // port can give, side by side, in one place. It also proves the change
    // that introduced the type moved NOTHING: before it, absence was spelled
    // `Ok(vec![])`, and an adapter that still answers with an empty record
    // set (row 2) must behave exactly as one that answers `Absent` (row 1).
    // A future edit that made either row refuse, or made row 3 advance, is
    // the downgrade §8.4.6 forbids and fails here.
    //
    //   Ok(Absent)      nothing published at the name  -> advance to did:web
    //   Ok(Found(&[]))  the same fact, spelled by an   -> advance to did:web
    //                   adapter that returns records
    //   Err(APH_E008)   the lookup never answered      -> REFUSE, and the
    //                                                     web port is never
    //                                                     consulted
    for lookup in [FakeTxt::absent(), FakeTxt::with(&[])] {
      let fetch = FakeFetch::with(SPEC_DOC);
      let key = block_on(super::resolve(
        super::MechanismSelection::NamedByDid,
        "did:web:notary.example.com#k1",
        &lookup,
        &fetch,
        NOW,
      ))
      .unwrap();
      std::assert_eq!(key.kid.as_deref(), Some("k1"));
      std::assert_eq!(fetch.asked().len(), 1, "absence did not advance to did:web");
    }

    let failing = FakeTxt::failing(crate::errors::AphError::NotaryServiceUnreachable);
    let fetch = FakeFetch::with(SPEC_DOC);
    let error = block_on(super::resolve(
      super::MechanismSelection::NamedByDid,
      "did:web:notary.example.com#k1",
      &failing,
      &fetch,
      NOW,
    ))
    .unwrap_err();
    std::assert_eq!(error.code(), "APH_E008");
    std::assert!(
      fetch.asked().is_empty(),
      "a failed lookup advanced to did:web: {:?}",
      fetch.asked()
    );
  }

  #[test]
  fn an_unparseable_did_document_is_unreachable_not_a_bad_signature() {
    // From a verifier's seat "the origin served junk" and "the origin was
    // down" are the same outcome — no key was obtained — and neither is
    // evidence about the envelope's signature. Reporting APH_E001 here would
    // accuse the notary of forging a proof it never got the chance to prove.
    let fetch = FakeFetch::with("{not json");
    let error = block_on(super::resolve_did_web("did:web:notary.example.com#k1", &fetch))
      .unwrap_err();
    std::assert_eq!(error.code(), "APH_E008");
  }

  #[test]
  fn a_did_web_with_no_host_yields_no_fetch_at_all() {
    // `did:web:` has no origin to trust, so there is nothing to request. The
    // guard belongs before the port call: without it the composer would ask
    // an adapter to fetch a URL built from an empty host, turning a
    // malformed DID into an outbound request an attacker chose the shape of.
    let fetch = FakeFetch::with(SPEC_DOC);
    let error = block_on(super::resolve_did_web("did:web:", &fetch)).unwrap_err();
    std::assert_eq!(error.code(), "APH_E010");
    std::assert!(fetch.asked().is_empty());
  }
}
