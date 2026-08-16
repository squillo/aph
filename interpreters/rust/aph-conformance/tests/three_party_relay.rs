//! THREE PARTIES: Alice → Bob → Carol, with Bob on both sides of the seam.
//!
//! ⛔ WHAT CROSSES WHICH BOUNDARY, and what does not.
//!
//! Two boundaries, and they are separate. Across the first, Alice's envelope
//! bytes reach Bob and Alice's published key and status list reach Bob's
//! resolver. Across the second, an envelope BOB minted under BOB's own
//! authority reaches Carol, together with Bob's published key and status list.
//!
//! Nothing crosses BOTH. Bob's outbound is not a re-presentation of Alice's
//! inbound — it is his own principal's signature over his own notary's
//! envelope — and Carol never resolves anything of Alice's in order to reach a
//! verdict about Bob.
//!
//! # Why a two-party test cannot reach this
//!
//! Two claims only appear once a verifier is also an issuer:
//!
//! 1. **A verifier's own identity does not leak into what it admits.** Bob
//!    holds a notary key, publishes a discovery surface and runs a status list.
//!    None of that may touch his verdict about Alice — provable only by
//!    comparing the verdict he reaches with those facts present against the one
//!    he reaches without them.
//! 2. **Carol's decision about Bob is independent of Bob's decision about
//!    Alice.** Each direction is tested: Bob refusing Alice must not cost Bob
//!    his standing with Carol, and Bob admitting Alice must not buy him any.
//!
//! A third property falls out of the relay and is worth pinning on its own:
//! forwarding a credential does not LAUNDER it. Bob can hand Alice's bytes
//! straight to Carol, and Carol will admit them — correctly, because a valid
//! credential is valid to whoever holds it — but what she admits is a statement
//! about ALICE. Nothing in it becomes a statement about Bob.

mod multi_party;

/// Alice's mandate window in the independence scenario: opened and CLOSED
/// before the instant both hops are evaluated at, so Bob's refusal of Alice is
/// a plain expiry (§8.3 step 6) and not a side effect of anything else.
const LAPSED_MANDATE_FROM: &str = "2026-05-19T00:00:00Z";
/// Upper bound of that window — a day before [`multi_party::VERIFIED_AT`].
const LAPSED_MANDATE_UNTIL: &str = "2026-05-20T00:00:00Z";
/// The envelope's own window, inside the lapsed mandate's as §8.3.1 step 1d
/// requires.
const LAPSED_ENVELOPE_FROM: &str = "2026-05-19T12:00:00Z";
/// `decisionTimestamp` for that envelope: the notary decided while the mandate
/// was still live, which is what makes this a lapse rather than a forgery.
const LAPSED_DECISION: &str = "2026-05-19T12:00:00Z";
/// `created` of the lapsed envelope's principal proof (§7.2.1 order).
const LAPSED_PRINCIPAL_CREATED: &str = "2026-05-19T12:00:01Z";
/// `created` of the lapsed envelope's countersignature (§7.2.1 order).
const LAPSED_NOTARY_CREATED: &str = "2026-05-19T12:00:02Z";

/// A wire carrying both hops' publications: each notary's `did:web` document
/// and a fresh status list in which nothing is revoked.
fn relay_wire() -> multi_party::Wire {
  let mut wire = multi_party::Wire::new();
  for party in [multi_party::alice(), multi_party::bob()] {
    party.publish_did_document(&mut wire);
    party.publish_status_list(&mut wire, &[], multi_party::STATUS_ISSUED_AT);
  }
  wire
}

/// Everything `resolver` touched that belongs to `party` — the evidence for a
/// claim about what a verifier did, or did not, need to know.
fn asked_about(
  resolver: &multi_party::Resolver<'_>,
  party: &multi_party::Party,
) -> std::vec::Vec<String> {
  let host = std::format!("{}.example", party.label);
  resolver
    .everything_asked()
    .into_iter()
    .filter(|asked| asked.contains(host.as_str()))
    .collect()
}

#[test]
fn each_hop_admits_and_neither_verifier_looks_at_the_other_hop() {
  // ACROSS BOUNDARY 1: Alice's envelope bytes and her published surfaces.
  // ACROSS BOUNDARY 2: Bob's OWN envelope bytes and his published surfaces.
  // NOT CROSSING EITHER: keys, structs, stores, and — asserted below — any
  // knowledge of the other hop.
  //
  // The relay, end to end, and the positive control for this file. Both hops
  // admit; then the ask-lists say something a verdict alone cannot: Bob
  // resolved only Alice's surfaces and Carol resolved only Bob's. Carol never
  // even learns Alice exists — which is the concrete form of "Carol's decision
  // about Bob is independent of Bob's decision about Alice", stated at the I/O
  // layer where it cannot be faked by a lucky comparison.
  let alice = multi_party::alice();
  let bob = multi_party::bob();
  let carol = multi_party::carol();
  let wire = relay_wire();
  let bob_resolver = wire.resolver();
  let carol_resolver = wire.resolver();

  let alice_to_bob = alice.mint(&alice.draft());
  let received_by_bob =
    multi_party::receive(&alice_to_bob).expect("Bob's strict parse (§8.3 step 1)");
  let bobs_verdict =
    multi_party::verify_inbound(&bob_resolver, &received_by_bob, multi_party::VERIFIED_AT)
      .expect("Bob admits Alice");
  std::assert_eq!(bobs_verdict.human_principal, alice.principal_did());

  // Bob now acts. This is HIS authority, minted by HIS notary — not Alice's
  // credential passed along.
  let bob_to_carol = bob.mint(&bob.draft());
  let received_by_carol =
    multi_party::receive(&bob_to_carol).expect("Carol's strict parse (§8.3 step 1)");
  let carols_verdict =
    multi_party::verify_inbound(&carol_resolver, &received_by_carol, multi_party::VERIFIED_AT)
      .expect("Carol admits Bob");
  std::assert_eq!(carols_verdict.human_principal, bob.principal_did());
  std::assert_eq!(carols_verdict.notary, bob.notary_did);

  std::assert!(
    asked_about(&bob_resolver, &bob).is_empty(),
    "Bob consulted his OWN surfaces while verifying Alice: {:?}",
    asked_about(&bob_resolver, &bob)
  );
  std::assert!(
    asked_about(&carol_resolver, &alice).is_empty(),
    "Carol consulted Alice's surfaces while verifying Bob: {:?}",
    asked_about(&carol_resolver, &alice)
  );
  std::assert!(
    asked_about(&carol_resolver, &carol).is_empty(),
    "Carol consulted her OWN surfaces while verifying Bob: {:?}",
    asked_about(&carol_resolver, &carol)
  );
  std::assert_eq!(
    asked_about(&carol_resolver, &bob).len(),
    3,
    "Carol reads exactly Bob's DNS anchor, his DID Document and his status list"
  );
}

#[test]
fn a_verifiers_own_identity_never_enters_what_it_admits() {
  // ACROSS THE WIRE: one envelope from Alice, verified twice — once on a wire
  // carrying Bob's own publications and once on a wire where Bob does not
  // exist. NOT SHARED, and the subject of the test: anything of Bob's may reach
  // Bob's verdict about Alice.
  //
  // Bob is not a neutral observer: he holds a notary key, publishes a discovery
  // surface, and runs a revocation list. A verifier implementation that let any
  // of that reach its verdict would be a verifier whose answers depend on who
  // is asking — and the failure would be invisible in a two-party suite, where
  // the verifier has no identity to leak.
  //
  // Two statements, and both are needed. FIRST, Bob's own key is not a key that
  // admits Alice: verifying her countersignature under it fails with APH_E001.
  // SECOND — the stronger one — Bob's verdict about Alice is byte-identical on
  // a wire where Bob has published nothing at all, and on that wire he still
  // never reaches for anything of his own.
  let alice = multi_party::alice();
  let bob = multi_party::bob();

  let alice_to_bob = alice.mint(&alice.draft());
  let received = multi_party::receive(&alice_to_bob).expect("Bob's strict parse");

  let full_wire = relay_wire();
  let bob_as_publisher = full_wire.resolver();
  let with_own_surfaces =
    multi_party::verify_inbound(&bob_as_publisher, &received, multi_party::VERIFIED_AT)
      .expect("Bob admits Alice");

  // The same envelope, verified from a wire on which Bob does not exist.
  let mut alice_only = multi_party::Wire::new();
  alice.publish_did_document(&mut alice_only);
  alice.publish_status_list(&mut alice_only, &[], multi_party::STATUS_ISSUED_AT);
  let bob_as_nobody = alice_only.resolver();
  let without_own_surfaces =
    multi_party::verify_inbound(&bob_as_nobody, &received, multi_party::VERIFIED_AT)
      .expect("Bob's verdict cannot depend on Bob being published");

  std::assert_eq!(
    with_own_surfaces, without_own_surfaces,
    "Bob reached a different verdict about Alice depending on facts about Bob"
  );
  std::assert!(
    asked_about(&bob_as_publisher, &bob).is_empty(),
    "Bob's own surfaces were consulted while verifying Alice: {:?}",
    asked_about(&bob_as_publisher, &bob)
  );

  // Stated at BOTH hops, so the claim holds for every verifier in the relay
  // rather than for the one that happened to be tested.
  let carol = multi_party::carol();
  let bobs_own_key = bob.notary_key().verifying_key();
  std::assert_eq!(
    aph_core::verify_proof(&received, aph_core::ProofRole::Notary, &bobs_own_key)
      .expect_err("Bob's own key never signed Alice's envelope")
      .code(),
    "APH_E001"
  );

  let bobs_outbound =
    multi_party::receive(&bob.mint(&bob.draft())).expect("Carol's strict parse");
  let carols_own_key = carol.notary_key().verifying_key();
  std::assert_eq!(
    aph_core::verify_proof(&bobs_outbound, aph_core::ProofRole::Notary, &carols_own_key)
      .expect_err("Carol's own key never signed Bob's envelope")
      .code(),
    "APH_E001"
  );
}

#[test]
fn carols_verdict_on_bob_is_independent_of_bobs_verdict_on_alice() {
  // ACROSS BOUNDARY 1: an envelope of Alice's whose mandate has lapsed.
  // ACROSS BOUNDARY 2: an envelope of Bob's, unrelated to it. NOT CROSSING:
  // Bob's VERDICT about Alice — it is a value in Bob's process and reaches
  // Carol by no route at all, which is what makes the two decisions separable.
  //
  // The independence claim, tested in BOTH directions, because either one alone
  // is a coincidence.
  //
  // Direction 1 — Bob REFUSES Alice (her mandate lapsed a day before the
  // instant both hops evaluate at) and Carol still admits Bob. Authority does
  // not flow along the relay: Bob's standing with Carol rests on Bob's own
  // principal and Bob's own notary, so nothing that happens upstream can
  // withdraw it.
  //
  // Direction 2 — Bob ADMITS Alice and Carol still REFUSES Bob, because Bob's
  // own notary has revoked Bob's mandate. A good inbound buys the middle hop
  // nothing at all.
  let alice = multi_party::alice();
  let bob = multi_party::bob();
  let wire = relay_wire();

  let mut lapsed = alice.draft();
  lapsed.mandate_valid_from = String::from(LAPSED_MANDATE_FROM);
  lapsed.mandate_valid_until = String::from(LAPSED_MANDATE_UNTIL);
  lapsed.valid_from = String::from(LAPSED_ENVELOPE_FROM);
  lapsed.valid_until = String::from(LAPSED_MANDATE_UNTIL);
  lapsed.decision_timestamp = String::from(LAPSED_DECISION);
  lapsed.principal_created = String::from(LAPSED_PRINCIPAL_CREATED);
  lapsed.notary_created = String::from(LAPSED_NOTARY_CREATED);

  let bob_resolver = wire.resolver();
  let received_by_bob = multi_party::receive(&alice.mint(&lapsed)).expect("Bob's strict parse");
  std::assert_eq!(
    multi_party::verify_inbound(&bob_resolver, &received_by_bob, multi_party::VERIFIED_AT)
      .expect_err("a lapsed mandate must refuse")
      .code(),
    "APH_E003"
  );

  let carol_resolver = wire.resolver();
  let received_by_carol = multi_party::receive(&bob.mint(&bob.draft())).expect("Carol's parse");
  let carols_verdict =
    multi_party::verify_inbound(&carol_resolver, &received_by_carol, multi_party::VERIFIED_AT)
      .expect("what Bob refused upstream is not evidence about Bob");
  std::assert_eq!(carols_verdict.human_principal, bob.principal_did());

  // Direction 2. A second wire, on which Bob's own notary has withdrawn Bob's
  // mandate while Alice's remains perfectly good.
  let mut wire_with_bob_revoked = multi_party::Wire::new();
  alice.publish_did_document(&mut wire_with_bob_revoked);
  alice.publish_status_list(&mut wire_with_bob_revoked, &[], multi_party::STATUS_ISSUED_AT);
  bob.publish_did_document(&mut wire_with_bob_revoked);
  bob.publish_status_list(
    &mut wire_with_bob_revoked,
    &[bob.status_index],
    multi_party::STATUS_ISSUED_AT,
  );

  let bob_resolver = wire_with_bob_revoked.resolver();
  let good_from_alice =
    multi_party::receive(&alice.mint(&alice.draft())).expect("Bob's strict parse");
  multi_party::verify_inbound(&bob_resolver, &good_from_alice, multi_party::VERIFIED_AT)
    .expect("Bob's own revocation says nothing about Alice");

  let carol_resolver = wire_with_bob_revoked.resolver();
  std::assert_eq!(
    multi_party::verify_inbound(&carol_resolver, &received_by_carol, multi_party::VERIFIED_AT)
      .expect_err("Bob's mandate was withdrawn by Bob's own notary")
      .code(),
    "APH_E015"
  );
}

#[test]
fn forwarding_a_credential_does_not_launder_it_into_the_forwarders_own() {
  // ACROSS THE WIRE: Alice's envelope bytes, unchanged, reaching Carol via Bob.
  // NOT CROSSING: anything of Bob's whatsoever — no key, no signature, no
  // publication — which is precisely why the credential Carol admits stays
  // Alice's.
  //
  // The relay's quietest property, and the one an implementer is most likely to
  // get wrong. Bob holds Alice's bytes and can obviously forward them; Carol
  // will ADMIT them, and that is correct — a verifiable credential is verifiable
  // by whoever holds it, which is the whole reason it needs no prior
  // relationship.
  //
  // What must NOT happen is that forwarding converts the claim. Everything
  // Carol admits names Alice: her human principal, her agent, her notary. Bob
  // appears nowhere in it, and Carol resolves Alice's key to reach that verdict
  // rather than Bob's — so a recipient that treated "my peer relayed this" as
  // "my peer vouched for this" would be reading a statement that was never
  // made.
  let alice = multi_party::alice();
  let bob = multi_party::bob();
  let wire = relay_wire();
  let carol_resolver = wire.resolver();

  // Bob relays verbatim: he has no way to alter a byte and keep it verifiable —
  // `two_party_exchange.rs` pins exactly that — so forwarding is literally
  // passing the same string along.
  let relayed_by_bob = alice.mint(&alice.draft());
  let received = multi_party::receive(&relayed_by_bob).expect("Carol's strict parse");

  let verdict =
    multi_party::verify_inbound(&carol_resolver, &received, multi_party::VERIFIED_AT)
      .expect("a valid credential is valid to whoever holds it");

  std::assert_eq!(verdict.human_principal, alice.principal_did());
  std::assert_eq!(verdict.agent, alice.agent_did);
  std::assert_eq!(verdict.notary, alice.notary_did);
  std::assert_ne!(
    verdict.human_principal,
    bob.principal_did(),
    "forwarding must not make the claim Bob's"
  );
  std::assert!(
    asked_about(&carol_resolver, &bob).is_empty(),
    "Carol resolved something of Bob's to verify a credential he only relayed: {:?}",
    asked_about(&carol_resolver, &bob)
  );
}
