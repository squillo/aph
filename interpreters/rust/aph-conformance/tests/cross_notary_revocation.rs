//! CROSS-NOTARY REVOCATION: Alice's notary withdraws a mandate, and Bob finds
//! out by reading Alice's PUBLISHED list — never her store.
//!
//! ⛔ WHAT CROSSES THE BOUNDARY IN THIS FILE, and what does not.
//!
//! Crossing: one signed JSON document, served at the endpoint §6.3.3.2 derives
//! from Alice's own notary DID. That document is the entire revocation
//! transport. Bob's refusal comes from a bit he decoded out of bytes he
//! fetched, authenticated against a key he resolved from Alice's separate
//! §8.4 discovery surface.
//!
//! Not crossing: Alice's revocation ledger. `Party::publish_status_list` is the
//! only way anything about it leaves Alice's side, and what leaves is a
//! document. Bob holds no handle to Alice's state, so a test here cannot pass
//! because two parties happen to share a Rust value.
//!
//! # Why this needs its own file
//!
//! Revocation is the one APH mechanism whose answer arrives AFTER issuance,
//! from a party the recipient does not control, over a channel the recipient
//! did not choose. Every failure mode below is therefore about trust rather
//! than about parsing:
//!
//! - the envelope does not get to choose which host answers (§6.3.3.2);
//! - same origin is NOT the same as authentic — §6.3.3.2 deliberately permits a
//!   different PATH, so any writable path on a notary's origin can serve a
//!   forged list, and only the §6.3.3.3 signature closes that;
//! - an old, genuinely-signed list is a rollback attempt, and the freshness
//!   bound is what caps how long one can work;
//! - "no claim was offered" and "the claim is that nothing is wrong" are
//!   different answers, and conflating them is how a check gets skipped.

mod multi_party;

/// Bob's notary is a REAL, published, discoverable notary — which is what makes
/// it the sharpest forger to test against. Same-origin plus a well-formed proof
/// plus a resolvable signer is still not Alice.
fn wire_with_both_notaries_published() -> multi_party::Wire {
  let mut wire = multi_party::Wire::new();
  for party in [multi_party::alice(), multi_party::bob()] {
    party.publish_did_document(&mut wire);
  }
  wire
}

#[test]
fn the_local_base64url_encoder_round_trips_through_aph_core() {
  // ACROSS THE WIRE: nothing. This one checks the ENCODING every published
  // status list is carried in, before any party uses it, because a boundary
  // that garbles its payload proves nothing about what the payload said.
  //
  // This suite publishes `encodedList` values, and `aph-core`'s base64url
  // ENCODER is `pub(crate)` while its decoder is public — so the encode half is
  // written out in `multi_party`, and that is the one place in this directory
  // where a second implementation of an existing transform exists.
  //
  // This test is what makes that safe: it feeds the local encoder's output
  // straight back through `aph_core::decode_encoded_list`, the same public
  // decoder a verifier uses, so the two cannot drift without failing here. The
  // inputs cover the three tail lengths base64 has to handle — the 1-byte and
  // 2-byte tails are where a padding mistake hides, and a no-padding encoder
  // that emitted `=` would fail the decode outright.
  for length in [0usize, 1, 2, 3, 4, 5, 255, multi_party::STATUS_LIST_BYTES] {
    // A byte pattern that walks the whole alphabet rather than a run of zeros,
    // which would encode to a single repeated character and hide an index bug.
    let bits: std::vec::Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
    let encoded = multi_party::encoded_list_value(&bits);
    std::assert!(
      !encoded.contains('='),
      "the `encodedList` encoding is base64url with NO padding"
    );
    let decoded = aph_core::decode_encoded_list(&encoded)
      .unwrap_or_else(|e| std::panic!("aph-core must decode a {length}-byte list: {e}"));
    std::assert_eq!(
      decoded,
      [
        multi_party::GZIP_PLACEHOLDER_HEADER.as_slice(),
        bits.as_slice()
      ]
      .concat(),
      "the round trip must return the header and the bits unchanged"
    );
    std::assert_eq!(
      multi_party::expand_status_list(&decoded).expect("the expander strips the header"),
      bits
    );
  }
}

#[test]
fn the_bit_this_suite_sets_is_the_bit_aph_core_reads() {
  // ACROSS THE WIRE: nothing — this pins the WRITER against the READER, so
  // that when a bit does cross a boundary both ends mean the same mandate by
  // it.
  //
  // Bit order is the one §6.3.3 mistake that does not announce itself: an
  // LSB-first reader does not error, it reads a real bit belonging to a
  // DIFFERENT mandate and answers with full confidence. So the setter this
  // suite publishes with is pinned against `aph_core::revocation_bit`, the
  // reader a verifier actually runs.
  //
  // Index 42 is chosen because 42 % 8 == 2: under the W3C profile's MSB-first
  // order its byte is 0b0010_0000, which an LSB-first reader would report as
  // index 45. Asserting 45 is CLEAR is what catches the reversal — an index at
  // a byte boundary would look identical under either reading.
  let index = multi_party::alice().status_index;
  std::assert_eq!(index % 8, 2, "the chosen index must not sit on a byte boundary");
  let bits = multi_party::status_bitstring(&[index]);

  std::assert!(
    aph_core::revocation_bit(&bits, index).expect("the index is inside the list"),
    "the bit this suite sets must be the bit aph-core reads"
  );
  for clear in [0u64, index - 1, index + 1, index + 3] {
    std::assert!(
      !aph_core::revocation_bit(&bits, clear).expect("the index is inside the list"),
      "index {clear} must be clear; setting {index} must not disturb its neighbours"
    );
  }

  // §6.3.3.4 case 2 names "its list is too short to contain `statusListIndex`"
  // explicitly: a verifier that read a missing bit as `0` would treat a
  // truncated list as a blanket "nothing is revoked".
  let past_the_end = (multi_party::STATUS_LIST_BYTES * 8) as u64;
  std::assert_eq!(
    aph_core::revocation_bit(&bits, past_the_end)
      .expect_err("an index past the end is not a clear bit")
      .code(),
    "APH_E008"
  );
}

#[test]
fn revocation_reaches_bob_as_a_published_document_and_nothing_else() {
  // ACROSS THE WIRE: the envelope, Alice's DID Document, and two successive
  // status lists at her derived endpoint. NOT CROSSING: Alice's revocation
  // ledger, and no message of any kind from Alice to Bob about the withdrawal.
  //
  // THE CENTRAL TEST. Notice what does NOT change between the admit and the
  // refusal: the envelope is the same string, every signature on it stays
  // valid, and Alice never speaks to Bob. The only thing that moved is a
  // document Alice's notary re-issued at its own derived endpoint — and Bob
  // refuses because of a bit he read out of it.
  //
  // That the envelope remains cryptographically perfect is asserted rather than
  // assumed, because it is the reason revocation needs a transport at all: a
  // signature cannot be un-made, so withdrawal has to be published somewhere a
  // stranger will look.
  //
  // APH_E015, held distinct from APH_E003: authority WITHDRAWN by the human is
  // not authority that ran out on schedule, and the remedies differ.
  let alice = multi_party::alice();
  let mut wire = wire_with_both_notaries_published();
  alice.publish_status_list(&mut wire, &[], multi_party::STATUS_ISSUED_AT);

  let on_the_wire = alice.mint(&alice.draft());
  let received = multi_party::receive(&on_the_wire).expect("Bob's strict parse");

  let before = wire.resolver();
  std::assert_eq!(
    multi_party::verify_inbound(&before, &received, multi_party::VERIFIED_AT)
      .expect("before revocation the mandate is live")
      .status,
    aph_core::StatusCheck::NotRevoked
  );

  // Alice's notary withdraws the mandate. This is a re-issue and republication
  // of one document; nothing else in the world changes.
  alice.publish_status_list(
    &mut wire,
    &[alice.status_index],
    multi_party::STATUS_ISSUED_AT,
  );

  let after = wire.resolver();
  std::assert_eq!(
    multi_party::verify_inbound(&after, &received, multi_party::VERIFIED_AT)
      .expect_err("a withdrawn mandate must refuse")
      .code(),
    "APH_E015"
  );
  std::assert_eq!(
    after.status_asked(),
    std::vec![alice.status_endpoint()],
    "Bob read Alice's published endpoint — derived from her own DID — and nothing else"
  );

  // The envelope itself is untouched. Both proofs still verify under the keys
  // Bob resolved from Alice's discovery surface, which is exactly why the
  // refusal had to come from somewhere other than the bytes.
  let principal_key = multi_party::resolve_key(
    &after,
    &alice.principal_verification_method(),
    multi_party::DECISION_TIMESTAMP,
  )
  .expect("a did:key principal resolves offline");
  let notary_key = multi_party::resolve_key(
    &after,
    &alice.notary_verification_method(),
    multi_party::DECISION_TIMESTAMP,
  )
  .expect("Alice's notary key resolves from her published document");
  aph_core::verify_proof(&received, aph_core::ProofRole::Principal, &principal_key)
    .expect("the human's signature is still valid after revocation");
  aph_core::verify_proof(&received, aph_core::ProofRole::Notary, &notary_key)
    .expect("the countersignature is still valid after revocation");
}

#[test]
fn a_forged_list_on_alices_own_origin_must_not_read_as_not_revoked() {
  // ACROSS THE WIRE: the envelope, Alice's DID Document, and a status list at
  // her endpoint that SOMEBODY ELSE signed. NOT SHARED: Alice's notary key —
  // the only thing that separates her document from the forger's.
  //
  // ⛔ SAME ORIGIN IS NOT THE SAME AS AUTHENTIC, and §6.3.3.2 makes that gap
  // deliberately: it permits a DIFFERENT PATH on the notary's origin, which is
  // how a notary with an exhausted list points at its successor. The
  // consequence is that any writable path on that origin — an upload directory,
  // a user-content route, a compromised publisher — can serve a document that
  // satisfies same-origin AND simply writes Alice's DID into its own `issuer`.
  // Only the §6.3.3.3 signature closes it.
  //
  // The forgery attempted here is the one that matters: taking a mandate Alice
  // REVOKED and publishing a list that says otherwise. If it read as "not
  // revoked", the transport built to enforce revocation would become the way a
  // revoked agent proves it is fine.
  //
  // TWO forgers, because they fail for the same reason from different starting
  // points: an attacker whose key nobody has ever heard of, and Bob's notary —
  // a real, published, resolvable notary whose key a verifier CAN find. Neither
  // is Alice, and that is the whole of the check.
  let alice = multi_party::alice();
  let bob = multi_party::bob();
  let forgers: [(&str, ed25519_dalek::SigningKey); 2] = [
    (
      "an attacker with a writable path on Alice's origin",
      multi_party::key_from_seed(&multi_party::ATTACKER_SEED),
    ),
    (
      "another notary, itself published and resolvable",
      bob.notary_key(),
    ),
  ];

  // The second forger's premise, made non-vacuous: Bob's notary key really is
  // discoverable through §8.4. Being resolvable is not being Alice.
  let probe = wire_with_both_notaries_published();
  multi_party::resolve_key(
    &probe.resolver(),
    &bob.notary_verification_method(),
    multi_party::DECISION_TIMESTAMP,
  )
  .expect("Bob's notary publishes a key any verifier can find");

  for (who, forger_key) in forgers {
    let mut wire = wire_with_both_notaries_published();
    // Alice really did revoke it.
    alice.publish_status_list(
      &mut wire,
      &[alice.status_index],
      multi_party::STATUS_ISSUED_AT,
    );
    // …and the forger overwrites what she published with a document that is
    // correct in every respect except who signed it: right endpoint, right
    // issuer string, right purpose, right vintage, fresh, and even naming
    // Alice's own `verificationMethod`.
    let forged = multi_party::sign_status_list(
      &multi_party::status_list_document(
        alice.notary_did,
        &alice.status_endpoint(),
        multi_party::STATUS_ISSUED_AT,
        &[],
      ),
      &forger_key,
      &alice.notary_verification_method(),
    );
    wire.publish_https(&alice.status_endpoint(), &forged);

    let resolver = wire.resolver();
    let received =
      multi_party::receive(&alice.mint(&alice.draft())).expect("Bob's strict parse");
    let outcome = multi_party::verify_inbound(&resolver, &received, multi_party::VERIFIED_AT);
    match outcome {
      std::result::Result::Ok(admission) => std::panic!(
        "a list forged by {who} was believed: {:?}",
        admission.status
      ),
      // §6.3.3.4 case 2 — the status could not be established. Refusal, and
      // never the silent "not revoked" the forger was buying.
      std::result::Result::Err(error) => std::assert_eq!(
        error.code(),
        "APH_E008",
        "a list forged by {who} must be refused as unestablished status"
      ),
    }
  }
}

#[test]
fn replaying_alices_own_older_list_cannot_roll_a_revocation_back() {
  // ACROSS THE WIRE: the envelope, and two documents Alice's OWN notary really
  // signed — the current one and an older one served again. NOT SHARED:
  // anything that would tell Bob which is current other than the `validFrom`
  // inside the bytes.
  //
  // The rollback that needs no key at all: capture a list Alice genuinely
  // signed BEFORE she revoked, and serve it again afterwards. Every signature
  // on it is real, the issuer is right, the origin is right — the only thing
  // wrong with it is that it is old.
  //
  // §6.3.3.3's freshness bound is what refuses it, and stating the bound
  // honestly matters: it caps how long a replay can work at 300 seconds plus 60
  // of skew, and does not reduce that window to zero. A copy fresher than the
  // bound is by construction indistinguishable from the current one. That is
  // precisely why the bound comes PAIRED with a republish cadence of 120
  // seconds — less than half the bound, so a publisher that misses a cycle is
  // late rather than down, and the exposure a replay can buy stays bounded.
  let alice = multi_party::alice();
  let mut wire = wire_with_both_notaries_published();

  // What Alice published before she revoked, signed by her own notary key.
  let pre_revocation = multi_party::sign_status_list(
    &multi_party::status_list_document(
      alice.notary_did,
      &alice.status_endpoint(),
      multi_party::STATUS_ISSUED_STALE,
      &[],
    ),
    &alice.notary_key(),
    &alice.notary_verification_method(),
  );

  alice.publish_status_list(
    &mut wire,
    &[alice.status_index],
    multi_party::STATUS_ISSUED_AT,
  );
  let received = multi_party::receive(&alice.mint(&alice.draft())).expect("Bob's strict parse");
  std::assert_eq!(
    multi_party::verify_inbound(&wire.resolver(), &received, multi_party::VERIFIED_AT)
      .expect_err("the current list says revoked")
      .code(),
    "APH_E015"
  );

  // The replay: Alice's own bytes, served again.
  wire.publish_https(&alice.status_endpoint(), &pre_revocation);
  let resolver = wire.resolver();
  match multi_party::verify_inbound(&resolver, &received, multi_party::VERIFIED_AT) {
    std::result::Result::Ok(admission) => {
      std::panic!("a stale list rolled the revocation back: {:?}", admission.status)
    }
    std::result::Result::Err(error) => std::assert_eq!(
      error.code(),
      "APH_E008",
      "a list past the §6.3.3.3 freshness bound leaves the status unestablished"
    ),
  }
}

#[test]
fn a_status_url_on_another_notarys_origin_is_refused_without_a_fetch() {
  // ACROSS THE WIRE: an envelope naming a status URL on BOB's origin, and good
  // signed lists on both origins. NOT CROSSING, and this is the assertion: the
  // named URL is never requested at all.
  //
  // The attack §6.3.3.2 exists to stop, in its multi-party form. If the
  // envelope could name the host that answers "is this revoked", then whoever
  // holds an old envelope also chooses the answer — and a host of their
  // choosing always says "not revoked".
  //
  // Bob's origin is used as the wrong host precisely because it is a LEGITIMATE
  // notary origin, published and resolvable: the rule is not "refuse hosts that
  // look suspicious", it is "the origin is derived from the notary's own DID
  // and nothing else".
  //
  // The zero-fetch assertion is half the claim. §6.3.3.2 says a verifier MUST
  // reject AND MUST NOT fetch the named URL — a verifier that fetched first and
  // rejected afterwards would still be a request an attacker chose the shape
  // of.
  let alice = multi_party::alice();
  let bob = multi_party::bob();
  let mut wire = wire_with_both_notaries_published();
  alice.publish_status_list(&mut wire, &[], multi_party::STATUS_ISSUED_AT);
  // Bob's origin even serves a perfectly good, perfectly signed list — so the
  // refusal cannot be attributed to the document being unavailable or bad.
  bob.publish_status_list(&mut wire, &[], multi_party::STATUS_ISSUED_AT);

  let mut misdirected = alice.draft();
  misdirected.status_list_credential = bob.status_endpoint();
  let received = multi_party::receive(&alice.mint(&misdirected)).expect("Bob's strict parse");

  let resolver = wire.resolver();
  std::assert_eq!(
    multi_party::verify_inbound(&resolver, &received, multi_party::VERIFIED_AT)
      .expect_err("the envelope may not choose which host answers")
      .code(),
    "APH_E008"
  );
  std::assert!(
    resolver.status_asked().is_empty(),
    "the named URL was fetched before being rejected: {:?}",
    resolver.status_asked()
  );
}

#[test]
fn an_envelope_offering_no_status_claim_is_skipped_never_assumed_live() {
  // ACROSS THE WIRE: an envelope carrying NO status reference, and a status
  // list that would say "revoked" if anyone asked for it. NOT CROSSING: that
  // list — no request is made, which is the assertion.
  //
  // §6.3.3.4 case 1, and the distinction is not pedantry. "No claim was
  // offered" and "the claim is that nothing is wrong" are different facts, and
  // a recipient that recorded the first as the second would be reporting a
  // revocation check that never happened.
  //
  // The skip also has to be free of I/O: enforcing a claim nobody made is not
  // fail-closed, it is fail-arbitrary, and it would refuse every conformant
  // envelope minted before revocation had a transport.
  let alice = multi_party::alice();
  let mut wire = wire_with_both_notaries_published();
  // Alice's notary DOES publish a list, and has revoked the index this party
  // would otherwise occupy — so an implementation that went looking anyway
  // would refuse, and the `Skipped` below would be impossible to reach by luck.
  alice.publish_status_list(
    &mut wire,
    &[alice.status_index],
    multi_party::STATUS_ISSUED_AT,
  );

  let mut silent = alice.draft();
  silent.status_index = std::option::Option::None;
  let on_the_wire = alice.mint(&silent);
  std::assert!(
    !on_the_wire.contains("credentialStatus"),
    "an envelope offering no status claim carries no `credentialStatus` key at all"
  );

  let received = multi_party::receive(&on_the_wire).expect("Bob's strict parse (§8.3 step 1)");
  let resolver = wire.resolver();
  let admission = multi_party::verify_inbound(&resolver, &received, multi_party::VERIFIED_AT)
    .expect("an envelope that offers no status claim is not refused for offering none");
  std::assert_eq!(admission.status, aph_core::StatusCheck::Skipped);
  std::assert_ne!(
    admission.status,
    aph_core::StatusCheck::NotRevoked,
    "`Skipped` must never be reported as `NotRevoked`"
  );
  std::assert!(
    resolver.status_asked().is_empty(),
    "a status surface was consulted for an envelope that made no status claim: {:?}",
    resolver.status_asked()
  );
}
