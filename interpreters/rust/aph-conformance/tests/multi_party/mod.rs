// Each scenario file in this directory compiles this module into its OWN test
// binary and uses a different slice of it, so whatever one scenario leaves
// untouched reads as dead code in that binary. Allowing it keeps `cargo test`
// output about the protocol rather than about scaffolding.
#![allow(dead_code)]

//! The cast, the wire, and the verifier that the multi-party scenarios share.
//!
//! # Why this directory exists
//!
//! Every other test in this repository is ONE party checking fixtures it was
//! handed. That proves an implementation agrees with itself. It cannot prove
//! the protocol's actual claim, which is about two strangers: *a recipient who
//! has never transacted with an issuer can verify what that issuer minted.*
//! The scenarios beside this file are that claim, executed.
//!
//! # ⛔ WHAT CROSSES A BOUNDARY HERE, AND WHAT DOES NOT
//!
//! Exactly three things cross, and all three are TEXT:
//!
//! 1. **the envelope**, as the JSON string a sender serialized and a recipient
//!    independently parsed ([`receive`]);
//! 2. **DNS TXT records and `did:web` documents**, as the strings a notary
//!    RENDERED through `aph_core::discovery::publish` and wrote onto the
//!    [`Wire`];
//! 3. **status list credentials**, as the signed JSON a notary published at
//!    its own derived endpoint.
//!
//! Nothing else. No party holds another party's key, signing key, envelope
//! struct, resolver, or store. A recipient's verdict is reached from bytes it
//! parsed and a key it resolved — never from a Rust value the sender also
//! holds. That is the whole point: a test that passed because two parties
//! shared a value would have proven nothing about interop, and would keep
//! passing against a verifier that admitted unconditionally.
//!
//! The one thing deliberately SHARED is [`Wire`], and sharing it is not a
//! cheat — it is the model. DNS and the public web genuinely are common
//! infrastructure that one party writes to and another reads from. What must
//! not be shared is key material, decisions, and stores, and none of those
//! live on the wire.
//!
//! # No network, no clock
//!
//! [`Resolver`] is an in-memory double over the three `aph_core::discovery`
//! ports; it opens no socket. Every instant is a constant passed in as an
//! argument, so no test can pass today and fail on the day a window closes.
//!
//! # Relationship to `principal_signed_example_test.rs`
//!
//! That file, in this same crate, is the house idiom this one follows: fixed
//! public seeds with their derived DIDs alongside, and real signing through
//! `aph-core`'s own path rather than hand-assembled proofs. It is not,
//! however, a multi-PARTY test — it has two ROLES on ONE side, a principal and
//! its own notary co-signing a single envelope. What is added here is a second
//! SIDE.

// ─────────────────────────────────────────────────────────────────────────
// Instants
//
// All of them constants. A suite that read a wall clock would pass today and
// fail on the day one of these windows closed, and the failure would look like
// a protocol bug.
// ─────────────────────────────────────────────────────────────────────────

/// Lower bound of every Delegation Mandate this suite mints.
pub const MANDATE_VALID_FROM: &str = "2026-05-20T00:00:00Z";

/// Upper bound of every Delegation Mandate this suite mints.
pub const MANDATE_VALID_UNTIL: &str = "2026-05-22T00:00:00Z";

/// The notary's `decisionTimestamp` — and, per §8.4.7, the instant a verifier
/// resolves the SIGNING KEY at. Not the instant it evaluates the envelope at:
/// a key that has since been rotated out was still the right key when the
/// envelope was signed, and conflating the two makes every envelope minted
/// before a rotation start failing the day the old key's `notAfter` passes.
pub const DECISION_TIMESTAMP: &str = "2026-05-21T00:00:00Z";

/// `created` of the principal proof — after the notary prepared the envelope
/// (§7.2.1).
pub const PRINCIPAL_CREATED: &str = "2026-05-21T00:00:01Z";

/// `created` of the notary countersignature — after the principal signed.
pub const NOTARY_CREATED: &str = "2026-05-21T00:00:02Z";

/// `validFrom` of every envelope this suite mints.
pub const ENVELOPE_VALID_FROM: &str = "2026-05-21T00:00:00Z";

/// `validUntil` of every envelope this suite mints.
pub const ENVELOPE_VALID_UNTIL: &str = "2026-05-22T00:00:00Z";

/// The instant a recipient evaluates at: inside every window above, and 30
/// seconds after [`STATUS_ISSUED_AT`] so a fresh status list is comfortably
/// inside §6.3.3.3's bound.
pub const VERIFIED_AT: &str = "2026-05-21T00:00:30Z";

/// A day after every mandate and envelope window in this suite has closed.
pub const AFTER_THE_WINDOW: &str = "2026-05-23T00:00:00Z";

/// `validFrom` of a status list published for [`VERIFIED_AT`].
pub const STATUS_ISSUED_AT: &str = "2026-05-21T00:00:00Z";

/// `validFrom` of a status list that is 630 seconds old at [`VERIFIED_AT`] —
/// past §6.3.3.3's 300-second bound even with the 60-second skew allowance.
pub const STATUS_ISSUED_STALE: &str = "2026-05-20T23:50:00Z";

/// `notBefore` of every notary key published to the wire.
pub const KEY_NOT_BEFORE: &str = "2026-05-01T00:00:00Z";

/// `notAfter` of every notary key published to the wire.
pub const KEY_NOT_AFTER: &str = "2026-06-01T00:00:00Z";

// ─────────────────────────────────────────────────────────────────────────
// Seeds
//
// ⛔ Every seed below is a single byte repeated 32 times. That is deliberate
// and it is the safety property: a repeated-byte seed is unmistakably a test
// fixture, authorizes nothing, and can be re-derived by any reader. It is the
// same convention `aph_core::credential_status`'s own fixtures use (`[9u8;
// 32]`).
//
// The sibling `principal_signed_example_test.rs` uses RFC 8032 §7.1 published
// vectors instead. That is the better anchor where it fits, and it does not
// fit here: §7.1 publishes three usable short-message vectors and this suite
// needs SEVEN distinct identities. Rather than mix two conventions in one
// cast, all seven are obviously-fake, and
// `the_seven_identities_are_fake_and_pairwise_distinct` pins both halves of
// that claim.
// ─────────────────────────────────────────────────────────────────────────

/// Alice's HUMAN PRINCIPAL. Never a production key.
const ALICE_PRINCIPAL_SEED: [u8; 32] = [0xa1; 32];
/// Alice's NOTARY SERVICE. Never a production key.
const ALICE_NOTARY_SEED: [u8; 32] = [0xa2; 32];
/// Bob's HUMAN PRINCIPAL. Never a production key.
const BOB_PRINCIPAL_SEED: [u8; 32] = [0xb1; 32];
/// Bob's NOTARY SERVICE. Never a production key.
const BOB_NOTARY_SEED: [u8; 32] = [0xb2; 32];
/// Carol's HUMAN PRINCIPAL. Never a production key.
const CAROL_PRINCIPAL_SEED: [u8; 32] = [0xc1; 32];
/// Carol's NOTARY SERVICE. Never a production key.
const CAROL_NOTARY_SEED: [u8; 32] = [0xc2; 32];

/// The key held by whoever is attacking the exchange — an on-path forger, or
/// somebody who found a writable path on a notary's origin. It belongs to no
/// party in the cast, which is exactly what every refusal below turns on.
pub const ATTACKER_SEED: [u8; 32] = [0xee; 32];

/// Every seed in the cast, with the identity it belongs to. Used only by the
/// tripwire that pins the fake-and-distinct property.
pub fn all_seeds() -> std::vec::Vec<(&'static str, [u8; 32])> {
  std::vec![
    ("alice/principal", ALICE_PRINCIPAL_SEED),
    ("alice/notary", ALICE_NOTARY_SEED),
    ("bob/principal", BOB_PRINCIPAL_SEED),
    ("bob/notary", BOB_NOTARY_SEED),
    ("carol/principal", CAROL_PRINCIPAL_SEED),
    ("carol/notary", CAROL_NOTARY_SEED),
    ("attacker", ATTACKER_SEED),
  ]
}

// ─────────────────────────────────────────────────────────────────────────
// The parties
// ─────────────────────────────────────────────────────────────────────────

/// One party: a human principal, that human's agent, and that human's OWN
/// notary service, on its own origin, with its own keys.
///
/// A party is a bundle of identity and nothing else. It holds no verifier
/// state and no view of the wire — the two are separated so that a test cannot
/// accidentally let a sender's knowledge reach a recipient's decision.
pub struct Party {
  /// Short name used in assertion messages.
  pub label: &'static str,
  /// Seed of the human's own signing key.
  principal_seed: [u8; 32],
  /// Seed of this party's notary service key.
  notary_seed: [u8; 32],
  /// The notary's `did:web` DID. Each party's is a DIFFERENT origin, which is
  /// what makes "resolve the sender's key" a real question.
  pub notary_did: &'static str,
  /// The key identifier this notary publishes under, and the fragment its
  /// proofs name.
  pub notary_kid: &'static str,
  /// This party's agent.
  pub agent_did: &'static str,
  /// Human-readable name carried in `credentialSubject.humanPrincipal`.
  pub display_name: &'static str,
  /// This party's position in its own notary's revocation bitstring. Distinct
  /// per party so a test cannot pass by reading somebody else's bit.
  pub status_index: u64,
  /// Two hex characters that make this party's envelope, mandate and proof ids
  /// unique, so a failure message says whose envelope it was about.
  id_tag: &'static str,
}

/// The sender in every scenario: Alice's notary mints for Alice's agent.
pub fn alice() -> Party {
  Party {
    label: "alice",
    principal_seed: ALICE_PRINCIPAL_SEED,
    notary_seed: ALICE_NOTARY_SEED,
    notary_did: "did:web:notary.alice.example",
    notary_kid: "k1",
    agent_did: "did:web:agent.alice.example",
    display_name: "Alice",
    status_index: 42,
    id_tag: "a1",
  }
}

/// The recipient in the two-party exchange, and the middle hop in the relay:
/// Bob verifies inbound AND issues outbound under his own authority.
pub fn bob() -> Party {
  Party {
    label: "bob",
    principal_seed: BOB_PRINCIPAL_SEED,
    notary_seed: BOB_NOTARY_SEED,
    notary_did: "did:web:notary.bob.example",
    notary_kid: "k1",
    agent_did: "did:web:agent.bob.example",
    display_name: "Bob",
    status_index: 1337,
    id_tag: "b1",
  }
}

/// The far end of the relay. Carol never hears from Alice.
pub fn carol() -> Party {
  Party {
    label: "carol",
    principal_seed: CAROL_PRINCIPAL_SEED,
    notary_seed: CAROL_NOTARY_SEED,
    notary_did: "did:web:notary.carol.example",
    notary_kid: "k1",
    agent_did: "did:web:agent.carol.example",
    display_name: "Carol",
    status_index: 7,
    id_tag: "c1",
  }
}

impl Party {
  /// The human's signing key. Private to this party; nothing in this suite
  /// hands it to another.
  pub fn principal_key(&self) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&self.principal_seed)
  }

  /// The notary service's signing key. Private to this party.
  pub fn notary_key(&self) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&self.notary_seed)
  }

  /// The human's `did:key`, DERIVED from the public half rather than
  /// transcribed — a recipient recovers this key offline from the identifier
  /// itself (§8.4.3), with no network and no prior trust relationship.
  pub fn principal_did(&self) -> String {
    aph_core::did_key_from_ed25519(&self.principal_key().verifying_key())
  }

  /// The DID URL the principal proof names. A `did:key` URL conventionally
  /// repeats its multibase suffix after the `#`.
  pub fn principal_verification_method(&self) -> String {
    let did = self.principal_did();
    let suffix = String::from(did.trim_start_matches("did:key:"));
    std::format!("{did}#{suffix}")
  }

  /// The DID URL the notary countersignature names.
  pub fn notary_verification_method(&self) -> String {
    std::format!("{did}#{kid}", did = self.notary_did, kid = self.notary_kid)
  }

  /// This notary's PUBLIC key in the shape both §8.4 publication mechanisms
  /// render from.
  pub fn published_key(&self) -> aph_core::NotaryPublicKey {
    aph_core::NotaryPublicKey {
      algorithm: aph_core::KeyAlgorithm::Ed25519,
      key_bytes: self.notary_key().verifying_key().to_bytes().to_vec(),
      kid: std::option::Option::Some(String::from(self.notary_kid)),
    }
  }

  /// The §6.3.3.2 status endpoint DERIVED from this notary's own DID.
  ///
  /// Derived, never string-built: this is the origin a verifier trusts, and
  /// the whole security argument of §6.3.3 is that the envelope does not get
  /// to choose which host answers "is this mandate revoked".
  pub fn status_endpoint(&self) -> String {
    aph_core::DidUrl::parse(self.notary_did)
      .web_status_url()
      .expect("a did:web notary derives a status endpoint")
  }

  /// Publishes this notary's key as a §8.4.5 DNS TXT record.
  ///
  /// Both the NAME and the RECORD come from `aph-core`: the name from
  /// `DidUrl::dns_txt_name`, the record from `publish::render_txt_record`. A
  /// test that hand-assembled either would be proving its own string
  /// formatting agrees with itself.
  pub fn publish_txt_record(&self, wire: &mut Wire, not_before: &str, not_after: &str) {
    let name = aph_core::DidUrl::parse(self.notary_did)
      .dns_txt_name()
      .expect("a did:web notary derives a DNS TXT name");
    let record =
      aph_core::discovery::publish::render_txt_record(&self.published_key(), not_before, not_after)
        .expect("a real Ed25519 key renders a §8.4.5 record");
    wire.publish_txt(&name, &record);
  }

  /// Publishes this notary's key as a §8.4.4 `did:web` DID Document.
  pub fn publish_did_document(&self, wire: &mut Wire) {
    let url = aph_core::DidUrl::parse(self.notary_did)
      .web_document_url()
      .expect("a did:web notary derives a document URL");
    let document =
      aph_core::discovery::publish::render_did_document(self.notary_did, &[self.published_key()])
        .expect("a real Ed25519 key renders a §8.4.4 document");
    wire.publish_https(&url, &document);
  }

  /// Publishes a SIGNED §6.3.3.3 status list at this notary's derived
  /// endpoint, with the bit SET for every index in `revoked`.
  ///
  /// Republishing is how a revocation reaches the world: this overwrites
  /// whatever was at the endpoint, exactly as re-issuing the document does.
  /// The notary's own revocation ledger never leaves this function — a
  /// recipient learns about it only by reading the published bytes.
  pub fn publish_status_list(&self, wire: &mut Wire, revoked: &[u64], issued_at: &str) {
    let endpoint = self.status_endpoint();
    let unsigned = status_list_document(self.notary_did, &endpoint, issued_at, revoked);
    let signed = sign_status_list(
      &unsigned,
      &self.notary_key(),
      &self.notary_verification_method(),
    );
    wire.publish_https(&endpoint, &signed);
  }

  /// The default outbound request for this party: in window, on an allowed
  /// channel, carrying a revocation reference into this notary's own list.
  ///
  /// Tests mutate one field of the returned value to build a refusal case, so
  /// the difference between "admitted" and "refused" is visible in one line.
  pub fn draft(&self) -> Mint {
    Mint {
      // Each id is a valid `urn:uuid:` with the party's own tag in the last
      // group, so a failure message says whose envelope it was talking about.
      envelope_id: std::format!("urn:uuid:00000000-0000-4000-8000-00000000{}e0", self.id_tag),
      mandate_id: std::format!("urn:uuid:00000000-0000-4000-8000-00000000{}d1", self.id_tag),
      principal_proof_id: std::format!(
        "urn:uuid:00000000-0000-4000-8000-00000000{}f1",
        self.id_tag
      ),
      notary_proof_id: std::format!(
        "urn:uuid:00000000-0000-4000-8000-00000000{}f2",
        self.id_tag
      ),
      channel: String::from("slack"),
      allowed_channels: std::vec![String::from("slack")],
      body_sha256: String::from(EMPTY_BODY_SHA256),
      preview: std::format!("{} says the rollout finished", self.display_name),
      mandate_valid_from: String::from(MANDATE_VALID_FROM),
      mandate_valid_until: String::from(MANDATE_VALID_UNTIL),
      valid_from: String::from(ENVELOPE_VALID_FROM),
      valid_until: String::from(ENVELOPE_VALID_UNTIL),
      decision_timestamp: String::from(DECISION_TIMESTAMP),
      principal_created: String::from(PRINCIPAL_CREATED),
      notary_created: String::from(NOTARY_CREATED),
      notary_service_id: String::from(self.notary_did),
      status_index: std::option::Option::Some(self.status_index),
      status_list_credential: self.status_endpoint(),
    }
  }

  /// Mints and fully signs an envelope, then hands back THE BYTES.
  ///
  /// Returning a `String` rather than a `NotarizationEnvelope` is the boundary
  /// this whole directory is about: the recipient must parse what it was sent.
  /// Every signature is real and made through `aph-core`'s own path, in
  /// §7.2.1's issuance order — the notary prepares the envelope, the human
  /// signs what was prepared, the notary countersigns the result.
  pub fn mint(&self, request: &Mint) -> String {
    let mut mandate = aph_core::DelegationMandate {
      id: request.mandate_id.clone(),
      human_principal_did: self.principal_did(),
      agent_did: String::from(self.agent_did),
      allowed_channels: request.allowed_channels.clone(),
      rate_limit_per_hour: std::option::Option::Some(20),
      valid_from: request.mandate_valid_from.clone(),
      valid_until: request.mandate_valid_until.clone(),
      // Both §7.2.1 bases REMOVE their own member, so these placeholders never
      // reach the signed bytes.
      principal_signature: String::new(),
      notary_signature: String::new(),
    };
    mandate.principal_signature = sign_mandate_role(
      &mandate,
      aph_core::ProofRole::Principal,
      &self.principal_key(),
    );
    mandate.notary_signature =
      sign_mandate_role(&mandate, aph_core::ProofRole::Notary, &self.notary_key());

    let principal_proof = aph_core::EnvelopeProof {
      r#type: String::from("DataIntegrityProof"),
      cryptosuite: std::option::Option::Some(String::from("eddsa-jcs-2022")),
      verification_method: self.principal_verification_method(),
      created: request.principal_created.clone(),
      proof_purpose: String::from("assertionMethod"),
      proof_value: String::new(),
      id: std::option::Option::Some(request.principal_proof_id.clone()),
      previous_proof: std::option::Option::None,
    };
    let notary_proof = aph_core::EnvelopeProof {
      r#type: String::from("DataIntegrityProof"),
      cryptosuite: std::option::Option::Some(String::from("eddsa-jcs-2022")),
      verification_method: self.notary_verification_method(),
      created: request.notary_created.clone(),
      proof_purpose: String::from("authentication"),
      proof_value: String::new(),
      id: std::option::Option::Some(request.notary_proof_id.clone()),
      previous_proof: std::option::Option::Some(request.principal_proof_id.clone()),
    };

    let mut envelope = aph_core::NotarizationEnvelope {
      aph_version: String::from("0.1"),
      context: std::vec![
        String::from("https://www.w3.org/ns/credentials/v2"),
        String::from("https://w3id.org/aph/v1"),
      ],
      r#type: std::vec![
        String::from("VerifiableCredential"),
        String::from("AgentSendAuthorizationCredential"),
      ],
      id: request.envelope_id.clone(),
      // §7.1.7: in PrincipalSigned mode the ISSUER is the human. The notary is
      // a witness, and §7.1.11 forbids inferring a signer from this field.
      issuer: self.principal_did(),
      valid_from: request.valid_from.clone(),
      valid_until: request.valid_until.clone(),
      credential_subject: aph_core::CredentialSubject {
        human_principal: aph_core::HumanPrincipalRef {
          id: self.principal_did(),
          display_name: String::from(self.display_name),
        },
        agent: aph_core::AgentRef {
          id: String::from(self.agent_did),
          agent_card_uri: std::option::Option::None,
          display_name: std::format!("{} Agent", self.display_name),
          version: String::from("1.0"),
        },
        channel: aph_core::ChannelDescriptor {
          kind: request.channel.clone(),
          recipient_addressing: serde_json::json!({
            "channelId": "C01234567",
            "teamId": "T01234567"
          }),
        },
        communication: aph_core::CommunicationDescriptor {
          content_class: String::from("Reply"),
          body_sha256: request.body_sha256.clone(),
          body_size: 0,
          preview_lines: 1,
          preview: request.preview.clone(),
        },
        policy: aph_core::PolicyDescriptor {
          decision: String::from("AlwaysAllow"),
          matched_scope: String::from("per-channel"),
          delegation_mandate_id: std::option::Option::Some(request.mandate_id.clone()),
          act_chain: std::vec::Vec::new(),
          attestation_mode: std::option::Option::Some(aph_core::AttestationMode::PrincipalSigned),
          delegation_mandate: std::option::Option::Some(mandate),
        },
        notarization: aph_core::NotarizationMetadata {
          notary_service: aph_core::NotaryServiceRef {
            id: request.notary_service_id.clone(),
            name: std::format!("{} Notary Service", self.display_name),
            version: String::from("0.1.0"),
            attested_digest: std::option::Option::None,
            attestation_uri: std::option::Option::None,
          },
          decision_timestamp: request.decision_timestamp.clone(),
          decision_latency_ms: 12,
        },
        apple_aur_acceptance: std::option::Option::None,
      },
      linked_mandate: std::option::Option::None,
      credential_status: request.status_index.map(|index| aph_core::CredentialStatusEntry {
        id: std::option::Option::None,
        r#type: aph_core::StatusEntryType::BitstringStatusListEntry,
        status_purpose: aph_core::StatusPurpose::Revocation,
        status_list_index: index.to_string(),
        status_list_credential: request.status_list_credential.clone(),
      }),
      proof: aph_core::EnvelopeProofs::Chain(std::vec![principal_proof, notary_proof]),
    };

    aph_core::sign_as_principal(&mut envelope, &self.principal_key())
      .expect("the principal signs the envelope its notary prepared");
    aph_core::countersign_as_notary(&mut envelope, &self.notary_key())
      .expect("the notary countersigns the principal's proof");
    serde_json::to_string(&envelope).expect("a signed envelope serializes")
  }
}

/// The signing key behind a raw seed, for the identities that are not parties
/// — today that is the attacker alone.
pub fn key_from_seed(seed: &[u8; 32]) -> ed25519_dalek::SigningKey {
  ed25519_dalek::SigningKey::from_bytes(seed)
}

/// A publishable §8.4 key for the identity behind `seed`, labelled `kid`.
///
/// Exists so a scenario can put SOMEBODY ELSE'S key at a notary's published
/// name — the substitution every "wrong key" refusal turns on — without any
/// party having to hand over key material.
pub fn publishable_key(seed: &[u8; 32], kid: &str) -> aph_core::NotaryPublicKey {
  aph_core::NotaryPublicKey {
    algorithm: aph_core::KeyAlgorithm::Ed25519,
    key_bytes: key_from_seed(seed).verifying_key().to_bytes().to_vec(),
    kid: std::option::Option::Some(String::from(kid)),
  }
}

/// Resolves the key a DID URL names through the §8.4.6 order, exactly as
/// [`verify_inbound`] does internally — a `did:key` offline, a `did:web`
/// through its DNS anchor and then its document.
///
/// Exposed so a scenario can make a second, narrower statement about a key a
/// recipient resolved — for instance that the same bytes fail a proof check
/// once the envelope has been tampered with — without reaching for the
/// sender's own signing key, which no recipient ever holds.
pub fn resolve_key(
  resolver: &Resolver<'_>,
  did_url: &str,
  at_rfc3339: &str,
) -> std::result::Result<ed25519_dalek::VerifyingKey, aph_core::AphError> {
  block_on(aph_core::discovery::composer::resolve(
    aph_core::discovery::composer::MechanismSelection::NamedByDid,
    did_url,
    resolver,
    resolver,
    at_rfc3339,
  ))?
  .to_ed25519()
}

/// SHA-256 of the empty byte string. A real digest of a real (empty) body, so
/// nothing in this suite carries a made-up hash that could be mistaken for
/// one.
pub const EMPTY_BODY_SHA256: &str =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Everything a party's notary needs in order to mint one envelope.
///
/// Owned strings rather than borrows so a test can build a refusal by cloning
/// the default and changing one field.
#[derive(std::clone::Clone)]
pub struct Mint {
  /// `urn:uuid:` identifier of the envelope.
  pub envelope_id: String,
  /// `urn:uuid:` identifier of the embedded Delegation Mandate.
  pub mandate_id: String,
  /// `id` of the principal proof — the head of the §7.1.11 chain.
  pub principal_proof_id: String,
  /// `id` of the notary countersignature.
  pub notary_proof_id: String,
  /// Channel this envelope is for.
  pub channel: String,
  /// Channels the mandate permits.
  pub allowed_channels: std::vec::Vec<String>,
  /// `credentialSubject.communication.bodySha256`.
  pub body_sha256: String,
  /// The preview line the recipient displays.
  pub preview: String,
  /// Mandate window, lower bound.
  pub mandate_valid_from: String,
  /// Mandate window, upper bound.
  pub mandate_valid_until: String,
  /// Envelope window, lower bound.
  pub valid_from: String,
  /// Envelope window, upper bound.
  pub valid_until: String,
  /// `notarization.decisionTimestamp`.
  pub decision_timestamp: String,
  /// `created` of the principal proof.
  pub principal_created: String,
  /// `created` of the notary countersignature.
  pub notary_created: String,
  /// `notarization.notaryService.id`. Separately settable from the proof's own
  /// `verificationMethod` so a test can pin what happens when they disagree.
  pub notary_service_id: String,
  /// Position in the notary's revocation bitstring, or `None` for an envelope
  /// that offers no status claim at all (§6.3.3.4 case 1).
  pub status_index: std::option::Option<u64>,
  /// The `statusListCredential` URL the envelope names.
  pub status_list_credential: String,
}

/// Signs one Delegation Mandate role over its §7.2.1 base.
///
/// The base comes from `aph_core::mandate_signing_base`, never from a local
/// re-derivation: a signer and a verifier that each build their own bytes is
/// exactly how two conformant-looking implementations stop interoperating.
pub fn sign_mandate_role(
  mandate: &aph_core::DelegationMandate,
  role: aph_core::ProofRole,
  key: &ed25519_dalek::SigningKey,
) -> String {
  let base = aph_core::mandate_signing_base(mandate, role)
    .expect("a serializable mandate always has a signing base");
  let signature: ed25519_dalek::Signature = ed25519_dalek::Signer::sign(key, base.as_bytes());
  aph_core::crypto::multibase::base58btc_encode(&signature.to_bytes())
}

/// Verifies one Delegation Mandate signature against its §7.2.1 base.
pub fn mandate_role_verifies(
  mandate: &aph_core::DelegationMandate,
  role: aph_core::ProofRole,
  key: &ed25519_dalek::VerifyingKey,
) -> bool {
  let base = match aph_core::mandate_signing_base(mandate, role) {
    std::result::Result::Ok(base) => base,
    std::result::Result::Err(_) => return false,
  };
  let encoded = match role {
    aph_core::ProofRole::Principal => &mandate.principal_signature,
    aph_core::ProofRole::Notary => &mandate.notary_signature,
  };
  let raw = match aph_core::crypto::multibase::base58btc_decode(encoded) {
    std::result::Result::Ok(bytes) => bytes,
    std::result::Result::Err(_) => return false,
  };
  let bytes: [u8; 64] = match std::convert::TryInto::try_into(raw.as_slice()) {
    std::result::Result::Ok(b) => b,
    std::result::Result::Err(_) => return false,
  };
  let signature = ed25519_dalek::Signature::from_bytes(&bytes);
  ed25519_dalek::Verifier::verify(key, base.as_bytes(), &signature).is_ok()
}

// ─────────────────────────────────────────────────────────────────────────
// The wire
// ─────────────────────────────────────────────────────────────────────────

/// The public infrastructure a notary publishes onto and a stranger reads
/// from: DNS TXT names and HTTPS URLs, each holding TEXT and nothing else.
///
/// This is the only value two parties share, and sharing it is the model
/// rather than a shortcut — DNS and the public web really are common. What is
/// NOT here is the thing that would make a passing test meaningless: no key,
/// no envelope struct, no verdict, and no party's store.
#[derive(std::default::Default)]
pub struct Wire {
  txt: std::collections::BTreeMap<String, std::vec::Vec<String>>,
  https: std::collections::BTreeMap<String, String>,
}

impl Wire {
  /// An empty internet: no name resolves, no URL answers.
  pub fn new() -> Self {
    Self::default()
  }

  /// Adds one TXT string at `name`, beside anything already published there.
  ///
  /// Additive because a real name legitimately holds unrelated records (SPF,
  /// site verification) and a rotating notary holds several APH records side
  /// by side — §8.4.5 step 3 selects among them and MUST NOT be denied a valid
  /// key by a malformed neighbour.
  pub fn publish_txt(&mut self, name: &str, record: &str) {
    self
      .txt
      .entry(String::from(name))
      .or_default()
      .push(String::from(record));
  }

  /// Puts `body` at `url`, REPLACING whatever was there.
  ///
  /// Replacement is the honest model for both of the things this suite needs
  /// it for: a notary re-issuing its status list after a revocation, and an
  /// attacker who can write to a path on that origin overwriting it.
  pub fn publish_https(&mut self, url: &str, body: &str) {
    self.https.insert(String::from(url), String::from(body));
  }

  /// A fresh reader over this wire, with its own record of what it asked for.
  ///
  /// Each party takes its own: the ask-lists are how a test proves a mechanism
  /// was NOT consulted, which is the only observable form of "did not
  /// downgrade" and of "did not need to know about the other hop".
  pub fn resolver(&self) -> Resolver<'_> {
    Resolver {
      wire: self,
      dns_asked: std::sync::Mutex::new(std::vec::Vec::new()),
      document_asked: std::sync::Mutex::new(std::vec::Vec::new()),
      status_asked: std::sync::Mutex::new(std::vec::Vec::new()),
    }
  }
}

/// One party's view of the [`Wire`]: an in-memory double over all three
/// `aph_core::discovery` ports, recording every name and URL it was asked for.
///
/// It carries only bytes in both directions, which is the property that makes
/// the scenarios beside this file a test of the PROTOCOL rather than of a
/// shared fixture.
pub struct Resolver<'w> {
  wire: &'w Wire,
  dns_asked: std::sync::Mutex<std::vec::Vec<String>>,
  document_asked: std::sync::Mutex<std::vec::Vec<String>>,
  status_asked: std::sync::Mutex<std::vec::Vec<String>>,
}

impl Resolver<'_> {
  /// Every DNS TXT name this resolver was asked for, in order.
  pub fn dns_asked(&self) -> std::vec::Vec<String> {
    self.dns_asked.lock().expect("test mutex poisoned").clone()
  }

  /// Every `did:web` document URL this resolver was asked for, in order.
  pub fn document_asked(&self) -> std::vec::Vec<String> {
    self
      .document_asked
      .lock()
      .expect("test mutex poisoned")
      .clone()
  }

  /// Every status list URL this resolver was asked for, in order.
  pub fn status_asked(&self) -> std::vec::Vec<String> {
    self.status_asked.lock().expect("test mutex poisoned").clone()
  }

  /// Everything this resolver touched, for an assertion about what a verifier
  /// did NOT need to look at.
  pub fn everything_asked(&self) -> std::vec::Vec<String> {
    let mut all = self.dns_asked();
    all.extend(self.document_asked());
    all.extend(self.status_asked());
    all
  }
}

impl aph_core::discovery::ports::TxtRecordLookup for Resolver<'_> {
  fn lookup_txt<'a>(
    &'a self,
    name: &'a str,
  ) -> aph_core::discovery::ports::DiscoveryFuture<
    'a,
    aph_core::discovery::DiscoveryOutcome<std::vec::Vec<String>>,
  > {
    std::boxed::Box::pin(async move {
      self
        .dns_asked
        .lock()
        .expect("test mutex poisoned")
        .push(String::from(name));
      // A name nobody published at is NXDOMAIN, and §8.4.6 ADVANCES past that
      // — it is an answer, not a failure. Spelling it `Absent` rather than
      // `Ok(vec![])` is the distinction the port's type exists to make.
      let outcome: std::result::Result<
        aph_core::discovery::DiscoveryOutcome<std::vec::Vec<String>>,
        aph_core::AphError,
      > = match self.wire.txt.get(name) {
        std::option::Option::Some(records) => std::result::Result::Ok(
          aph_core::discovery::DiscoveryOutcome::Found(records.clone()),
        ),
        std::option::Option::None => {
          std::result::Result::Ok(aph_core::discovery::DiscoveryOutcome::Absent)
        }
      };
      outcome
    })
  }
}

impl aph_core::discovery::ports::DidDocumentFetch for Resolver<'_> {
  fn fetch_did_document<'a>(
    &'a self,
    url: &'a str,
  ) -> aph_core::discovery::ports::DiscoveryFuture<'a, String> {
    std::boxed::Box::pin(async move {
      self
        .document_asked
        .lock()
        .expect("test mutex poisoned")
        .push(String::from(url));
      // No `Absent` on this port, and the omission is the contract: a 404 is
      // one more way an origin failed to hand over a document, and a verifier
      // cannot tell it from a 503. Absence on the did:web path is decided
      // AFTER parsing, by the document lacking the named fragment.
      let body: std::result::Result<String, aph_core::AphError> = match self.wire.https.get(url) {
        std::option::Option::Some(body) => std::result::Result::Ok(body.clone()),
        std::option::Option::None => {
          std::result::Result::Err(aph_core::AphError::NotaryServiceUnreachable)
        }
      };
      body
    })
  }
}

impl aph_core::discovery::ports::StatusCredentialFetch for Resolver<'_> {
  fn fetch_status_credential<'a>(
    &'a self,
    url: &'a str,
  ) -> aph_core::discovery::ports::DiscoveryFuture<'a, String> {
    std::boxed::Box::pin(async move {
      self
        .status_asked
        .lock()
        .expect("test mutex poisoned")
        .push(String::from(url));
      // Also no `Absent`, and here it is a security property: the status
      // surface has no alternate mechanism to advance to, so a URL that does
      // not answer is §6.3.3.4 case 2 — the check FAILED — never a licence to
      // skip it.
      let body: std::result::Result<String, aph_core::AphError> = match self.wire.https.get(url) {
        std::option::Option::Some(body) => std::result::Result::Ok(body.clone()),
        std::option::Option::None => {
          std::result::Result::Err(aph_core::AphError::NotaryServiceUnreachable)
        }
      };
      body
    })
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Status list publication
// ─────────────────────────────────────────────────────────────────────────

/// Length of every bitstring this suite publishes: 16,384 bytes = 131,072
/// entries, the minimum the W3C Bitstring Status List profile requires so that
/// the list itself does not identify whose mandate was revoked.
pub const STATUS_LIST_BYTES: usize = 16 * 1024;

/// A ten-byte RFC 1952 header: magic, DEFLATE method, no flags, zero mtime, no
/// extra flags, unknown OS.
///
/// ⛔ THE STREAMS THIS SUITE PUBLISHES ARE NOT REAL DEFLATE. §6.3.3.3 does
/// mandate GZIP, and a deployment's expander really does inflate; here the
/// "compressed" payload is this header followed by the raw bitstring, and
/// [`expand_status_list`] strips the header back off. The reason is a
/// dependency boundary rather than convenience: neither `aph-core` nor
/// `aph-conformance` links a compression codec — the workspace manifest pins
/// that on purpose, since `aph-core` goes into a wasm binding — and
/// hand-writing an inflater inside a test would be a second implementation of
/// a codec with no protocol content in it. This is the same stand-in
/// `aph_core::credential_status`'s own tests use, for the same reason, so what
/// is exercised end to end here is the §6.3.3.4 DECISION.
///
/// What the stand-in does NOT weaken: the bytes still travel base64url-encoded
/// inside published JSON, `aph_core::decode_encoded_list` still enforces the
/// multibase prefix and this magic, and the recipient's verdict still comes
/// from the bit it read out of them.
pub const GZIP_PLACEHOLDER_HEADER: [u8; 10] = [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff];

/// The caller-supplied expansion `aph_core::check_envelope_status` takes.
///
/// It honours the byte cap that contract puts on an expander — stopping rather
/// than handing back an over-long buffer — because that cap can only bound
/// anything at the place that produces the bytes.
pub fn expand_status_list(
  compressed: &[u8],
) -> std::result::Result<std::vec::Vec<u8>, aph_core::AphError> {
  // Sliced through `get`: a decompressor handed short input must report a
  // failure, never panic a verifier's task.
  let expanded = match compressed.get(GZIP_PLACEHOLDER_HEADER.len()..) {
    std::option::Option::Some(rest) => rest,
    std::option::Option::None => {
      return std::result::Result::Err(aph_core::AphError::NotaryServiceUnreachable);
    }
  };
  if expanded.len() > aph_core::credential_status::MAX_EXPANDED_LIST_BYTES {
    return std::result::Result::Err(aph_core::AphError::NotaryServiceUnreachable);
  }
  std::result::Result::Ok(std::vec::Vec::from(expanded))
}

/// A [`STATUS_LIST_BYTES`]-long bitstring with the bit SET at every index in
/// `revoked`.
///
/// Bit order is the W3C profile's: index 0 is the MOST significant bit of the
/// first byte. Getting it backwards would not fail — it would read a real bit
/// belonging to a DIFFERENT mandate — so the scenario files pin this setter
/// against `aph_core::revocation_bit`, the reader a verifier actually uses.
pub fn status_bitstring(revoked: &[u64]) -> std::vec::Vec<u8> {
  let mut bits = std::vec![0u8; STATUS_LIST_BYTES];
  for index in revoked {
    let byte = usize::try_from(index / 8).expect("a test index fits a usize");
    std::assert!(
      byte < bits.len(),
      "index {index} is past the end of a {STATUS_LIST_BYTES}-byte list"
    );
    bits[byte] |= 0x80u8 >> (index % 8) as u32;
  }
  bits
}

/// The multibase `encodedList` value for a bitstring: `u` + base64url-no-pad
/// over [`GZIP_PLACEHOLDER_HEADER`] followed by the bits.
pub fn encoded_list_value(bits: &[u8]) -> String {
  let mut bytes = std::vec::Vec::from(GZIP_PLACEHOLDER_HEADER);
  bytes.extend_from_slice(bits);
  std::format!(
    "{prefix}{body}",
    prefix = aph_core::credential_status::MULTIBASE_BASE64URL_PREFIX,
    body = base64url_no_pad(&bytes)
  )
}

/// base64url with no padding (RFC 4648 §5), the encoding `encodedList` wraps
/// its GZIP stream in.
///
/// ⛔ WHY THIS IS WRITTEN OUT HERE. `aph-core` already has this exact
/// transform, and it is `pub(crate)` — reachable from that crate's own tests
/// and from nowhere else — while `aph-conformance` deliberately carries no
/// `base64` dependency of its own. So the encode direction is unreachable from
/// an integration test, and only the encode direction: `decode_encoded_list`
/// IS public. That asymmetry is what makes this safe rather than a second
/// source of truth — `the_local_base64url_encoder_round_trips_through_aph_core`
/// feeds this function's output straight back through `aph-core`'s public
/// decoder, so the two cannot drift without a test failing.
fn base64url_no_pad(bytes: &[u8]) -> String {
  const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
  for chunk in bytes.chunks(3) {
    // Missing bytes contribute zero bits, and the loop below emits one
    // character per 6 bits actually present — which is what "no padding"
    // means: a 1-byte tail is 2 characters, a 2-byte tail is 3.
    let mut buffer = 0u32;
    for (position, byte) in chunk.iter().enumerate() {
      buffer |= u32::from(*byte) << (16 - 8 * position);
    }
    let characters = chunk.len() + 1;
    for slot in 0..characters {
      let index = ((buffer >> (18 - 6 * slot)) & 0x3f) as usize;
      out.push(char::from(ALPHABET[index]));
    }
  }
  out
}

/// A §6.3.3.3 status list credential, UNSIGNED — the shape a notary starts
/// from, and the shape an attacker forging one also starts from.
///
/// `issuer` is a parameter rather than being read off anything, because the
/// forgery this mechanism has to survive is precisely a document that writes
/// somebody else's DID into its own `issuer`.
pub fn status_list_document(
  issuer_did: &str,
  endpoint: &str,
  issued_at: &str,
  revoked: &[u64],
) -> String {
  let encoded = encoded_list_value(&status_bitstring(revoked));
  serde_json::to_string(&serde_json::json!({
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "id": endpoint,
    "type": ["VerifiableCredential", "BitstringStatusListCredential"],
    "issuer": issuer_did,
    "validFrom": issued_at,
    "credentialSubject": {
      "id": std::format!("{endpoint}#list"),
      "type": "BitstringStatusList",
      "statusPurpose": "revocation",
      "encodedList": encoded,
    }
  }))
  .expect("a JSON object serializes")
}

/// Attaches a §6.3.3.3 proof to a status list document.
///
/// Signed over `aph_core::status_list_signing_base` — the document minus its
/// own `proof` member, JCS-canonicalized — which is the same base
/// `verify_status_list_proof` recomputes on the reading side. Taking the key
/// as an argument is what lets a scenario hand this the ATTACKER's key and
/// prove the result does not read as "not revoked".
pub fn sign_status_list(
  unsigned_json: &str,
  key: &ed25519_dalek::SigningKey,
  verification_method: &str,
) -> String {
  let base =
    aph_core::status_list_signing_base(unsigned_json).expect("the document is a JSON object");
  let signature: ed25519_dalek::Signature = ed25519_dalek::Signer::sign(key, base.as_bytes());
  let mut value: serde_json::Value =
    serde_json::from_str(unsigned_json).expect("the document is valid JSON");
  value
    .as_object_mut()
    .expect("the document is a JSON object")
    .insert(
      String::from("proof"),
      serde_json::json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "proofPurpose": "assertionMethod",
        "verificationMethod": verification_method,
        "proofValue": aph_core::crypto::multibase::base58btc_encode(&signature.to_bytes()),
      }),
    );
  serde_json::to_string(&value).expect("re-serializing a JSON object cannot fail")
}

// ─────────────────────────────────────────────────────────────────────────
// The recipient
// ─────────────────────────────────────────────────────────────────────────

/// §8.3 step 1 — the strict parse, at the recipient's own boundary.
///
/// This is where the wire becomes a value. Every scenario calls it on a
/// `String` the sender produced, so the struct a recipient reasons about is one
/// the RECIPIENT built. An unknown field is a hard error (§7.1's
/// `deny_unknown_fields`), which is why the error is a message rather than an
/// `AphError`: §11's fifteen codes describe protocol outcomes, and bytes that
/// are not an envelope at all never reach one.
pub fn receive(bytes: &str) -> std::result::Result<aph_core::NotarizationEnvelope, String> {
  serde_json::from_str(bytes).map_err(|error| error.to_string())
}

/// What a recipient learned when it admitted an envelope.
///
/// Compared for equality in the relay scenario, where the claim under test is
/// that a verifier reaches the SAME verdict regardless of facts about itself.
#[derive(std::fmt::Debug, std::clone::Clone, std::cmp::PartialEq, std::cmp::Eq)]
pub struct Admission {
  /// The mode the proof STRUCTURE supports — never the declared label alone.
  pub mode: aph_core::AttestationMode,
  /// The human whose own key signed.
  pub human_principal: String,
  /// The agent the human authorized.
  pub agent: String,
  /// The notary that countersigned.
  pub notary: String,
  /// What §6.3.3.4 decided about the parent mandate.
  pub status: aph_core::StatusCheck,
}

/// The whole of §8.3 / §8.3.1 as a recipient runs it, against an envelope the
/// recipient parsed and keys the recipient resolved.
///
/// Nothing about the sender is assumed. The only inputs are the recipient's own
/// view of the wire, the parsed bytes, and the instant to evaluate at — passed
/// in, never read from a clock.
///
/// ⛔ WHAT THIS FUNCTION IS, so a reader does not mistake the scenarios for a
/// test of themselves. It is COMPOSITION, not logic: with two exceptions every
/// refusal below is `aph-core`'s, reached by calling `aph-core`'s public
/// functions in §8.3's order. The exceptions are named where they occur — the
/// wall-clock window comparison (`aph-core` deliberately owns no clock) and the
/// notary-DID binding (this harness's policy) — and no scenario depends on the
/// second. There is no assembled §8.3 recipient anywhere else in this
/// repository, which is exactly the gap these scenarios exist to close; if one
/// ever ships in `aph-core`, this should collapse onto it rather than persist
/// beside it.
///
/// Steps run in §8.3's order, and the order is load-bearing: every local check
/// that can refuse does so before the one step that may cost a network round
/// trip (8a, revocation status).
///
/// # Errors
///
/// The §11 code of the first step that refused. Callers assert the CODE, not
/// merely that something failed — a suite that only asserted `is_err()` would
/// pass against a verifier that refused everything for the wrong reason.
pub fn verify_inbound(
  resolver: &Resolver<'_>,
  envelope: &aph_core::NotarizationEnvelope,
  at_rfc3339: &str,
) -> std::result::Result<Admission, aph_core::AphError> {
  // §8.3.1 step 1a — refuse a claim weaker than policy demands BEFORE doing
  // work on unauthenticated input. Every recipient in this suite requires the
  // human's own signature; a notary's assertion about a human is strictly
  // weaker and is refused with APH_E012.
  aph_core::require_mode(envelope, aph_core::AttestationMode::PrincipalSigned)?;

  // §7.1.11 — the label is not evidence. This is what stops a notary key alone
  // from writing `PrincipalSigned` above a proof of its own.
  let mode = aph_core::verify_proof_structure(envelope)?;

  let principal_proof = match envelope.proof.principal() {
    std::option::Option::Some(proof) => proof,
    std::option::Option::None => {
      return std::result::Result::Err(aph_core::AphError::proof_chain_invalid(
        "a PrincipalSigned envelope must carry a principal proof (§7.1.11)",
      ));
    }
  };
  let notary_proof = match envelope.proof.notary() {
    std::option::Option::Some(proof) => proof,
    std::option::Option::None => {
      return std::result::Result::Err(aph_core::AphError::proof_chain_invalid(
        "a PrincipalSigned envelope must carry a notary countersignature (§7.1.11)",
      ));
    }
  };

  // §8.3.1 step 1b — the principal is a `did:key`, so the key IS the
  // identifier. Resolved through the same composer the notary key goes
  // through, which means this path provably touches no port at all (§8.4.3).
  let principal_key = block_on(aph_core::discovery::composer::resolve(
    aph_core::discovery::composer::MechanismSelection::NamedByDid,
    &principal_proof.verification_method,
    resolver,
    resolver,
    &envelope.credential_subject.notarization.decision_timestamp,
  ))?
  .to_ed25519()?;

  // §8.3.1 step 1c — APH_E011. A countersignature cannot rescue an
  // unauthorized envelope, so this runs before the notary proof is looked at.
  aph_core::verify_proof(envelope, aph_core::ProofRole::Principal, &principal_key)?;

  // §8.3 step 2 for the notary proof — the §8.4.6 chain, across a trust
  // boundary. The instant is the envelope's own `decisionTimestamp` (§8.4.7),
  // NOT `at_rfc3339`: the question is which key was valid when the envelope was
  // signed.
  let notary_key = block_on(aph_core::discovery::composer::resolve(
    aph_core::discovery::composer::MechanismSelection::NamedByDid,
    &notary_proof.verification_method,
    resolver,
    resolver,
    &envelope.credential_subject.notarization.decision_timestamp,
  ))?
  .to_ed25519()?;

  // §8.3 steps 3-5 — APH_E001.
  aph_core::verify_proof(envelope, aph_core::ProofRole::Notary, &notary_key)?;

  // §7.2.1 — the notary prepares, the human signs, the notary countersigns.
  aph_core::verify_timestamp_order(envelope)?;

  // §8.3.1 step 1d — is the embedded mandate THIS envelope's parent, and does
  // this envelope's window fall inside the mandate's?
  aph_core::verify_embedded_mandate_binding(envelope)?;

  // §6.1 — the mandate's own two signatures. Without these the mandate is a
  // shape, and an attacker could staple any well-formed mandate to any
  // envelope. Checked under the SAME two keys the proofs were checked under, so
  // a mandate signed by anyone else fails here.
  if let std::option::Option::Some(mandate) = envelope
    .credential_subject
    .policy
    .delegation_mandate
    .as_ref()
  {
    if !mandate_role_verifies(mandate, aph_core::ProofRole::Principal, &principal_key) {
      return std::result::Result::Err(aph_core::AphError::PrincipalSignatureInvalid);
    }
    if !mandate_role_verifies(mandate, aph_core::ProofRole::Notary, &notary_key) {
      return std::result::Result::Err(aph_core::AphError::NotarySignatureInvalid);
    }
    // §8.3 step 6, applied to the authority rather than the credential: an
    // envelope inside its own window whose MANDATE has run out is authority
    // that expired on schedule (APH_E003), which §11 holds distinct from
    // authority that was withdrawn (APH_E015).
    if !mandate.is_valid_at(at_rfc3339) {
      return std::result::Result::Err(aph_core::AphError::mandate_expired(mandate.id.as_str()));
    }
  }

  // §8.3 step 6 — `validFrom <= now <= validUntil`. `aph-core` deliberately
  // owns no clock, so this is the recipient's step, and the instant arrives as
  // an argument.
  if !instant_is_inside_window(&envelope.valid_from, &envelope.valid_until, at_rfc3339) {
    return std::result::Result::Err(aph_core::AphError::mandate_expired(envelope.id.as_str()));
  }

  // A recipient that resolved the signing key from one DID and then asks a
  // DIFFERENT DID's origin whether the mandate is revoked has authenticated the
  // wrong party's answer. §6.3.3.2 derives the status origin from
  // `notaryService.id`; §8.3 resolves the key from `proof.verificationMethod`.
  // Requiring them to name the same DID is this harness's policy, stated
  // because §11's fifteen codes have no dedicated binding failure and
  // APH_E013 is the nearest — it is a malformed proof block, in that the proof
  // does not belong to the notary the envelope names.
  let signing_did = aph_core::DidUrl::parse(&notary_proof.verification_method).did;
  let named_notary = &envelope.credential_subject.notarization.notary_service.id;
  if &signing_did != named_notary {
    return std::result::Result::Err(aph_core::AphError::proof_chain_invalid(std::format!(
      "the notary proof was made under `{signing_did}` but the envelope names \
       `{named_notary}` as its notary service; the revocation status of one \
       party is not evidence about another (§6.3.3.2 step 1)"
    )));
  }

  // §8.3 step 8a — the only step that may cost a round trip, and the last one
  // for that reason. The key handed in is the one resolved above: an
  // unauthenticated status list is an unauthenticated assertion about whether
  // somebody's authority still holds.
  let expander: &aph_core::credential_status::ExpandEncodedList<'_> = &expand_status_list;
  let status = block_on(aph_core::check_envelope_status(
    envelope,
    resolver,
    expander,
    &notary_key,
    at_rfc3339,
  ))?;

  std::result::Result::Ok(Admission {
    mode,
    human_principal: envelope.credential_subject.human_principal.id.clone(),
    agent: envelope.credential_subject.agent.id.clone(),
    notary: named_notary.clone(),
    status,
  })
}

/// `from <= at <= until`, compared as RFC 3339 instants.
///
/// Delegated to `aph-core`'s own window comparison rather than to a string
/// compare, which would order `+00:00` differently from the same instant
/// written `Z`. The throwaway mandate is the shape that comparison lives on;
/// `aph-conformance` links no date library of its own, and introducing one to
/// re-answer a question this workspace already answers is how two components
/// come to disagree about when a window closed.
fn instant_is_inside_window(from: &str, until: &str, at: &str) -> bool {
  aph_core::DelegationMandate {
    id: String::new(),
    human_principal_did: String::new(),
    agent_did: String::new(),
    allowed_channels: std::vec::Vec::new(),
    rate_limit_per_hour: std::option::Option::None,
    valid_from: String::from(from),
    valid_until: String::from(until),
    principal_signature: String::new(),
    notary_signature: String::new(),
  }
  .is_valid_at(at)
}

/// Drives a future to completion on the calling thread.
///
/// The three discovery ports return futures because a real adapter does I/O;
/// none of the doubles here does, so every future is `Ready` on the first poll.
///
/// ⛔ WHY THIS IS COPIED RATHER THAN REUSED. `aph-core` has the identical
/// twelve lines, and they are `#[cfg(test)] pub(crate)` — reachable from that
/// crate's own tests and from nowhere else. The alternative, an async runtime
/// dependency, is one the workspace manifest forbids this crate outright:
/// `aph-resolver` is the ONLY crate permitted an edge to `tokio`, and that
/// separation is what keeps the rest of the workspace testable with no runtime
/// at all. So the choice is these twelve lines or a banned dependency.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
  struct ThreadWaker(std::thread::Thread);
  impl std::task::Wake for ThreadWaker {
    fn wake(self: std::sync::Arc<Self>) {
      self.0.unpark();
    }
  }
  let waker = std::task::Waker::from(std::sync::Arc::new(ThreadWaker(std::thread::current())));
  let mut context = std::task::Context::from_waker(&waker);
  let mut future = std::pin::pin!(future);
  loop {
    match std::future::Future::poll(future.as_mut(), &mut context) {
      std::task::Poll::Ready(value) => return value,
      std::task::Poll::Pending => std::thread::park(),
    }
  }
}
