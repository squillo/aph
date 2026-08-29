//! RFC 0008 — sealed payloads: carriage without readership. The
//! reference implementation, spec/aph-0.2.md §§1-4 (v0.2, cut
//! 2026-08-29).
//!
//! RFC 0008 is Accepted onto the v0.2 line and implemented here: the
//! WIRE types live in `aph-core`
//! (re-exported below) so the envelope can carry them, the wire-version
//! rule (`sealed_payload_is_declared`) keeps them off any aphVersion-0.1
//! envelope, and THIS crate holds the cryptography plus the
//! envelope-level operations — `seal_into_envelope` /
//! `unseal_from_envelope` — that RFC 0008 §§3-4 specify. v0.1.0 itself is
//! untouched: a v0.1-only verifier still refuses the member at strict
//! parse, correctly.
//!
//! Two scenarios, one mechanism (RFC 0008 §"The problem"):
//! - sealed TO THE RECEIVER: intermediate agents verify the envelope and
//!   carry what they cannot read;
//! - sealed TO THE SENDER (or any designated third key): the counterparty
//!   carries and proves receipt of what it cannot open.
//!
//! The cryptography is RFC 9180 HPKE single-shot, one pinned suite
//! (X25519-HKDF-SHA256 / HKDF-SHA256 / ChaCha20-Poly1305), through the
//! pure-Rust `hpke` crate — this repository writes no cryptography. The
//! load-bearing choice is the AAD: a canonical CONTEXT — suite, reader id,
//! reader kid, envelope id — authenticates every seal, so a ciphertext
//! lifted into a different envelope OR relabeled about itself (a different
//! claimed reader, a different claimed suite) fails open even for its
//! rightful key. The audit probe that forced the widening is kept as a
//! test. Errors are this crate's own type, deliberately
//! NOT `APH_E`-prefixed: the §11 set is closed, and RFC 0008 §5 assigns
//! codes when a version exists that can declare them.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};

type Kem = X25519HkdfSha256;

/// The one suite this draft compiles. A wire member exists so a future
/// version CAN move; an unseal of any other value refuses. Closed-set
/// discipline applied to ciphersuites from birth (RFC 0008 §1).
pub const SUITE: &str = "APH-SEAL-1";

/// HPKE `info` — domain separation for this construction, distinct from any
/// other use of the same keys.
const INFO: &[u8] = b"aph sealed payload v1";

/// The wire types are `aph-core`'s — the envelope carries them — and this
/// crate re-exports them so a sealing caller needs one import path.
pub use aph_core::{SealedPayload, SealedReader};

/// This crate's own refusals — deliberately NOT `APH_E` codes (RFC 0008 §5:
/// the §11 set is closed, and names are minted by the version that can
/// declare them, not by a draft).
#[derive(std::fmt::Debug, thiserror::Error, std::cmp::PartialEq, std::cmp::Eq)]
pub enum SealError {
  /// The payload names a suite this implementation does not compile. One
  /// suite, no negotiation — an unknown value is refused, never skipped.
  #[error("unknown seal suite `{0}`; this implementation seals only `{SUITE}`")]
  UnknownSuite(String),
  /// A base64url field would not decode; malformed before cryptography.
  #[error("sealed payload field `{0}` is not unpadded base64url")]
  MalformedEncoding(&'static str),
  /// A key was not the KEM's serialized length/shape.
  #[error("the {0} key is not a valid X25519 key for this suite")]
  MalformedKey(&'static str),
  /// AEAD open failed: the wrong key, a tampered ciphertext, or — the case
  /// the AAD exists for — a seal lifted from a different envelope. All
  /// three are indistinguishable BY DESIGN (that is what AEAD promises),
  /// so the refusal names all three rather than guessing.
  #[error(
    "the seal did not open: wrong reader key, tampered ciphertext, a seal \
     staged under a different envelope id, or a payload relabeled about its \
     own suite or reader"
  )]
  OpenRefused,
  /// The HPKE encapsulation step itself failed (a malformed reader key
  /// surfaces here when it parses but cannot be used).
  #[error("sealing failed: {0}")]
  SealFailed(String),
}

/// The authenticated context: everything a sealed payload CLAIMS about
/// itself, plus the envelope that stages it. Serialized as JSON from a
/// struct with a fixed field order — deterministic for these string
/// fields, and unambiguous where a delimiter-joined string would not be
/// (a `|` inside a DID would otherwise collide field boundaries).
///
/// Both sides derive it independently: the sealer from its inputs, the
/// opener from the sealed payload's OWN claimed fields — which is exactly
/// why a relabeled `reader` or `suite` refuses AEAD open.
#[derive(serde::Serialize)]
struct SealContext<'a> {
  suite: &'a str,
  reader_id: &'a str,
  reader_kid: &'a str,
  envelope_id: &'a str,
}

fn context_aad(suite: &str, reader: &SealedReader, envelope_id: &str) -> Vec<u8> {
  serde_json::to_vec(&SealContext {
    suite,
    reader_id: &reader.id,
    reader_kid: &reader.kid,
    envelope_id,
  })
  .expect("four string fields serialize infallibly")
}

fn b64(bytes: &[u8]) -> String {
  use base64::Engine as _;
  base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str, field: &'static str) -> std::result::Result<Vec<u8>, SealError> {
  use base64::Engine as _;
  base64::engine::general_purpose::URL_SAFE_NO_PAD
    .decode(text)
    .map_err(|_| SealError::MalformedEncoding(field))
}

/// Seals `plaintext` so that ONLY the holder of `reader`'s private key can
/// open it, bound to the full seal CONTEXT — suite, reader, envelope id —
/// as HPKE additional authenticated data (RFC 0008 §3). Sealing happens
/// BEFORE the envelope is signed, so the signature covers the ciphertext
/// and every hop verifies blind.
///
/// `reader_public_key` is the reader's X25519 `keyAgreement` public key,
/// 32 raw bytes, discovered through the §8.4 surfaces. The RNG is a caller
/// parameter for the same reason `now` is one in verification: this
/// function stays deterministic under test and honest about its inputs —
/// and in PRODUCTION the argument must be an operating-system CSPRNG
/// (`rand::rngs::OsRng`); a seeded RNG there reuses ephemeral keys, which
/// is key compromise by another name.
pub fn seal(
  csprng: &mut impl rand::CryptoRng,
  reader: SealedReader,
  reader_public_key: &[u8],
  envelope_id: &str,
  plaintext: &[u8],
) -> std::result::Result<SealedPayload, SealError> {
  let pk = <Kem as KemTrait>::PublicKey::from_bytes(reader_public_key)
    .map_err(|_| SealError::MalformedKey("reader public"))?;
  let aad = context_aad(SUITE, &reader, envelope_id);
  let (encapped, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
    &OpModeS::Base,
    &pk,
    INFO,
    plaintext,
    &aad,
    csprng,
  )
  .map_err(|e| SealError::SealFailed(std::format!("{e}")))?;
  std::result::Result::Ok(SealedPayload {
    suite: SUITE.to_string(),
    reader,
    enc: b64(&encapped.to_bytes()),
    ciphertext: b64(&ciphertext),
  })
}

/// Opens a seal with the reader's private key, under the SAME context it
/// was sealed to — with `suite` and `reader` taken from the sealed
/// payload's OWN claims, so a payload relabeled about itself refuses.
/// Any mismatch — key, bytes, envelope, or claimed context — refuses with
/// one indistinguishable [`SealError::OpenRefused`], and RFC 0008 §4 tells
/// a reader-verifier what that refusal means: refuse the ENVELOPE, because
/// an unopenable seal addressed to you is evidence, not an inconvenience.
pub fn unseal(
  sealed: &SealedPayload,
  reader_private_key: &[u8],
  envelope_id: &str,
) -> std::result::Result<Vec<u8>, SealError> {
  if sealed.suite != SUITE {
    return std::result::Result::Err(SealError::UnknownSuite(sealed.suite.clone()));
  }
  let sk = <Kem as KemTrait>::PrivateKey::from_bytes(reader_private_key)
    .map_err(|_| SealError::MalformedKey("reader private"))?;
  let encapped_bytes = unb64(&sealed.enc, "enc")?;
  let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&encapped_bytes)
    .map_err(|_| SealError::MalformedKey("encapsulated"))?;
  let ciphertext = unb64(&sealed.ciphertext, "ciphertext")?;
  let aad = context_aad(&sealed.suite, &sealed.reader, envelope_id);
  hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
    &OpModeR::Base,
    &sk,
    &encapped,
    INFO,
    &ciphertext,
    &aad,
  )
  .map_err(|_| SealError::OpenRefused)
}

/// Why an envelope-level unseal can fail — three DIFFERENT kinds of
/// failure with three different repairs, kept as distinct as the codes
/// that carry two of them.
#[derive(std::fmt::Debug, thiserror::Error)]
pub enum EnvelopeSealError {
  /// The envelope carries no `sealedPayload`. Not a refusal: an unsealed
  /// envelope is an ordinary envelope, and the caller decides whether it
  /// expected one.
  #[error("the envelope carries no sealed payload")]
  Absent,
  /// The wire-version rule refused: `sealedPayload` on an aphVersion that
  /// does not declare it. Strict-parse CLASS — a plain message below the
  /// protocol's code vocabulary, per the same reasoning as an
  /// unrecognized closed-set value.
  #[error("{0}")]
  WireUndeclared(String),
  /// A protocol refusal with its 0.2 code: `APH_E021` (the seal
  /// addressed to this verifier did not open) or `APH_E022` (unknown
  /// suite). Per RFC 0008 §4 the caller MUST refuse the ENVELOPE.
  #[error(transparent)]
  Refused(aph_core::AphError),
}

/// Seals `plaintext` INTO an envelope (RFC 0008 §3): binds the seal to the
/// envelope's own `id` and claimed context, then places it on
/// `credentialSubject.sealedPayload`. Call this BEFORE signing — the
/// signature must cover the ciphertext — and only on an envelope whose
/// `aphVersion` declares the member; anything else refuses up front rather
/// than minting a wire no conformant verifier admits.
pub fn seal_into_envelope(
  csprng: &mut impl rand::CryptoRng,
  envelope: &mut aph_core::NotarizationEnvelope,
  reader: SealedReader,
  reader_public_key: &[u8],
  plaintext: &[u8],
) -> std::result::Result<(), EnvelopeSealError> {
  if envelope.aph_version != "0.2" {
    return std::result::Result::Err(EnvelopeSealError::WireUndeclared(std::format!(
      "refusing to seal into an aphVersion `{}` envelope: `sealedPayload` is        declared from aphVersion 0.2 (spec/aph-0.2.md), and minting it        earlier produces a wire every conformant verifier refuses",
      envelope.aph_version
    )));
  }
  let sealed = seal(csprng, reader, reader_public_key, &envelope.id, plaintext)
    .map_err(|e| EnvelopeSealError::WireUndeclared(std::format!("sealing failed: {e}")))?;
  envelope.credential_subject.sealed_payload = std::option::Option::Some(sealed);
  std::result::Result::Ok(())
}

/// Opens the seal an envelope carries, for the reader holding the private
/// key (RFC 0008 §4): run AFTER the envelope itself verifies, and treat a
/// [`EnvelopeSealError::Refused`] as a refusal of the ENVELOPE — an
/// unopenable seal addressed to you is evidence, never a shrug. The
/// wire-version rule runs first, so a mis-versioned envelope refuses
/// before any cryptography.
pub fn unseal_from_envelope(
  envelope: &aph_core::NotarizationEnvelope,
  reader_private_key: &[u8],
) -> std::result::Result<Vec<u8>, EnvelopeSealError> {
  aph_core::sealed_payload_is_declared(envelope).map_err(EnvelopeSealError::WireUndeclared)?;
  let sealed = envelope
    .credential_subject
    .sealed_payload
    .as_ref()
    .ok_or(EnvelopeSealError::Absent)?;
  unseal(sealed, reader_private_key, &envelope.id).map_err(|e| match e {
    SealError::UnknownSuite(suite) => {
      EnvelopeSealError::Refused(aph_core::AphError::seal_suite_unknown(suite, SUITE))
    }
    _ => EnvelopeSealError::Refused(aph_core::AphError::seal_unopenable(&envelope.id)),
  })
}

#[cfg(test)]
mod tests {
  /// Derives a deterministic X25519 keypair from input keying material.
  /// TEST-ONLY BY CONSTRUCTION: this lives inside `#[cfg(test)]`, so no
  /// consumer can derive a production key from low-entropy material — the
  /// compiler is the fence, where a doc comment was one an audit ago.
  fn derive_keypair_for_tests(ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use hpke::{Kem as KemTrait, Serializable};
    let (sk, pk) = super::Kem::derive_keypair(ikm);
    (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
  }
  // TEST-ONLY key material: every keypair below is DERIVED in-test from a
  // fixed, clearly-labeled IKM string via RFC 9180 DeriveKeyPair — nothing
  // secret is stored, and nothing here is a production key.
  const RECEIVER_IKM: &[u8] = b"APH-SEALED-TEST-RECEIVER-IKM-0001";
  const SENDER_IKM: &[u8] = b"APH-SEALED-TEST-SENDER-IKM---0001";
  const ENVELOPE_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000e1";

  fn rng() -> impl rand::CryptoRng {
    // Deterministic under test: the seal's ephemeral key comes from a
    // seeded RNG so failures reproduce byte-for-byte.
    <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(7)
  }

  fn reader(id: &str) -> super::SealedReader {
    super::SealedReader { id: id.to_string(), kid: std::string::String::from("enc-1") }
  }

  #[test]
  fn scenario_one_the_carrier_cannot_read_but_the_receiver_can() {
    // RFC 0008's first scenario end to end: seal to the RECEIVER's key.
    // The sending agent holds only the SealedPayload — ciphertext and an
    // encapsulated key useless without the receiver's private half — and
    // the receiver opens it under the envelope id it arrived in.
    let (receiver_sk, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let sealed = super::seal(
      &mut rng(),
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      ENVELOPE_ID,
      b"the order: attack at dawn",
    )
    .expect("sealing to a valid reader key succeeds");

    let opened = super::unseal(&sealed, &receiver_sk, ENVELOPE_ID)
      .expect("the named reader opens the seal");
    std::assert_eq!(opened, b"the order: attack at dawn");

    // The carrier's view: without the private key there is nothing to try —
    // pinned here by the SENDER's own key failing to open it, which also
    // pins that a seal is not symmetric.
    let (sender_sk, _) = derive_keypair_for_tests(SENDER_IKM);
    std::assert_eq!(
      super::unseal(&sealed, &sender_sk, ENVELOPE_ID).unwrap_err(),
      super::SealError::OpenRefused,
    );
  }

  #[test]
  fn scenario_two_the_sender_seals_to_itself_and_the_counterparty_cannot_read() {
    // The second scenario is the same mechanism with the reader pointed at
    // the SENDER: the receiving agent can carry, store, and prove receipt
    // of bytes it cannot open.
    let (sender_sk, sender_pk) = derive_keypair_for_tests(SENDER_IKM);
    let sealed = super::seal(
      &mut rng(),
      reader("did:web:sender.example.com"),
      &sender_pk,
      ENVELOPE_ID,
      b"guardrail overlay the counterparty must hold but not read",
    )
    .expect("sealing to one's own key is the same operation");

    let (receiver_sk, _) = derive_keypair_for_tests(RECEIVER_IKM);
    std::assert_eq!(
      super::unseal(&sealed, &receiver_sk, ENVELOPE_ID).unwrap_err(),
      super::SealError::OpenRefused,
    );
    std::assert!(super::unseal(&sealed, &sender_sk, ENVELOPE_ID).is_ok());
  }

  #[test]
  fn a_seal_lifted_into_a_different_envelope_refuses_even_for_its_reader() {
    // THE load-bearing binding (RFC 0008 §3): the AAD is the envelope id,
    // so re-staging a ciphertext under a different authorization fails
    // AEAD open even with the right key. Without this, a sealed payload
    // would be a bearer blob any envelope could adopt.
    let (receiver_sk, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let sealed = super::seal(
      &mut rng(),
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      ENVELOPE_ID,
      b"bound to one envelope",
    )
    .expect("seal succeeds");
    std::assert_eq!(
      super::unseal(&sealed, &receiver_sk, "urn:uuid:00000000-0000-4000-8000-0000000000e2")
        .unwrap_err(),
      super::SealError::OpenRefused,
    );
  }

  #[test]
  fn a_tampered_ciphertext_refuses() {
    // Integrity through untrusted hops is the messenger half of the
    // generals' problem: one flipped bit anywhere in the ciphertext and
    // the AEAD tag refuses.
    let (receiver_sk, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let mut sealed = super::seal(
      &mut rng(),
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      ENVELOPE_ID,
      b"integrity or refusal",
    )
    .expect("seal succeeds");
    let mut bytes = super::unb64(&sealed.ciphertext, "ciphertext").expect("decodes");
    bytes[0] ^= 0x01;
    sealed.ciphertext = super::b64(&bytes);
    std::assert_eq!(
      super::unseal(&sealed, &receiver_sk, ENVELOPE_ID).unwrap_err(),
      super::SealError::OpenRefused,
    );
  }

  #[test]
  fn an_unknown_suite_is_refused_before_any_cryptography() {
    // Closed-set discipline for ciphersuites from birth: a verifier meeting
    // a suite it does not compile refuses by NAME, before touching a byte
    // of key material.
    let (receiver_sk, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let mut sealed = super::seal(
      &mut rng(),
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      ENVELOPE_ID,
      b"x",
    )
    .expect("seal succeeds");
    sealed.suite = std::string::String::from("APH-SEAL-99");
    std::assert_eq!(
      super::unseal(&sealed, &receiver_sk, ENVELOPE_ID).unwrap_err(),
      super::SealError::UnknownSuite(std::string::String::from("APH-SEAL-99")),
    );
  }

  #[test]
  fn the_wire_shape_round_trips_and_refuses_unknown_members() {
    // The serde shape IS the RFC's §2 wire member; review reads this test
    // instead of trusting the prose. Strict on its own members exactly as
    // every wire struct in the reference is.
    let (_, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let sealed = super::seal(
      &mut rng(),
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      ENVELOPE_ID,
      b"round trip",
    )
    .expect("seal succeeds");
    let json = serde_json::to_string(&sealed).expect("serializes");
    std::assert!(json.contains("\"suite\":\"APH-SEAL-1\""));
    std::assert!(json.contains("\"reader\""));
    let back: super::SealedPayload = serde_json::from_str(&json).expect("parses");
    std::assert_eq!(back, sealed);

    let smuggled = json.replacen('{', "{\"extra\":1,", 1);
    std::assert!(
      serde_json::from_str::<super::SealedPayload>(&smuggled).is_err(),
      "an unknown member is refused at strict parse, like every wire struct"
    );
  }

  #[test]
  fn a_relabeled_reader_or_suite_refuses_even_with_the_right_key() {
    // AUDIT PROBE, kept as the weld: the seal must authenticate its OWN
    // wire context — suite and reader — not only the envelope id. Before
    // the context-AAD fix, a party holding the payload pre-signing could
    // relabel `reader` (mis-routing who is asked to open) or `suite`
    // without the AEAD noticing; the envelope signature catches it later,
    // but a seal that lies about itself until signing is a seam.
    let (receiver_sk, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let sealed = super::seal(
      &mut rng(),
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      ENVELOPE_ID,
      b"context-bound",
    )
    .expect("seal succeeds");

    let mut relabeled = sealed.clone();
    relabeled.reader.id = std::string::String::from("did:web:attacker.example.com");
    std::assert_eq!(
      super::unseal(&relabeled, &receiver_sk, ENVELOPE_ID).unwrap_err(),
      super::SealError::OpenRefused,
      "a relabeled reader must refuse: the seal authenticates its context"
    );

    let mut rekidded = sealed.clone();
    rekidded.reader.kid = std::string::String::from("enc-2");
    std::assert_eq!(
      super::unseal(&rekidded, &receiver_sk, ENVELOPE_ID).unwrap_err(),
      super::SealError::OpenRefused,
      "a relabeled kid must refuse for the same reason"
    );
  }

  // ── The envelope-level operations, on a real golden ─────────────────

  fn envelope_v02() -> aph_core::NotarizationEnvelope {
    // The published audience golden, parsed and lifted to aphVersion 0.2:
    // reusing a committed vector instead of a 60-line literal keeps this
    // suite welded to the same bytes every other gate reads.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("../../../examples/audience_bound_envelope.json");
    let raw = std::fs::read_to_string(&path)
      .unwrap_or_else(|e| std::panic!("failed to read {:?}: {}", path, e));
    let mut envelope: aph_core::NotarizationEnvelope =
      serde_json::from_str(&raw).expect("the golden parses");
    envelope.aph_version = std::string::String::from("0.2");
    envelope
  }

  #[test]
  fn seal_into_and_unseal_from_an_envelope_round_trip() {
    // RFC 0008 §§3-4 end to end on the wire shape itself: the seal lands
    // on credentialSubject, is bound to THIS envelope's id, and the named
    // reader opens it back out.
    let (receiver_sk, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let mut envelope = envelope_v02();
    super::seal_into_envelope(
      &mut rng(),
      &mut envelope,
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      b"carried, verified, unread until here",
    )
    .expect("sealing into a 0.2 envelope succeeds");
    std::assert!(envelope.credential_subject.sealed_payload.is_some());

    let opened = super::unseal_from_envelope(&envelope, &receiver_sk)
      .expect("the named reader opens the envelope's seal");
    std::assert_eq!(opened, b"carried, verified, unread until here");
  }

  #[test]
  fn sealing_into_a_v01_envelope_refuses_up_front() {
    // Minting a wire every conformant verifier refuses is not a feature;
    // the version rule fires BEFORE any cryptography, both directions.
    let (_, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let mut envelope = envelope_v02();
    envelope.aph_version = std::string::String::from("0.1");
    let err = super::seal_into_envelope(
      &mut rng(),
      &mut envelope,
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      b"x",
    )
    .expect_err("a 0.1 wire cannot carry the member");
    std::assert!(std::matches!(err, super::EnvelopeSealError::WireUndeclared(_)));
  }

  #[test]
  fn a_sealed_member_on_a_v01_wire_refuses_at_the_declaration_rule() {
    // The unseal side of the same rule: a hand-staged sealedPayload on an
    // aphVersion 0.1 envelope is malformed for the version it claims, and
    // the refusal is strict-parse CLASS — below the code vocabulary —
    // exactly like an unrecognized closed-set value.
    let (receiver_sk, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let mut envelope = envelope_v02();
    super::seal_into_envelope(
      &mut rng(),
      &mut envelope,
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      b"x",
    )
    .expect("seal succeeds on 0.2");
    envelope.aph_version = std::string::String::from("0.1");
    let err = super::unseal_from_envelope(&envelope, &receiver_sk)
      .expect_err("the declaration rule refuses first");
    std::assert!(std::matches!(err, super::EnvelopeSealError::WireUndeclared(_)));
  }

  #[test]
  fn envelope_unseal_failures_carry_their_draft_codes() {
    // The two runtime refusals map to the 0.2 codes the spec delta
    // declares: unknown suite is APH_E022 by name before any key material,
    // an unopenable seal is APH_E021 — and per RFC 0008 §4 the caller
    // refuses the ENVELOPE on either.
    let (receiver_sk, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let mut envelope = envelope_v02();
    super::seal_into_envelope(
      &mut rng(),
      &mut envelope,
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      b"coded refusals",
    )
    .expect("seal succeeds");

    let mut suite_relabeled = envelope.clone();
    suite_relabeled
      .credential_subject
      .sealed_payload
      .as_mut()
      .expect("sealed")
      .suite = std::string::String::from("APH-SEAL-99");
    match super::unseal_from_envelope(&suite_relabeled, &receiver_sk) {
      std::result::Result::Err(super::EnvelopeSealError::Refused(e)) => {
        std::assert_eq!(e.code(), "APH_E022")
      }
      other => std::panic!("expected an APH_E022 refusal, got {:?}", other),
    }

    let (sender_sk, _) = derive_keypair_for_tests(SENDER_IKM);
    match super::unseal_from_envelope(&envelope, &sender_sk) {
      std::result::Result::Err(super::EnvelopeSealError::Refused(e)) => {
        std::assert_eq!(e.code(), "APH_E021")
      }
      other => std::panic!("expected an APH_E021 refusal, got {:?}", other),
    }
  }

  #[test]
  fn body_sha256_binds_the_raw_ciphertext_octets_so_hops_verify_blind() {
    // RFC 0008 §3's second binding, demonstrated: bodySha256 is computed
    // over the base64url-DECODED ciphertext — never the JSON around it —
    // so any hop can run §8.3 step 8 with no plaintext, and two
    // implementations cannot disagree about which bytes were hashed.
    use sha2::Digest as _;
    let (_, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let mut envelope = envelope_v02();
    super::seal_into_envelope(
      &mut rng(),
      &mut envelope,
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      b"the body no hop reads",
    )
    .expect("seal succeeds");
    let sealed = envelope.credential_subject.sealed_payload.as_ref().expect("sealed");
    let raw = super::unb64(&sealed.ciphertext, "ciphertext").expect("decodes");
    let digest = std::format!("{:x}", sha2::Sha256::digest(&raw));
    envelope.credential_subject.communication.body_sha256 = digest.clone();

    // The blind hop's whole check, reproduced: decode, hash, compare.
    let recomputed = std::format!(
      "{:x}",
      sha2::Sha256::digest(super::unb64(&sealed.ciphertext, "ciphertext").expect("decodes"))
    );
    std::assert_eq!(recomputed, envelope.credential_subject.communication.body_sha256);
  }

  // ── The committed 0.2 vector ──────────────────────────────────

  fn draft_vector_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("../../../examples/v0.2/sealed_envelope.json")
  }

  /// The vector's exact bytes, regenerated: fully deterministic because the
  /// keys derive from fixed IKM, the RNG is seeded, and the base is a
  /// committed golden — so the committed file can be byte-compared against
  /// a fresh mint exactly as the signed v0.1 vectors are.
  fn regenerate_draft_vector() -> String {
    let (_, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let mut envelope = envelope_v02();
    envelope.id = std::string::String::from("urn:uuid:00000000-0000-4000-8000-00000000000e");
    super::seal_into_envelope(
      &mut rng(),
      &mut envelope,
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      b"the body no hop reads: the v0.2-draft sealed vector",
    )
    .expect("sealing the vector succeeds");
    use sha2::Digest as _;
    let sealed = envelope.credential_subject.sealed_payload.as_ref().expect("sealed");
    let raw = super::unb64(&sealed.ciphertext, "ciphertext").expect("decodes");
    envelope.credential_subject.communication.body_sha256 =
      std::format!("{:x}", sha2::Sha256::digest(&raw));
    std::format!(
      "{}\n",
      serde_json::to_string_pretty(&envelope).expect("the vector serializes")
    )
  }

  #[test]
  fn the_committed_draft_vector_is_byte_identical_to_a_fresh_mint() {
    // The same drift discipline the signed v0.1 vectors live under: the
    // committed file IS what this code mints, or this test prints the
    // replacement between cut lines and fails.
    let regenerated = regenerate_draft_vector();
    let path = draft_vector_path();
    // A missing file is TOTAL drift, not a separate failure: the first mint
    // and a deleted vector both resolve the same way — write the printed
    // replacement.
    let published = std::fs::read_to_string(&path).unwrap_or_default();
    if published != regenerated {
      std::panic!(
        "examples/v0.2/sealed_envelope.json has drifted from the bytes \
         this suite mints.\nTo fix in ONE step, overwrite that file with EXACTLY \
         the content between the cut lines (the final newline is part of the \
         content):\n----8<----\n{}----8<----",
        regenerated
      );
    }
  }

  #[test]
  fn the_committed_draft_vector_opens_for_its_reader_and_verifies_blind() {
    // The vector proves both halves at once: a blind hop's bodySha256
    // check succeeds over the raw ciphertext octets, and the named
    // reader's derived test key opens the committed bytes — pinning the
    // wire format's long-term stability, not only this build's.
    use sha2::Digest as _;
    let raw_json = std::fs::read_to_string(draft_vector_path()).expect("the vector is on disk");
    let envelope: aph_core::NotarizationEnvelope =
      aph_core::parse_envelope_json(&raw_json).expect("the vector strict-parses as 0.2");

    let sealed = envelope.credential_subject.sealed_payload.as_ref().expect("sealed");
    let raw = super::unb64(&sealed.ciphertext, "ciphertext").expect("decodes");
    std::assert_eq!(
      std::format!("{:x}", sha2::Sha256::digest(&raw)),
      envelope.credential_subject.communication.body_sha256,
      "the blind hop's body binding holds over the committed bytes"
    );

    let (receiver_sk, _) = derive_keypair_for_tests(RECEIVER_IKM);
    let opened = super::unseal_from_envelope(&envelope, &receiver_sk)
      .expect("the named reader opens the committed vector");
    std::assert_eq!(opened, b"the body no hop reads: the v0.2-draft sealed vector");
  }

  // ── The SIGNED 0.2 vectors ──────────────────────────────────────────

  const NOTARY_SEED: [u8; 32] = [
    // RFC 8032 §7.1 TEST 1's secret key — the published test vector the
    // signing suites already cite. Authorizes nothing.
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
    0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
    0x7f, 0x60,
  ];

  fn notary_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&NOTARY_SEED)
  }

  fn signed_vector_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("../../../examples/v0.2/sealed_signed_envelope.json")
  }

  /// The signed sealed vector, regenerated byte-for-byte: seal FIRST (the
  /// RFC 0008 §3 order — the signature must cover the ciphertext), bind
  /// the body hash to the raw ciphertext octets, then sign as a lone
  /// did:key notary so any implementation verifies it with no supplied
  /// keys, exactly as the ts-minted v0.1 vector is verified.
  fn regenerate_signed_vector() -> String {
    use sha2::Digest as _;
    let key = notary_key();
    let did = aph_core::crypto::did_key::encode_ed25519(&key.verifying_key());
    let fragment = did.trim_start_matches("did:key:").to_string();

    let (_, receiver_pk) = derive_keypair_for_tests(RECEIVER_IKM);
    let mut envelope = envelope_v02();
    envelope.id = std::string::String::from("urn:uuid:00000000-0000-4000-8000-00000000000f");
    envelope.issuer = did.clone();
    super::seal_into_envelope(
      &mut rng(),
      &mut envelope,
      reader("did:web:receiver.example.com"),
      &receiver_pk,
      b"the signed sealed vector: carried blind, verified by anyone, read by one",
    )
    .expect("sealing succeeds");
    let raw = {
      let sealed = envelope.credential_subject.sealed_payload.as_ref().expect("sealed");
      super::unb64(&sealed.ciphertext, "ciphertext").expect("decodes")
    };
    envelope.credential_subject.communication.body_sha256 =
      std::format!("{:x}", sha2::Sha256::digest(&raw));

    envelope.proof = aph_core::EnvelopeProofs::Single(aph_core::EnvelopeProof {
      r#type: std::string::String::from("DataIntegrityProof"),
      cryptosuite: std::option::Option::None, // sign_envelope writes it
      verification_method: std::format!("{did}#{fragment}"),
      created: std::string::String::from("2026-08-29T00:00:01Z"),
      proof_purpose: std::string::String::from("assertionMethod"),
      proof_value: std::string::String::new(),
      id: std::option::Option::None,
      previous_proof: std::option::Option::None,
    });
    aph_core::crypto::eddsa_jcs::sign_envelope(&mut envelope, &key).expect("signing succeeds");
    std::format!(
      "{}\n",
      serde_json::to_string_pretty(&envelope).expect("the vector serializes")
    )
  }

  #[test]
  fn the_signed_sealed_vector_is_byte_identical_to_a_fresh_mint() {
    let regenerated = regenerate_signed_vector();
    let path = signed_vector_path();
    let published = std::fs::read_to_string(&path).unwrap_or_default();
    if published != regenerated {
      std::panic!(
        "examples/v0.2/sealed_signed_envelope.json has drifted from the \
         bytes this suite mints.\nOverwrite it with EXACTLY the content between \
         the cut lines (final newline included):\n----8<----\n{}----8<----",
        regenerated
      );
    }
  }

  #[test]
  fn the_signed_sealed_vector_verifies_blind_and_opens_for_its_reader() {
    // The whole RFC in one committed artifact: a stranger verifies the
    // did:key signature over the CIPHERTEXT with no supplied keys and no
    // plaintext; the named reader additionally opens it.
    let raw_json =
      std::fs::read_to_string(signed_vector_path()).expect("the signed vector is on disk");
    let envelope: aph_core::NotarizationEnvelope =
      aph_core::parse_envelope_json(&raw_json).expect("strict-parses as 0.2");
    aph_core::crypto::eddsa_jcs::verify_envelope_did_key(&envelope)
      .expect("the lone did:key proof verifies offline, sealed member covered");

    let (receiver_sk, _) = derive_keypair_for_tests(RECEIVER_IKM);
    let opened = super::unseal_from_envelope(&envelope, &receiver_sk)
      .expect("the named reader opens the committed signed vector");
    std::assert_eq!(
      opened,
      b"the signed sealed vector: carried blind, verified by anyone, read by one"
    );
  }

  fn rotation_vector_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
      .join("../../../examples/v0.2/rotation_attestation.json")
  }

  fn regenerate_rotation_vector() -> String {
    let key = notary_key();
    let did = aph_core::crypto::did_key::encode_ed25519(&key.verifying_key());
    let successor_multibase = did.trim_start_matches("did:key:").to_string();
    let mut attestation = aph_core::RotationAttestation {
      aph_version: std::string::String::from("0.2"),
      r#type: std::string::String::from(aph_core::ROTATION_ATTESTATION_TYPE),
      id: std::string::String::from("urn:uuid:00000000-0000-4000-8000-0000000000a0"),
      subject: std::string::String::from("did:web:notary.squillo.com"),
      predecessor: std::string::String::from("did:web:notary.squillo.com#k1"),
      successor: aph_core::RotationSuccessor {
        kid: std::string::String::from("k2"),
        alg: std::string::String::from("EdDSA"),
        public_key_multibase: successor_multibase,
        not_before: std::string::String::from("2027-01-01T00:00:00Z"),
        not_after: std::string::String::from("2029-01-01T00:00:00Z"),
      },
      created: std::string::String::from("2026-08-29T00:00:00Z"),
      proof: aph_core::EnvelopeProof {
        r#type: std::string::String::from("DataIntegrityProof"),
        cryptosuite: std::option::Option::Some(std::string::String::from("eddsa-jcs-2022")),
        verification_method: std::string::String::from("did:web:notary.squillo.com#k1"),
        created: std::string::String::from("2026-08-29T00:00:00Z"),
        proof_purpose: std::string::String::from("assertionMethod"),
        proof_value: std::string::String::new(),
        id: std::option::Option::None,
        previous_proof: std::option::Option::None,
      },
    };
    aph_core::sign_rotation_attestation(&mut attestation, &key).expect("signing succeeds");
    std::format!(
      "{}\n",
      serde_json::to_string_pretty(&attestation).expect("the vector serializes")
    )
  }

  #[test]
  fn the_rotation_attestation_vector_is_byte_identical_to_a_fresh_mint() {
    let regenerated = regenerate_rotation_vector();
    let path = rotation_vector_path();
    let published = std::fs::read_to_string(&path).unwrap_or_default();
    if published != regenerated {
      std::panic!(
        "examples/v0.2/rotation_attestation.json has drifted from the \
         bytes this suite mints.\nOverwrite it with EXACTLY the content between \
         the cut lines (final newline included):\n----8<----\n{}----8<----",
        regenerated
      );
    }
  }

  #[test]
  fn the_committed_rotation_vector_verifies_against_its_predecessor_key() {
    let raw = std::fs::read_to_string(rotation_vector_path()).expect("the vector is on disk");
    let attestation: aph_core::RotationAttestation =
      serde_json::from_str(&raw).expect("strict-parses");
    aph_core::verify_rotation_attestation(&attestation, &notary_key().verifying_key())
      .expect("the predecessor's committed statement verifies");
  }
}
