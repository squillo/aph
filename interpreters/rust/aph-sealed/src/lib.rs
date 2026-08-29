//! DRAFT implementation of RFC 0008 — sealed payloads: carriage without
//! readership.
//!
//! ⚠ EXPERIMENTAL AND OFF-WIRE. RFC 0008 is a Draft targeting the v0.2
//! line; v0.1.0 is final and its strict parse refuses any envelope carrying
//! a `sealedPayload` member, correctly. This crate exists so the RFC's
//! design review reads working code with tests instead of prose: the type
//! is shaped exactly as the RFC's §2 wire member, and the two operations
//! implement its §3 bindings. Nothing here touches `NotarizationEnvelope`.
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
//! load-bearing choice is the AAD: the envelope `id` authenticates every
//! seal, so a ciphertext lifted into a different envelope fails open even
//! for its rightful reader. Errors are this crate's own type, deliberately
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

/// Who may open a seal: a DID and which of its `keyAgreement` keys.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedReader {
  /// DID whose key opens the seal — the final recipient, the sender itself,
  /// or a designated third party. The mechanism does not care which; that
  /// choice IS the two scenarios.
  pub id: String,
  /// Which `keyAgreement` key of that DID. Signing keys are never converted
  /// to encryption keys (RFC 0008 §2).
  pub kid: String,
}

/// RFC 0008 §2's wire member, byte-for-byte the shape review is reviewing.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedPayload {
  /// Always [`SUITE`] in this draft; refused on mismatch at unseal.
  pub suite: String,
  /// Who can open it.
  pub reader: SealedReader,
  /// base64url (unpadded): the HPKE encapsulated key.
  pub enc: String,
  /// base64url (unpadded): AEAD ciphertext, tag included.
  pub ciphertext: String,
}

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
    "the seal did not open: wrong reader key, tampered ciphertext, or a seal \
     staged under a different envelope id"
  )]
  OpenRefused,
  /// The HPKE encapsulation step itself failed (a malformed reader key
  /// surfaces here when it parses but cannot be used).
  #[error("sealing failed: {0}")]
  SealFailed(String),
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
/// open it, bound to `envelope_id` (RFC 0008 §3: the AAD). Sealing happens
/// BEFORE the envelope is signed, so the signature covers the ciphertext
/// and every hop verifies blind.
///
/// `reader_public_key` is the reader's X25519 `keyAgreement` public key,
/// 32 raw bytes, discovered through the §8.4 surfaces. The RNG is a caller
/// parameter for the same reason `now` is one in verification: this
/// function stays deterministic under test and honest about its inputs.
pub fn seal(
  csprng: &mut (impl rand::RngCore + rand::CryptoRng),
  reader: SealedReader,
  reader_public_key: &[u8],
  envelope_id: &str,
  plaintext: &[u8],
) -> std::result::Result<SealedPayload, SealError> {
  let pk = <Kem as KemTrait>::PublicKey::from_bytes(reader_public_key)
    .map_err(|_| SealError::MalformedKey("reader public"))?;
  let (encapped, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
    &OpModeS::Base,
    &pk,
    INFO,
    plaintext,
    envelope_id.as_bytes(),
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

/// Opens a seal with the reader's private key, under the SAME envelope id
/// it was sealed to. Any mismatch — key, bytes, or envelope — refuses with
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
  hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
    &OpModeR::Base,
    &sk,
    &encapped,
    INFO,
    &ciphertext,
    envelope_id.as_bytes(),
  )
  .map_err(|_| SealError::OpenRefused)
}

/// Derives a deterministic X25519 keypair from input keying material —
/// exposed for TESTS and examples only, so fixtures need no stored private
/// keys. Production keys come from an operator's own key management, never
/// from this function; the doc comment is the fence.
pub fn derive_keypair_for_tests(ikm: &[u8]) -> (Vec<u8>, Vec<u8>) {
  let (sk, pk) = Kem::derive_keypair(ikm);
  (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
  // TEST-ONLY key material: every keypair below is DERIVED in-test from a
  // fixed, clearly-labeled IKM string via RFC 9180 DeriveKeyPair — nothing
  // secret is stored, and nothing here is a production key.
  const RECEIVER_IKM: &[u8] = b"APH-SEALED-TEST-RECEIVER-IKM-0001";
  const SENDER_IKM: &[u8] = b"APH-SEALED-TEST-SENDER-IKM---0001";
  const ENVELOPE_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000e1";

  fn rng() -> impl rand::RngCore + rand::CryptoRng {
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
    let (receiver_sk, receiver_pk) = super::derive_keypair_for_tests(RECEIVER_IKM);
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
    let (sender_sk, _) = super::derive_keypair_for_tests(SENDER_IKM);
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
    let (sender_sk, sender_pk) = super::derive_keypair_for_tests(SENDER_IKM);
    let sealed = super::seal(
      &mut rng(),
      reader("did:web:sender.example.com"),
      &sender_pk,
      ENVELOPE_ID,
      b"guardrail overlay the counterparty must hold but not read",
    )
    .expect("sealing to one's own key is the same operation");

    let (receiver_sk, _) = super::derive_keypair_for_tests(RECEIVER_IKM);
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
    let (receiver_sk, receiver_pk) = super::derive_keypair_for_tests(RECEIVER_IKM);
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
    let (receiver_sk, receiver_pk) = super::derive_keypair_for_tests(RECEIVER_IKM);
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
    let (receiver_sk, receiver_pk) = super::derive_keypair_for_tests(RECEIVER_IKM);
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
    let (_, receiver_pk) = super::derive_keypair_for_tests(RECEIVER_IKM);
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
}
