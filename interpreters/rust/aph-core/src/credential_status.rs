//! Revocation status transport — the parsing and decision half (spec §6.3.3).
//!
//! §6.3.1 makes revocation normative and §6.3.2 makes expiry normative, but
//! only expiry is readable from an envelope alone. This module is the
//! machinery a third-party recipient uses to learn, at verification time,
//! that the parent Delegation Mandate was withdrawn: the status entry that
//! travels on the envelope (§6.3.3.1), the endpoint the verifier DERIVES
//! from the notary's own `did:web` (§6.3.3.2), the status list credential
//! served there (§6.3.3.3), and the three-outcome decision of §6.3.3.4.
//!
//! **The whole security argument is one sentence: the envelope does not get
//! to choose which host answers "is this mandate revoked".** The origin is
//! derived from `credentialSubject.notarization.notaryService.id`; a
//! `statusListCredential` carried in the envelope is bound same-origin
//! against that derivation and REFUSED WITHOUT BEING FETCHED when it is not
//! (§6.3.3.2). Whoever holds an old envelope would otherwise also choose the
//! host, and a host of the attacker's choosing always answers *not revoked*.
//!
//! **Fetching still happens elsewhere.** As with [`crate::discovery`], this
//! crate parses and decides; the one HTTPS GET arrives through
//! [`crate::discovery::ports::StatusCredentialFetch`], the sibling port
//! declared beside the `did:web` document port. That is why every rule below
//! is exercised against fixed strings with no network.
//!
//! ## Two obligations this module deliberately does NOT discharge
//!
//! 1. **⛔ The status list credential's own proof is NOT verified here.**
//!    §6.3.3.3 requires it, and it is load-bearing rather than decorative:
//!    same-origin permits a DIFFERENT PATH (that is how a notary points at a
//!    second list, §6.3.3.6), so a host with any writable path — an upload
//!    directory, a user-content route — lets an attacker publish a forged
//!    list that satisfies same-origin AND simply writes the notary's DID
//!    into its own `issuer`. Only the signature closes that. Verifying it
//!    needs the notary's key, and resolving a key needs the two §8.4
//!    discovery ports and the host's cache — state this crate does not hold,
//!    and a key this crate must not GUESS (the envelope's key is the one
//!    valid at `decisionTimestamp` per §8.4.7, which after a rotation is not
//!    the key the CURRENT list is signed with). The caller therefore owns
//!    the step, and [`status_list_signing_base`] plus
//!    [`StatusListCredential::proof_verification_method`] are provided so it
//!    is a few lines rather than a re-derivation.
//! 2. **The GZIP expansion of `encodedList` is supplied by the caller.**
//!    `aph-core`'s eight dependencies are serde, serde_json, thiserror,
//!    chrono, two signature primitives (`ed25519-dalek`, `p256`) and two
//!    encoders (`bs58`, `base64`) — there is no compression codec among
//!    them, while the pinned vintage (§14.1, W3C Bitstring Status List
//!    v1.0) mandates GZIP. Rather than vendor a decompressor into a
//!    security-critical parse path or mint a second port for what is a pure
//!    codec and not a domain seam, [`check_credential_status`] takes the
//!    expansion as a plain function argument. It is called LAST — after
//!    same-origin binding, issuer binding, purpose and freshness have all
//!    passed — so a caller's decompressor never sees bytes from an origin
//!    the verifier did not derive.

/// `credentialStatus.type` — the pinned entry type of §6.3.3.1.
pub const STATUS_ENTRY_TYPE: &str = "BitstringStatusListEntry";

/// The only `statusPurpose` APH defines (§6.3.3.5).
pub const STATUS_PURPOSE_REVOCATION: &str = "revocation";

/// The `type` a status list credential must carry (§6.3.3.3).
pub const STATUS_LIST_CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";

/// The `type` the status list credential's subject carries, when it carries
/// one (§6.3.3.3 leaves the member to the W3C profile).
pub const STATUS_LIST_SUBJECT_TYPE: &str = "BitstringStatusList";

/// Last path segment of the derived status endpoint (§6.3.3.2 step 2), the
/// counterpart of `did.json` in §8.4.4 step 2.
pub const STATUS_ENDPOINT_LEAF: &str = "aph-status.json";

/// §6.3.3.3 freshness bound: a status list credential issued more than this
/// many seconds before `now` MUST NOT be accepted.
pub const STATUS_MAX_AGE_SECONDS: i64 = 300;

/// §6.3.3.3 clock-skew tolerance, the same 60 seconds §8.3 step 6 allows.
/// Applied in BOTH directions: it widens the staleness bound and it is the
/// only amount by which a credential may be dated into the future.
pub const STATUS_CLOCK_SKEW_SECONDS: i64 = 60;

/// Multibase prefix for base64url-no-pad, the encoding `encodedList` uses.
pub const MULTIBASE_BASE64URL_PREFIX: char = 'u';

/// Hard cap on the expanded bitstring this module will index into.
///
/// The expansion is performed by a caller-supplied decompressor over bytes
/// fetched from the network, so the size the verifier is willing to hold has
/// to be stated somewhere. 1 MiB addresses 8,388,608 mandates — orders of
/// magnitude past any notary this specification contemplates — while keeping
/// a decompression bomb from turning one inbound envelope into a memory
/// exhaustion.
pub const MAX_EXPANDED_LIST_BYTES: usize = 1024 * 1024;

/// `credentialStatus.type`, a closed set of exactly one member (§6.3.3.1).
///
/// Modelled as an enum rather than a `String` so an unrecognized value is a
/// hard deserialization error — which is precisely where §6.3.3.1 routes it,
/// §7.1's strict parse at §8.3 step 1.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::marker::Copy,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
pub enum StatusEntryType {
  /// The W3C Bitstring Status List v1.0 entry type, the vintage §14.1 pins.
  #[serde(rename = "BitstringStatusListEntry")]
  BitstringStatusListEntry,
}

/// `credentialStatus.statusPurpose`, a closed set of exactly one member
/// (§6.3.3.5).
///
/// `"suspension"` is deliberately absent: suspension is reversible and
/// §6.3.2 forbids re-activation, so admitting it would put a lifecycle in
/// the transport that the mandate itself does not have.
///
/// Modelled as an enum for a security reason §6.3.3.5 states outright: a
/// verifier MUST NOT read a purpose it does not recognize as "no status
/// claim was made", because a producer could then disable the check on any
/// verifier by writing a word that verifier has never seen. An enum makes
/// that opt-out unconstructible — the envelope fails to parse at all.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::marker::Copy,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
pub enum StatusPurpose {
  /// The mandate's authority was withdrawn by the human who granted it.
  #[serde(rename = "revocation")]
  Revocation,
}

/// The status reference an envelope carries at top-level `credentialStatus`
/// (spec §6.3.3.1, §7.1.1).
///
/// **Whose status this is.** In W3C VC 2.0 `credentialStatus` describes the
/// credential carrying it. In APH it describes the **parent Delegation
/// Mandate** named by `credentialSubject.policy.delegationMandateId`: an
/// issued envelope stays cryptographically valid whatever happens
/// afterwards, and revocation applies to Delegation Mandates only.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialStatusEntry {
  /// Identifier for this status entry. Omitted when absent.
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub id: std::option::Option<String>,
  /// Always [`StatusEntryType::BitstringStatusListEntry`].
  #[serde(rename = "type")]
  pub r#type: StatusEntryType,
  /// Always [`StatusPurpose::Revocation`].
  pub status_purpose: StatusPurpose,
  /// This mandate's position in the list, a base-10 integer **in a JSON
  /// string** (§6.3.3.6).
  ///
  /// A `String` on the wire AND in Rust, never a numeric type. In runtimes
  /// where every JSON number is an IEEE-754 double, an index past 2^53 is
  /// silently rounded — and a rounded index does not raise a parse error, it
  /// reads a DIFFERENT BIT, so the verifier answers a question about some
  /// other mandate with full confidence. Typing the field `String` makes a
  /// JSON number a deserialization failure instead of a wrong answer.
  /// [`Self::index`] is the only way to a number, and it goes through
  /// `u64`.
  pub status_list_index: String,
  /// Absolute `https:` URL of the status list credential. Bound same-origin
  /// against the derived endpoint before it is ever fetched (§6.3.3.2).
  pub status_list_credential: String,
}

impl CredentialStatusEntry {
  /// Parses [`Self::status_list_index`] as a base-10 `u64` (§6.3.3.6).
  ///
  /// # Errors
  ///
  /// `APH_E008` for anything that is not a base-10 integer inside `u64`.
  /// §6.3.3.1 routes a malformed status reference to §8.3 step 1, but the
  /// §11 taxonomy is a CLOSED set of fifteen with no "malformed envelope"
  /// code; `APH_E008` is §6.3.3.4 case 2 — "the verifier could not establish
  /// the status" — which is literally what an unreadable index leaves. The
  /// envelope is refused either way; only the reported code differs.
  pub fn index(&self) -> std::result::Result<u64, crate::errors::AphError> {
    // Rejected explicitly rather than left to `from_str`: `u64::from_str`
    // accepts a leading `+`, and a sign on a bit position is not a base-10
    // integer in the sense §6.3.3.6 means.
    if self.status_list_index.is_empty()
      || !self.status_list_index.bytes().all(|b| b.is_ascii_digit())
    {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
    match self.status_list_index.parse::<u64>() {
      std::result::Result::Ok(index) => std::result::Result::Ok(index),
      // Overflow past u64 is unreachable for any real list but must not
      // wrap or panic: it is simply an index no published list contains.
      std::result::Result::Err(_) => {
        std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable)
      }
    }
  }
}

/// A status list credential fetched from the notary's own origin
/// (spec §6.3.3.3).
///
/// Deliberately NOT `deny_unknown_fields`, for the same reason
/// [`crate::discovery::did_document::DidDocument`] is not: this is a general
/// W3C artifact that legitimately carries more than APH reads (`name`,
/// `description`, `ttl`, `validUntil`, `renderMethod`). Rejecting those
/// would make APH unable to consume ordinary status list credentials. The
/// ENVELOPE's own [`CredentialStatusEntry`] is strict, because that one is
/// APH's wire shape and is covered by a signature.
#[derive(std::fmt::Debug, std::clone::Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusListCredential {
  /// JSON-LD contexts the document declares.
  #[serde(default, rename = "@context")]
  pub context: std::vec::Vec<serde_json::Value>,
  /// The credential's own identifier, when it carries one.
  #[serde(default)]
  pub id: std::option::Option<String>,
  /// JSON-LD type array; MUST include [`STATUS_LIST_CREDENTIAL_TYPE`].
  #[serde(default, rename = "type")]
  pub r#type: std::vec::Vec<String>,
  /// The issuing notary. W3C permits a bare DID string or an object with an
  /// `id`, so both are kept verbatim and read through
  /// [`Self::issuer_did`].
  #[serde(default)]
  pub issuer: serde_json::Value,
  /// RFC 3339 issuance instant. The freshness bound of §6.3.3.3 is measured
  /// from this, so a document without it cannot be accepted.
  #[serde(default, rename = "validFrom")]
  pub valid_from: std::option::Option<String>,
  /// The subject carrying the purpose and the bitstring.
  #[serde(rename = "credentialSubject")]
  pub credential_subject: StatusListSubject,
  /// The notary's proof over this document. Kept verbatim: this module does
  /// not verify it (see the module preamble), it only surfaces the
  /// verification method the caller must resolve.
  #[serde(default)]
  pub proof: serde_json::Value,
}

/// The `credentialSubject` of a status list credential (spec §6.3.3.3).
#[derive(std::fmt::Debug, std::clone::Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusListSubject {
  /// Subject identifier, when present.
  #[serde(default)]
  pub id: std::option::Option<String>,
  /// Subject type; [`STATUS_LIST_SUBJECT_TYPE`] when present.
  #[serde(default, rename = "type")]
  pub r#type: std::option::Option<String>,
  /// The purpose this list expresses. A `String` here, NOT the
  /// [`StatusPurpose`] enum the envelope entry uses, and the asymmetry is
  /// the spec's: an unrecognized purpose on the ENVELOPE is malformed wire
  /// (§6.3.3.5, refused at §8.3 step 1), while an unrecognized purpose in
  /// the fetched DOCUMENT is §6.3.3.4 case 2 — the status could not be
  /// established — and carries `APH_E008`. Parsing it as an enum here would
  /// collapse the second case into the first.
  #[serde(rename = "statusPurpose")]
  pub status_purpose: String,
  /// Multibase base64url of the GZIP-compressed bitstring.
  #[serde(rename = "encodedList")]
  pub encoded_list: String,
}

impl StatusListCredential {
  /// The issuing DID, whether `issuer` is a string or an object with an
  /// `id` — both are W3C-legal and a verifier that read only one form would
  /// refuse conformant notaries.
  pub fn issuer_did(&self) -> std::option::Option<&str> {
    match &self.issuer {
      serde_json::Value::String(did) => std::option::Option::Some(did.as_str()),
      serde_json::Value::Object(object) => object.get("id").and_then(|v| v.as_str()),
      _ => std::option::Option::None,
    }
  }

  /// The `proof.verificationMethod` the caller must resolve through §8.4 to
  /// check this document's signature — the step named in the module
  /// preamble as NOT performed here.
  ///
  /// `None` when the document carries no proof or no method, which the
  /// caller MUST treat as §6.3.3.4 case 2 rather than as "nothing to check".
  pub fn proof_verification_method(&self) -> std::option::Option<&str> {
    match &self.proof {
      serde_json::Value::Object(object) => {
        object.get("verificationMethod").and_then(|v| v.as_str())
      }
      // A proof chain on a status list is not a shape §6.3.3.3 defines, so
      // an array is reported as "no single method" rather than guessed at.
      _ => std::option::Option::None,
    }
  }

  /// Applies every §6.3.3.3 check this crate can make without a key: the
  /// credential type, the issuer binding, the purpose, and the freshness
  /// bound.
  ///
  /// `notary_did` is the DID the endpoint was DERIVED from (§6.3.3.2 step
  /// 1), never a value read out of the document — same-origin alone does not
  /// make a document authoritative, because one host serves many documents.
  ///
  /// # Errors
  ///
  /// `APH_E008` for every failure, per §6.3.3.4 case 2's single-code rule:
  /// the verifier's action (reject) and the operator's remediation (repair
  /// the notary's status surface) are identical for all of them.
  pub fn validate(
    &self,
    notary_did: &str,
    now_rfc3339: &str,
  ) -> std::result::Result<(), crate::errors::AphError> {
    if !self.r#type.iter().any(|t| t == STATUS_LIST_CREDENTIAL_TYPE) {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
    // Checked only when present: §6.3.3.3 names the purpose, the issuer, the
    // proof and the freshness bound as APH's normative checks and leaves the
    // subject's own `type` to the W3C profile, so REQUIRING it here would
    // refuse documents that are conformant as far as APH ever said.
    if self
      .credential_subject
      .r#type
      .as_deref()
      .is_some_and(|subject_type| subject_type != STATUS_LIST_SUBJECT_TYPE)
    {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
    if self.credential_subject.status_purpose != STATUS_PURPOSE_REVOCATION {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
    if self.issuer_did() != std::option::Option::Some(notary_did) {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
    self.check_freshness(now_rfc3339)
  }

  /// The §6.3.3.3 freshness bound, split out so it can be pinned on its own.
  ///
  /// Fails CLOSED in every direction: a missing or unparseable `validFrom`,
  /// an unparseable `now`, a credential older than
  /// [`STATUS_MAX_AGE_SECONDS`] plus the skew allowance, and a credential
  /// dated further into the future than the skew allowance all refuse. A
  /// future-dated document is refused because the alternative is a notary
  /// (or an attacker who reached its publishing pipeline) buying unbounded
  /// staleness by writing tomorrow's date.
  pub fn check_freshness(
    &self,
    now_rfc3339: &str,
  ) -> std::result::Result<(), crate::errors::AphError> {
    let issued = match self.valid_from.as_deref() {
      std::option::Option::Some(value) => value,
      std::option::Option::None => {
        return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
      }
    };
    let issued = match chrono::DateTime::parse_from_rfc3339(issued) {
      std::result::Result::Ok(t) => t,
      std::result::Result::Err(_) => {
        return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
      }
    };
    let now = match chrono::DateTime::parse_from_rfc3339(now_rfc3339) {
      std::result::Result::Ok(t) => t,
      std::result::Result::Err(_) => {
        return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
      }
    };
    let age_seconds = (now - issued).num_seconds();
    if age_seconds > STATUS_MAX_AGE_SECONDS + STATUS_CLOCK_SKEW_SECONDS {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
    if age_seconds < -STATUS_CLOCK_SKEW_SECONDS {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
    std::result::Result::Ok(())
  }
}

/// Parses a status list credential from the bytes an adapter fetched.
///
/// # Errors
///
/// `APH_E008` — a document that will not parse is indistinguishable, from a
/// verifier's seat, from a status surface that could not be reached
/// (§6.3.3.4 case 2). This mirrors
/// [`crate::discovery::did_document::parse_did_document`].
pub fn parse_status_list_credential(
  json: &str,
) -> std::result::Result<StatusListCredential, crate::errors::AphError> {
  match serde_json::from_str::<StatusListCredential>(json) {
    std::result::Result::Ok(credential) => std::result::Result::Ok(credential),
    std::result::Result::Err(_) => {
      std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable)
    }
  }
}

/// The canonical bytes a status list credential's proof covers: the document
/// with its `proof` member removed, JCS-canonicalized.
///
/// Provided because this module does not verify that proof (module
/// preamble): the caller resolves the notary key through §8.4 and checks the
/// signature over exactly these bytes. Deriving the base a second time in
/// the host is how signer and verifier drift apart, which is the reason
/// [`crate::crypto::proof_base`] exists for envelopes.
///
/// # Errors
///
/// `APH_E008` when the body is not a JSON object.
pub fn status_list_signing_base(
  raw_json: &str,
) -> std::result::Result<String, crate::errors::AphError> {
  let mut value = match serde_json::from_str::<serde_json::Value>(raw_json) {
    std::result::Result::Ok(v) => v,
    std::result::Result::Err(_) => {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
  };
  match value.as_object_mut() {
    std::option::Option::Some(object) => {
      object.remove("proof");
    }
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
  }
  std::result::Result::Ok(crate::crypto::jcs::canonicalize_rfc8785(&value))
}

/// Decodes `encodedList` to the GZIP stream it wraps (§6.3.3.3).
///
/// The value is MULTIBASE — a `u` prefix naming base64url-no-pad — and the
/// prefix is REQUIRED rather than tolerated as optional. §14.1 pins the
/// vintage precisely because a value that two vintages read differently
/// looks conformant to both and interoperates with neither; the earlier
/// Status List 2021 shape wrote bare base64url at this position, and quietly
/// accepting it would mean silently reading a different specification's
/// document.
///
/// The GZIP magic is checked here, before the bytes are handed to a
/// caller-supplied decompressor, so that codec is never asked to read a
/// format nobody agreed on.
///
/// # Errors
///
/// `APH_E008` for a missing prefix, an undecodable body, or bytes that are
/// not a GZIP stream.
pub fn decode_encoded_list(
  encoded: &str,
) -> std::result::Result<std::vec::Vec<u8>, crate::errors::AphError> {
  let body = match encoded.strip_prefix(MULTIBASE_BASE64URL_PREFIX) {
    std::option::Option::Some(body) => body,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
  };
  let bytes = match crate::crypto::base64url::decode(body) {
    std::result::Result::Ok(bytes) => bytes,
    std::result::Result::Err(_) => {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
  };
  // RFC 1952 §2.3.1: every GZIP member begins 0x1f 0x8b.
  if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
    return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
  }
  std::result::Result::Ok(bytes)
}

/// Reads the revocation bit at `index` from an EXPANDED bitstring
/// (§6.3.3.4 case 3).
///
/// Bit order is the W3C profile's: index 0 is the MOST significant bit of
/// the first byte. Getting this backwards reads a real bit belonging to a
/// different mandate rather than failing, so it is pinned by test.
///
/// # Errors
///
/// `APH_E008` when the list is too short to contain `index`, or larger than
/// [`MAX_EXPANDED_LIST_BYTES`]. §6.3.3.4 case 2 names "its list is too short
/// to contain `statusListIndex`" explicitly: a verifier that read a missing
/// bit as `0` would treat a truncated list as a blanket "nothing is
/// revoked".
pub fn revocation_bit(
  expanded_list: &[u8],
  index: u64,
) -> std::result::Result<bool, crate::errors::AphError> {
  if expanded_list.len() > MAX_EXPANDED_LIST_BYTES {
    return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
  }
  let byte_offset = index / 8;
  // `u64 -> usize` is lossy on a 32-bit target, and a wrapped offset would
  // index the WRONG mandate rather than fail, so the conversion is checked.
  let byte_offset = match usize::try_from(byte_offset) {
    std::result::Result::Ok(offset) => offset,
    std::result::Result::Err(_) => {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
  };
  let byte = match expanded_list.get(byte_offset) {
    std::option::Option::Some(byte) => *byte,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
  };
  let bit_in_byte = (index % 8) as u32;
  let mask = 0x80u8 >> bit_in_byte;
  std::result::Result::Ok(byte & mask != 0)
}

/// The two non-refusing outcomes of §6.3.3.4. The third outcome — revoked —
/// is an `APH_E015` error, not a value, because a verifier that could hold
/// "revoked" as a success value could forget to act on it.
#[derive(std::fmt::Debug, std::clone::Clone, std::marker::Copy, std::cmp::PartialEq, std::cmp::Eq)]
pub enum StatusCheck {
  /// §6.3.3.4 case 1 — the envelope carried no `credentialStatus`, so no
  /// claim was offered and none was checked. NOT the same as "not revoked".
  Skipped,
  /// §6.3.3.4 case 3, negative — the bit at `statusListIndex` is `0`.
  NotRevoked,
}

/// §8.3 step 8a over a whole envelope: the §6.3.3.4 trichotomy, end to end.
///
/// Absent ⇒ [`StatusCheck::Skipped`] with no error and no I/O. Present ⇒ the
/// derived endpoint is computed from the envelope's OWN notary DID, the
/// carried `statusListCredential` is bound same-origin against it, the
/// document is fetched, validated and indexed, and a set bit is `APH_E015`.
/// Anything that leaves the status unestablished is `APH_E008`.
///
/// `expand_encoded_list` decompresses the GZIP stream — see the module
/// preamble for why the codec is the caller's. It is invoked only after
/// every other check has passed.
///
/// # Errors
///
/// `APH_E015` when the parent mandate's bit is set; `APH_E008` for every
/// The GZIP-then-base64url expansion of a status list's `encodedList`,
/// supplied by the caller rather than performed here.
///
/// WHY A CALLER-SUPPLIED CLOSURE AND NOT A DEPENDENCY: this crate has no
/// compression dependency and deliberately keeps none — it is linked into a
/// wasm binding and into a kernel that both pay for every byte. The expansion
/// is a pure `&[u8] -> Vec<u8>` transform with no protocol content, so it
/// belongs to whoever already has an inflate implementation.
///
/// WHY AN ALIAS: the same signature appeared inline in two public functions,
/// which is the duplication `clippy::type_complexity` exists to catch —
/// spelling one contract twice invites the two spellings to drift (§3.4).
pub type ExpandEncodedList<'a> =
  dyn std::ops::Fn(&[u8]) -> std::result::Result<std::vec::Vec<u8>, crate::errors::AphError> + 'a;

/// §6.3.3.4 case-2 outcome, including an envelope that carries a status
/// reference but no `delegationMandateId` for it to be the status OF
/// (§6.3.3.1).
pub async fn check_envelope_status(
  envelope: &crate::envelope::NotarizationEnvelope,
  fetch: &dyn crate::discovery::ports::StatusCredentialFetch,
  expand_encoded_list: &ExpandEncodedList<'_>,
  now_rfc3339: &str,
) -> std::result::Result<StatusCheck, crate::errors::AphError> {
  let entry = match envelope.credential_status.as_ref() {
    std::option::Option::Some(entry) => entry,
    // §6.3.3.4 case 1. Returning BEFORE touching the port is the whole
    // point: enforcing a claim nobody made is not fail-closed, it is
    // fail-arbitrary, and it would refuse every conformant pre-revision
    // envelope.
    std::option::Option::None => return std::result::Result::Ok(StatusCheck::Skipped),
  };
  let mandate_id = match envelope
    .credential_subject
    .policy
    .delegation_mandate_id
    .as_deref()
  {
    std::option::Option::Some(id) => id,
    // §6.3.3.1: an envelope carrying `credentialStatus` MUST also carry a
    // non-null `delegationMandateId`. The spec routes this to §8.3 step 1 as
    // malformed wire; the §11 taxonomy has no malformed-envelope code, so it
    // lands as case 2 — a status reference with no subject leaves the status
    // unestablished, which is what `APH_E008` says.
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
  };
  check_credential_status(
    entry,
    mandate_id,
    envelope
      .credential_subject
      .notarization
      .notary_service
      .id
      .as_str(),
    fetch,
    expand_encoded_list,
    now_rfc3339,
  )
  .await
}

/// [`check_envelope_status`] with the three envelope-derived inputs passed
/// explicitly, for a caller that holds them without holding an envelope.
///
/// `notary_service_id` MUST be the notary DID from
/// `credentialSubject.notarization.notaryService.id` (§6.3.3.2 step 1) — the
/// party whose key signed the mandate. Passing anything the envelope's
/// status entry influenced would hand the attacker back the origin choice
/// this whole module exists to take away.
///
/// # Errors
///
/// As [`check_envelope_status`].
pub async fn check_credential_status(
  entry: &CredentialStatusEntry,
  delegation_mandate_id: &str,
  notary_service_id: &str,
  fetch: &dyn crate::discovery::ports::StatusCredentialFetch,
  expand_encoded_list: &ExpandEncodedList<'_>,
  now_rfc3339: &str,
) -> std::result::Result<StatusCheck, crate::errors::AphError> {
  // Read the index BEFORE any network work: an unreadable index makes the
  // fetch pointless, and §6.3.3.6's whole argument is that a bad index must
  // never reach a bit lookup.
  let index = entry.index()?;

  // §6.3.3.2 step 1-2. A notary whose id is not a `did:web` derives no
  // origin, so the same-origin rule cannot be satisfied and case 2 applies.
  let derived = match crate::discovery::DidUrl::parse(notary_service_id).web_status_url() {
    std::option::Option::Some(url) => url,
    std::option::Option::None => {
      return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
    }
  };

  // §6.3.3.2 same-origin binding. This runs BEFORE the port is touched and
  // the function returns without touching it — "MUST reject the envelope and
  // MUST NOT fetch the named URL". `same_origin` also refuses a non-`https:`
  // URL, which is the other half of the same sentence.
  if !crate::discovery::same_origin(&derived, &entry.status_list_credential) {
    return std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
  }

  // The bound URL is fetched, not the derived one: §6.3.3.2 permits a
  // DIFFERENT PATH on the same origin, which is how a notary with an
  // exhausted list points at its successor (§6.3.3.6).
  let body = fetch
    .fetch_status_credential(&entry.status_list_credential)
    .await?;
  let credential = parse_status_list_credential(&body)?;
  credential.validate(notary_service_id, now_rfc3339)?;

  let compressed = decode_encoded_list(&credential.credential_subject.encoded_list)?;
  let expanded = expand_encoded_list(&compressed)?;
  if revocation_bit(&expanded, index)? {
    return std::result::Result::Err(crate::errors::AphError::mandate_revoked(
      delegation_mandate_id,
    ));
  }
  std::result::Result::Ok(StatusCheck::NotRevoked)
}

#[cfg(test)]
mod tests {
  /// The notary every fixture below is issued by, and the origin every
  /// derived endpoint therefore lands on.
  const NOTARY_DID: &str = "did:web:aph-notary.squillo.com";
  /// The derived endpoint for [`NOTARY_DID`] under §6.3.3.2.
  const DERIVED_ENDPOINT: &str =
    "https://aph-notary.squillo.com/.well-known/aph-status.json";
  /// `validFrom` of every fresh fixture, paired with [`NOW`].
  const ISSUED_AT: &str = "2026-05-28T00:00:00Z";
  /// The verification instant: 30 seconds after [`ISSUED_AT`], comfortably
  /// inside the §6.3.3.3 bound.
  const NOW: &str = "2026-05-28T00:00:30Z";

  /// A fetch port double that records every URL it was asked for, so a test
  /// can prove a refusal happened WITHOUT a fetch rather than merely
  /// assert an error code.
  struct RecordingFetch {
    body: String,
    urls: std::sync::Mutex<std::vec::Vec<String>>,
  }

  impl RecordingFetch {
    fn new(body: &str) -> Self {
      Self {
        body: String::from(body),
        urls: std::sync::Mutex::new(std::vec::Vec::new()),
      }
    }

    fn calls(&self) -> usize {
      self.urls.lock().expect("test mutex is uncontended").len()
    }
  }

  impl crate::discovery::ports::StatusCredentialFetch for RecordingFetch {
    fn fetch_status_credential<'a>(
      &'a self,
      url: &'a str,
    ) -> crate::discovery::ports::DiscoveryFuture<'a, String> {
      std::boxed::Box::pin(async move {
        self
          .urls
          .lock()
          .expect("test mutex is uncontended")
          .push(String::from(url));
        let out: std::result::Result<String, crate::errors::AphError> =
          std::result::Result::Ok(self.body.clone());
        out
      })
    }
  }

  /// A port that always fails the way a dead origin does.
  struct UnreachableFetch {
    calls: std::sync::atomic::AtomicUsize,
  }

  impl crate::discovery::ports::StatusCredentialFetch for UnreachableFetch {
    fn fetch_status_credential<'a>(
      &'a self,
      _url: &'a str,
    ) -> crate::discovery::ports::DiscoveryFuture<'a, String> {
      std::boxed::Box::pin(async move {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let out: std::result::Result<String, crate::errors::AphError> =
          std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable);
        out
      })
    }
  }

  /// The stand-in for the caller's GZIP decompressor.
  ///
  /// Tests do not compress anything: they hand the arm a "compressed" buffer
  /// that is a GZIP header followed by the bitstring, and this expander
  /// strips the header. That keeps every assertion about the §6.3.3.4
  /// DECISION rather than about a codec `aph-core` does not link, and it is
  /// exactly the seam a real caller fills with three lines over a gzip
  /// reader.
  fn test_expander(
    compressed: &[u8],
  ) -> std::result::Result<std::vec::Vec<u8>, crate::errors::AphError> {
    // Sliced through `get` rather than `[..]`: a decompressor handed short
    // input must report a failure, never panic a verifier's task.
    match compressed.get(GZIP_HEADER.len()..) {
      std::option::Option::Some(rest) => std::result::Result::Ok(std::vec::Vec::from(rest)),
      std::option::Option::None => {
        std::result::Result::Err(crate::errors::AphError::NotaryServiceUnreachable)
      }
    }
  }

  /// A ten-byte RFC 1952 header: magic, DEFLATE method, no flags, zero
  /// mtime, no extra flags, unknown OS. Enough to satisfy the magic check
  /// [`super::decode_encoded_list`] performs.
  const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff];

  /// Builds the multibase `encodedList` value for a bitstring, wrapping it
  /// in the header [`test_expander`] strips back off.
  fn encoded_list_for(bits: &[u8]) -> String {
    let mut bytes = std::vec::Vec::from(GZIP_HEADER);
    bytes.extend_from_slice(bits);
    std::format!(
      "{}{}",
      super::MULTIBASE_BASE64URL_PREFIX,
      crate::crypto::base64url::encode(&bytes)
    )
  }

  /// A status list credential document with the given bitstring.
  fn status_document(bits: &[u8]) -> String {
    std::format!(
      r#"{{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "{endpoint}",
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "{issuer}",
  "validFrom": "{issued}",
  "credentialSubject": {{
    "id": "{endpoint}#list",
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "{encoded}"
  }}
}}"#,
      endpoint = DERIVED_ENDPOINT,
      issuer = NOTARY_DID,
      issued = ISSUED_AT,
      encoded = encoded_list_for(bits)
    )
  }

  /// An entry pointing at `url` for bit `index`.
  fn entry_at(url: &str, index: &str) -> super::CredentialStatusEntry {
    super::CredentialStatusEntry {
      id: std::option::Option::None,
      r#type: super::StatusEntryType::BitstringStatusListEntry,
      status_purpose: super::StatusPurpose::Revocation,
      status_list_index: String::from(index),
      status_list_credential: String::from(url),
    }
  }

  #[test]
  fn entry_round_trips_and_omits_an_absent_id() {
    // Pins the wire shape of §6.3.3.1 in both directions. The `id` member is
    // OPTIONAL and Pattern A, so an entry without one must serialize with no
    // `id` key at all — a `null` there would change the JCS bytes of every
    // envelope carrying a status reference.
    let json = r#"{"type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":"94567","statusListCredential":"https://aph-notary.squillo.com/.well-known/aph-status.json"}"#;
    let entry: super::CredentialStatusEntry =
      serde_json::from_str(json).expect("the §6.3.3.1 shape parses");
    std::assert_eq!(entry.index().unwrap(), 94567u64);
    let back = serde_json::to_string(&entry).expect("entry serializes");
    std::assert_eq!(back, json);
  }

  #[test]
  fn a_numeric_index_is_a_parse_failure() {
    // §6.3.3.6's entire argument: in runtimes where every JSON number is an
    // IEEE-754 double an index past 2^53 rounds SILENTLY and reads a
    // different mandate's bit. Typing the field `String` must make the
    // numeric form unparseable rather than merely discouraged.
    let json = r#"{"type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":94567,"statusListCredential":"https://aph-notary.squillo.com/.well-known/aph-status.json"}"#;
    let parsed = serde_json::from_str::<super::CredentialStatusEntry>(json);
    std::assert!(parsed.is_err(), "a JSON number at statusListIndex must not parse");
  }

  #[test]
  fn an_unrecognized_purpose_is_a_parse_failure_not_a_skip() {
    // §6.3.3.5: a verifier that treated an unknown purpose as "no status
    // claim was made" would let any producer disable the check by writing a
    // word that verifier has never seen. The closed enum makes that opt-out
    // unconstructible — the envelope does not parse at all.
    let json = r#"{"type":"BitstringStatusListEntry","statusPurpose":"suspension","statusListIndex":"1","statusListCredential":"https://aph-notary.squillo.com/.well-known/aph-status.json"}"#;
    std::assert!(serde_json::from_str::<super::CredentialStatusEntry>(json).is_err());
    let wrong_type = r#"{"type":"StatusList2021Entry","statusPurpose":"revocation","statusListIndex":"1","statusListCredential":"https://aph-notary.squillo.com/.well-known/aph-status.json"}"#;
    // §14.1 pins ONE vintage: an entry from a different vintage of the same
    // idea must not be read as though it were this one.
    std::assert!(serde_json::from_str::<super::CredentialStatusEntry>(wrong_type).is_err());
  }

  #[test]
  fn entry_rejects_an_unknown_member() {
    // The entry travels inside the signed envelope, which parses strictly
    // (§7.1). A member APH never defined must be a hard error here too, or
    // the strictness stops at the envelope's edge.
    let json = r#"{"type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":"1","statusListCredential":"https://aph-notary.squillo.com/.well-known/aph-status.json","statusSize":2}"#;
    std::assert!(serde_json::from_str::<super::CredentialStatusEntry>(json).is_err());
  }

  #[test]
  fn index_refuses_signs_and_whitespace() {
    // `u64::from_str` accepts a leading `+`, and a permissive index parse is
    // how "+1" and "1" become two spellings of one bit — a producer could
    // then write an index one verifier reads and another refuses.
    let mut entry = entry_at(DERIVED_ENDPOINT, "+1");
    std::assert!(entry.index().is_err());
    entry.status_list_index = String::from(" 1");
    std::assert!(entry.index().is_err());
    entry.status_list_index = String::from("");
    std::assert!(entry.index().is_err());
    entry.status_list_index = String::from("1_000");
    std::assert!(entry.index().is_err());
  }

  #[test]
  fn revocation_bit_reads_the_most_significant_bit_first() {
    // W3C bit order: index 0 is the MSB of byte 0. Reversing it does not
    // fail, it reads a real bit belonging to a DIFFERENT mandate — a wrong
    // answer delivered with full confidence — so the order is pinned here
    // rather than trusted to the reader.
    let list: [u8; 2] = [0b1000_0001, 0b0000_0010];
    std::assert!(super::revocation_bit(&list, 0).unwrap());
    std::assert!(!super::revocation_bit(&list, 1).unwrap());
    std::assert!(super::revocation_bit(&list, 7).unwrap());
    std::assert!(super::revocation_bit(&list, 14).unwrap());
    std::assert!(!super::revocation_bit(&list, 15).unwrap());
  }

  #[test]
  fn an_index_past_the_list_is_a_refusal_not_a_zero() {
    // §6.3.3.4 case 2 names a too-short list explicitly. Reading a missing
    // bit as `0` would turn a truncated (or maliciously trimmed) list into a
    // blanket "nothing is revoked".
    let list: [u8; 1] = [0x00];
    std::assert_eq!(super::revocation_bit(&list, 8).unwrap_err().code(), "APH_E008");
  }

  #[test]
  fn encoded_list_requires_the_multibase_prefix_and_gzip_magic() {
    // §14.1 pins W3C Bitstring Status List v1.0, whose `encodedList` is
    // multibase. The predecessor vintage wrote bare base64url at the same
    // position, so accepting a missing prefix would mean silently reading a
    // different specification's document and calling it conformant.
    let bare = crate::crypto::base64url::encode(&[0x1f, 0x8b, 0x08]);
    std::assert_eq!(
      super::decode_encoded_list(&bare).unwrap_err().code(),
      "APH_E008"
    );
    // Non-GZIP bytes are refused BEFORE a caller's decompressor sees them.
    let not_gzip = std::format!(
      "{}{}",
      super::MULTIBASE_BASE64URL_PREFIX,
      crate::crypto::base64url::encode(b"plain")
    );
    std::assert_eq!(
      super::decode_encoded_list(&not_gzip).unwrap_err().code(),
      "APH_E008"
    );
    let good = encoded_list_for(&[0x00]);
    std::assert_eq!(super::decode_encoded_list(&good).unwrap()[0], 0x1f);
  }

  #[test]
  fn freshness_bound_is_five_minutes_plus_one_minute_of_skew() {
    // §6.3.3.3 is normative about both numbers and they are the reason the
    // check is worth a network round trip at all: a bound measured in hours
    // would cost a fetch and buy nothing, because the mandate would usually
    // expire before a stale answer changed.
    let document = status_document(&[0x00]);
    let credential = super::parse_status_list_credential(&document).unwrap();
    // 359s old: inside 300 + 60.
    std::assert!(credential.check_freshness("2026-05-28T00:05:59Z").is_ok());
    // 361s old: outside.
    std::assert_eq!(
      credential
        .check_freshness("2026-05-28T00:06:01Z")
        .unwrap_err()
        .code(),
      "APH_E008"
    );
    // Dated further into the future than the skew allowance: refused, or a
    // publisher buys unbounded staleness by writing tomorrow's date.
    std::assert_eq!(
      credential
        .check_freshness("2026-05-27T23:58:00Z")
        .unwrap_err()
        .code(),
      "APH_E008"
    );
  }

  #[test]
  fn validate_binds_the_issuer_to_the_derived_notary() {
    // Same-origin alone does not make a document authoritative: one host
    // serves many documents, and the path is the envelope's to name. The
    // issuer binding is what ties the answer to the party whose key signed
    // the mandate.
    let document = status_document(&[0x00]).replace(NOTARY_DID, "did:web:evil.example");
    let credential = super::parse_status_list_credential(&document).unwrap();
    std::assert_eq!(
      credential.validate(NOTARY_DID, NOW).unwrap_err().code(),
      "APH_E008"
    );
  }

  #[test]
  fn validate_refuses_a_document_whose_purpose_is_not_revocation() {
    // On the fetched DOCUMENT an unrecognized purpose is §6.3.3.4 case 2
    // (APH_E008), not the parse failure the ENVELOPE entry raises. The
    // asymmetry is the spec's and is easy to collapse by accident, so both
    // halves are pinned.
    let document = status_document(&[0x00]).replace(
      "\"statusPurpose\": \"revocation\"",
      "\"statusPurpose\": \"suspension\"",
    );
    let credential = super::parse_status_list_credential(&document).unwrap();
    std::assert_eq!(
      credential.validate(NOTARY_DID, NOW).unwrap_err().code(),
      "APH_E008"
    );
  }

  #[test]
  fn a_status_document_may_carry_members_aph_does_not_read() {
    // The status list credential is a general W3C artifact. Parsing it
    // strictly would refuse ordinary documents carrying `name`, `ttl` or a
    // `validUntil` — the same reason `DidDocument` is not strict either.
    let document = status_document(&[0x00]).replace(
      "\"validFrom\":",
      "\"name\": \"Squillo revocation list\", \"ttl\": 300, \"validFrom\":",
    );
    let credential = super::parse_status_list_credential(&document)
      .expect("extra W3C members must not refuse the document");
    std::assert!(credential.validate(NOTARY_DID, NOW).is_ok());
  }

  #[test]
  fn issuer_is_read_from_a_string_or_an_object() {
    // W3C permits both forms and notaries emit both; a verifier that read
    // only one would refuse conformant issuers for a JSON-shape reason.
    let document = status_document(&[0x00]).replace(
      &std::format!("\"issuer\": \"{}\"", NOTARY_DID),
      &std::format!("\"issuer\": {{\"id\": \"{}\"}}", NOTARY_DID),
    );
    let credential = super::parse_status_list_credential(&document).unwrap();
    std::assert_eq!(credential.issuer_did(), std::option::Option::Some(NOTARY_DID));
    std::assert!(credential.validate(NOTARY_DID, NOW).is_ok());
  }

  #[test]
  fn signing_base_drops_the_proof_and_is_stable() {
    // The caller verifies the notary's signature over exactly these bytes
    // (module preamble). Shipping the base here is what keeps the host from
    // re-deriving it and drifting from the signer.
    let signed = status_document(&[0x00]).replace(
      "\n}",
      ",\n  \"proof\": {\"type\": \"DataIntegrityProof\", \"proofValue\": \"zNotChecked\"}\n}",
    );
    let base = super::status_list_signing_base(&signed).unwrap();
    std::assert!(!base.contains("proofValue"));
    // Byte-identical to the base of the same document with no proof at all,
    // which is the property a signer relies on.
    let unsigned = super::status_list_signing_base(&status_document(&[0x00])).unwrap();
    std::assert_eq!(base, unsigned);
  }

  // ── The §6.3.3.4 trichotomy, end to end ─────────────────────────────

  /// An envelope whose notary is [`NOTARY_DID`], carrying `status` and
  /// naming `mandate` as the parent Delegation Mandate.
  ///
  /// Built from the checked-in Slack golden so the trichotomy is exercised
  /// against a real published wire sample rather than a shape invented for
  /// this test — the golden is also what proves, in
  /// `golden_envelope_bytes_are_unchanged_by_the_new_field`, that an absent
  /// status reference changes nothing.
  fn envelope_with(
    status: std::option::Option<super::CredentialStatusEntry>,
    mandate: std::option::Option<&str>,
  ) -> crate::envelope::NotarizationEnvelope {
    let raw = std::include_str!("../tests/golden/slack_reply_envelope.json");
    let mut envelope: crate::envelope::NotarizationEnvelope =
      serde_json::from_str(raw).expect("golden fixture parses");
    envelope.credential_subject.notarization.notary_service.id = String::from(NOTARY_DID);
    envelope.credential_subject.policy.delegation_mandate_id =
      mandate.map(String::from);
    envelope.credential_status = status;
    envelope
  }

  /// The mandate id every revoked-path assertion expects back in `APH_E015`.
  const MANDATE_ID: &str = "urn:uuid:00000000-0000-4000-8000-0000000000d1";

  #[test]
  fn absent_status_skips_without_error_and_without_touching_the_port() {
    // §6.3.3.4 case 1. Enforcing a claim nobody made is not fail-closed, it
    // is fail-arbitrary: it would refuse every conformant envelope written
    // before this revision. The port call count is the load-bearing
    // assertion — "skip" must mean no I/O at all, not a fetch whose result
    // is discarded.
    let fetch = RecordingFetch::new("");
    let envelope = envelope_with(std::option::Option::None, std::option::Option::Some(MANDATE_ID));
    let outcome = crate::discovery::test_support::block_on(super::check_envelope_status(
      &envelope,
      &fetch,
      &test_expander,
      NOW,
    ))
    .expect("an absent status reference is not an error");
    std::assert_eq!(outcome, super::StatusCheck::Skipped);
    std::assert_eq!(fetch.calls(), 0, "case 1 must perform no fetch");
  }

  #[test]
  fn a_clear_bit_admits_the_envelope() {
    // §6.3.3.4 case 3, negative. The positive control for every refusal
    // below: without it a test suite where everything rejects would pass
    // even if the arm refused unconditionally.
    let fetch = RecordingFetch::new(&status_document(&[0b0100_0000]));
    let entry = entry_at(DERIVED_ENDPOINT, "0");
    let envelope = envelope_with(
      std::option::Option::Some(entry),
      std::option::Option::Some(MANDATE_ID),
    );
    let outcome = crate::discovery::test_support::block_on(super::check_envelope_status(
      &envelope,
      &fetch,
      &test_expander,
      NOW,
    ))
    .expect("a clear bit continues verification");
    std::assert_eq!(outcome, super::StatusCheck::NotRevoked);
    std::assert_eq!(fetch.calls(), 1);
  }

  #[test]
  fn a_set_bit_rejects_with_aph_e015_naming_the_mandate() {
    // §6.3.3.4 case 3. The code matters as much as the refusal: E015 says a
    // human WITHDREW the authority, while a signature code would send an
    // operator to inspect key material for a decision no key was involved
    // in. The mandate id has to travel with it or the operator cannot tell
    // WHICH grant was pulled.
    let fetch = RecordingFetch::new(&status_document(&[0b0010_0000]));
    let entry = entry_at(DERIVED_ENDPOINT, "2");
    let envelope = envelope_with(
      std::option::Option::Some(entry),
      std::option::Option::Some(MANDATE_ID),
    );
    let error = crate::discovery::test_support::block_on(super::check_envelope_status(
      &envelope,
      &fetch,
      &test_expander,
      NOW,
    ))
    .expect_err("a set bit must refuse the envelope");
    std::assert_eq!(error.code(), "APH_E015");
    std::assert!(
      std::format!("{}", error).contains(MANDATE_ID),
      "APH_E015 must name the revoked mandate"
    );
  }

  #[test]
  fn an_unreachable_status_surface_rejects_rather_than_skipping() {
    // §6.3.3.4 case 2, and the reason it is not case 1: an attacker who can
    // make the status check FAIL must not thereby get to choose that it is
    // SKIPPED. This is §8.4.6's published-and-failed rule one level up.
    let fetch = UnreachableFetch {
      calls: std::sync::atomic::AtomicUsize::new(0),
    };
    let entry = entry_at(DERIVED_ENDPOINT, "0");
    let envelope = envelope_with(
      std::option::Option::Some(entry),
      std::option::Option::Some(MANDATE_ID),
    );
    let error = crate::discovery::test_support::block_on(super::check_envelope_status(
      &envelope,
      &fetch,
      &test_expander,
      NOW,
    ))
    .expect_err("an offered-but-unreachable reference must refuse");
    std::assert_eq!(error.code(), "APH_E008");
    std::assert_eq!(
      fetch.calls.load(std::sync::atomic::Ordering::SeqCst),
      1,
      "the derived origin was reached for, and it is the reach that failed"
    );
  }

  #[test]
  fn a_cross_origin_status_url_is_refused_without_being_fetched() {
    // THE security core of §6.3.3.2. The authority for "is this mandate
    // revoked" is the notary that issued it; if the envelope could name the
    // host answering, then whoever holds an old envelope also chooses that
    // host — and a host of the attacker's choosing always answers "not
    // revoked". The spec says MUST reject and MUST NOT fetch, so the CALL
    // COUNT is the assertion. An error code alone would still pass if the
    // implementation fetched first and refused afterwards, by which time the
    // verifier has already made a request an attacker steered.
    let fetch = RecordingFetch::new(&status_document(&[0x00]));
    let entry = entry_at("https://evil.example/.well-known/aph-status.json", "0");
    let envelope = envelope_with(
      std::option::Option::Some(entry),
      std::option::Option::Some(MANDATE_ID),
    );
    let error = crate::discovery::test_support::block_on(super::check_envelope_status(
      &envelope,
      &fetch,
      &test_expander,
      NOW,
    ))
    .expect_err("a cross-origin status URL must refuse");
    std::assert_eq!(error.code(), "APH_E008");
    std::assert_eq!(fetch.calls(), 0, "the named URL must never be fetched");
  }

  #[test]
  fn a_same_host_different_port_or_scheme_is_also_cross_origin() {
    // "Same-origin" is scheme + host + PORT, and a verifier that compared
    // only the host would accept `http://` (no TLS anchor at all) and a
    // service on another port that the notary's certificate never covered.
    // Both must refuse unfetched, exactly like a foreign host.
    for url in [
      "http://aph-notary.squillo.com/.well-known/aph-status.json",
      "https://aph-notary.squillo.com:8443/.well-known/aph-status.json",
      // Userinfo is the classic disguise: the HOST here is `evil.example`,
      // and a prefix comparison would call it the notary's own origin.
      "https://aph-notary.squillo.com@evil.example/.well-known/aph-status.json",
    ] {
      let fetch = RecordingFetch::new(&status_document(&[0x00]));
      let envelope = envelope_with(
        std::option::Option::Some(entry_at(url, "0")),
        std::option::Option::Some(MANDATE_ID),
      );
      let error = crate::discovery::test_support::block_on(super::check_envelope_status(
        &envelope,
        &fetch,
        &test_expander,
        NOW,
      ))
      .expect_err(url);
      std::assert_eq!(error.code(), "APH_E008", "{}", url);
      std::assert_eq!(fetch.calls(), 0, "{}", url);
    }
  }

  #[test]
  fn a_different_path_on_the_derived_origin_is_admitted_and_is_what_gets_fetched() {
    // §6.3.3.2 permits a different PATH deliberately — it is how a notary
    // whose list is exhausted points at the successor list (§6.3.3.6). A
    // verifier that pinned the whole URL instead of the origin would refuse
    // every notary that ever filled a list.
    let fetch = RecordingFetch::new(&status_document(&[0x00]));
    let second_list = "https://aph-notary.squillo.com/status/list-2.json";
    let envelope = envelope_with(
      std::option::Option::Some(entry_at(second_list, "0")),
      std::option::Option::Some(MANDATE_ID),
    );
    let outcome = crate::discovery::test_support::block_on(super::check_envelope_status(
      &envelope,
      &fetch,
      &test_expander,
      NOW,
    ))
    .expect("a same-origin second list is legitimate");
    std::assert_eq!(outcome, super::StatusCheck::NotRevoked);
    let asked = fetch.urls.lock().expect("test mutex is uncontended").clone();
    std::assert_eq!(
      asked,
      std::vec![String::from(second_list)],
      "the BOUND url is fetched, not the derived one"
    );
  }

  #[test]
  fn a_notary_that_is_not_did_web_cannot_be_status_checked() {
    // §6.3.3.4 case 2, first bullet: with no `did:web` there is no origin to
    // derive, so the same-origin rule cannot be satisfied at all. Refusing
    // is the only safe reading — treating it as case 1 would let any
    // producer disable the check by issuing under a `did:key` notary.
    let fetch = RecordingFetch::new(&status_document(&[0x00]));
    let mut envelope = envelope_with(
      std::option::Option::Some(entry_at(DERIVED_ENDPOINT, "0")),
      std::option::Option::Some(MANDATE_ID),
    );
    envelope.credential_subject.notarization.notary_service.id =
      String::from("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV");
    let error = crate::discovery::test_support::block_on(super::check_envelope_status(
      &envelope,
      &fetch,
      &test_expander,
      NOW,
    ))
    .expect_err("no derivable origin must refuse");
    std::assert_eq!(error.code(), "APH_E008");
    std::assert_eq!(fetch.calls(), 0);
  }

  #[test]
  fn a_status_reference_with_no_parent_mandate_is_refused() {
    // §6.3.3.1: an envelope carrying `credentialStatus` MUST also carry a
    // non-null `delegationMandateId`. A status reference with nothing to be
    // the status OF would leave a verifier checking a bit whose subject it
    // cannot name — and `APH_E015` could not name the mandate it refused.
    let fetch = RecordingFetch::new(&status_document(&[0x00]));
    let envelope = envelope_with(
      std::option::Option::Some(entry_at(DERIVED_ENDPOINT, "0")),
      std::option::Option::None,
    );
    let error = crate::discovery::test_support::block_on(super::check_envelope_status(
      &envelope,
      &fetch,
      &test_expander,
      NOW,
    ))
    .expect_err("a subjectless status reference must refuse");
    std::assert_eq!(error.code(), "APH_E008");
    std::assert_eq!(fetch.calls(), 0);
  }

  #[test]
  fn a_stale_document_rejects_even_though_it_fetched_cleanly() {
    // §6.3.3.3's bound is what makes the check worth its round trip. A
    // verifier that fetched successfully and then ignored the age would
    // accept a list frozen at the moment before a revocation.
    let fetch = RecordingFetch::new(&status_document(&[0x00]));
    let envelope = envelope_with(
      std::option::Option::Some(entry_at(DERIVED_ENDPOINT, "0")),
      std::option::Option::Some(MANDATE_ID),
    );
    let error = crate::discovery::test_support::block_on(super::check_envelope_status(
      &envelope,
      &fetch,
      &test_expander,
      // 361 seconds after ISSUED_AT: past 300 + 60.
      "2026-05-28T00:06:01Z",
    ))
    .expect_err("a stale status list must refuse");
    std::assert_eq!(error.code(), "APH_E008");
    std::assert_eq!(fetch.calls(), 1);
  }

  #[test]
  fn the_expander_never_runs_on_a_document_that_failed_an_earlier_check() {
    // The decompressor is caller-supplied and runs over network bytes, so
    // the order of operations is a security property: same-origin, issuer,
    // purpose and freshness all pass FIRST, and only then is a codec asked
    // to expand anything. This test would fail if the arm expanded before
    // validating.
    let expanded = std::sync::atomic::AtomicUsize::new(0);
    let counting = |compressed: &[u8]| -> std::result::Result<
      std::vec::Vec<u8>,
      crate::errors::AphError,
    > {
      expanded.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
      test_expander(compressed)
    };
    let fetch = RecordingFetch::new(
      &status_document(&[0x00]).replace(NOTARY_DID, "did:web:evil.example"),
    );
    let envelope = envelope_with(
      std::option::Option::Some(entry_at(DERIVED_ENDPOINT, "0")),
      std::option::Option::Some(MANDATE_ID),
    );
    let error = crate::discovery::test_support::block_on(super::check_envelope_status(
      &envelope,
      &fetch,
      &counting,
      NOW,
    ))
    .expect_err("a foreign issuer must refuse");
    std::assert_eq!(error.code(), "APH_E008");
    std::assert_eq!(
      expanded.load(std::sync::atomic::Ordering::SeqCst),
      0,
      "the caller's decompressor must not see bytes from a rejected document"
    );
  }

  #[test]
  fn golden_envelope_bytes_are_unchanged_by_the_new_field() {
    // ⛔ PATTERN A, the rule that keeps every fixture and all four real
    // Ed25519 signatures valid without regeneration (§7.1.1, §7.5): an
    // envelope carrying NO status reference must be BYTE-IDENTICAL to one
    // written before the field existed. `#[serde(default)]` alone would emit
    // an explicit `null`, changing the JCS bytes of every golden and
    // invalidating every signature over them. This test reads the
    // checked-in golden, round-trips it through the type that now has the
    // field, and compares the SIGNING BASE — the exact bytes a proof
    // covers — so a regression is caught as the signature breakage it is.
    let raw = std::include_str!("../tests/golden/slack_reply_envelope.json");
    let envelope: crate::envelope::NotarizationEnvelope =
      serde_json::from_str(raw).expect("golden fixture parses");
    std::assert!(
      envelope.credential_status.is_none(),
      "the golden predates the field and must parse with it absent"
    );
    let reserialized = serde_json::to_string(&envelope).expect("envelope serializes");
    std::assert!(
      !reserialized.contains("credentialStatus"),
      "an absent status reference must emit no key at all"
    );
    let from_type: serde_json::Value =
      serde_json::from_str(&reserialized).expect("round-trip parses");
    let from_disk: serde_json::Value = serde_json::from_str(raw).expect("golden parses as JSON");
    std::assert_eq!(
      crate::crypto::jcs::canonicalize_rfc8785(&from_type),
      crate::crypto::jcs::canonicalize_rfc8785(&from_disk),
      "the canonical bytes a signature covers must be unchanged"
    );
  }

  #[test]
  fn proof_verification_method_is_surfaced_for_the_caller() {
    // This module does not check the proof, so it must at least hand the
    // caller the one thing needed to: which key to resolve through §8.4.
    let signed = status_document(&[0x00]).replace(
      "\n}",
      ",\n  \"proof\": {\"type\": \"DataIntegrityProof\", \"verificationMethod\": \"did:web:aph-notary.squillo.com#k1\"}\n}",
    );
    let credential = super::parse_status_list_credential(&signed).unwrap();
    std::assert_eq!(
      credential.proof_verification_method(),
      std::option::Option::Some("did:web:aph-notary.squillo.com#k1")
    );
    let unsigned = super::parse_status_list_credential(&status_document(&[0x00])).unwrap();
    std::assert_eq!(
      unsigned.proof_verification_method(),
      std::option::Option::None
    );
  }
}
