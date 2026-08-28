//! NotarizationEnvelope — the W3C VC 2.0-shaped credential carrying an
//! APH notarization. This is the canonical on-wire shape.
//!
//! The envelope is a JSON-LD compatible W3C Verifiable Credential 2.0
//! payload. The `@context` field carries the JSON-LD contexts; the `type`
//! field MUST include `"VerifiableCredential"` plus
//! `"AgentSendAuthorizationCredential"`. All struct field names use
//! snake_case in Rust and camelCase on the wire (via
//! `#[serde(rename_all = "camelCase")]`), except `@context` (JSON-LD
//! convention) and `type` (Rust reserved keyword routed through `r#type`
//! + explicit `#[serde(rename = "type")]` for defense in depth).
//!
//! This module is shape-only — `proof.proof_value` is a String; no
//! cryptographic validation occurs in this module. The STRUCTURAL rules of
//! spec §7.1.11 (chain length, proof purposes, `previousProof` linkage,
//! label/structure agreement) live in [`crate::verification`]; signature
//! checking lives in [`crate::crypto`].

/// Top-level APH envelope. JSON-LD compatible W3C VC 2.0 credential.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotarizationEnvelope {
  /// APH version pin (`"0.1"`).
  pub aph_version: String,
  /// JSON-LD `@context` array. Always begins with W3C VC 2.0 context.
  #[serde(rename = "@context")]
  pub context: Vec<String>,
  /// JSON-LD `type` array; MUST include `"VerifiableCredential"` and
  /// `"AgentSendAuthorizationCredential"`.
  #[serde(rename = "type")]
  pub r#type: Vec<String>,
  /// `urn:uuid:...` envelope identifier.
  pub id: String,
  /// DID of the notary service.
  pub issuer: String,
  /// RFC 3339 issuance timestamp.
  pub valid_from: String,
  /// RFC 3339 expiry timestamp.
  pub valid_until: String,
  /// Inner credential subject (the notarized claim).
  pub credential_subject: CredentialSubject,
  /// Optional link to an AP2 IntentMandate (for cross-protocol mandates).
  #[serde(default)]
  pub linked_mandate: std::option::Option<LinkedMandate>,
  /// Revocation status reference for the **parent Delegation Mandate** named
  /// by `credentialSubject.policy.delegationMandateId` — NOT for this
  /// envelope (spec §6.3.3.1 narrows the W3C reading, and
  /// [`crate::credential_status`] carries the argument).
  ///
  /// **`skip_serializing_if` is load-bearing, not tidiness.** Unlike
  /// `linked_mandate` directly above — which §7.1.1 permits to appear as an
  /// explicit `null` — this field is OMITTED when absent, so an envelope
  /// carrying no status reference is BYTE-IDENTICAL to one written before
  /// the field existed. That identity is what keeps every published example,
  /// every golden fixture and all four real Ed25519 signatures valid without
  /// regeneration: the signing base is this struct serialized and
  /// canonicalized (`crate::crypto::proof_base::signing_base`), so a bare
  /// `#[serde(default)]` here would emit `"credentialStatus":null`, change
  /// those bytes, and invalidate every signature over them.
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub credential_status:
    std::option::Option<crate::credential_status::CredentialStatusEntry>,
  /// Cryptographic proof: a single notary proof, or a two-element proof
  /// chain (spec §7.1.11). See [`EnvelopeProofs`].
  pub proof: EnvelopeProofs,
}

/// One proof, or a two-element chain (spec §7.1.11).
///
/// Untagged because the wire carries either a JSON object or a JSON array
/// under the same `proof` key; the shape IS the discriminator.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(untagged)]
pub enum EnvelopeProofs {
  /// A single notary proof. The envelope is `NotaryAttested` (§7.1.11).
  Single(EnvelopeProof),
  /// An ordered proof chain: principal proof, then notary countersignature.
  Chain(std::vec::Vec<EnvelopeProof>),
}

impl EnvelopeProofs {
  /// Every proof, in wire order.
  pub fn all(&self) -> &[EnvelopeProof] {
    match self {
      // `from_ref` gives the single form the same slice shape as the chain
      // form, so callers that iterate never branch on the variant.
      Self::Single(proof) => std::slice::from_ref(proof),
      Self::Chain(proofs) => proofs.as_slice(),
    }
  }

  /// The principal proof — the head of a well-formed two-element chain.
  /// `None` for a single proof or a chain of any other length.
  ///
  /// A chain of any other length is malformed under §7.1.11, so refusing to
  /// name a "principal proof" inside one is deliberate: a caller that got a
  /// proof back from a three-element array would be reading a structure the
  /// spec rejects as though it were valid.
  pub fn principal(&self) -> std::option::Option<&EnvelopeProof> {
    match self {
      Self::Single(_) => std::option::Option::None,
      Self::Chain(proofs) => {
        if proofs.len() == 2 {
          proofs.first()
        } else {
          std::option::Option::None
        }
      }
    }
  }

  /// The notary proof: the lone proof, or the tail of a two-element chain.
  pub fn notary(&self) -> std::option::Option<&EnvelopeProof> {
    match self {
      Self::Single(proof) => std::option::Option::Some(proof),
      Self::Chain(proofs) => {
        if proofs.len() == 2 {
          proofs.get(1)
        } else {
          std::option::Option::None
        }
      }
    }
  }

  /// True when this is the array form, whatever its length.
  pub fn is_chain(&self) -> bool {
    std::matches!(self, Self::Chain(_))
  }
}

/// Which of the two attestation modes an envelope declares (spec §7.1.7).
///
/// The wire spells these exactly as written, so no serde rename is needed.
/// ABSENT means `NotaryAttested` — see [`PolicyDescriptor::effective_attestation_mode`].
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::marker::Copy,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
pub enum AttestationMode {
  /// The human's own key signed this envelope; `proof` is a chain.
  PrincipalSigned,
  /// A notary asserts the human authorized this. Strictly weaker.
  NotaryAttested,
}

impl AttestationMode {
  /// The exact wire spelling, for error messages and logs.
  ///
  /// Returned as `&'static str` rather than via `Display` so an error
  /// constructor can name a mode without allocating, and so the string an
  /// operator reads in a log is byte-identical to the one on the wire.
  pub fn label(&self) -> &'static str {
    match self {
      Self::PrincipalSigned => "PrincipalSigned",
      Self::NotaryAttested => "NotaryAttested",
    }
  }
}

impl std::fmt::Display for AttestationMode {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    std::write!(f, "{}", self.label())
  }
}

impl std::str::FromStr for AttestationMode {
  type Err = std::string::String;

  /// The inverse of [`AttestationMode::label`], and the ONE place the wire
  /// spellings are matched. Every binding's `require_attestation_mode` takes
  /// the required mode as a caller-supplied string, and until this impl
  /// existed each binding matched the spellings itself — four identical
  /// copies of one meaning, each a site where a defaulting typo would BE the
  /// downgrade that gate exists to refuse. The bindings now call this and
  /// stay glue.
  ///
  /// The error is a plain message rather than an [`crate::errors::AphError`]
  /// on purpose: an unknown label here is a CALLER's programming mistake
  /// (nothing from the wire is involved), so it must not dress itself in a
  /// protocol code a caller might route on.
  fn from_str(label: &str) -> std::result::Result<Self, Self::Err> {
    match label {
      "PrincipalSigned" => std::result::Result::Ok(Self::PrincipalSigned),
      "NotaryAttested" => std::result::Result::Ok(Self::NotaryAttested),
      other => std::result::Result::Err(std::format!(
        "unknown attestation mode `{}`: expected `PrincipalSigned` or `NotaryAttested`",
        other
      )),
    }
  }
}

/// The closed channel-kind vocabulary (§7.1.5), as a TYPE.
///
/// **Why this exists.** `ChannelDescriptor.kind` reached v0.1 as a bare
/// `String`, so nothing in this crate refused a value outside the closed
/// set — while the independent TypeScript implementation refused it at
/// parse. Two implementations of one specification reached opposite
/// verdicts on the same bytes, which is the defect class a second
/// implementation exists to surface. This enum is the same repair already
/// applied to `AttestationMode` above and `StatusPurpose` in
/// `credential_status`: model the closed set as a closed type, so an
/// unrecognized value is a constructible failure instead of a silent pass.
///
/// The wire field itself stays `String` in this revision (adopting the enum
/// as the field type is a deliberate, separate breaking change); verifiers
/// enforce the set via [`crate::verification::require_closed_vocabulary`].
#[derive(std::fmt::Debug, std::clone::Clone, std::marker::Copy, std::cmp::PartialEq, std::cmp::Eq)]
pub enum ChannelKind {
  /// Wire value `slack`.
  Slack,
  /// Wire value `email`.
  Email,
  /// Wire value `discord`.
  Discord,
  /// Wire value `teams`.
  Teams,
  /// Wire value `whatsapp`.
  Whatsapp,
  /// Wire value `google_chat` — snake_case by erratum; every published
  /// example and signed fixture emits this spelling.
  GoogleChat,
  /// Wire value `imessage`.
  Imessage,
  /// Wire value `service` — a service endpoint an agent delivers a
  /// state-changing act to (RFC 0002). The endpoint IS the end-delivery
  /// medium, which is why this is a channel kind and not a name for the
  /// agent-to-agent rail that carried it (§1.1.1).
  Service,
  /// Wire value `squillo` — an in-application messaging surface where a
  /// human reads the message in that application's client (RFC 0007). A
  /// peer of [`Self::Slack`] and [`Self::Discord`], not a layer across
  /// them. NOT the membership-scope value of the same spelling that
  /// RFC 0004 refused: this names the DELIVERY MEDIUM.
  Squillo,
}

impl ChannelKind {
  /// Every member of the closed set, in §7.1.5 order. The ONE enumerable
  /// other surfaces (docs, tests, bindings) derive from.
  pub const ALL: [Self; 9] = [
    Self::Slack,
    Self::Email,
    Self::Discord,
    Self::Teams,
    Self::Whatsapp,
    Self::GoogleChat,
    Self::Imessage,
    Self::Service,
    Self::Squillo,
  ];

  /// The exact wire spelling. Exhaustive on purpose: adding a channel kind
  /// without deciding its wire spelling must not compile.
  pub fn label(&self) -> &'static str {
    match self {
      Self::Slack => "slack",
      Self::Email => "email",
      Self::Discord => "discord",
      Self::Teams => "teams",
      Self::Whatsapp => "whatsapp",
      Self::GoogleChat => "google_chat",
      Self::Imessage => "imessage",
      Self::Service => "service",
      Self::Squillo => "squillo",
    }
  }

  /// The whole closed set, comma-joined, for the strict-parse refusal
  /// message. DERIVED from [`Self::ALL`] rather than written out beside it:
  /// a hand-maintained second copy of a closed vocabulary is precisely the
  /// defect closing the set exists to prevent, and this message is read by
  /// implementers deciding what to emit — it going stale would teach them
  /// the wrong set.
  fn labels_for_error() -> std::string::String {
    Self::ALL
      .iter()
      .map(Self::label)
      .collect::<std::vec::Vec<&'static str>>()
      .join(", ")
  }
}

impl std::fmt::Display for ChannelKind {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    std::write!(f, "{}", self.label())
  }
}

impl std::str::FromStr for ChannelKind {
  type Err = std::string::String;

  /// The inverse of [`ChannelKind::label`], and the ONE place the wire
  /// spellings are matched. The error is a plain message, not an
  /// [`crate::errors::AphError`]: §8.3 step 1 classifies an unrecognized
  /// value as a STRICT-PARSE rejection, the layer below the protocol's
  /// closed set of error codes — exactly as the TypeScript implementation
  /// models it with `AphParseError`. The message mirrors that
  /// implementation's shape so the two report the same failure the same way.
  fn from_str(label: &str) -> std::result::Result<Self, Self::Err> {
    match label {
      "slack" => std::result::Result::Ok(Self::Slack),
      "email" => std::result::Result::Ok(Self::Email),
      "discord" => std::result::Result::Ok(Self::Discord),
      "teams" => std::result::Result::Ok(Self::Teams),
      "whatsapp" => std::result::Result::Ok(Self::Whatsapp),
      "google_chat" => std::result::Result::Ok(Self::GoogleChat),
      "imessage" => std::result::Result::Ok(Self::Imessage),
      "service" => std::result::Result::Ok(Self::Service),
      "squillo" => std::result::Result::Ok(Self::Squillo),
      other => std::result::Result::Err(std::format!(
        "`{}` is not in the closed set {{{}}}",
        other,
        Self::labels_for_error()
      )),
    }
  }
}

// serde for ChannelKind DELEGATES to `label()` / `from_str` rather than
// restating the wire spellings in attributes. A `rename_all` or a set of
// `#[serde(rename = ...)]` lines would be a SECOND mapping of the same
// vocabulary, free to drift from the first — and the spellings here are
// exactly the irregular ones a second copy gets wrong (`google_chat` is
// snake_case among single words; `DM` is upper among PascalCase). One
// mapping, two directions.
impl serde::Serialize for ChannelKind {
  fn serialize<S: serde::Serializer>(
    &self,
    serializer: S,
  ) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(self.label())
  }
}

impl<'de> serde::Deserialize<'de> for ChannelKind {
  fn deserialize<D: serde::Deserializer<'de>>(
    deserializer: D,
  ) -> std::result::Result<Self, D::Error> {
    let raw = <std::string::String as serde::Deserialize>::deserialize(deserializer)?;
    <Self as std::str::FromStr>::from_str(&raw).map_err(serde::de::Error::custom)
  }
}

/// The closed content-class vocabulary (§7.1.6), as a TYPE.
///
/// Same repair, same reasons as [`ChannelKind`] above: the wire field is a
/// `String` and nothing refused values outside the closed set. See that
/// type's documentation for the full account.
#[derive(std::fmt::Debug, std::clone::Clone, std::marker::Copy, std::cmp::PartialEq, std::cmp::Eq)]
pub enum ContentClass {
  /// Wire value `Reply`.
  Reply,
  /// Wire value `New`.
  New,
  /// Wire value `Mention`.
  Mention,
  /// Wire value `DM` — both letters uppercase on the wire.
  Dm,
  /// Wire value `Channel`.
  Channel,
  /// Wire value `BulkSend`.
  BulkSend,
  /// Wire value `Broadcast`.
  Broadcast,
  /// Wire value `Mutation` — this act CHANGES STATE rather than carrying a
  /// message (RFC 0002). It is required to match at both the mandate and
  /// envelope layer (§6.2), so a notarized mutation is recorded as one
  /// inside the signature.
  Mutation,
}

impl ContentClass {
  /// Every member of the closed set, in §7.1.6 order.
  pub const ALL: [Self; 8] = [
    Self::Reply,
    Self::New,
    Self::Mention,
    Self::Dm,
    Self::Channel,
    Self::BulkSend,
    Self::Broadcast,
    Self::Mutation,
  ];

  /// The exact wire spelling. Exhaustive on purpose.
  pub fn label(&self) -> &'static str {
    match self {
      Self::Reply => "Reply",
      Self::New => "New",
      Self::Mention => "Mention",
      Self::Dm => "DM",
      Self::Channel => "Channel",
      Self::BulkSend => "BulkSend",
      Self::Broadcast => "Broadcast",
      Self::Mutation => "Mutation",
    }
  }

  /// The whole closed set, comma-joined, for the strict-parse refusal
  /// message. DERIVED from [`Self::ALL`] rather than written out beside it:
  /// a hand-maintained second copy of a closed vocabulary is precisely the
  /// defect closing the set exists to prevent, and this message is read by
  /// implementers deciding what to emit — it going stale would teach them
  /// the wrong set.
  fn labels_for_error() -> std::string::String {
    Self::ALL
      .iter()
      .map(Self::label)
      .collect::<std::vec::Vec<&'static str>>()
      .join(", ")
  }
}

impl std::fmt::Display for ContentClass {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    std::write!(f, "{}", self.label())
  }
}

impl std::str::FromStr for ContentClass {
  type Err = std::string::String;

  /// The inverse of [`ContentClass::label`]. Error shape per
  /// [`ChannelKind::from_str`]'s documentation.
  fn from_str(label: &str) -> std::result::Result<Self, Self::Err> {
    match label {
      "Reply" => std::result::Result::Ok(Self::Reply),
      "New" => std::result::Result::Ok(Self::New),
      "Mention" => std::result::Result::Ok(Self::Mention),
      "DM" => std::result::Result::Ok(Self::Dm),
      "Channel" => std::result::Result::Ok(Self::Channel),
      "BulkSend" => std::result::Result::Ok(Self::BulkSend),
      "Broadcast" => std::result::Result::Ok(Self::Broadcast),
      "Mutation" => std::result::Result::Ok(Self::Mutation),
      other => std::result::Result::Err(std::format!(
        "`{}` is not in the closed set {{{}}}",
        other,
        Self::labels_for_error()
      )),
    }
  }
}

// serde for ContentClass DELEGATES to `label()` / `from_str` rather than
// restating the wire spellings in attributes. A `rename_all` or a set of
// `#[serde(rename = ...)]` lines would be a SECOND mapping of the same
// vocabulary, free to drift from the first — and the spellings here are
// exactly the irregular ones a second copy gets wrong (`google_chat` is
// snake_case among single words; `DM` is upper among PascalCase). One
// mapping, two directions.
impl serde::Serialize for ContentClass {
  fn serialize<S: serde::Serializer>(
    &self,
    serializer: S,
  ) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(self.label())
  }
}

impl<'de> serde::Deserialize<'de> for ContentClass {
  fn deserialize<D: serde::Deserializer<'de>>(
    deserializer: D,
  ) -> std::result::Result<Self, D::Error> {
    let raw = <std::string::String as serde::Deserialize>::deserialize(deserializer)?;
    <Self as std::str::FromStr>::from_str(&raw).map_err(serde::de::Error::custom)
  }
}

/// The notarized claim: who authorized what, on which channel, under
/// which policy, attested by which notary.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSubject {
  /// The human on whose behalf the agent acted.
  pub human_principal: HumanPrincipalRef,
  /// The agent that produced the communication.
  pub agent: AgentRef,
  /// Delivery channel and recipient addressing.
  pub channel: ChannelDescriptor,
  /// What was sent: content class, body hash, size, preview.
  pub communication: CommunicationDescriptor,
  /// The authorization decision and the scope it matched.
  pub policy: PolicyDescriptor,
  /// Which notary decided, when, and how long it took.
  pub notarization: NotarizationMetadata,
  /// Last-position additive field. Optional Apple Foundation Models AUR
  /// acceptance claim per `(user_id, device_id, aur_version_hash)`.
  /// `#[serde(default, skip_serializing_if = "Option::is_none")]` preserves
  /// wire back-compat (legacy envelopes omit the field and continue to
  /// deserialize cleanly).
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub apple_aur_acceptance: std::option::Option<AppleAurAcceptanceClaim>,
  /// Last-position additive field. What the sender says this act MEANS, in
  /// terms of one or more independently published vocabularies (RFC 0006).
  ///
  /// Omitted when absent, so an envelope making no such claim is
  /// byte-identical to one written before the field existed and every
  /// signature over those bytes stays valid.
  ///
  /// ⚠ EMITTING THIS IS VERSION-GATED, and the reason is structural rather
  /// than stylistic: every wire struct in this module carries
  /// `deny_unknown_fields`, so a verifier built before this field existed
  /// does not ignore it — it fails at STRICT PARSE, below the protocol's own
  /// error vocabulary. A producer MUST NOT emit this until it has reason to
  /// believe the recipient understands it; the AgentCard extension
  /// declaration (§10.1) is the existing mechanism for forming that belief.
  /// Adding the field to this type is safe for everyone. Putting it on the
  /// wire is not, and that asymmetry is the whole of the rule.
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub act_classification: std::option::Option<ActClassification>,
}

/// Reference to the human on whose behalf the agent acted.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanPrincipalRef {
  /// DID of the human principal.
  pub id: String,
  /// Human-readable name, for display in consent UIs and audit logs.
  pub display_name: String,
}

/// Reference to the agent that produced the communication.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentRef {
  /// DID of the agent (typically `did:web:...`).
  pub id: String,
  /// Optional URI of the agent's A2A Agent Card.
  #[serde(default)]
  pub agent_card_uri: std::option::Option<String>,
  /// Human-readable agent name.
  pub display_name: String,
  /// Agent version string, so a recipient can tell releases apart.
  pub version: String,
}

/// Delivery channel and its channel-shaped recipient addressing.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelDescriptor {
  /// Channel kind, drawn from the closed set (§7.1.5).
  ///
  /// Typed rather than `String`: an unrecognized value is now a parse
  /// failure, which is what §8.3 step 1 has always required and what the
  /// independent TypeScript implementation already did.
  pub kind: ChannelKind,
  /// Channel-shaped opaque blob (opaque to APH core).
  pub recipient_addressing: serde_json::Value,
}

/// What was sent: classification plus the hash that binds this credential
/// to a specific message body.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommunicationDescriptor {
  /// Content classification, drawn from the closed set (§7.1.6).
  ///
  /// Typed for the same reason as `ChannelDescriptor.kind`: the closed set
  /// lived in prose while the field admitted any string.
  pub content_class: ContentClass,
  /// SHA-256 of the message body, 64 lowercase hex characters.
  pub body_sha256: String,
  /// Body length in bytes.
  pub body_size: u64,
  /// Number of body lines included in `preview`.
  pub preview_lines: u32,
  /// Truncated body excerpt for human review at decision time.
  pub preview: String,
}

/// The authorization decision and the scope that produced it.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyDescriptor {
  /// `"AlwaysAllow" | "AskEveryTime" | "NeverAllow"`.
  pub decision: PolicyDecision,
  /// e.g., `"per-channel" | "per-recipient" | "global"`.
  pub matched_scope: String,
  /// Parent delegation mandate, absent for one-shot AskEveryTime grants.
  #[serde(default)]
  pub delegation_mandate_id: std::option::Option<String>,
  /// OAuth 2.0 Token Exchange `act` chain (RFC 8693) — optional cross-system
  /// principal chain. Each element is a DID string.
  #[serde(default)]
  pub act_chain: Vec<String>,
  /// Who proved the authorization (§7.1.7). ABSENT means `NotaryAttested`.
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub attestation_mode: std::option::Option<AttestationMode>,
  /// The complete parent mandate, embedded so the human's signature on it
  /// verifies offline (§7.1.7.1).
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub delegation_mandate: std::option::Option<crate::delegation_mandate::DelegationMandate>,
}

impl PolicyDescriptor {
  /// The declared mode, resolving ABSENT to `NotaryAttested` per §7.1.7.
  ///
  /// Absence is not "unknown": §7.1.7 fixes it as `NotaryAttested` so that
  /// every envelope written before `attestationMode` existed keeps a single,
  /// unambiguous meaning — the weaker one. Defaulting the other way would
  /// silently promote every legacy envelope to a claim no one made.
  pub fn effective_attestation_mode(&self) -> AttestationMode {
    match self.attestation_mode {
      std::option::Option::Some(mode) => mode,
      std::option::Option::None => AttestationMode::NotaryAttested,
    }
  }
}

/// Which notary made the decision, when, and how long it took.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotarizationMetadata {
  /// The notary service that decided.
  pub notary_service: NotaryServiceRef,
  /// RFC 3339 decision timestamp.
  pub decision_timestamp: String,
  /// Decision latency in milliseconds — audit evidence for whether a human
  /// was plausibly in the loop.
  pub decision_latency_ms: u64,
}

/// Identity of the notary service, used for key discovery (spec §8.4).
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotaryServiceRef {
  /// DID of the notary.
  pub id: String,
  /// Human-readable notary service name.
  pub name: String,
  /// Notary implementation version.
  pub version: String,
  /// Content digest of the attested release this notary reports running
  /// (spec §7.1.9, §15.3). Declared here because parsing is strict: a
  /// field a conformant notary may send must exist in the shape a
  /// conformant verifier parses. `#[serde(default)]` keeps every envelope
  /// written before this field byte-identical.
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub attested_digest: std::option::Option<String>,
  /// Where the k-of-3 attestation for `attested_digest` may be fetched
  /// (spec §15.3). Carrying it proves nothing on its own — an attestation
  /// attests what was PUBLISHED, never what is RUNNING (§15.7).
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub attestation_uri: std::option::Option<String>,
}

/// Cross-protocol links carried alongside the send authorization.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedMandate {
  /// URI of an AP2 IntentMandate cross-linking payment authorization.
  #[serde(default)]
  pub ap2_intent_mandate_uri: std::option::Option<String>,
  /// Optional base64-encoded AP2 SignedPayload for self-contained
  /// verification when the verifier cannot dereference
  /// `ap2_intent_mandate_uri`. `#[serde(default)]` preserves wire
  /// back-compat for envelopes written before this field was added.
  #[serde(default)]
  pub ap2_signed_payload_b64: std::option::Option<String>,
  /// Optional cross-vault mutation mandate for LinkedMandates issued by a
  /// cross-vault federation engine.
  /// `#[serde(default, skip_serializing_if = "...")]` preserves
  /// wire back-compat (legacy envelopes omit the field).
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub vault_mutation: std::option::Option<
    crate::vault_mutation::VaultMutationMandate,
  >,
}

#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
/// The cryptographic proof block: either a W3C Data Integrity Proof or a
/// detached JWS, per spec §8.2.
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvelopeProof {
  /// Always `"DataIntegrityProof"` for the JCS-canonicalized cryptosuites,
  /// or `"JsonWebSignature2020"` for compact JWS detached.
  #[serde(rename = "type")]
  pub r#type: String,
  /// Required for DataIntegrityProof — `"eddsa-jcs-2022"` or
  /// `"ecdsa-jcs-2019"` — and OMITTED, not nulled, for
  /// `JsonWebSignature2020` (§7.1.11).
  ///
  /// `skip_serializing_if` is load-bearing rather than cosmetic: this member
  /// sits inside the §7.2.1 canonicalization base, so emitting
  /// `"cryptosuite": null` would put a member in the SIGNED bytes that an
  /// implementer following the spec's proof table never builds, and no JWS
  /// envelope this crate minted would verify anywhere else.
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub cryptosuite: std::option::Option<String>,
  /// DID URL referencing the verifying key
  /// (e.g., `did:key:z6Mk...#z6Mk...`).
  pub verification_method: String,
  /// RFC 3339.
  pub created: String,
  /// `"assertionMethod"` for a principal proof or a lone notary proof;
  /// `"authentication"` for the notary countersignature of a chain (§7.1.11).
  pub proof_purpose: String,
  /// Multibase or base64url-encoded signature bytes.
  pub proof_value: String,
  /// Identifier for this proof, unique within the envelope. REQUIRED when
  /// `proof` is a chain, absent for a lone proof, which links to nothing.
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub id: std::option::Option<String>,
  /// The `id` of the proof this one countersigns. Present on the notary
  /// proof of a chain; absent on the principal proof, its head.
  #[serde(default, skip_serializing_if = "std::option::Option::is_none")]
  pub previous_proof: std::option::Option<String>,
}

/// Last-position sibling struct. Carries Apple Foundation Models AUR
/// acceptance per `(user_id, device_id, aur_version_hash)` tuple.
/// Embedded as `Option<AppleAurAcceptanceClaim>` on
/// `CredentialSubject.apple_aur_acceptance`. The field is
/// `#[serde(default, skip_serializing_if = "...")]` so legacy envelopes that
/// predate this claim continue to deserialize cleanly.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppleAurAcceptanceClaim {
  /// User-scoped DID for whom acceptance was recorded.
  pub user_id: String,
  /// Device-scoped opaque identifier (acceptance is recorded per
  /// `(user_id, device_id)` pair).
  pub device_id: String,
  /// SHA-256 hex of the Apple AUR snapshot text accepted.
  pub aur_version_hash: String,
  /// RFC 3339 acceptance timestamp.
  pub accepted_at: String,
  /// `"foundation_models_framework_aur"` for forward-compat with future Apple legal documents.
  pub document_kind: String,
}

/// The closed §7.1.7 policy-decision vocabulary, as a type.
///
/// Same repair, same reasons as [`ChannelKind`] above, found by the same
/// audit discipline one field over: the wire field was a bare `String` the
/// reference validated NOWHERE, while the independent TypeScript
/// implementation refused an unrecognized value at parse — two
/// conformant-claiming implementations reaching opposite verdicts on the
/// same bytes. The reference was the permissive surface, and per the
/// standing guardrail the permissive surface is the wrong one. The Snapp
/// had declared this vocabulary as an enum all along; the reference was the
/// LAST populator without the type.
///
/// The doc-comment on the wire field (§7.1.7) carries the semantic warning:
/// this records the human's standing CONFIGURATION, never the verdict on
/// this act.
#[derive(std::fmt::Debug, std::clone::Clone, std::marker::Copy, std::cmp::PartialEq, std::cmp::Eq)]
pub enum PolicyDecision {
  /// Wire value `AlwaysAllow`.
  AlwaysAllow,
  /// Wire value `AskEveryTime` — and it stays `AskEveryTime` after the
  /// human approves; the mandate's existence is what asserts the approval
  /// (§9.1 admits no path to issuance that bypasses `Approved`).
  AskEveryTime,
  /// Wire value `NeverAllow` — recorded, but never yields an envelope.
  NeverAllow,
}

impl PolicyDecision {
  /// Every member of the closed set, in §7.1.7 order.
  pub const ALL: [Self; 3] = [Self::AlwaysAllow, Self::AskEveryTime, Self::NeverAllow];

  /// The exact wire spelling. Exhaustive on purpose.
  pub fn label(&self) -> &'static str {
    match self {
      Self::AlwaysAllow => "AlwaysAllow",
      Self::AskEveryTime => "AskEveryTime",
      Self::NeverAllow => "NeverAllow",
    }
  }

  /// The whole closed set, comma-joined, for the strict-parse refusal
  /// message — DERIVED from [`Self::ALL`], per the siblings' reasoning.
  fn labels_for_error() -> std::string::String {
    Self::ALL
      .iter()
      .map(Self::label)
      .collect::<std::vec::Vec<&'static str>>()
      .join(", ")
  }
}

impl std::fmt::Display for PolicyDecision {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    std::write!(f, "{}", self.label())
  }
}

impl std::str::FromStr for PolicyDecision {
  type Err = std::string::String;

  /// The inverse of [`PolicyDecision::label`]. Error shape per
  /// [`ChannelKind::from_str`]'s documentation: a plain message, because
  /// §8.3 step 1 classifies an unrecognized value as a strict-parse
  /// rejection, below the protocol's closed set of error codes.
  fn from_str(label: &str) -> std::result::Result<Self, Self::Err> {
    match label {
      "AlwaysAllow" => std::result::Result::Ok(Self::AlwaysAllow),
      "AskEveryTime" => std::result::Result::Ok(Self::AskEveryTime),
      "NeverAllow" => std::result::Result::Ok(Self::NeverAllow),
      other => std::result::Result::Err(std::format!(
        "`{}` is not in the closed set {{{}}}",
        other,
        Self::labels_for_error()
      )),
    }
  }
}

impl serde::Serialize for PolicyDecision {
  fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(self.label())
  }
}

impl<'de> serde::Deserialize<'de> for PolicyDecision {
  fn deserialize<D: serde::Deserializer<'de>>(
    deserializer: D,
  ) -> std::result::Result<Self, D::Error> {
    let raw = <std::string::String as serde::Deserialize>::deserialize(deserializer)?;
    <Self as std::str::FromStr>::from_str(&raw).map_err(serde::de::Error::custom)
  }
}

/// What a sender says an act MEANS, against vocabularies both parties can
/// resolve independently (RFC 0006).
///
/// # What this proves, and what it does not
///
/// It proves WHICH VOCABULARY THE SENDER CITED, inside the signature. It does
/// NOT prove the sender classified correctly: a sender can label a funds
/// transfer as a scheduling proposal and sign it. What the binding buys is
/// that a DISAGREEMENT becomes visible where a MISUNDERSTANDING was
/// invisible — two parties now mean the same thing by a word, and a recipient
/// can check the claim against the payload it accompanies. That is worth
/// having, it is not integrity of classification, and no caller should
/// present it as the latter.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActClassification {
  /// Every vocabulary the verdict depended on, in fold order.
  ///
  /// A LIST because an overlay is a separate published artifact with its own
  /// digest: a classifier that ran against a base and a tightening overlay
  /// was produced by TWO artifacts, and naming only one would put a false
  /// statement inside a signature.
  ///
  /// NON-EMPTY, refused at parse: labels resolve against the vocabularies
  /// that define them, so a claim citing nothing is labels nobody can look
  /// up — meaningless rather than merely sparse. The independent TypeScript
  /// implementation refused this from its first draft; this constraint is
  /// what keeps the reference from silently accepting bytes it refuses.
  #[serde(deserialize_with = "non_empty_vocabularies")]
  pub vocabularies: std::vec::Vec<VocabularyRef>,
  /// The family-qualified labels this act carries.
  ///
  /// A LIST because one act carries verdicts from several families at once —
  /// what kind of act it is, how reversible, how wide its blast radius, what
  /// routing it implies. Carrying one would discard the verdicts a
  /// recipient's policy most wants.
  pub labels: std::vec::Vec<ActLabel>,
}

/// Refuses an empty `vocabularies` array at parse (§7.1.12: the member is
/// required AND non-empty). Absent-vs-empty is the §8.4.6 distinction one
/// field down: an envelope with no claim omits the whole object, and an
/// object present but citing nothing is malformed, not minimal.
fn non_empty_vocabularies<'de, D: serde::Deserializer<'de>>(
  deserializer: D,
) -> std::result::Result<std::vec::Vec<VocabularyRef>, D::Error> {
  let refs = <std::vec::Vec<VocabularyRef> as serde::Deserialize>::deserialize(deserializer)?;
  if refs.is_empty() {
    return std::result::Result::Err(serde::de::Error::custom(
      "`vocabularies` is empty; a classification must name every vocabulary \
       the verdict depended on, and one that names none claims nothing",
    ));
  }
  std::result::Result::Ok(refs)
}

/// One family-qualified label: `FAMILY/LABEL`.
///
/// A TYPE rather than a `String` with a comment, for the reason this whole
/// wave exists: a rule that lives only in prose is open in every
/// implementation that never read the prose. An unqualified label is
/// ambiguous — `ACCESS_GRANT` means nothing without the family that scopes
/// it, and two vocabularies may both define a bare word — so an unqualified
/// one is refused at parse rather than carried and disambiguated later by
/// whoever guesses.
///
/// # What is validated, and what deliberately is not
///
/// The STRUCTURE is ours: exactly one separator, neither side empty. The
/// SPELLING is the vocabulary's — no character set is imposed, because a
/// third-party vocabulary may name its families in a convention this project
/// has not thought of, and refusing those would make the extension model in
/// RFC 0006 a formality. Refuse what is meaningless; do not legislate taste.
#[derive(std::fmt::Debug, std::clone::Clone, std::cmp::PartialEq, std::cmp::Eq)]
pub struct ActLabel {
  family: String,
  label: String,
}

impl ActLabel {
  /// The family that scopes this label.
  pub fn family(&self) -> &str {
    &self.family
  }

  /// The label within that family.
  pub fn label(&self) -> &str {
    &self.label
  }

  /// The wire spelling, `FAMILY/LABEL`.
  pub fn qualified(&self) -> std::string::String {
    std::format!("{}/{}", self.family, self.label)
  }
}

impl std::fmt::Display for ActLabel {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    std::write!(f, "{}", self.qualified())
  }
}

impl std::str::FromStr for ActLabel {
  type Err = std::string::String;

  /// The ONE place the qualified form is matched. The error is a plain
  /// message rather than an [`crate::errors::AphError`], for the same reason
  /// the closed vocabularies' is: §8.3 step 1 classifies a malformed value as
  /// a STRICT-PARSE rejection, the layer below the protocol's closed set of
  /// error codes.
  fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
    let (family, label) = match raw.split_once('/') {
      std::option::Option::Some(parts) => parts,
      std::option::Option::None => {
        return std::result::Result::Err(std::format!(
          "`{}` is not family-qualified: a label is written `FAMILY/LABEL`",
          raw
        ));
      }
    };
    if family.is_empty() || label.is_empty() {
      return std::result::Result::Err(std::format!(
        "`{}` has an empty family or label; both sides of the `/` are required",
        raw
      ));
    }
    if label.contains('/') {
      return std::result::Result::Err(std::format!(
        "`{}` has more than one `/`; a label names exactly one family",
        raw
      ));
    }
    std::result::Result::Ok(Self {
      family: family.to_string(),
      label: label.to_string(),
    })
  }
}

impl serde::Serialize for ActLabel {
  fn serialize<S: serde::Serializer>(
    &self,
    serializer: S,
  ) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(&self.qualified())
  }
}

impl<'de> serde::Deserialize<'de> for ActLabel {
  fn deserialize<D: serde::Deserializer<'de>>(
    deserializer: D,
  ) -> std::result::Result<Self, D::Error> {
    let raw = <std::string::String as serde::Deserialize>::deserialize(deserializer)?;
    <Self as std::str::FromStr>::from_str(&raw).map_err(serde::de::Error::custom)
  }
}

/// A published vocabulary, named and pinned.
///
/// Deliberately NOT a path into a serialization. The name identifies the
/// thing; a path identifies one encoding of it, and encodings move — this
/// project watched a bundle's blocks change nesting under a toolchain bump
/// with no source change at all. A signature cannot be re-pointed afterward,
/// so a reference must name the vocabulary rather than its current shape.
#[derive(
  std::fmt::Debug,
  std::clone::Clone,
  std::cmp::PartialEq,
  std::cmp::Eq,
  serde::Serialize,
  serde::Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VocabularyRef {
  /// The vocabulary's name, as its bundle declares it.
  pub name: String,
  /// The version, as its bundle declares it.
  pub version: String,
  /// The bundle's integrity digest, VERBATIM — the same `sha256-…` string
  /// the compiled bundle already carries, never a re-encoding of it.
  ///
  /// Carrying it verbatim keeps ONE spelling of a digest across the whole
  /// system. A re-encoding is a second derivation of one fact, and two
  /// derivations of one fact drift. The digest is also what makes the
  /// reference checkable at all: without it a citation points at whatever
  /// the publisher serves today, and a publisher — or anyone who compromises
  /// their origin — could change what a signed envelope meant after it was
  /// signed.
  pub digest: String,
}

#[cfg(test)]
mod tests {
  // -------- helpers --------

  fn sample_human_principal() -> super::HumanPrincipalRef {
    super::HumanPrincipalRef {
      id: "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy".to_string(),
      display_name: "Scott Wyatt".to_string(),
    }
  }

  fn sample_agent() -> super::AgentRef {
    super::AgentRef {
      id: "did:web:agent.squillo.com".to_string(),
      agent_card_uri: std::option::Option::Some(
        "https://agent.squillo.com/.well-known/agent-card.json".to_string(),
      ),
      display_name: "Squillo Concierge".to_string(),
      version: "1.0".to_string(),
    }
  }

  fn sample_channel() -> super::ChannelDescriptor {
    super::ChannelDescriptor {
      kind: super::ChannelKind::Slack,
      recipient_addressing: serde_json::json!({
        "teamId": "T01234567",
        "channelId": "C01234567",
        "parentTs": "1716249600.000100"
      }),
    }
  }

  fn sample_communication() -> super::CommunicationDescriptor {
    super::CommunicationDescriptor {
      content_class: super::ContentClass::Reply,
      body_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
      body_size: 1842,
      preview_lines: 3,
      preview: "hello world".to_string(),
    }
  }

  fn sample_policy() -> super::PolicyDescriptor {
    super::PolicyDescriptor {
      decision: super::PolicyDecision::AskEveryTime,
      matched_scope: "per-channel".to_string(),
      delegation_mandate_id: std::option::Option::None,
      act_chain: std::vec::Vec::new(),
      attestation_mode: std::option::Option::None,
      delegation_mandate: std::option::Option::None,
    }
  }

  #[test]
  fn attestation_fields_are_omitted_when_absent_and_accepted_when_present() {
    // The two §15.3 attestation fields were added to a struct that parses
    // with `deny_unknown_fields` and whose output is signed. Two things must
    // both hold: a notary that makes no attestation claim serializes
    // byte-identically to before the fields existed (or every signature over
    // an existing envelope breaks), and a notary that does make one is not
    // rejected as carrying unknown fields (or conformant verifiers would
    // refuse conformant notaries).
    let bare = sample_notary_service();
    let json = serde_json::to_string(&bare).unwrap();
    std::assert!(
      !json.contains("attestedDigest") && !json.contains("attestationUri"),
      "absent attestation fields must not appear on the wire: {}",
      json
    );

    let with_claim: super::NotaryServiceRef = serde_json::from_str(
      r#"{"id":"did:web:notary.squillo.com","name":"Squillo Notary Service","version":"0.1.0","attestedDigest":"sha256:abc","attestationUri":"https://notary.squillo.com/.well-known/aph-attestation.json"}"#,
    )
    .expect("a notary advertising an attestation must parse");
    std::assert_eq!(
      with_claim.attested_digest.as_deref(),
      std::option::Option::Some("sha256:abc")
    );
  }

  fn sample_notary_service() -> super::NotaryServiceRef {
    super::NotaryServiceRef {
      id: "did:web:notary.squillo.com".to_string(),
      name: "Squillo Notary Service".to_string(),
      version: "0.1.0".to_string(),
      attested_digest: std::option::Option::None,
      attestation_uri: std::option::Option::None,
    }
  }

  fn sample_notarization_metadata() -> super::NotarizationMetadata {
    super::NotarizationMetadata {
      notary_service: sample_notary_service(),
      decision_timestamp: "2026-05-21T00:00:01Z".to_string(),
      decision_latency_ms: 1834,
    }
  }

  fn sample_credential_subject() -> super::CredentialSubject {
    super::CredentialSubject {
      human_principal: sample_human_principal(),
      agent: sample_agent(),
      channel: sample_channel(),
      communication: sample_communication(),
      policy: sample_policy(),
      notarization: sample_notarization_metadata(),
      apple_aur_acceptance: std::option::Option::None,
      act_classification: std::option::Option::None,
    }
  }

  fn sample_linked_mandate() -> super::LinkedMandate {
    super::LinkedMandate {
      ap2_intent_mandate_uri: std::option::Option::Some(
        "urn:uuid:11111111-1111-4111-8111-111111111111".to_string(),
      ),
      ap2_signed_payload_b64: std::option::Option::None,
      vault_mutation: std::option::Option::None,
    }
  }

  fn sample_proof() -> super::EnvelopeProof {
    super::EnvelopeProof {
      r#type: "DataIntegrityProof".to_string(),
      cryptosuite: std::option::Option::Some("eddsa-jcs-2022".to_string()),
      verification_method:
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"
          .to_string(),
      created: "2026-05-21T00:00:01Z".to_string(),
      proof_purpose: "assertionMethod".to_string(),
      proof_value:
        "z3WgvA9JHkbV3qLZHcM4FxBp4xHfQVnVnPKKDdyazQwQGdGzxsRdmZWBxXwQvN6P2sLZbLP4HnRy9LcZdpFLLM6h"
          .to_string(),
      id: std::option::Option::None,
      previous_proof: std::option::Option::None,
    }
  }

  fn sample_envelope() -> super::NotarizationEnvelope {
    super::NotarizationEnvelope {
      aph_version: "0.1".to_string(),
      context: std::vec![
        "https://www.w3.org/ns/credentials/v2".to_string(),
        "https://w3id.org/aph/v1".to_string(),
      ],
      r#type: std::vec![
        "VerifiableCredential".to_string(),
        "AgentSendAuthorizationCredential".to_string(),
      ],
      id: "urn:uuid:00000000-0000-4000-8000-000000000001".to_string(),
      issuer: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV".to_string(),
      valid_from: "2026-05-21T00:00:00Z".to_string(),
      valid_until: "2026-05-22T00:00:00Z".to_string(),
      credential_subject: sample_credential_subject(),
      linked_mandate: std::option::Option::None,
      // Pattern A (§7.1.1): absent here means NO `credentialStatus` key on
      // the wire, which is what keeps this fixture byte-identical to the
      // pre-revocation shape its signatures were made over.
      credential_status: std::option::Option::None,
      proof: super::EnvelopeProofs::Single(sample_proof()),
    }
  }

  fn sample_principal_proof() -> super::EnvelopeProof {
    super::EnvelopeProof {
      r#type: "DataIntegrityProof".to_string(),
      cryptosuite: std::option::Option::Some("eddsa-jcs-2022".to_string()),
      // The human principal's own DID URL — the same DID
      // `sample_human_principal()` carries, which is what §7.1.11 binds.
      verification_method:
        "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy#z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy"
          .to_string(),
      created: "2026-05-21T00:00:02Z".to_string(),
      proof_purpose: "assertionMethod".to_string(),
      proof_value: "z-illustrative-principal-proof-value".to_string(),
      id: std::option::Option::Some("urn:uuid:00000000-0000-4000-8000-0000000000a1".to_string()),
      previous_proof: std::option::Option::None,
    }
  }

  fn sample_notary_countersignature() -> super::EnvelopeProof {
    super::EnvelopeProof {
      r#type: "DataIntegrityProof".to_string(),
      cryptosuite: std::option::Option::Some("eddsa-jcs-2022".to_string()),
      verification_method:
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"
          .to_string(),
      created: "2026-05-21T00:00:03Z".to_string(),
      proof_purpose: "authentication".to_string(),
      proof_value: "z-illustrative-notary-countersignature".to_string(),
      id: std::option::Option::Some("urn:uuid:00000000-0000-4000-8000-0000000000b1".to_string()),
      previous_proof: std::option::Option::Some(
        "urn:uuid:00000000-0000-4000-8000-0000000000a1".to_string(),
      ),
    }
  }

  // -------- Test 1: per-struct round-trip --------

  #[test]
  fn round_trip_human_principal_ref() {
    // Per-struct round-trips exist because deny_unknown_fields makes every
    // sub-struct independently strict: a field lost or renamed here would
    // fail only when that specific object is parsed. This one carries the
    // human's DID — the identity the whole credential attests.
    let v = sample_human_principal();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::HumanPrincipalRef = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_agent_ref() {
    // The agent identity a recipient checks against the delegation; its
    // optional agentCardUri must survive round-tripping alongside the
    // required fields.
    let v = sample_agent();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::AgentRef = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_channel_descriptor() {
    // Holds the opaque recipientAddressing blob (§7.4), the one place
    // arbitrary JSON is preserved verbatim — this pins that it survives
    // untouched rather than being normalized or dropped.
    let v = sample_channel();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::ChannelDescriptor = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_communication_descriptor() {
    // Carries bodySha256 and bodySize — the binding between the credential
    // and the actual message. Any loss here breaks the APH_E009 body-hash
    // check that stops a signature being reused for a different body.
    let v = sample_communication();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::CommunicationDescriptor = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_policy_descriptor() {
    // The authorization record itself (decision, matched scope, delegation
    // id, act chain). Dropping actChain or delegationMandateId would erase
    // the evidence a verifier uses to trace authority back to the human.
    let v = sample_policy();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::PolicyDescriptor = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_notary_service_ref() {
    // Identifies which notary made the decision — needed for key discovery
    // (§8.4) and for auditing which service to hold accountable.
    let v = sample_notary_service();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::NotaryServiceRef = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_notarization_metadata() {
    // Decision timestamp and latency: audit evidence for whether a human
    // was plausibly in the loop, so it must survive intact.
    let v = sample_notarization_metadata();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::NotarizationMetadata = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_credential_subject() {
    // Composition test: the six sub-objects must nest correctly together.
    // Per-struct round-trips above cannot catch a broken assembly (e.g. a
    // field attached at the wrong level).
    let v = sample_credential_subject();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::CredentialSubject = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_linked_mandate() {
    // Cross-protocol link (AP2 payment authorization, vault mutation). It
    // holds three independently-optional fields, so round-tripping proves
    // none of them is lost when the others are absent.
    let v = sample_linked_mandate();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::LinkedMandate = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_envelope_proof() {
    // The signature block itself. If any proof field failed to round-trip,
    // a re-serialized envelope would carry an unverifiable proof.
    let v = sample_proof();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::EnvelopeProof = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  #[test]
  fn round_trip_notarization_envelope() {
    // The whole credential end to end — the exact operation a relaying
    // verifier performs. This is the last line of defense against any
    // field being silently dropped in transit.
    let v = sample_envelope();
    let s = serde_json::to_string(&v).unwrap();
    let v2: super::NotarizationEnvelope = serde_json::from_str(&s).unwrap();
    std::assert_eq!(v, v2);
  }

  // -------- Test 2: wire-key shape for reserved/JSON-LD names --------

  #[test]
  fn envelope_serializes_type_as_type_and_context_as_at_context() {
    // Two JSON-LD keys Rust cannot name directly: "@context" (illegal
    // identifier) and "type" (keyword, written r#type). Both depend on
    // explicit #[serde(rename)] attributes — drop one and the envelope
    // stops being a valid W3C Verifiable Credential.
    let v = sample_envelope();
    let s = serde_json::to_string(&v).unwrap();
    std::assert!(
      s.contains("\"type\":"),
      "envelope must serialize r#type as \"type\": {}",
      s
    );
    std::assert!(
      s.contains("\"@context\":"),
      "envelope must serialize context as \"@context\": {}",
      s
    );
    std::assert!(
      !s.contains("\"rType\""),
      "envelope must NOT serialize as \"rType\": {}",
      s
    );
    std::assert!(
      !s.contains("\"r#type\""),
      "envelope must NOT serialize as \"r#type\": {}",
      s
    );
  }

  #[test]
  fn proof_serializes_type_as_type() {
    // Same r#type rename, applied on the nested proof block — pinned
    // separately because the attribute must be repeated per struct and is
    // easy to omit on a newly added one.
    let v = sample_proof();
    let s = serde_json::to_string(&v).unwrap();
    std::assert!(
      s.contains("\"type\":"),
      "proof must serialize r#type as \"type\": {}",
      s
    );
    std::assert!(
      !s.contains("\"rType\""),
      "proof must NOT serialize as \"rType\": {}",
      s
    );
  }

  // -------- Test 3: deny_unknown_fields rejection --------

  #[test]
  fn envelope_rejects_unknown_field() {
    // Strict parsing (§7.1, §8.3 step 1) is normative: an unknown envelope
    // field must be a hard error. Accepting-and-ignoring would let a
    // producer smuggle a claim the verifier never evaluates.
    let s = serde_json::json!({
      "aphVersion": "0.1",
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/aph/v1"
      ],
      "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
      "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
      "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
      "validFrom": "2026-05-21T00:00:00Z",
      "validUntil": "2026-05-22T00:00:00Z",
      "credentialSubject": {
        "humanPrincipal": {
          "id": "did:key:abc",
          "displayName": "X"
        },
        "agent": {
          "id": "did:web:agent.squillo.com",
          "displayName": "X",
          "version": "1.0"
        },
        "channel": {
          "kind": "slack",
          "recipientAddressing": {}
        },
        "communication": {
          "contentClass": "Reply",
          "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "bodySize": 0,
          "previewLines": 0,
          "preview": ""
        },
        "policy": {
          "decision": "AskEveryTime",
          "matchedScope": "per-channel"
        },
        "notarization": {
          "notaryService": {
            "id": "did:web:notary.squillo.com",
            "name": "Squillo Notary Service",
            "version": "0.1.0"
          },
          "decisionTimestamp": "2026-05-21T00:00:01Z",
          "decisionLatencyMs": 0
        }
      },
      "proof": {
        "type": "DataIntegrityProof",
        "verificationMethod": "did:key:abc#abc",
        "created": "2026-05-21T00:00:01Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z..."
      },
      "extraKey": "x"
    })
    .to_string();
    let r: std::result::Result<super::NotarizationEnvelope, _> = serde_json::from_str(&s);
    std::assert!(
      r.is_err(),
      "deny_unknown_fields must reject extraKey: {:?}",
      r
    );
  }

  #[test]
  fn human_principal_ref_rejects_unknown_field() {
    // deny_unknown_fields does NOT cascade to nested structs — each one
    // needs its own attribute. This pins that the nested case is covered,
    // not merely the top level.
    let s = serde_json::json!({
      "id": "did:key:abc",
      "displayName": "X",
      "rogue": true
    })
    .to_string();
    let r: std::result::Result<super::HumanPrincipalRef, _> = serde_json::from_str(&s);
    std::assert!(
      r.is_err(),
      "deny_unknown_fields must reject rogue field: {:?}",
      r
    );
  }

  // -------- Test 4: defaults on optional fields --------

  #[test]
  fn envelope_deserializes_without_linked_mandate() {
    // Most envelopes carry no cross-protocol link, so the common case must
    // parse with the key absent — under deny_unknown_fields this works
    // only while #[serde(default)] is present.
    let s = serde_json::json!({
      "aphVersion": "0.1",
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/aph/v1"
      ],
      "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
      "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
      "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
      "validFrom": "2026-05-21T00:00:00Z",
      "validUntil": "2026-05-22T00:00:00Z",
      "credentialSubject": {
        "humanPrincipal": {
          "id": "did:key:abc",
          "displayName": "X"
        },
        "agent": {
          "id": "did:web:agent.squillo.com",
          "displayName": "X",
          "version": "1.0"
        },
        "channel": {
          "kind": "slack",
          "recipientAddressing": {}
        },
        "communication": {
          "contentClass": "Reply",
          "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "bodySize": 0,
          "previewLines": 0,
          "preview": ""
        },
        "policy": {
          "decision": "AskEveryTime",
          "matchedScope": "per-channel"
        },
        "notarization": {
          "notaryService": {
            "id": "did:web:notary.squillo.com",
            "name": "Squillo Notary Service",
            "version": "0.1.0"
          },
          "decisionTimestamp": "2026-05-21T00:00:01Z",
          "decisionLatencyMs": 0
        }
      },
      "proof": {
        "type": "DataIntegrityProof",
        "verificationMethod": "did:key:abc#abc",
        "created": "2026-05-21T00:00:01Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z..."
      }
    })
    .to_string();
    let v: super::NotarizationEnvelope =
      serde_json::from_str(&s).expect("must deserialize with linkedMandate omitted");
    std::assert!(v.linked_mandate.is_none());
  }

  #[test]
  fn envelope_round_trips_a_credential_status_under_the_camel_case_wire_key() {
    // Why this exists: until it did, NOTHING in the repo parsed or emitted a
    // `credentialStatus` ON THE WIRE. The §6.3.3 tests set the field in Rust
    // and the golden test only asserts the key is ABSENT, so the camelCase
    // spelling the field exists to produce — and `deny_unknown_fields`
    // accepting it on `NotarizationEnvelope` at all — were pinned by nothing.
    // A rename to `credential_status`, or the field being dropped from the
    // struct, would have passed the entire suite while making every
    // status-bearing envelope from a conformant notary unparseable.
    //
    // What it pins, in order: the key is ACCEPTED by the strict parser; the
    // nested entry lands in the typed field with its closed enums resolved;
    // and serializing re-emits under exactly `credentialStatus` with exactly
    // the four required members (Pattern A drops the absent `id` — a `null`
    // there would change the JCS bytes a proof covers).
    let s = serde_json::json!({
      "aphVersion": "0.1",
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/aph/v1"
      ],
      "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
      "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
      "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
      "validFrom": "2026-05-21T00:00:00Z",
      "validUntil": "2026-05-22T00:00:00Z",
      "credentialSubject": {
        "humanPrincipal": {
          "id": "did:key:abc",
          "displayName": "X"
        },
        "agent": {
          "id": "did:web:agent.squillo.com",
          "displayName": "X",
          "version": "1.0"
        },
        "channel": {
          "kind": "slack",
          "recipientAddressing": {}
        },
        "communication": {
          "contentClass": "Reply",
          "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "bodySize": 0,
          "previewLines": 0,
          "preview": ""
        },
        "policy": {
          "decision": "AskEveryTime",
          "matchedScope": "per-channel",
          // §6.3.3.1 forbids a status reference with no parent mandate to be
          // the status OF, so the wire sample carries both or it is not a
          // sample of anything a notary may emit.
          "delegationMandateId": "urn:uuid:00000000-0000-4000-8000-0000000000d1"
        },
        "notarization": {
          "notaryService": {
            "id": "did:web:aph-notary.squillo.com",
            "name": "Squillo Notary Service",
            "version": "0.1.0"
          },
          "decisionTimestamp": "2026-05-21T00:00:01Z",
          "decisionLatencyMs": 0
        }
      },
      "credentialStatus": {
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "94567",
        "statusListCredential": "https://aph-notary.squillo.com/.well-known/aph-status.json"
      },
      "proof": {
        "type": "DataIntegrityProof",
        "verificationMethod": "did:key:abc#abc",
        "created": "2026-05-21T00:00:01Z",
        "proofPurpose": "assertionMethod",
        "proofValue": "z..."
      }
    })
    .to_string();
    let v: super::NotarizationEnvelope = serde_json::from_str(&s)
      .expect("deny_unknown_fields must ACCEPT the credentialStatus key");
    let entry = v
      .credential_status
      .as_ref()
      .expect("the wire key must land in the typed field");
    std::assert_eq!(
      entry.r#type,
      crate::credential_status::StatusEntryType::BitstringStatusListEntry
    );
    std::assert_eq!(
      entry.status_purpose,
      crate::credential_status::StatusPurpose::Revocation
    );
    std::assert_eq!(entry.index().expect("the index is readable"), 94567u64);

    // Re-emitted under the SAME key: compared as parsed JSON, not as a
    // substring, so a serializer that wrote the right characters in the
    // wrong place could not pass.
    let back = serde_json::to_string(&v).expect("envelope serializes");
    let reparsed: serde_json::Value = serde_json::from_str(&back).expect("round-trip is JSON");
    let emitted = reparsed
      .get("credentialStatus")
      .expect("the member must be re-emitted as `credentialStatus`");
    std::assert_eq!(
      emitted,
      &serde_json::json!({
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "94567",
        "statusListCredential": "https://aph-notary.squillo.com/.well-known/aph-status.json"
      }),
      "the absent optional `id` must not appear, as a null or otherwise"
    );
    // And the member is INSIDE the bytes the notary proof covers. That is
    // what makes the reference unstrippable in flight: an attacker who
    // deleted `credentialStatus` to force §6.3.3.4 case 1 — the skip — would
    // be altering the signing base, and the proof would stop verifying.
    // Asserted on the canonical base rather than on the struct because the
    // base is the only place the property is actually true or false.
    let base = crate::crypto::proof_base::signing_base(
      &v,
      crate::crypto::proof_base::ProofRole::Notary,
    )
    .expect("a single notary proof builds a notary base");
    std::assert!(
      base.contains("\"credentialStatus\""),
      "the status reference must be covered by the notary signature"
    );
  }

  #[test]
  fn agent_ref_deserializes_without_agent_card_uri() {
    // Not every agent publishes an A2A AgentCard; omitting the URI must
    // stay legal rather than making those agents unable to be notarized.
    let s = serde_json::json!({
      "id": "did:web:agent.squillo.com",
      "displayName": "X",
      "version": "1.0"
    })
    .to_string();
    let v: super::AgentRef =
      serde_json::from_str(&s).expect("must deserialize with agentCardUri omitted");
    std::assert!(v.agent_card_uri.is_none());
  }

  #[test]
  fn policy_descriptor_deserializes_without_optionals() {
    // The one-shot AskEveryTime shape has no delegation and no act chain,
    // so both optional fields must be omissible together — the defaults
    // that make a human-present decision representable at all.
    let s = serde_json::json!({
      "decision": "AskEveryTime",
      "matchedScope": "per-channel"
    })
    .to_string();
    let v: super::PolicyDescriptor =
      serde_json::from_str(&s).expect("must deserialize with optionals omitted");
    std::assert!(v.delegation_mandate_id.is_none());
    std::assert!(v.act_chain.is_empty());
    std::assert!(v.attestation_mode.is_none());
    std::assert!(v.delegation_mandate.is_none());
  }

  #[test]
  fn linked_mandate_deserializes_without_ap2_uri() {
    // A linkedMandate may carry a vault mutation with no payment link, so
    // its fields must be independently optional rather than all-or-nothing.
    let s = serde_json::json!({}).to_string();
    let v: super::LinkedMandate =
      serde_json::from_str(&s).expect("must deserialize with ap2IntentMandateUri omitted");
    std::assert!(v.ap2_intent_mandate_uri.is_none());
  }

  #[test]
  fn envelope_proof_deserializes_without_cryptosuite() {
    // cryptosuite applies to DataIntegrityProof but not to the
    // JsonWebSignature2020 form (§8.2), so a JWS-style proof must parse
    // without it instead of being rejected as malformed.
    let s = serde_json::json!({
      "type": "JsonWebSignature2020",
      "verificationMethod": "did:key:abc#abc",
      "created": "2026-05-21T00:00:01Z",
      "proofPurpose": "assertionMethod",
      "proofValue": "z..."
    })
    .to_string();
    let v: super::EnvelopeProof =
      serde_json::from_str(&s).expect("must deserialize with cryptosuite omitted");
    std::assert!(v.cryptosuite.is_none());
  }

  // -------- Test 5: camelCase wire form --------

  #[test]
  fn human_principal_ref_serializes_camel_case() {
    // Rust field names are snake_case; the wire is camelCase. This pins
    // that the rename_all attribute is actually applied — without it every
    // key would silently change and no other implementation could parse it.
    let v = super::HumanPrincipalRef {
      id: "did:key:abc".to_string(),
      display_name: "Scott".to_string(),
    };
    let s = serde_json::to_string(&v).unwrap();
    std::assert!(
      s.contains("\"displayName\""),
      "must serialize display_name as displayName: {}",
      s
    );
    std::assert!(
      !s.contains("\"display_name\""),
      "must NOT serialize as display_name: {}",
      s
    );
  }

  // -------- Test 6: AppleAurAcceptanceClaim round-trip --------

  #[test]
  fn apple_aur_acceptance_claim_round_trip() {
    // Registered optional extension (spec §7.5.1). It must round-trip
    // fully when present while staying absent-by-default, so that
    // extension-free envelopes keep their exact pre-extension bytes.
    let claim = super::AppleAurAcceptanceClaim {
      user_id: "did:key:z6MkUserAbc123".to_string(),
      device_id: "device-opaque-id-001".to_string(),
      aur_version_hash:
        "a3b4c5d6e7f8091011121314151617181920212223242526272829303132333435".to_string(),
      accepted_at: "2026-06-09T00:00:00Z".to_string(),
      document_kind: "foundation_models_framework_aur".to_string(),
    };
    let subject = super::CredentialSubject {
      human_principal: sample_human_principal(),
      agent: sample_agent(),
      channel: sample_channel(),
      communication: sample_communication(),
      policy: sample_policy(),
      notarization: sample_notarization_metadata(),
      apple_aur_acceptance: std::option::Option::Some(claim.clone()),
      act_classification: std::option::Option::None,
    };
    let s = serde_json::to_string(&subject).unwrap();
    // wire form must use camelCase key
    std::assert!(
      s.contains("\"appleAurAcceptance\""),
      "must serialize apple_aur_acceptance as appleAurAcceptance: {}",
      s
    );
    let v2: super::CredentialSubject = serde_json::from_str(&s).unwrap();
    std::assert_eq!(subject, v2);
    let recovered = v2.apple_aur_acceptance.expect("must be Some after round-trip");
    std::assert_eq!(recovered.document_kind, "foundation_models_framework_aur");
    std::assert_eq!(recovered.user_id, claim.user_id);
    std::assert_eq!(recovered.device_id, claim.device_id);
    std::assert_eq!(recovered.aur_version_hash, claim.aur_version_hash);
    std::assert_eq!(recovered.accepted_at, claim.accepted_at);
  }

  // -------- Test 7: legacy wire back-compat (field absent) --------

  #[test]
  fn credential_subject_legacy_omit_apple_aur_acceptance() {
    // A legacy CredentialSubject JSON payload that does NOT contain
    // `appleAurAcceptance` must still deserialize cleanly with
    // `apple_aur_acceptance == None` (wire back-compat).
    let s = serde_json::json!({
      "humanPrincipal": {
        "id": "did:key:z6MkLegacyUser",
        "displayName": "Legacy User"
      },
      "agent": {
        "id": "did:web:agent.squillo.com",
        "displayName": "Squillo Concierge",
        "version": "1.0"
      },
      "channel": {
        "kind": "slack",
        "recipientAddressing": {}
      },
      "communication": {
        "contentClass": "Reply",
        "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "bodySize": 0,
        "previewLines": 0,
        "preview": ""
      },
      "policy": {
        "decision": "AskEveryTime",
        "matchedScope": "per-channel"
      },
      "notarization": {
        "notaryService": {
          "id": "did:web:notary.squillo.com",
          "name": "Squillo Notary Service",
          "version": "0.1.0"
        },
        "decisionTimestamp": "2026-05-21T00:00:01Z",
        "decisionLatencyMs": 0
      }
    })
    .to_string();
    let v: super::CredentialSubject = serde_json::from_str(&s)
      .expect("legacy payload without appleAurAcceptance must deserialize cleanly");
    std::assert!(
      v.apple_aur_acceptance.is_none(),
      "apple_aur_acceptance must be None when absent from legacy wire payload"
    );
  }

  // -------- Test 8: proof-chain wire forms (§7.1.11) --------

  #[test]
  fn envelope_proofs_round_trips_the_single_object_wire_form() {
    // `proof` is untagged: the JSON SHAPE is the only discriminator between
    // a lone notary proof and a chain. If the object form ever deserialized
    // into `Chain` (or failed), every one of the eight published envelopes
    // — all of which carry a single object — would stop parsing.
    let single = super::EnvelopeProofs::Single(sample_proof());
    let s = serde_json::to_string(&single).unwrap();
    std::assert!(
      s.starts_with('{'),
      "the single form must serialize as a JSON OBJECT, not an array: {}",
      s
    );
    let back: super::EnvelopeProofs = serde_json::from_str(&s).unwrap();
    std::assert_eq!(single, back);
  }

  #[test]
  fn envelope_proofs_round_trips_the_array_wire_form() {
    // The other half of the untagged discrimination. §7.2.1 makes the array
    // form load-bearing: `[{…}]` and `{…}` canonicalize to different bytes,
    // which is what domain-separates a principal proof from a lone notary
    // proof. Collapsing the array to an object on re-serialization would
    // silently forge that domain separation away.
    let chain = super::EnvelopeProofs::Chain(std::vec![
      sample_principal_proof(),
      sample_notary_countersignature(),
    ]);
    let s = serde_json::to_string(&chain).unwrap();
    std::assert!(
      s.starts_with('['),
      "the chain form must serialize as a JSON ARRAY: {}",
      s
    );
    let back: super::EnvelopeProofs = serde_json::from_str(&s).unwrap();
    std::assert_eq!(chain, back);
  }

  #[test]
  fn envelope_with_absent_additive_fields_emits_none_of_their_keys() {
    // `attestationMode`, `id` and `previousProof` were added to structs
    // whose serialized bytes are what signatures cover. An envelope that
    // sets none of them MUST serialize byte-identically to one written
    // before the fields existed, or every already-issued signature breaks.
    let json = serde_json::to_string(&sample_envelope()).unwrap();
    std::assert!(
      !json.contains("attestationMode"),
      "absent attestationMode must not appear on the wire: {}",
      json
    );
    std::assert!(
      !json.contains("delegationMandate\""),
      "absent embedded delegationMandate must not appear on the wire: {}",
      json
    );
    std::assert!(
      !json.contains("previousProof"),
      "absent previousProof must not appear on the wire: {}",
      json
    );
    std::assert!(
      !json.contains("\"id\":null"),
      "absent proof id must be omitted, never emitted as null: {}",
      json
    );
  }

  #[test]
  fn all_returns_every_proof_for_both_wire_forms() {
    // `all()` is what lets a caller iterate proofs without branching on the
    // variant. If the single form returned an empty slice, a verifier
    // looping over `all()` would verify NOTHING and report success.
    std::assert_eq!(
      super::EnvelopeProofs::Single(sample_proof()).all().len(),
      1
    );
    std::assert_eq!(
      super::EnvelopeProofs::Chain(std::vec![
        sample_principal_proof(),
        sample_notary_countersignature(),
      ])
      .all()
      .len(),
      2
    );
  }

  #[test]
  fn principal_is_none_for_a_single_proof() {
    // A lone proof is the NOTARY's (§7.1.11). Reporting it as the principal
    // proof would let a caller present a notary attestation as the human's
    // own signature — the exact confusion `attestationMode` exists to stop.
    std::assert!(
      super::EnvelopeProofs::Single(sample_proof())
        .principal()
        .is_none()
    );
  }

  #[test]
  fn notary_is_the_lone_proof_and_the_tail_of_a_chain() {
    // Both wire forms carry a notary proof, and it is the proof steps 2-9 of
    // §8.3 verify. A caller must be able to reach it identically either way.
    let single = super::EnvelopeProofs::Single(sample_proof());
    std::assert_eq!(
      single.notary().map(|p| p.proof_purpose.as_str()),
      std::option::Option::Some("assertionMethod")
    );
    let chain = super::EnvelopeProofs::Chain(std::vec![
      sample_principal_proof(),
      sample_notary_countersignature(),
    ]);
    std::assert_eq!(
      chain.notary().map(|p| p.proof_purpose.as_str()),
      std::option::Option::Some("authentication")
    );
  }

  #[test]
  fn accessors_refuse_to_name_proofs_inside_a_malformed_chain() {
    // §7.1.11 fixes chain length at exactly two. A three-element array is
    // rejected there, but these accessors are called by code that has not
    // run that check yet, so they must not hand back a "principal proof" or
    // "notary proof" from a structure the spec refuses — a caller would
    // verify one signature out of three and believe the chain sound.
    let over_long = super::EnvelopeProofs::Chain(std::vec![
      sample_principal_proof(),
      sample_notary_countersignature(),
      sample_notary_countersignature(),
    ]);
    std::assert!(over_long.principal().is_none());
    std::assert!(over_long.notary().is_none());
  }

  #[test]
  fn is_chain_reports_the_array_form_at_any_length() {
    // The distinction is the WIRE form, not validity: a one-element array is
    // still a chain (an invalid one). If `is_chain()` reported false for it,
    // §7.2.1's stripped-notary-proof attack would slip past — the whole
    // point is that a one-element array is recognised and then rejected.
    std::assert!(
      super::EnvelopeProofs::Chain(std::vec![sample_principal_proof()]).is_chain()
    );
    std::assert!(!super::EnvelopeProofs::Single(sample_proof()).is_chain());
  }

  #[test]
  fn absent_attestation_mode_resolves_to_notary_attested() {
    // §7.1.7 fixes ABSENT as `NotaryAttested`, the WEAKER claim. All eight
    // published envelopes omit the field; defaulting the other way would
    // silently promote every one of them to asserting the human personally
    // signed, which no party ever claimed.
    std::assert_eq!(
      sample_policy().effective_attestation_mode(),
      super::AttestationMode::NotaryAttested
    );
  }

  #[test]
  fn declared_attestation_mode_is_returned_verbatim() {
    // The default must apply only to absence. If it overrode a present
    // value, a `PrincipalSigned` envelope would be downgraded to the notary's
    // assertion and the human's signature would go unchecked.
    let mut policy = sample_policy();
    policy.attestation_mode = std::option::Option::Some(super::AttestationMode::PrincipalSigned);
    std::assert_eq!(
      policy.effective_attestation_mode(),
      super::AttestationMode::PrincipalSigned
    );
  }

  #[test]
  fn attestation_mode_wire_spelling_matches_the_closed_enum() {
    // §7.1.7 fixes a CLOSED enum with these exact spellings, and other
    // implementations compare the string. A serde rename or a variant
    // rename would make our envelopes unreadable to them, and `label()` is
    // what error messages show an operator, so both must agree.
    std::assert_eq!(
      serde_json::to_string(&super::AttestationMode::PrincipalSigned).unwrap(),
      "\"PrincipalSigned\""
    );
    std::assert_eq!(
      serde_json::to_string(&super::AttestationMode::NotaryAttested).unwrap(),
      "\"NotaryAttested\""
    );
    std::assert_eq!(super::AttestationMode::PrincipalSigned.label(), "PrincipalSigned");
    std::assert_eq!(super::AttestationMode::NotaryAttested.label(), "NotaryAttested");
  }

  #[test]
  fn envelope_parses_a_chain_and_the_principal_signed_label_from_the_wire() {
    // End-to-end wire acceptance of the §7.1.11 shape: a verifier written
    // against this crate must be able to receive a real `PrincipalSigned`
    // envelope. Both additive fields sit under `deny_unknown_fields`, so
    // without the declarations a conformant producer would be rejected.
    let mut envelope = sample_envelope();
    envelope.credential_subject.policy.attestation_mode =
      std::option::Option::Some(super::AttestationMode::PrincipalSigned);
    envelope.proof = super::EnvelopeProofs::Chain(std::vec![
      sample_principal_proof(),
      sample_notary_countersignature(),
    ]);
    let s = serde_json::to_string(&envelope).unwrap();
    let back: super::NotarizationEnvelope =
      serde_json::from_str(&s).expect("a PrincipalSigned chain envelope must parse");
    std::assert_eq!(envelope, back);
  }
}

#[cfg(test)]
mod act_classification_tests {
  // WHY THIS MODULE EXISTS. `actClassification` is the first field added to
  // `credentialSubject` since every wire struct in this module acquired
  // `deny_unknown_fields`, which makes EMITTING it a version-gated event: a
  // verifier built before the field existed fails at strict parse rather than
  // ignoring it. Adding the field to the type is safe for everyone; putting
  // it on the wire is not. These tests pin the half that must stay safe.

  /// A published golden, which predates this field and must stay untouched.
  fn golden() -> std::string::String {
    std::include_str!("../../../../examples/slack_reply_envelope.json").to_string()
  }

  #[test]
  fn an_envelope_without_the_claim_round_trips_byte_identically() {
    // THE PIN THAT MATTERS, and it is verified by mutation rather than by
    // observing green: dropping `skip_serializing_if` from the field turns
    // this red. `skip_serializing_if` is a claim about OUTPUT, and a claim
    // about output is worth exactly as much as the byte comparison nobody
    // ran. Every published envelope predates this field — if it leaked into
    // serialization as `"actClassification": null`, every existing signature
    // over those bytes would break at once, and it would break SILENTLY,
    // because the envelope still parses.
    let raw = golden();
    let parsed: super::NotarizationEnvelope =
      serde_json::from_str(&raw).expect("a published golden must parse");
    std::assert!(
      parsed.credential_subject.act_classification.is_none(),
      "a published golden predates this field and must carry no claim"
    );
    let reserialized = serde_json::to_string(&parsed).expect("it serializes");
    std::assert!(
      !reserialized.contains("actClassification"),
      "an absent claim must not appear in output at all: {}",
      reserialized
    );
  }

  #[test]
  fn a_classification_round_trips_through_serde() {
    // Pins that the serde delegation is wired for the nested types, including
    // `ActLabel`'s hand-written impls — a derive would have put a STRUCT on
    // the wire here instead of the `FAMILY/LABEL` string.
    let claim = super::ActClassification {
      vocabularies: std::vec![super::VocabularyRef {
        name: "aph_guardrails".to_string(),
        version: "0.1.0-alpha.1".to_string(),
        digest: "sha256-y6E/EGldCz2ogpVB7wlnS5orbnAjcCpoUBaDietJmXA=".to_string(),
      }],
      labels: std::vec![
        "APH_ACT_ACCESS/ACCESS_GRANT".parse().expect("a qualified label parses"),
      ],
    };
    let json = serde_json::to_string(&claim).expect("it serializes");
    std::assert!(
      json.contains("\"APH_ACT_ACCESS/ACCESS_GRANT\""),
      "a label rides the wire as its qualified STRING, not as a struct: {}",
      json
    );
    let back: super::ActClassification =
      serde_json::from_str(&json).expect("it round-trips");
    std::assert_eq!(claim, back);
  }

  #[test]
  fn a_claim_citing_no_vocabulary_is_refused_at_parse() {
    // THE DIVERGENCE PIN, found by audit rather than by design: the
    // independent TypeScript implementation refused an empty `vocabularies`
    // from its first draft while this crate's derived Deserialize accepted
    // it — two conformant-claiming implementations reaching opposite
    // verdicts on the same bytes, the exact defect class QQ-era work closed
    // for `allowedChannels`, reintroduced in a field one day old. Per the
    // standing guardrail, the ACCEPTING surface was the wrong one.
    let refused = serde_json::from_str::<super::ActClassification>(
      r#"{"vocabularies":[],"labels":["A/B"]}"#,
    );
    std::assert!(refused.is_err(), "a claim citing no vocabulary must be refused");
    std::assert!(
      refused.unwrap_err().to_string().contains("claims nothing"),
      "the refusal must say why an empty citation is meaningless"
    );
  }

  #[test]
  fn an_unqualified_label_is_refused_at_parse() {
    // WHY: a bare `ACCESS_GRANT` names nothing — the family is what scopes
    // it, and two vocabularies may both define the same bare word. Refusing
    // at parse is what stops the ambiguity being resolved later by whoever
    // guesses.
    let refused = "ACCESS_GRANT".parse::<super::ActLabel>();
    std::assert!(refused.is_err(), "an unqualified label must be refused");
    let message = refused.unwrap_err();
    std::assert!(
      message.contains("family-qualified"),
      "the refusal must say what shape was expected: {}",
      message
    );
  }

  #[test]
  fn a_label_with_an_empty_side_or_two_separators_is_refused() {
    // The structural errors that would otherwise yield a label naming an
    // empty family, or one whose family is itself ambiguous.
    for raw in ["/ACCESS_GRANT", "APH_ACT_ACCESS/", "A/B/C"] {
      std::assert!(
        raw.parse::<super::ActLabel>().is_err(),
        "`{}` is structurally meaningless and must be refused",
        raw
      );
    }
  }

  #[test]
  fn a_third_party_spelling_is_accepted_because_only_structure_is_ours() {
    // WHY: RFC 0006's extension model lets anyone publish a vocabulary. A
    // character-set rule imposed here would make that a formality — a
    // vocabulary naming its families in a convention this project did not
    // anticipate would be unusable. Refuse what is meaningless; do not
    // legislate taste.
    let parsed: super::ActLabel = "acme.finance/wire-transfer.initiate"
      .parse()
      .expect("an unfamiliar but well-formed spelling must be accepted");
    std::assert_eq!(parsed.family(), "acme.finance");
    std::assert_eq!(parsed.label(), "wire-transfer.initiate");
  }
}

#[cfg(test)]
mod closed_vocabulary_tests {
  // These tests exist because the closed sets of §7.1.5 and §7.1.6 lived
  // only in prose while the wire fields were bare `String`s: this crate
  // accepted an out-of-set `kind` while the independent TypeScript
  // implementation refused it — two conformant-claiming verifiers reaching
  // opposite verdicts on the same bytes. Each test pins one half of the
  // repair.

  #[test]
  fn every_channel_kind_wire_spelling_round_trips() {
    // label() and from_str() are the two halves of one mapping; if either
    // drifts (the google_chat snake_case erratum is the standing example of
    // how), envelopes minted by one implementation stop verifying in
    // another. ALL is the enumerable, so a variant added without updating
    // it is caught here rather than in a consumer.
    for kind in super::ChannelKind::ALL {
      let back: super::ChannelKind = kind
        .label()
        .parse()
        .expect("every published wire spelling must parse");
      std::assert_eq!(kind, back);
    }
  }

  #[test]
  fn every_content_class_wire_spelling_round_trips() {
    // Same pin as the channel-kind twin. `DM` is the value most likely to
    // drift (a naive case transform yields `Dm`), so the round trip is what
    // stands between the enum and a silent casing fork.
    for class in super::ContentClass::ALL {
      let back: super::ContentClass = class
        .label()
        .parse()
        .expect("every published wire spelling must parse");
      std::assert_eq!(class, back);
    }
  }

  #[test]
  fn every_policy_decision_wire_spelling_round_trips() {
    // The §7.1.7 set joins the closure late — an audit found this crate
    // validating it NOWHERE while the independent implementation refused at
    // parse — so it gets the same round-trip weld its two older siblings
    // have: label() and from_str() are two halves of one mapping, and this
    // is what keeps them from parting.
    for decision in super::PolicyDecision::ALL {
      let back: super::PolicyDecision = decision
        .label()
        .parse()
        .expect("every published wire spelling must parse");
      std::assert_eq!(decision, back);
    }
  }

  #[test]
  fn an_unrecognized_policy_decision_is_refused_and_names_the_closed_set() {
    // `Sometimes` is a value no revision has ever defined and none will —
    // the durable form of a refusal pin, per the graduation lesson: pins
    // written against values someone is actively requesting have short
    // lives. A decision outside the set is how a producer would route past
    // policy keyed on one.
    let err = "Sometimes"
      .parse::<super::PolicyDecision>()
      .expect_err("a value outside the closed set must be refused");
    std::assert!(err.contains("closed set"), "must name the closed set: {err}");
    std::assert!(err.contains("AskEveryTime"), "must list the members: {err}");
  }

  #[test]
  fn an_unrecognized_channel_kind_is_refused_and_names_the_closed_set() {
    // The divergence pin. This test was written against `service`, which
    // was then the exact value a draft wanted to emit and the reference
    // silently accepted. `service` has since been ADMITTED — the RFC's
    // stated prerequisite was this closure landing, and it did — so the pin
    // now uses a value that names no medium and never will. The property
    // under test never changed: an unrecognized value is refused, and the
    // message names the closed set so an operator reading a log learns what
    // WOULD have been accepted.
    let err = "carrier_pigeon"
      .parse::<super::ChannelKind>()
      .expect_err("a value outside the closed set must be refused");
    std::assert!(err.contains("closed set"), "error must name the closed set: {err}");
    std::assert!(err.contains("google_chat"), "error must list the members: {err}");
  }

  #[test]
  fn an_unrecognized_content_class_is_refused() {
    // Twin of the channel-kind refusal, and it graduated the same way:
    // `Mutation` was this test's subject until the specification admitted
    // it. The replacement is a plausible-looking class that is not a member,
    // which is the case an operator actually hits.
    std::assert!("Digest".parse::<super::ContentClass>().is_err());
    std::assert!("reply".parse::<super::ContentClass>().is_err(), "case matters: wire is `Reply`");
  }

  #[test]
  fn the_closed_sets_hold_their_declared_census() {
    // A deliberate census tripwire, not bookkeeping: adding a channel kind
    // or content class is a NORMATIVE event with a dozen documentation and
    // fixture surfaces attached. This test failing is the checklist firing.
    // When the service-act revision lands, update this count IN THE SAME
    // CHANGE as the spec tables, the examples inventory, and the bindings.
    std::assert_eq!(super::ChannelKind::ALL.len(), 9);
    std::assert_eq!(super::ContentClass::ALL.len(), 8);
    std::assert_eq!(super::PolicyDecision::ALL.len(), 3);
  }
}

#[cfg(test)]
mod closed_vocabulary_deserialization_tests {
  // WHERE THE GUARANTEE MOVED. Before the field types closed, a separate
  // `require_closed_vocabulary` helper walked a parsed envelope and validated
  // two `String`s. That helper is gone — not because the check stopped
  // mattering, but because it is now unreachable-by-construction: a
  // `NotarizationEnvelope` cannot exist holding a value outside either closed
  // set, so the check happens at DESERIALIZATION and nothing downstream can
  // observe a violation. These tests are that helper's refusal cases, moved
  // to the boundary that now enforces them. Keeping them here is what stops
  // the swap from silently deleting the evidence a refusal was ever required.

  fn golden() -> std::string::String {
    std::include_str!("../tests/golden/slack_reply_envelope.json").to_string()
  }

  #[test]
  fn a_conformant_envelope_still_parses_after_the_types_closed() {
    // The swap must not narrow what the corpus admits. If this fails, the
    // wire spellings drifted from `label()` — the exact failure the serde
    // delegation exists to make impossible.
    let parsed: std::result::Result<super::NotarizationEnvelope, _> =
      serde_json::from_str(&golden());
    std::assert!(parsed.is_ok(), "the slack golden must still parse: {parsed:?}");
  }

  #[test]
  fn an_envelope_naming_an_unrecognized_channel_is_refused_at_parse() {
    // Written when `service` was the live refusal case; it is now an
    // admitted kind, so the pin moved to a value outside the set. What it
    // proves is unchanged and is the whole point of closing the field: the
    // refusal happens AT PARSE, before any verification step runs, so a
    // verifier cannot silently verify an act it cannot describe.
    let doc = golden().replace("\"kind\": \"slack\"", "\"kind\": \"carrier_pigeon\"");
    let parsed: std::result::Result<super::NotarizationEnvelope, _> =
      serde_json::from_str(&doc);
    let err = parsed.expect_err("an unrecognized channel kind must be refused at parse");
    let msg = err.to_string();
    std::assert!(msg.contains("closed set"), "must name the closed set: {msg}");
  }

  #[test]
  fn an_envelope_naming_an_unrecognized_content_class_is_refused_at_parse() {
    let doc = golden().replace("\"contentClass\": \"Reply\"", "\"contentClass\": \"Digest\"");
    let parsed: std::result::Result<super::NotarizationEnvelope, _> =
      serde_json::from_str(&doc);
    std::assert!(parsed.is_err(), "an unrecognized content class must be refused at parse");
  }

  #[test]
  fn the_wire_spellings_survive_a_round_trip_through_serde() {
    // serde delegates to `label()`/`from_str`, so this pins that the
    // delegation is actually wired: a derive with a `rename_all` would pass
    // the tests above and still emit `Dm` for `DM`.
    for kind in super::ChannelKind::ALL {
      let json = serde_json::to_string(&kind).expect("a channel kind serializes");
      std::assert_eq!(json, std::format!("\"{}\"", kind.label()));
      let back: super::ChannelKind = serde_json::from_str(&json).expect("and parses back");
      std::assert_eq!(kind, back);
    }
    for class in super::ContentClass::ALL {
      let json = serde_json::to_string(&class).expect("a content class serializes");
      std::assert_eq!(json, std::format!("\"{}\"", class.label()));
      let back: super::ContentClass = serde_json::from_str(&json).expect("and parses back");
      std::assert_eq!(class, back);
    }
  }
}
