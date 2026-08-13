//! Vendored cross-vault wire types carried by `LinkedMandate.vault_mutation`.
//!
//! These types originate in the cross-vault federation layer of the
//! reference implementation. They are vendored here so an APH envelope can
//! carry a `VaultMutationMandate` without an external dependency. Their
//! serde output MUST match the originating implementation byte-for-byte —
//! every attribute below is load-bearing wire shape:
//!
//! - `VaultMutationKind` is internally tagged: `#[serde(tag = "kind",
//!   rename_all = "PascalCase")]`. The `rename_all` applies to VARIANT
//!   names only (already PascalCase); struct-variant FIELDS keep their
//!   snake_case Rust names on the wire (e.g.
//!   `{"kind":"WriteInto","dest_vault_id":"..."}`).
//! - `VaultMutationMandate` has NO `rename_all`: its fields serialize as
//!   `kind`, `grant_scope_id`, and (when present) `ap2_signed_payload_b64`.
//! - The ID newtypes are `#[serde(transparent)]` / newtype structs and
//!   serialize as bare JSON strings.

/// Wire-form view of a vault identifier (36-char UUID hex-dashed).
#[derive(Clone, Debug, PartialEq, Eq, Hash, ::serde::Serialize, ::serde::Deserialize)]
#[serde(transparent)]
pub struct VaultIdStr(pub String);

impl VaultIdStr {
  /// Wraps an existing vault identifier string.
  pub fn new(value: impl Into<String>) -> Self {
    Self(value.into())
  }
  /// Borrows the identifier as it appears on the wire.
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

/// Wire-form view of a principal DID URI.
#[derive(Clone, Debug, PartialEq, Eq, Hash, ::serde::Serialize, ::serde::Deserialize)]
#[serde(transparent)]
pub struct PrincipalDidUri(pub String);

impl PrincipalDidUri {
  /// Wraps an existing principal DID URI string.
  pub fn new(value: impl Into<String>) -> Self {
    Self(value.into())
  }
  /// Borrows the DID URI as it appears on the wire.
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

/// Stable identifier for a cross-vault grant. Wire form: 36-char UUID
/// hex-dashed string.
#[derive(Clone, Debug, PartialEq, Eq, Hash, ::serde::Serialize, ::serde::Deserialize)]
#[serde(transparent)]
pub struct GrantId(pub String);

impl GrantId {
  /// Wraps an existing grant identifier string.
  pub fn new(value: impl Into<String>) -> Self {
    Self(value.into())
  }
  /// Borrows the identifier as it appears on the wire.
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

/// What kind of cross-vault mutation the APH envelope is notarizing.
#[derive(Clone, Debug, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
#[serde(tag = "kind", rename_all = "PascalCase")]
pub enum VaultMutationKind {
  /// Write data into another vault.
  WriteInto {
    /// Vault receiving the write.
    dest_vault_id: VaultIdStr,
  },
  /// Share data out of a vault to the grantee.
  ShareFrom {
    /// Vault the shared data originates from.
    src_vault_id: VaultIdStr,
  },
  /// Promote an artifact across a vault boundary.
  CrossVaultPromote {
    /// Artifact being promoted.
    artifact_id: String,
  },
  /// Extend the granted authority to a downstream principal.
  Redelegate {
    /// DID of the principal receiving the redelegated authority.
    downstream_grantee_id: PrincipalDidUri,
  },
  /// Withdraw a previously issued grant.
  Revoke,
  /// Move a bridged item between lifecycle stages.
  BridgeStageTransition {
    /// Stage the item is leaving.
    from_stage: String,
    /// Stage the item is entering.
    to_stage: String,
  },
  /// Application-defined mutation, for shapes this enum does not model.
  Custom {
    /// Application that defines the mutation.
    snapp_id: String,
    /// Application-scoped mutation name.
    mutation_slug: String,
  },
}

/// Body of the `LinkedMandate.vault_mutation` field on the APH
/// `NotarizationEnvelope`.
#[derive(Clone, Debug, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultMutationMandate {
  /// Which mutation is being authorized.
  pub kind: VaultMutationKind,
  /// Grant scope the mutation executes under.
  pub grant_scope_id: GrantId,
  /// Base64 AP2-signed payload, present only for commerce-impacting
  /// mutations. Omitted entirely when absent so the canonical bytes of
  /// mandates without it are unchanged.
  #[serde(skip_serializing_if = "Option::is_none", default)]
  pub ap2_signed_payload_b64: Option<String>,
}

#[cfg(test)]
mod tests {
  // -------- wire-shape pins: VaultMutationKind (internally tagged) --------
  //
  // The enum-level `rename_all = "PascalCase"` renames VARIANTS only.
  // Struct-variant field names stay snake_case on the wire. These tests
  // pin that exact shape so an accidental `rename_all_fields` or camelCase
  // drift fails loudly.

  #[test]
  fn write_into_wire_shape() {
    // Most common cross-vault variant. Pins both halves of the mixed
    // casing — PascalCase discriminator, snake_case payload key — because
    // this object rides inside a signed envelope and any casing drift
    // changes the canonical bytes the notary signed.
    let v = super::VaultMutationKind::WriteInto {
      dest_vault_id: super::VaultIdStr::new("11111111-1111-4111-8111-111111111111"),
    };
    let json = serde_json::to_value(&v).unwrap();
    std::assert_eq!(
      json,
      serde_json::json!({
        "kind": "WriteInto",
        "dest_vault_id": "11111111-1111-4111-8111-111111111111"
      })
    );
  }

  #[test]
  fn share_from_wire_shape() {
    // Sibling of WriteInto with the opposite data direction; pinned
    // separately so a copy-paste that swapped src_vault_id for
    // dest_vault_id — inverting who grants access to whom — is caught.
    let v = super::VaultMutationKind::ShareFrom {
      src_vault_id: super::VaultIdStr::new("22222222-2222-4222-8222-222222222222"),
    };
    let json = serde_json::to_value(&v).unwrap();
    std::assert_eq!(
      json,
      serde_json::json!({
        "kind": "ShareFrom",
        "src_vault_id": "22222222-2222-4222-8222-222222222222"
      })
    );
  }

  #[test]
  fn cross_vault_promote_wire_shape() {
    // Multi-word variant: confirms PascalCase renaming joins the words
    // ("CrossVaultPromote", not "Cross_Vault_Promote") while the payload
    // key stays snake_case — the split-casing rule at its trickiest.
    let v = super::VaultMutationKind::CrossVaultPromote {
      artifact_id: String::from("artifact-1"),
    };
    let json = serde_json::to_value(&v).unwrap();
    std::assert_eq!(
      json,
      serde_json::json!({"kind": "CrossVaultPromote", "artifact_id": "artifact-1"})
    );
  }

  #[test]
  fn redelegate_wire_shape() {
    // Redelegation extends authority to a third party, so its DID payload
    // is the security-critical field; pinned to catch any change that
    // would drop or rename the grantee inside a signed mandate.
    let v = super::VaultMutationKind::Redelegate {
      downstream_grantee_id: super::PrincipalDidUri::new("did:key:zDownstream"),
    };
    let json = serde_json::to_value(&v).unwrap();
    std::assert_eq!(
      json,
      serde_json::json!({
        "kind": "Redelegate",
        "downstream_grantee_id": "did:key:zDownstream"
      })
    );
  }

  #[test]
  fn revoke_wire_shape() {
    // The only fieldless variant: internal tagging must still emit a
    // tagged object ({"kind":"Revoke"}), not a bare string. A revocation
    // that silently changed shape could be dropped by a strict parser.
    let v = super::VaultMutationKind::Revoke;
    let json = serde_json::to_value(&v).unwrap();
    std::assert_eq!(json, serde_json::json!({"kind": "Revoke"}));
  }

  #[test]
  fn bridge_stage_transition_wire_shape() {
    // Two-field variant: pins that both keys are emitted flat alongside
    // the discriminator (not nested under a sub-object) and keep their
    // declared order-independent names.
    let v = super::VaultMutationKind::BridgeStageTransition {
      from_stage: String::from("staged"),
      to_stage: String::from("committed"),
    };
    let json = serde_json::to_value(&v).unwrap();
    std::assert_eq!(
      json,
      serde_json::json!({
        "kind": "BridgeStageTransition",
        "from_stage": "staged",
        "to_stage": "committed"
      })
    );
  }

  #[test]
  fn custom_wire_shape() {
    // The extension escape hatch third parties will actually populate, so
    // its shape is the one most likely to be relied on externally and the
    // least safe to change.
    let v = super::VaultMutationKind::Custom {
      snapp_id: String::from("snapp-1"),
      mutation_slug: String::from("do-thing"),
    };
    let json = serde_json::to_value(&v).unwrap();
    std::assert_eq!(
      json,
      serde_json::json!({
        "kind": "Custom",
        "snapp_id": "snapp-1",
        "mutation_slug": "do-thing"
      })
    );
  }

  // -------- round-trip: all kinds --------

  #[test]
  fn all_kinds_round_trip() {
    // Exhaustive sweep over all seven variants: the wire-shape tests above
    // pin serialization only, so this proves the deserializer accepts what
    // the serializer emits for every variant, including any added later.
    let kinds = std::vec![
      super::VaultMutationKind::WriteInto {
        dest_vault_id: super::VaultIdStr::new("11111111-1111-4111-8111-111111111111"),
      },
      super::VaultMutationKind::ShareFrom {
        src_vault_id: super::VaultIdStr::new("22222222-2222-4222-8222-222222222222"),
      },
      super::VaultMutationKind::CrossVaultPromote {
        artifact_id: String::from("artifact-1"),
      },
      super::VaultMutationKind::Redelegate {
        downstream_grantee_id: super::PrincipalDidUri::new("did:key:zDownstream"),
      },
      super::VaultMutationKind::Revoke,
      super::VaultMutationKind::BridgeStageTransition {
        from_stage: String::from("staged"),
        to_stage: String::from("committed"),
      },
      super::VaultMutationKind::Custom {
        snapp_id: String::from("snapp-1"),
        mutation_slug: String::from("do-thing"),
      },
    ];
    for kind in kinds {
      let s = serde_json::to_string(&kind).unwrap();
      let back: super::VaultMutationKind = serde_json::from_str(&s).unwrap();
      std::assert_eq!(kind, back, "round-trip mismatch for {:?}", kind);
    }
  }

  // -------- wire-shape pins: VaultMutationMandate --------

  #[test]
  fn mandate_wire_shape_without_payload() {
    // Absent-vs-null matters for signatures: ap2_signed_payload_b64 must be
    // OMITTED entirely when None, not emitted as null. An extra null member
    // would change the canonical JCS bytes and break verification of
    // mandates signed before the field existed.
    let m = super::VaultMutationMandate {
      kind: super::VaultMutationKind::WriteInto {
        dest_vault_id: super::VaultIdStr::new("11111111-1111-4111-8111-111111111111"),
      },
      grant_scope_id: super::GrantId::new("33333333-3333-4333-8333-333333333333"),
      ap2_signed_payload_b64: std::option::Option::None,
    };
    let json = serde_json::to_value(&m).unwrap();
    // No rename_all on the mandate: snake_case field names on the wire.
    // `ap2_signed_payload_b64` is skipped entirely when None.
    std::assert_eq!(
      json,
      serde_json::json!({
        "kind": {
          "kind": "WriteInto",
          "dest_vault_id": "11111111-1111-4111-8111-111111111111"
        },
        "grant_scope_id": "33333333-3333-4333-8333-333333333333"
      })
    );
  }

  #[test]
  fn mandate_wire_shape_with_payload() {
    // Counterpart to the omitted-field pin: when the AP2 payload IS
    // present it must appear under its exact snake_case key, since a
    // commerce-impacting mutation's payment cross-link is the field a
    // verifier most needs to find.
    let m = super::VaultMutationMandate {
      kind: super::VaultMutationKind::Revoke,
      grant_scope_id: super::GrantId::new("33333333-3333-4333-8333-333333333333"),
      ap2_signed_payload_b64: std::option::Option::Some(String::from("cGF5bG9hZA==")),
    };
    let json = serde_json::to_value(&m).unwrap();
    std::assert_eq!(
      json,
      serde_json::json!({
        "kind": {"kind": "Revoke"},
        "grant_scope_id": "33333333-3333-4333-8333-333333333333",
        "ap2_signed_payload_b64": "cGF5bG9hZA=="
      })
    );
  }

  #[test]
  fn mandate_round_trip() {
    // Whole-struct round-trip over a populated mandate, ensuring the nested
    // kind object and the flat sibling fields survive together — the
    // per-field pins above cannot catch a broken composition.
    let m = super::VaultMutationMandate {
      kind: super::VaultMutationKind::Custom {
        snapp_id: String::from("snapp-1"),
        mutation_slug: String::from("do-thing"),
      },
      grant_scope_id: super::GrantId::new("33333333-3333-4333-8333-333333333333"),
      ap2_signed_payload_b64: std::option::Option::Some(String::from("cGF5bG9hZA==")),
    };
    let s = serde_json::to_string(&m).unwrap();
    let back: super::VaultMutationMandate = serde_json::from_str(&s).unwrap();
    std::assert_eq!(m, back);
  }

  #[test]
  fn mandate_deserializes_without_ap2_payload() {
    // Backward compatibility: mandates minted before ap2_signed_payload_b64
    // was added omit the key entirely and must still parse (via
    // #[serde(default)]) rather than failing as malformed.
    let s = serde_json::json!({
      "kind": {"kind": "Revoke"},
      "grant_scope_id": "33333333-3333-4333-8333-333333333333"
    })
    .to_string();
    let m: super::VaultMutationMandate =
      serde_json::from_str(&s).expect("must deserialize with ap2_signed_payload_b64 omitted");
    std::assert!(m.ap2_signed_payload_b64.is_none());
  }

  // -------- ID newtypes serialize as bare strings --------

  #[test]
  fn id_newtypes_are_transparent_strings() {
    // These newtypes exist for type safety in Rust only — on the wire they
    // must stay bare JSON strings. Losing #[serde(transparent)] would wrap
    // each id in an object and invalidate every signed envelope carrying a
    // vault mutation.
    std::assert_eq!(
      serde_json::to_value(super::VaultIdStr::new("v-1")).unwrap(),
      serde_json::json!("v-1")
    );
    std::assert_eq!(
      serde_json::to_value(super::PrincipalDidUri::new("did:key:zX")).unwrap(),
      serde_json::json!("did:key:zX")
    );
    std::assert_eq!(
      serde_json::to_value(super::GrantId::new("g-1")).unwrap(),
      serde_json::json!("g-1")
    );
    std::assert_eq!(super::VaultIdStr::new("v-1").as_str(), "v-1");
    std::assert_eq!(super::PrincipalDidUri::new("did:key:zX").as_str(), "did:key:zX");
    std::assert_eq!(super::GrantId::new("g-1").as_str(), "g-1");
  }
}
