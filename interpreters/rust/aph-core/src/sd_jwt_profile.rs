//! SD-JWT-VC draft version pinning for the APH profile.
//!
//! APH uses SD-JWT-VC as the recipient-verifier-friendly compact wire form.
//! IETF drafts evolve; this module pins the exact draft we support so that
//! an uncommitted move to a newer draft surfaces as visible breakage.

/// Pinned IETF draft of SD-JWT-VC that APH 0.1 supports.
pub const SD_JWT_VC_DRAFT_PIN: &str = "draft-ietf-oauth-sd-jwt-vc-16";

/// Pinned IETF draft of the underlying SD-JWT base spec.
pub const SD_JWT_BASE_DRAFT_PIN: &str = "draft-ietf-oauth-selective-disclosure-jwt-22";

/// APH-specific SD-JWT `typ` header value.
pub const APH_SD_JWT_TYP: &str = "dc+sd-jwt";

/// The SD-JWT-VC draft revisions and media type this implementation pins.
#[derive(std::fmt::Debug, std::clone::Clone, std::cmp::PartialEq, std::cmp::Eq)]
pub struct SdJwtVcProfile {
  /// Pinned SD-JWT-VC draft revision.
  pub sd_jwt_vc_draft: &'static str,
  /// Pinned base SD-JWT draft revision.
  pub sd_jwt_base_draft: &'static str,
  /// `typ` header value for APH SD-JWT presentations.
  pub typ_header: &'static str,
}

/// Returns the profile this build pins. Drafts change incompatibly between
/// revisions, so peers must agree on these exact values.
pub fn current_profile() -> SdJwtVcProfile {
  SdJwtVcProfile {
    sd_jwt_vc_draft: SD_JWT_VC_DRAFT_PIN,
    sd_jwt_base_draft: SD_JWT_BASE_DRAFT_PIN,
    typ_header: APH_SD_JWT_TYP,
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn pinned_constants_match_spec_text() {
    // These pin SPECIFIC IETF draft revisions (spec §10.4). Drafts change
    // incompatibly between revisions, so silently tracking a newer one
    // would break interop with peers built against the pinned draft.
    std::assert_eq!(super::SD_JWT_VC_DRAFT_PIN, "draft-ietf-oauth-sd-jwt-vc-16");
    std::assert_eq!(
      super::SD_JWT_BASE_DRAFT_PIN,
      "draft-ietf-oauth-selective-disclosure-jwt-22"
    );
    std::assert_eq!(super::APH_SD_JWT_TYP, "dc+sd-jwt");
  }

  #[test]
  fn current_profile_matches_constants() {
    // The struct is the runtime view of the constants above; if the two
    // drifted, code reading the profile would advertise a different draft
    // than the one the constants document.
    let p = super::current_profile();
    std::assert_eq!(p.sd_jwt_vc_draft, super::SD_JWT_VC_DRAFT_PIN);
    std::assert_eq!(p.sd_jwt_base_draft, super::SD_JWT_BASE_DRAFT_PIN);
    std::assert_eq!(p.typ_header, super::APH_SD_JWT_TYP);
  }
}
