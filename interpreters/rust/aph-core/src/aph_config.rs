//! APH configuration constants — version pins, default TTLs, JCS profile.

/// APH protocol version pin. Bump only with coordinated rollout.
pub const APH_VERSION: &str = "0.1";

/// W3C VC 2.0 context URL.
pub const W3C_VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";

/// APH context URL (resolves to the published `aph` repo's `v1` JSON-LD context).
pub const APH_CONTEXT_V1: &str = "https://w3id.org/aph/v1";

/// Default mandate TTL: 24 hours. Per-channel adapter may override.
pub const DEFAULT_MANDATE_TTL_SECONDS: u64 = 24 * 60 * 60;

/// Maximum body preview lines included in `communication.preview` field.
pub const MAX_PREVIEW_LINES: usize = 5;

/// Maximum body size in bytes that a Verifier MUST accept without truncation
/// requirement. Larger bodies still notarize but Verifiers MAY decline preview.
pub const MAX_BODY_PREVIEW_BYTES: usize = 8 * 1024;

/// Signature algorithm identifier — ES256 (p256 ECDSA over SHA-256).
pub const ALG_ES256: &str = "ES256";

/// Signature algorithm identifier — EdDSA (Ed25519).
pub const ALG_EDDSA: &str = "EdDSA";

/// JSON-LD `type` discriminator for an APH credential.
pub const APH_CREDENTIAL_TYPE: &str = "AgentSendAuthorizationCredential";

/// `cryptosuite` identifier for Data Integrity Proof, JCS-canonicalized EdDSA.
pub const APH_DI_CRYPTOSUITE: &str = "eddsa-jcs-2022";

#[cfg(test)]
mod tests {
  #[test]
  fn version_is_0_1() {
    // aphVersion is emitted into every envelope and verifiers MUST reject
    // unsupported versions, so bumping this constant is a wire-breaking
    // change that should never happen by accident.
    std::assert_eq!(super::APH_VERSION, "0.1");
  }

  #[test]
  fn contexts_are_https_urls() {
    // JSON-LD context URIs are compared literally by verifiers and must be
    // https — an http or relative URI would both fail those comparisons
    // and invite an insecure fetch by a resolving processor.
    std::assert!(super::W3C_VC_CONTEXT_V2.starts_with("https://"));
    std::assert!(super::APH_CONTEXT_V1.starts_with("https://"));
  }
}
