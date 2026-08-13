//! A2A Agent Card extension descriptor for APH.
//!
//! When an agent advertises APH support on its AgentCard, it adds the
//! extension declaration produced by `aph_a2a_extension()`. Verifiers can
//! discover APH support by scanning `agent_card.extensions` for the
//! `APH_EXTENSION_URI`.
//!
//! The `AgentExtension` shape is vendored here from the A2A Agent Card
//! model: an opaque capability declaration (uri / description / required)
//! that peers who do not understand it safely ignore.

/// An extension capability declared on an Agent Card.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentExtension {
  uri: String,
  description: String,
  required: bool,
}

impl AgentExtension {
  /// Declares an extension capability with the given URI, description, and
  /// whether peers must understand it to interoperate.
  pub fn new(uri: impl Into<String>, description: impl Into<String>, required: bool) -> Self {
    Self {
      uri: uri.into(),
      description: description.into(),
      required,
    }
  }

  /// Opaque extension identifier, compared byte-for-byte by peers.
  pub fn uri(&self) -> &str {
    &self.uri
  }
  /// Human-readable summary shown when inspecting an Agent Card.
  pub fn description(&self) -> &str {
    &self.description
  }
  /// Whether a peer must understand this extension to interoperate.
  pub fn required(&self) -> bool {
    self.required
  }
}

/// URI for the APH notarization extension on the AgentCard.
pub const APH_EXTENSION_URI: &str = "aph://extensions/notarization/v1";

/// Creates the APH notarization extension declaration.
pub fn aph_a2a_extension() -> crate::a2a_extension::AgentExtension {
  crate::a2a_extension::AgentExtension::new(
    APH_EXTENSION_URI,
    "APH (Agent per Human) outbound communication notarization",
    false,
  )
}

#[cfg(test)]
mod tests {
  #[test]
  fn aph_uri_pinned() {
    // The A2A extension spec requires this URI be declared as one exact
    // constant and compared byte-for-byte, never assembled from parts. A
    // single character of drift makes peers fail to recognize APH support.
    std::assert_eq!(super::APH_EXTENSION_URI, "aph://extensions/notarization/v1");
  }

  #[test]
  fn aph_extension_is_optional() {
    // required:false is deliberate — advertising APH must not make peers
    // that lack it unable to talk to us. Flipping this to true would break
    // interop with every non-APH A2A agent.
    let ext = super::aph_a2a_extension();
    std::assert_eq!(ext.uri(), super::APH_EXTENSION_URI);
    std::assert!(!ext.required());
  }

  #[test]
  fn description_is_non_empty() {
    // The description is what a human sees when inspecting an AgentCard's
    // capabilities; empty would leave the extension unexplained there.
    let ext = super::aph_a2a_extension();
    std::assert!(!ext.description().is_empty());
  }
}
