//! `aph-conformance` — companion test harness for the APH protocol.
//!
//! This crate validates that the `aph_core` types round-trip cleanly through
//! serde JSON for 7 in-source golden envelope fixtures. The fixtures are
//! deserialize-clean instances of `aph_core::NotarizationEnvelope` that
//! exercise the wire shape end-to-end (W3C VC 2.0 + JSON-LD
//! `@context`/`type` arrays + camelCase + `deny_unknown_fields` + optional
//! `linkedMandate`).
//!
//! The spec repository's canonical `examples/` directory is separately
//! exercised by `tests/repo_examples_test.rs`, which welds this interpreter
//! to the published example envelopes.
//!
//! It also carries the §6.3.3 REVOCATION STATUS vectors, kept apart from
//! `golden_envelopes()` because they answer a different question — "does an
//! independent implementation refuse what the transport says it must?" —
//! and because that list's length is part of `aph-cli`'s `golden` output.
//! They are the runnable half of `spec/schemas/*.schema.json`: the schemas
//! state the shape, the vectors state the refusals a schema cannot express.
//!
//! Coverage matrix:
//! 1. Minimal outbound email (no linked mandate, empty act_chain)
//! 2. Slack reply with linked AP2 IntentMandate
//! 3. Inbound verification (foreign issuer DID:web)
//! 4. Delegation scope embedded (delegation_mandate_id + per-recipient scope)
//! 5. Multi-recipient broadcast (recipient_addressing carries array)
//! 6. Discord with attachment (recipient_addressing carries attachment ref)
//! 7. iMessage with retention metadata (recipient_addressing carries policy hints)

/// Returns the list of golden envelope JSON strings covering the matrix
/// documented at the module preamble.
///
/// All envelopes are deserialize-clean instances of
/// `aph_core::NotarizationEnvelope`.
pub fn golden_envelopes() -> std::vec::Vec<&'static str> {
  std::vec::Vec::from([
    GOLDEN_01_MINIMAL_EMAIL,
    GOLDEN_02_SLACK_WITH_AP2,
    GOLDEN_03_INBOUND_VERIFY,
    GOLDEN_04_DELEGATION_SCOPE,
    GOLDEN_05_MULTI_RECIPIENT,
    GOLDEN_06_DISCORD_ATTACHMENT,
    GOLDEN_07_IMESSAGE_RETENTION,
  ])
}

/// Golden 1: Minimal outbound email. No linked mandate, no delegation, empty
/// act_chain. Channel kind `"email"` with `{to: [...]}` addressing.
const GOLDEN_01_MINIMAL_EMAIL: &str = r#"{
  "aphVersion": "0.1",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/aph/v1"
  ],
  "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
  "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
  "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
  "validFrom": "2026-05-28T00:00:00Z",
  "validUntil": "2026-05-29T00:00:00Z",
  "credentialSubject": {
    "humanPrincipal": {
      "id": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
      "displayName": "Scott Wyatt"
    },
    "agent": {
      "id": "did:web:agent.squillo.com",
      "agentCardUri": "https://agent.squillo.com/.well-known/agent-card.json",
      "displayName": "Squillo Concierge",
      "version": "1.0"
    },
    "channel": {
      "kind": "email",
      "recipientAddressing": {
        "to": ["bob@example.com"]
      }
    },
    "communication": {
      "contentClass": "DM",
      "bodySha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "bodySize": 1842,
      "previewLines": 3,
      "preview": "Hi Bob,\nThanks for the update — sending the draft now.\nBest,\nScott"
    },
    "policy": {
      "decision": "AskEveryTime",
      "matchedScope": "per-recipient"
    },
    "notarization": {
      "notaryService": {
        "id": "did:web:notary.squillo.com",
        "name": "Squillo Notary Service",
        "version": "0.1.0"
      },
      "decisionTimestamp": "2026-05-28T00:00:01Z",
      "decisionLatencyMs": 1834
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
    "created": "2026-05-28T00:00:01Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3WgvA9JHkbV3qLZHcM4FxBp4xHfQVnVnPKKDdyazQwQGdGzxsRdmZWBxXwQvN6P2sLZbLP4HnRy9LcZdpFLLM6h"
  }
}"#;

/// Golden 2: Slack reply with a linked AP2 IntentMandate URI. Exercises the
/// optional `linkedMandate.ap2IntentMandateUri` cross-protocol field.
const GOLDEN_02_SLACK_WITH_AP2: &str = r#"{
  "aphVersion": "0.1",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/aph/v1"
  ],
  "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
  "id": "urn:uuid:00000000-0000-4000-8000-000000000002",
  "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
  "validFrom": "2026-05-28T01:00:00Z",
  "validUntil": "2026-05-29T01:00:00Z",
  "credentialSubject": {
    "humanPrincipal": {
      "id": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
      "displayName": "Scott Wyatt"
    },
    "agent": {
      "id": "did:web:agent.squillo.com",
      "displayName": "Squillo Concierge",
      "version": "1.0"
    },
    "channel": {
      "kind": "slack",
      "recipientAddressing": {
        "teamId": "T01234567",
        "channelId": "C01234567",
        "parentTs": "1716249600.000100"
      }
    },
    "communication": {
      "contentClass": "Reply",
      "bodySha256": "ab1c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8aa",
      "bodySize": 412,
      "previewLines": 2,
      "preview": "Got it — pushing the patch now.\nWill follow up after CI."
    },
    "policy": {
      "decision": "AlwaysAllow",
      "matchedScope": "per-channel"
    },
    "notarization": {
      "notaryService": {
        "id": "did:web:notary.squillo.com",
        "name": "Squillo Notary Service",
        "version": "0.1.0"
      },
      "decisionTimestamp": "2026-05-28T01:00:01Z",
      "decisionLatencyMs": 287
    }
  },
  "linkedMandate": {
    "ap2IntentMandateUri": "urn:uuid:11111111-1111-4111-8111-111111111111"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
    "created": "2026-05-28T01:00:01Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "z4nUC7Ax8VnAFwLqRf1mGqVNxNFCsW1FQbHkbiVcVuQrjEPmEsAQbsbnAJDXt5oTzBhmAjJxYpqLpkPNwH7w8tBcz"
  }
}"#;

/// Golden 3: Inbound verification — envelope issued by a foreign notary
/// (did:web) and pinned to the ES256 cryptosuite. Exercises the cross-issuer
/// inbound verification path.
const GOLDEN_03_INBOUND_VERIFY: &str = r#"{
  "aphVersion": "0.1",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/aph/v1"
  ],
  "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
  "id": "urn:uuid:00000000-0000-4000-8000-000000000003",
  "issuer": "did:web:notary.acme.example",
  "validFrom": "2026-05-28T02:00:00Z",
  "validUntil": "2026-05-29T02:00:00Z",
  "credentialSubject": {
    "humanPrincipal": {
      "id": "did:key:z6MkuFHaR1ME2YQbWLh6hqGYDVxxC7ueoVcd5dGyfAkfRZ3v9zJWh9LM",
      "displayName": "Alice Foreign"
    },
    "agent": {
      "id": "did:web:agent.acme.example",
      "displayName": "Acme Concierge",
      "version": "2.3"
    },
    "channel": {
      "kind": "email",
      "recipientAddressing": {
        "to": ["scott@squillo.com"]
      }
    },
    "communication": {
      "contentClass": "Reply",
      "bodySha256": "c0ffee98fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855aa",
      "bodySize": 932,
      "previewLines": 3,
      "preview": "Hello Scott,\nPer our earlier discussion, the contract is ready.\nBest, Alice"
    },
    "policy": {
      "decision": "AlwaysAllow",
      "matchedScope": "global"
    },
    "notarization": {
      "notaryService": {
        "id": "did:web:notary.acme.example",
        "name": "Acme Notary Service",
        "version": "1.2.3"
      },
      "decisionTimestamp": "2026-05-28T02:00:01Z",
      "decisionLatencyMs": 412
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-jcs-2019",
    "verificationMethod": "did:web:notary.acme.example#key-1",
    "created": "2026-05-28T02:00:01Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "zBC3kFGHJ7TtNxsWqRf1mGqVNxNFCsW1FQbHkbiVcVuQrjEPmEsAQbsbnAJDXt5oTzBhmAjJxYpqLpkPNwH7w8tBcz"
  }
}"#;

/// Golden 4: Delegation scope embedded — `policy.delegationMandateId` is set,
/// `actChain` carries a multi-hop principal chain. Exercises delegation-aware
/// envelope consumers.
const GOLDEN_04_DELEGATION_SCOPE: &str = r#"{
  "aphVersion": "0.1",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/aph/v1"
  ],
  "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
  "id": "urn:uuid:00000000-0000-4000-8000-000000000004",
  "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
  "validFrom": "2026-05-28T03:00:00Z",
  "validUntil": "2026-05-29T03:00:00Z",
  "credentialSubject": {
    "humanPrincipal": {
      "id": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
      "displayName": "Scott Wyatt"
    },
    "agent": {
      "id": "did:web:concierge.squillo.com",
      "displayName": "Squillo Concierge",
      "version": "1.0"
    },
    "channel": {
      "kind": "email",
      "recipientAddressing": {
        "to": ["partner@example.com"]
      }
    },
    "communication": {
      "contentClass": "DM",
      "bodySha256": "deadbeef98fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "bodySize": 2104,
      "previewLines": 4,
      "preview": "Partner,\nForwarding the signed letter of intent.\nRegards,\nScott (via delegated agent)"
    },
    "policy": {
      "decision": "AlwaysAllow",
      "matchedScope": "per-recipient",
      "delegationMandateId": "urn:uuid:22222222-2222-4222-8222-222222222222",
      "actChain": [
        "did:web:concierge.squillo.com",
        "did:web:notary.squillo.com"
      ]
    },
    "notarization": {
      "notaryService": {
        "id": "did:web:notary.squillo.com",
        "name": "Squillo Notary Service",
        "version": "0.1.0"
      },
      "decisionTimestamp": "2026-05-28T03:00:01Z",
      "decisionLatencyMs": 921
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
    "created": "2026-05-28T03:00:01Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "z5MvkkR3DcWqLZHcM4FxBp4xHfQVnVnPKKDdyazQwQGdGzxsRdmZWBxXwQvN6P2sLZbLP4HnRy9LcZdpFLLM6hA"
  }
}"#;

/// Golden 5: Multi-recipient broadcast. `recipient_addressing.to` carries an
/// array of 3 addresses + cc + bcc. Exercises addressing free-form value shape.
const GOLDEN_05_MULTI_RECIPIENT: &str = r#"{
  "aphVersion": "0.1",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/aph/v1"
  ],
  "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
  "id": "urn:uuid:00000000-0000-4000-8000-000000000005",
  "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
  "validFrom": "2026-05-28T04:00:00Z",
  "validUntil": "2026-05-29T04:00:00Z",
  "credentialSubject": {
    "humanPrincipal": {
      "id": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
      "displayName": "Scott Wyatt"
    },
    "agent": {
      "id": "did:web:agent.squillo.com",
      "displayName": "Squillo Concierge",
      "version": "1.0"
    },
    "channel": {
      "kind": "email",
      "recipientAddressing": {
        "to": [
          "alice@example.com",
          "bob@example.com",
          "carol@example.com"
        ],
        "cc": ["dave@example.com"],
        "bcc": ["audit@squillo.com"]
      }
    },
    "communication": {
      "contentClass": "Broadcast",
      "bodySha256": "feedface98fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "bodySize": 3214,
      "previewLines": 5,
      "preview": "Team,\nQuarterly update attached.\nKey wins this quarter:\n- Item A\n- Item B"
    },
    "policy": {
      "decision": "AskEveryTime",
      "matchedScope": "per-recipient",
      "actChain": []
    },
    "notarization": {
      "notaryService": {
        "id": "did:web:notary.squillo.com",
        "name": "Squillo Notary Service",
        "version": "0.1.0"
      },
      "decisionTimestamp": "2026-05-28T04:00:02Z",
      "decisionLatencyMs": 2103
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
    "created": "2026-05-28T04:00:02Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "z6NwxlT5DcWqLZHcM4FxBp4xHfQVnVnPKKDdyazQwQGdGzxsRdmZWBxXwQvN6P2sLZbLP4HnRy9LcZdpFLLM6hB"
  }
}"#;

/// Golden 6: Discord message with an attachment reference embedded in
/// `recipient_addressing`. Exercises non-text channel + attachment metadata.
const GOLDEN_06_DISCORD_ATTACHMENT: &str = r#"{
  "aphVersion": "0.1",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/aph/v1"
  ],
  "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
  "id": "urn:uuid:00000000-0000-4000-8000-000000000006",
  "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
  "validFrom": "2026-05-28T05:00:00Z",
  "validUntil": "2026-05-29T05:00:00Z",
  "credentialSubject": {
    "humanPrincipal": {
      "id": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
      "displayName": "Scott Wyatt"
    },
    "agent": {
      "id": "did:web:agent.squillo.com",
      "displayName": "Squillo Concierge",
      "version": "1.0"
    },
    "channel": {
      "kind": "discord",
      "recipientAddressing": {
        "guildId": "987654321098765432",
        "channelId": "123456789012345678",
        "attachments": [
          {
            "filename": "diagram.png",
            "contentType": "image/png",
            "size": 48211,
            "sha256": "deadc0de8fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855a"
          }
        ]
      }
    },
    "communication": {
      "contentClass": "DM",
      "bodySha256": "ba5eba1198fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "bodySize": 78,
      "previewLines": 1,
      "preview": "Here's the architecture sketch we discussed."
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
      "decisionTimestamp": "2026-05-28T05:00:01Z",
      "decisionLatencyMs": 184
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
    "created": "2026-05-28T05:00:01Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "z7OxylU6DcWqLZHcM4FxBp4xHfQVnVnPKKDdyazQwQGdGzxsRdmZWBxXwQvN6P2sLZbLP4HnRy9LcZdpFLLM6hC"
  }
}"#;

/// Golden 7: iMessage with retention metadata. `recipient_addressing` carries
/// retention policy hints (expireAfter, mediaPolicy). Exercises retention-aware
/// channel kinds.
const GOLDEN_07_IMESSAGE_RETENTION: &str = r#"{
  "aphVersion": "0.1",
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/aph/v1"
  ],
  "type": ["VerifiableCredential", "AgentSendAuthorizationCredential"],
  "id": "urn:uuid:00000000-0000-4000-8000-000000000007",
  "issuer": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
  "validFrom": "2026-05-28T06:00:00Z",
  "validUntil": "2026-05-29T06:00:00Z",
  "credentialSubject": {
    "humanPrincipal": {
      "id": "did:key:z6MkfAkfRZ3v9zJWh9LM2YQbWLh6hqGYDVxxC7ueoVcd5dGy",
      "displayName": "Scott Wyatt"
    },
    "agent": {
      "id": "did:web:agent.squillo.com",
      "displayName": "Squillo Concierge",
      "version": "1.0"
    },
    "channel": {
      "kind": "imessage",
      "recipientAddressing": {
        "to": ["+15551234567"],
        "retention": {
          "expireAfterSeconds": 86400,
          "mediaPolicy": "ephemeral",
          "readReceipts": false
        }
      }
    },
    "communication": {
      "contentClass": "DM",
      "bodySha256": "1eaff00d98fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "bodySize": 142,
      "previewLines": 2,
      "preview": "Running late — be there in 10.\nNo need to wait outside."
    },
    "policy": {
      "decision": "AlwaysAllow",
      "matchedScope": "per-recipient"
    },
    "notarization": {
      "notaryService": {
        "id": "did:web:notary.squillo.com",
        "name": "Squillo Notary Service",
        "version": "0.1.0"
      },
      "decisionTimestamp": "2026-05-28T06:00:01Z",
      "decisionLatencyMs": 92
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV#z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV",
    "created": "2026-05-28T06:00:01Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "z8PyzmV7DcWqLZHcM4FxBp4xHfQVnVnPKKDdyazQwQGdGzxsRdmZWBxXwQvN6P2sLZbLP4HnRy9LcZdpFLLM6hD"
  }
}"#;

// ============================================================
// Revocation status transport vectors (spec §6.3.3).
//
// Kept apart from `golden_envelopes()` on purpose. That list is the
// channel-shape matrix; it is iterated by `aph-cli`'s `golden` subcommand
// and its length is part of that command's output, so growing it to carry a
// security mechanism would change an operator-facing surface for an
// unrelated reason. These vectors answer a different question — "does an
// independent implementation refuse what §6.3.3 says it must?" — and a
// non-Rust adopter can consume them beside `spec/schemas/*.schema.json`
// without linking anything.
//
// Every URL below is anchored at the notary `did:web:aph-notary.squillo.com`,
// whose DERIVED status endpoint under §6.3.3.2 is
// `https://aph-notary.squillo.com/.well-known/aph-status.json`.
// ============================================================

/// The notary every status vector is issued by; its `did:web` host is the
/// only origin any of them may legitimately name.
pub const STATUS_VECTOR_NOTARY_DID: &str = "did:web:aph-notary.squillo.com";

/// The endpoint §6.3.3.2 derives from [`STATUS_VECTOR_NOTARY_DID`].
pub const STATUS_VECTOR_DERIVED_ENDPOINT: &str =
  "https://aph-notary.squillo.com/.well-known/aph-status.json";

/// `credentialStatus` entries a conformant verifier MUST ACCEPT as
/// well-formed, paired with what each one exercises.
///
/// Acceptance here means "parses and binds", not "the mandate is live": the
/// bit still decides that.
pub fn status_entry_vectors_accept() -> std::vec::Vec<(&'static str, &'static str)> {
  std::vec::Vec::from([
    (
      "the derived endpoint itself, the shape a single-list notary emits",
      STATUS_ENTRY_AT_DERIVED_ENDPOINT,
    ),
    (
      "a DIFFERENT PATH on the derived origin — §6.3.3.2 permits it, and \
       §6.3.3.6 requires it once a list is exhausted",
      STATUS_ENTRY_SECOND_LIST_SAME_ORIGIN,
    ),
    (
      "an entry carrying the OPTIONAL `id` member",
      STATUS_ENTRY_WITH_ID,
    ),
    (
      "an index past 2^53 — the value that rounds, and reads another \
       mandate's bit, in any implementation that parses it as a number",
      STATUS_ENTRY_INDEX_BEYOND_DOUBLE_PRECISION,
    ),
  ])
}

/// `credentialStatus` entries that PARSE and are then refused by
/// §6.3.3.2's same-origin binding, paired with the rule each one violates.
///
/// These are refused WITHOUT the named URL being fetched: an implementation
/// that fetches first and refuses afterwards has already made a request an
/// attacker steered, so a vector run that only checks the outcome is not
/// checking the rule. The distinction from
/// [`status_entry_vectors_refuse_at_parse`] is the spec's own — that set is
/// malformed wire refused at §8.3 step 1, this set is well-formed wire
/// refused at step 8a.
pub fn status_entry_vectors_refuse_at_binding() -> std::vec::Vec<(&'static str, &'static str)> {
  std::vec::Vec::from([
    (
      "§6.3.3.2 cross-origin: a host of the attacker's choosing always \
       answers `not revoked` — REFUSE WITHOUT FETCHING",
      STATUS_ENTRY_CROSS_ORIGIN,
    ),
    (
      "§6.3.3.2 non-https: the TLS name is the entire trust anchor — \
       REFUSE WITHOUT FETCHING",
      STATUS_ENTRY_HTTP_SCHEME,
    ),
    (
      "§6.3.3.2 userinfo disguise: the HOST here is `evil.example` — \
       REFUSE WITHOUT FETCHING",
      STATUS_ENTRY_USERINFO_DISGUISE,
    ),
  ])
}

/// `credentialStatus` entries a conformant verifier MUST refuse as MALFORMED
/// WIRE — §7.1's strict parse at §8.3 step 1 — paired with the rule each one
/// violates.
///
/// An implementation that accepted any of these and then handled it later
/// has already lost the property that makes the check unskippable: a
/// producer could disable status checking on that verifier by writing a
/// value it does not recognize.
pub fn status_entry_vectors_refuse_at_parse() -> std::vec::Vec<(&'static str, &'static str)> {
  std::vec::Vec::from([
    (
      "§6.3.3.6 numeric index: a JSON number is the f64 rounding hazard the \
       string form exists to make unconstructible",
      STATUS_ENTRY_NUMERIC_INDEX,
    ),
    (
      "§6.3.3.5 excluded purpose: `suspension` is reversible and §6.3.2 \
       forbids re-activation; an unrecognized purpose is a FAILURE, never \
       a skip",
      STATUS_ENTRY_SUSPENSION_PURPOSE,
    ),
    (
      "§14.1 wrong vintage: a different vintage of the same idea looks \
       conformant and never interoperates",
      STATUS_ENTRY_LEGACY_VINTAGE_TYPE,
    ),
    (
      "§7.1 strict parse: a member APH never defined",
      STATUS_ENTRY_UNKNOWN_MEMBER,
    ),
  ])
}

/// Status list credentials a conformant verifier MUST REFUSE, paired with
/// the §6.3.3.3 rule each one violates. All are §6.3.3.4 case 2
/// (`APH_E008`), whatever specifically failed.
///
/// Each is dated against [`STATUS_VECTOR_EVALUATION_INSTANT`].
pub fn status_document_vectors_refuse() -> std::vec::Vec<(&'static str, &'static str)> {
  std::vec::Vec::from([
    (
      "§6.3.3.3 issuer binding: same-origin alone does not make a document \
       authoritative, because one host serves many documents",
      STATUS_DOCUMENT_FOREIGN_ISSUER,
    ),
    (
      "§6.3.3.3 purpose: an unrecognized purpose in the fetched DOCUMENT is \
       case 2, not the parse failure the envelope entry raises",
      STATUS_DOCUMENT_SUSPENSION_PURPOSE,
    ),
    (
      "§6.3.3.3 freshness: issued 361s before the evaluation instant, past \
       the 300s bound plus 60s of skew",
      STATUS_DOCUMENT_STALE,
    ),
    (
      "§6.3.3.3 freshness: no `validFrom` at all, so the bound cannot be \
       applied and the document cannot be accepted",
      STATUS_DOCUMENT_NO_VALID_FROM,
    ),
    (
      "§6.3.3.1 vintage: a `type` from the predecessor status-list \
       specification",
      STATUS_DOCUMENT_WRONG_TYPE,
    ),
  ])
}

/// The `now` every status document vector is evaluated against. Chosen 30
/// seconds after the fresh vectors' `validFrom`, comfortably inside
/// §6.3.3.3's bound so a passing vector is passing on its merits.
pub const STATUS_VECTOR_EVALUATION_INSTANT: &str = "2026-05-28T00:00:30Z";

/// A status list credential a conformant verifier MUST ACCEPT, whose bit at
/// index 2 is CLEAR: correct issuer, purpose, vintage and freshness, and a
/// mandate that has not been revoked.
///
/// `encodedList` is a REAL multibase-base64url GZIP stream, not a
/// placeholder: it expands to 16,384 zero bytes — 131,072 entries, the
/// minimum list size the W3C profile requires for herd privacy. An adopter
/// with any gzip library can therefore run the whole mechanism end to end
/// against these two documents, which is the point of shipping vectors at
/// all. `aph-core` itself links no DEFLATE codec (see `credential_status`'s
/// module docs), so its own tests exercise the decision and leave the codec
/// to the caller.
pub const STATUS_DOCUMENT_FRESH_NOT_REVOKED: &str = r#"{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "https://aph-notary.squillo.com/.well-known/aph-status.json",
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "did:web:aph-notary.squillo.com",
  "validFrom": "2026-05-28T00:00:00Z",
  "credentialSubject": {
    "id": "https://aph-notary.squillo.com/.well-known/aph-status.json#list",
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "uH4sIAAAAAAAC_-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA"
  }
}"#;

/// The same list with the bit at index 2 SET: the mandate was revoked, and a
/// verifier MUST refuse the envelope with `APH_E015`.
///
/// Index 2 rather than 0 so a reader that has the bit order backwards fails:
/// with MSB-first order (the W3C profile's, and the only correct one) the
/// first byte is `0b0010_0000`, which an LSB-first reader would report as
/// index 5. Byte 0 bit 0 would have looked identical under either reading.
pub const STATUS_DOCUMENT_FRESH_REVOKED_AT_INDEX_2: &str = r#"{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "https://aph-notary.squillo.com/.well-known/aph-status.json",
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "did:web:aph-notary.squillo.com",
  "validFrom": "2026-05-28T00:00:00Z",
  "credentialSubject": {
    "id": "https://aph-notary.squillo.com/.well-known/aph-status.json#list",
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "uH4sIAAAAAAAC_-3BIQEAAAACIKf4f6UzLEADAAAAAAAAAAAAAAAAAAAAvA1-s-l1AEAAAA"
  }
}"#;

/// The plain shape: the entry names the derived endpoint itself.
const STATUS_ENTRY_AT_DERIVED_ENDPOINT: &str = r#"{
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "0",
  "statusListCredential": "https://aph-notary.squillo.com/.well-known/aph-status.json"
}"#;

/// A second list at another path on the SAME origin — legitimate, and the
/// case a verifier that pinned the whole URL instead of the origin breaks.
const STATUS_ENTRY_SECOND_LIST_SAME_ORIGIN: &str = r#"{
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "131071",
  "statusListCredential": "https://aph-notary.squillo.com/status/list-2.json"
}"#;

/// The optional `id` member, present.
const STATUS_ENTRY_WITH_ID: &str = r#"{
  "id": "https://aph-notary.squillo.com/.well-known/aph-status.json#94567",
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "94567",
  "statusListCredential": "https://aph-notary.squillo.com/.well-known/aph-status.json"
}"#;

/// 2^53 + 1. Read through a double this becomes 9007199254740992 — a
/// DIFFERENT bit, with no parse error anywhere to warn the verifier.
const STATUS_ENTRY_INDEX_BEYOND_DOUBLE_PRECISION: &str = r#"{
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "9007199254740993",
  "statusListCredential": "https://aph-notary.squillo.com/.well-known/aph-status.json"
}"#;

/// The whole attack §6.3.3.2 exists to stop.
const STATUS_ENTRY_CROSS_ORIGIN: &str = r#"{
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "0",
  "statusListCredential": "https://evil.example/.well-known/aph-status.json"
}"#;

/// Right host, no TLS — and the certificate chain IS the trust model.
const STATUS_ENTRY_HTTP_SCHEME: &str = r#"{
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "0",
  "statusListCredential": "http://aph-notary.squillo.com/.well-known/aph-status.json"
}"#;

/// Reads as the notary's host to a prefix comparison; connects to
/// `evil.example`.
const STATUS_ENTRY_USERINFO_DISGUISE: &str = r#"{
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "0",
  "statusListCredential": "https://aph-notary.squillo.com@evil.example/.well-known/aph-status.json"
}"#;

/// The f64 hazard in its constructible form.
const STATUS_ENTRY_NUMERIC_INDEX: &str = r#"{
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": 94567,
  "statusListCredential": "https://aph-notary.squillo.com/.well-known/aph-status.json"
}"#;

/// A purpose APH deliberately excludes.
const STATUS_ENTRY_SUSPENSION_PURPOSE: &str = r#"{
  "type": "BitstringStatusListEntry",
  "statusPurpose": "suspension",
  "statusListIndex": "0",
  "statusListCredential": "https://aph-notary.squillo.com/.well-known/aph-status.json"
}"#;

/// The predecessor specification's entry type.
const STATUS_ENTRY_LEGACY_VINTAGE_TYPE: &str = r#"{
  "type": "StatusList2021Entry",
  "statusPurpose": "revocation",
  "statusListIndex": "0",
  "statusListCredential": "https://aph-notary.squillo.com/.well-known/aph-status.json"
}"#;

/// A member APH never defined, inside a strictly-parsed envelope member.
const STATUS_ENTRY_UNKNOWN_MEMBER: &str = r#"{
  "type": "BitstringStatusListEntry",
  "statusPurpose": "revocation",
  "statusListIndex": "0",
  "statusListCredential": "https://aph-notary.squillo.com/.well-known/aph-status.json",
  "statusSize": 2
}"#;

/// Served from the right origin, signed by nobody in particular, claiming a
/// different notary.
const STATUS_DOCUMENT_FOREIGN_ISSUER: &str = r#"{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "did:web:evil.example",
  "validFrom": "2026-05-28T00:00:00Z",
  "credentialSubject": {
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "uH4sIAAAAAAAA_wMAAAAAAAAAAAA"
  }
}"#;

/// A reversible purpose in a document, which is case 2 rather than a parse
/// error.
const STATUS_DOCUMENT_SUSPENSION_PURPOSE: &str = r#"{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "did:web:aph-notary.squillo.com",
  "validFrom": "2026-05-28T00:00:00Z",
  "credentialSubject": {
    "type": "BitstringStatusList",
    "statusPurpose": "suspension",
    "encodedList": "uH4sIAAAAAAAA_wMAAAAAAAAAAAA"
  }
}"#;

/// 361 seconds before [`STATUS_VECTOR_EVALUATION_INSTANT`]: one second past
/// 300 + 60.
const STATUS_DOCUMENT_STALE: &str = r#"{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "did:web:aph-notary.squillo.com",
  "validFrom": "2026-05-27T23:54:29Z",
  "credentialSubject": {
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "uH4sIAAAAAAAA_wMAAAAAAAAAAAA"
  }
}"#;

/// No issuance instant, so the freshness bound has nothing to measure.
const STATUS_DOCUMENT_NO_VALID_FROM: &str = r#"{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "BitstringStatusListCredential"],
  "issuer": "did:web:aph-notary.squillo.com",
  "credentialSubject": {
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "uH4sIAAAAAAAA_wMAAAAAAAAAAAA"
  }
}"#;

/// The predecessor specification's credential type.
const STATUS_DOCUMENT_WRONG_TYPE: &str = r#"{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "StatusList2021Credential"],
  "issuer": "did:web:aph-notary.squillo.com",
  "validFrom": "2026-05-28T00:00:00Z",
  "credentialSubject": {
    "type": "BitstringStatusList",
    "statusPurpose": "revocation",
    "encodedList": "uH4sIAAAAAAAA_wMAAAAAAAAAAAA"
  }
}"#;
