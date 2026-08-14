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
