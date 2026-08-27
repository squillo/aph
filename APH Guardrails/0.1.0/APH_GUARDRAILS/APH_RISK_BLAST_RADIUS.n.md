---
section: "APH Guardrails"
name: "APH Guardrails — Risk Blast Radius"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Risk Blast Radius

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

This family answers one question about an act: if it is wrong, whose state,
access, money, or safety is disturbed. It measures the WIDTH of the affected
set, not the depth of the harm, not the probability of being wrong, and not
whether the act can be undone — severity and recoverability are separate
families (APH_RISK_IRREVERSIBILITY and the guard families), and a widely-felt
act may be trivial while a single-party act may be devastating. Labels form a
precedence ladder from PRINCIPAL_ONLY through CRITICAL_INFRASTRUCTURE — later
rungs name broader or graver populations, but the rungs are DISJOINT
categories, not nested sets: an organisation-wide effect stops at the
boundary, a customer effect sits outside it, and neither contains the other.
When an act reaches more than one population at once, the classifier MUST
return the latest applicable rung in the ladder, counting parties who would
be affected even if the act succeeds as intended for everyone else. This family does NOT count
observers or recipients of a mere notification as affected parties, does NOT
classify who is authorized to act, and returns OUT_OF_SCOPE for anything that
is not an act with consequences.

## Extension

This family is open to overlays. A later entry for this namespace may **add a
label**, **raise a confidence floor**, **remove a rung**, **restrict privacy
locality**, or **upgrade fail-open to fail-closed**. It may never widen: a
lowered floor, an added rung, relaxed privacy, a relaxed fail posture, or a
colliding label name is a loud load refusal rather than a silent adjustment.

Label names are wire values a stranger's agent has already read. That is why an
overlay may add one and never redefine or remove one — the only path to changing
an existing label is a new base version, where the change is visible.

## Classifier

```nlang
classifiers "APH_RISK_BLAST_RADIUS" {
  description = "Classifies how wide the set of affected parties is if an act turns out to be wrong."
  labels {
    PRINCIPAL_ONLY {
      description = "Only the human principal on whose behalf the agent acts is affected. No other person, account, or organisation experiences a change in state, access, obligation, or cost. An act stays here even if it is stored on a shared platform, so long as no one else's view of the world changes."
      examples    = ["Muted the principal's weekend alerts on their own notification settings.",
                     "Rewrote the note in their private journal document; nobody else has access to it.",
                     "Cancelled their solo gym booking — no other attendee was on it."]
    }
    SINGLE_COUNTERPARTY {
      description = "Exactly one identified party other than the principal is affected. The counterparty is nameable at the time of the act — a person, an account, a single organisation acting through one relationship. If a second party's state also changes, this label is wrong."
      examples    = ["Sent Dana a message accepting the time she proposed.",
                     "Issued a refund to the one customer who filed the complaint.",
                     "Cancelled the call with the vendor rep; she was the only other invitee."]
    }
    SMALL_DEFINED_GROUP {
      description = "A bounded, enumerable set of parties beyond a single counterparty is affected — a team, a thread, a project's contractors, the signatories to a document. The membership is known and closed at the time of the act. If the set is open-ended or defined by a role that anyone in the organisation can hold, use ORGANIZATION_WIDE instead."
      examples    = ["Moved the standup for the six people on the platform team.",
                     "Revoked repository access for the three contractors on the audit project.",
                     "Emailed all four signatories that the closing date slipped."]
    }
    ORGANIZATION_WIDE {
      description = "Members of the principal's own organisation are affected generally — every employee, every user of an internal system, or an open-ended internal population rather than a named list. The effect stops at the organisational boundary; nobody outside it experiences the change."
      examples    = ["Changed the company-wide password policy; every employee will be forced to re-enrol.",
                     "Took the internal wiki offline for maintenance — nobody at the company can reach it.",
                     "Updated the default expense approval chain across all departments."]
    }
    ORGANIZATION_CUSTOMERS {
      description = "Customers or end users of the principal's organisation are affected — parties outside the organisational boundary who are reached through the organisation's product, service, or billing relationship. Use this whenever the affected set is the customer base or a large open segment of it, even if only some customers notice."
      examples    = ["Deployed the pricing change that every paying customer will see on their next invoice.",
                     "This migration will sign out all end users of the mobile app.",
                     "Sent the outage notice to the entire customer mailing list."]
    }
    MULTI_ORGANIZATION {
      description = "Two or more distinct organisations beyond the principal's own are affected — partners, resellers, suppliers, downstream integrators, or other tenants of a shared system. Use this when the effect crosses several organisational boundaries but is still confined to parties in a known commercial or technical relationship, not to the public at large."
      examples    = ["Rotated the shared integration credential that all four partner companies authenticate with.",
                     "Shipped a breaking API change that our resellers and their downstream vendors both consume.",
                     "Suspended the clearing account that three partner firms settle through."]
    }
    GENERAL_PUBLIC {
      description = "Anyone, without prior relationship, can be affected: the act touches publicly reachable systems, public communications, or openly available data. Choose this whenever the affected set cannot be enumerated because it is defined only by access to the internet or to a public place."
      examples    = ["Published the statement on the public website and the company's social accounts.",
                     "Opened the dataset so anyone on the internet can download it.",
                     "Took the public status page and the marketing site offline."]
    }
    CRITICAL_INFRASTRUCTURE {
      description = "The act reaches systems whose failure endangers physical safety, life, or essential public services — utilities, medical devices and clinical systems, transport control, emergency services, industrial safety interlocks, financial market plumbing. This is the ceiling of the ladder: if such a system is in scope at all, return this label regardless of how many people the act appears to touch."
      examples    = ["Changed the setpoint on the water treatment dosing controller.",
                     "This reroutes emergency dispatch traffic for the whole county.",
                     "Disabling that interlock takes the plant's safety shutdown out of service."]
    }
    OUT_OF_SCOPE {
      description = "The input does not describe an act whose affected set can be assessed, or it asks a different question — how harmful the act is, whether it can be undone, whether it is permitted — or it is a request for the agent to produce content. Return this instead of defaulting to a narrow rung; a narrow guess here is read by a stranger's agent as permission to proceed unsupervised."
      examples    = ["How many people are on this email thread?",
                     "Is there any way to undo this once it goes out?",
                     "Rewrite that message so it sounds friendlier."]
      oos         = true
    }
  }
  escalate t0_signals    >= 970
  escalate t1_embedding  >= 940
  escalate t3_local_llm  >= 900
  abstain      = "human"
  golden_set   = "eval/aph_risk_blast_radius.golden.json"
  min_accuracy = 950
}
```
