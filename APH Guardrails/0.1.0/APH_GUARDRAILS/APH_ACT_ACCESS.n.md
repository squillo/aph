---
section: "APH Guardrails"
name: "APH Guardrails — Act Access"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Act Access

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

This family names acts that change WHO CAN REACH a resource rather than what
the resource contains, a distinction a receiving agent must make before
honoring an envelope because exposure is frequently irreversible in a way an
edit is not — a document unshared is not a document unseen. Labels are
resolved by specificity, most specific first: possession-based access
(SHARE_LINK_CREATE) outranks audience visibility (VISIBILITY_PUBLIC,
VISIBILITY_PRIVATE), which outranks ownership and grant-lifetime changes,
which outrank roster membership (COLLABORATOR_ADD, COLLABORATOR_REMOVE), which
outrank the boundary-aware share labels, which outrank the residual
ACCESS_GRANT and ACCESS_REVOKE. It deliberately does NOT classify
authentication or credential lifecycle acts (password resets, MFA enrollment,
key rotation), nor any change to the resource itself, which belongs to
APH_ACT_DATA_MUTATION, nor severity, sensitivity, or routing, which are
separate families. RESIDUAL RULE, which closes a hole the precedence order
would otherwise carry: this family is open to overlays, an overlay may ADD a
label, and an added label sits nowhere in the order above — so a rule stated
only over the enumerated set is uncomputable for it, and the permissive
reading wins by default. Therefore any label not named in that order ranks at
the MOST-EXPOSING position for precedence, and a consumer that receives a
label it does not recognize MUST treat the act as widening reach rather than
narrowing it. Three boundary facts hold regardless of any label a later
overlay adds: an act extending reach past the organization's trust boundary is
a boundary-crossing share, an act minting possession-based access is a link
creation, and an act opening a resource to an unbounded audience is a
publication. No overlay-added label may claim a message carrying one of those
facts.

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
classifiers "APH_ACT_ACCESS" {
  description = "Classifies acts that change who can reach a resource, as distinct from acts that change the resource itself."
  labels {
    ACCESS_GRANT {
      description = "Confers a permission, role, or capability level on an identified principal for an identified resource, where the principal's position relative to the organization boundary is not the operative fact. This is the residual addition label: it applies only when no more specific label in this family does. If the act names a recipient audience whose internal or external status is determinable, SHARE_INTERNAL or SHARE_EXTERNAL takes precedence."
      examples    = ["Give Priya write permission on the billing dataset.",
                     "Grant the on-call engineer the incident-responder role until this is resolved.",
                     "Let the analytics service account read from the orders table."]
    }
    ACCESS_REVOKE {
      description = "Withdraws an existing permission, role, capability, or credential-borne access from an identified principal, key, or share link. This is the residual withdrawal label; disabling or expiring a previously issued shareable link belongs here, not under SHARE_LINK_CREATE. Removing someone from a persistent membership roster is COLLABORATOR_REMOVE, and closing a general audience without naming a principal is VISIBILITY_PRIVATE."
      examples    = ["Remove Jordan's admin rights on the production console immediately.",
                     "Turn off the share link we sent the vendor last quarter — it should stop working now.",
                     "Revoke that API key's access to the customer export endpoint."]
    }
    SHARE_EXTERNAL {
      description = "Extends reach over a resource to one or more recipients outside the organization's trust boundary — another company, a client, a contractor's own domain, a personal address. The boundary crossing is the operative fact. Takes precedence over ACCESS_GRANT; does not apply when the resource is opened to an unbounded or anonymous audience, which is VISIBILITY_PUBLIC."
      examples    = ["Share the design folder with the agency's team at brightpath.example so they can review it.",
                     "Give our outside counsel access to the diligence room.",
                     "Let the client's finance department into the shared invoice folder."]
    }
    SHARE_INTERNAL {
      description = "Extends reach over a resource to recipients inside the organization's trust boundary — a named colleague, team, department, or the whole company. Takes precedence over ACCESS_GRANT when the recipient audience is stated and demonstrably internal. Opening a resource to everyone including unauthenticated readers is VISIBILITY_PUBLIC, not this label, even when phrased as sharing with 'everyone'."
      examples    = ["Share the roadmap deck with the whole product org.",
                     "Open this analysis up to everyone on the sales team.",
                     "Let the other engineers on our team see the incident postmortem."]
    }
    VISIBILITY_PUBLIC {
      description = "Opens a resource to an unbounded audience, including principals with no prior relationship to the organization and, typically, unauthenticated readers. Publishing, listing, indexing, and 'anyone can view' settings land here. Takes precedence over the share labels, because the recipient set is not enumerable."
      examples    = ["Publish the changelog so anyone on the internet can read it without signing in.",
                     "Make the status page publicly visible.",
                     "Flip that knowledge base article to public so search engines can index it."]
    }
    VISIBILITY_PRIVATE {
      description = "Closes a resource's general audience so that reach is limited to explicitly granted principals — unpublishing, de-listing, or restricting from company-wide to named viewers. The act targets the audience setting rather than any one principal's permission; withdrawing an identified principal's access is ACCESS_REVOKE."
      examples    = ["Take the pricing page private again — only people we've explicitly invited should see it.",
                     "Lock this folder down so it is no longer visible to the whole company.",
                     "Unpublish the draft and restrict it to named viewers only."]
    }
    OWNERSHIP_TRANSFER {
      description = "Moves the owner, primary administrator, or controlling principal of a resource from one party to another, changing who may thereafter decide the resource's access. The prior owner may retain lesser access or none. Takes precedence over ACCESS_GRANT and ACCESS_REVOKE even though it implies both."
      examples    = ["Make Dana the owner of the marketing workspace; I'll step down to editor.",
                     "Hand the repository over to the platform team's service account.",
                     "Transfer this account's primary administrator to Luis before I leave."]
    }
    COLLABORATOR_ADD {
      description = "Adds a principal to a persistent membership roster — a project, workspace, team, channel, or group — thereby conferring the participation rights that membership carries. The target is the roster, not a per-resource permission; a permission granted directly on one resource is ACCESS_GRANT or a share label."
      examples    = ["Add Ravi to the Q3 launch project as a collaborator.",
                     "Put the new contractor on the design workspace roster.",
                     "Bring Chen into the incident channel's member list."]
    }
    COLLABORATOR_REMOVE {
      description = "Removes a principal from a persistent membership roster, ending the participation rights that membership carried. Takes precedence over ACCESS_REVOKE whenever the target is a roster rather than a specific permission, key, or link."
      examples    = ["Take Sam off the launch project — he has rotated to another team.",
                     "Remove the contractor from the workspace now that the engagement has ended.",
                     "Drop the former vendor's account from the project members."]
    }
    GRANT_EXTEND {
      description = "Pushes out the expiry of an access that already exists, without changing its scope, its permission level, or who holds it. Renewals of time-boxed grants and share links land here. If the act also widens scope, adds a permission, or names a new principal, it is ACCESS_GRANT instead. BOUNDARY against APH_ACT_AUTHORITY::EXTEND_SCOPE, which a reader will otherwise conflate: the object of THIS label is a RESOURCE GRANT's reach in time — extending someone's read window on a dataset confers no power to act on anyone's behalf. The object of EXTEND_SCOPE is the DELEGATION CHAIN, where lifetime is a dimension of authority, so pushing a mandate's expiry later widens who may act for whom and belongs to that family. The two are not the same act with the verb order flipped, and one message may legitimately produce a label from each family."
      examples    = ["Push the auditor's access out another two weeks — same permissions, just longer.",
                     "The vendor's link expires tomorrow; renew it through the end of the month.",
                     "Extend Maya's temporary admin window until the migration is done, nothing more."]
    }
    ACCESS_NARROW {
      description = "Reduces an existing access without ending it — a shorter expiry, a lower permission level, a smaller set of resources, or a tighter condition — so the resulting permission set is a strict subset of the prior one and the principal retains something. The inverse of GRANT_EXTEND, and the label a consumer needs to tell 'less' from 'none': withdrawing the access entirely is ACCESS_REVOKE, and any change that adds a permission or a principal while removing another is not this label, because a mixed change is not a narrowing."
      examples    = ["Drop the contractor from editor to viewer on that folder; keep the access.",
                     "Cut the auditor's window from ninety days to two weeks — same permissions.",
                     "Restrict that service account to the billing tables only, not the whole schema."]
    }
    SHARE_LINK_CREATE {
      description = "Mints a URL, token, or invite code that confers access to whoever possesses it, rather than to an identified principal. Possession-based access is the operative fact, so this label outranks every other in the family when a link or token is created — including when the link is described as internal-only or expiring. Disabling an existing link is ACCESS_REVOKE."
      examples    = ["Generate a view-only link to this report that I can paste into the email.",
                     "Create a link anyone who has it can use to upload their files to the intake folder.",
                     "Make me a shareable URL for the deck that expires in seven days."]
    }
    OUT_OF_SCOPE {
      description = "The act does not change who can reach a resource. Authentication and credential lifecycle acts, changes to the contents of a record, communications, approvals, and payments terminate here rather than being forced into an access label."
      examples    = ["Delete the customer's record from the CRM permanently.",
                     "Reset my password and turn two-factor authentication back on for my own login.",
                     "Approve the twelve thousand dollar purchase order for the new laptops."]
      oos         = true
    }
  }
  escalate t0_signals    >= 975
  escalate t1_embedding  >= 940
  escalate t3_local_llm  >= 910
  abstain      = "human"
  golden_set   = "eval/aph_act_access.golden.json"
  min_accuracy = 955
}
```
