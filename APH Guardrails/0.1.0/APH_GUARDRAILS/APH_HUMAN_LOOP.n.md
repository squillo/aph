---
section: "APH Guardrails"
name: "APH Guardrails — Human Loop"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Human Loop

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

APH_HUMAN_LOOP is the routing terminal of the taxonomy: the other families
describe what an act IS, and this one alone says how much human involvement it
takes before an agent may proceed. Its labels run from AUTONOMOUS to REFUSE,
but they are NOT a total order and MUST NOT be composed by taking a maximum —
see COMPOSITION below for the rule. The family is sealed and
fail-closed because it grants capability: an unavailable, degraded, or
unclassifiable answer must withhold the act and reach a human, never default
to autonomy. It deliberately does NOT judge how urgent, severe, or reversible
an act is, and it does not name WHICH human — identity and delegation live in
the APH claim itself, not in this vocabulary. COMPOSITION: these labels are
NOT a total order and MUST NOT be composed by taking a maximum. Two
axes are orthogonal to the approval ladder and are dropped by any max-rule.
SUPERVISED_EXECUTION is a DURING-the-act requirement, not a weaker form of the
BEFORE-the-act approval rungs; an act needing both prior sign-off and a human
watching it run requires BOTH, and a max would silently discard the
supervision. ROLE_APPROVAL_REQUIRED and DUAL_APPROVAL_REQUIRED constrain WHO
approves, not HOW MUCH approval, and likewise survive alongside a higher rung.
This family therefore reports the SINGLE STRONGEST GATE it can name; a
consumer combining it with other signals MUST take the UNION of requirements,
never the maximum of rungs.

## Extension

**This family is sealed.** Every overlay against it is refused in full — not
clamped, not partially applied. Sealing is not a direction restriction: an
overlay that only tightens is refused too, because these definitions are not
negotiable by the parties relying on them. Elsewhere in this vocabulary the
worst a contributor can do is make a family stricter, but here even ADDING a
label would open a gap, since a new label is a new bucket an act can be sorted
into, and any bucket that is not a refusal bucket is a permission.

The only way this family changes is a new base version, which a verifier can
see and choose to accept.

*Honest scope: the seal is authored intent. Whether it is enforced is a
property of the consuming runtime's fold, not of these bytes — verify your own
engine refuses overlays against sealed specs rather than assuming the
declaration enforces itself.*

## Classifier

```nlang
classifiers "APH_HUMAN_LOOP" {
  description = "The minimum degree of human involvement required before an agent may carry out the proposed act"
  sealed       = true
  fail_posture = "fail_closed"
  labels {
    AUTONOMOUS {
      description = "The agent may carry out the act with no human involvement before, during, or after it. Reserved for acts that are routine, reversible, low blast radius, and already covered by the agent's standing delegation."
      examples    = ["Go ahead and file that receipt against my travel expense report.",
                     "Pull the latest sales numbers into the weekly dashboard.",
                     "Archive the threads I have already replied to."]
    }
    NOTIFY_AFTER {
      description = "The agent may act immediately without waiting, but a durable notice to the principal is part of the act and must be delivered afterwards. If the notification channel is unavailable, the act is not complete; it does not become AUTONOMOUS."
      examples    = ["Reschedule my Thursday one-on-one and let me know where it lands.",
                     "Reply to the vendor accepting the standard renewal terms, then drop me a note.",
                     "Order a replacement laptop charger and tell me afterwards what it cost."]
    }
    ACKNOWLEDGE_BEFORE {
      description = "A human must see the proposed act and acknowledge it before the agent proceeds, but is not being asked to evaluate or accept responsibility for it — a tap-through, not a judgement. Any human authenticated on the principal's side satisfies this rung; silence does not."
      examples    = ["Send the draft to the client once I have had a chance to glance at it.",
                     "Post the status update, but ping me first so I know it is going out.",
                     "Cancel the Friday session — just wait for my thumbs up before you do it."]
    }
    SUPERVISED_EXECUTION {
      description = "Prior consent is not sufficient: a human must be attached for the duration of the act, watching it run and able to halt it partway. Chosen when the act unfolds over time and harm accrues mid-flight, rather than at a single commit point. ORTHOGONAL: this requirement is not superseded by any approval rung. If an act needs both prior approval and live supervision, both hold."
      examples    = ["Run the data migration while I watch, so I can stop it if it goes sideways.",
                     "Start the customer call but stay on the line with me the whole time.",
                     "Begin clearing the duplicate records with me on screen."]
    }
    APPROVAL_REQUIRED {
      description = "The agent must obtain an explicit, act-specific approval from the principal or a delegate already authorised for this kind of act, and must not proceed without it. The approval must name the act as it will actually be performed; a general prior instruction does not satisfy this rung."
      examples    = ["Sign the NDA on my behalf once I have approved the final text.",
                     "Pay this invoice, but only after I confirm the amount.",
                     "Do not send anything to the regulator until I explicitly say yes."]
    }
    ROLE_APPROVAL_REQUIRED {
      description = "Approval must come from a human holding a specific authorised role or licence — controller, clinician, counsel, officer — and approval from the principal alone is not sufficient. This vocabulary names that a role gate exists; which role, and how it is proven, is carried by the surrounding claim. ORTHOGONAL: this constrains WHO may approve and survives alongside any higher rung; it is not discharged by escalation."
      examples    = ["This refund is above my limit, it needs the finance controller to approve it.",
                     "Publishing the clinical summary requires sign off from the supervising physician.",
                     "Legal has to clear this contract language before it goes anywhere."]
    }
    DUAL_APPROVAL_REQUIRED {
      description = "Two distinct humans must each approve the act, and neither may be the requester; one person holding two roles does not satisfy it. Used where the control being enforced is separation of duties rather than expertise. ORTHOGONAL: this constrains WHO may approve and survives alongside any higher rung; it is not discharged by escalation."
      examples    = ["Any wire over fifty thousand needs two of us to sign off on it.",
                     "Dropping a production database takes a second engineer co-signing.",
                     "Changing the payroll bank details requires two separate approvers."]
    }
    ESCALATE_TO_PRINCIPAL {
      description = "The agent must not act and must not seek approval through the requesting channel; it hands the decision back to the human it acts for, taking no position on the merits. Chosen when the act may be perfectly legitimate but sits outside the agent's delegation, or when the request itself looks wrong enough that the counterparty should not be the one to resolve it."
      examples    = ["I am not the right one to decide this — I am taking it back to my principal.",
                     "This is outside what I have been delegated, so I am handing it to the account holder.",
                     "Something about this request does not line up; I am stopping and asking the person I work for."]
    }
    REFUSE {
      description = "The agent must decline and must not route the act to anyone for approval, because no approval available through this path could authorise it — unlawful acts, acts that defeat the agent's own accountability, or acts outside the agent's declared capability. Distinct from ESCALATE_TO_PRINCIPAL, where a human legitimately may still decide."
      examples    = ["I will not move funds to an account that changed partway through this thread.",
                     "No — I am not going to disable the audit log.",
                     "I cannot help you pose as the account holder to their bank."]
    }
    OUT_OF_SCOPE {
      description = "No proposed act is present to route — narration, transcript fragments, notes, or text not addressed to the agent as a request. Consumers must never read this as permission to proceed: with fail_closed and a human abstain, the absence of a routing answer withholds the capability rather than granting it."
      examples    = ["Meeting notes: attendees were Dana, Priya, and Mo.",
                     "Just so you know, the shipment landed yesterday afternoon.",
                     "Sorry, ignore that — I was talking to someone else in the room."]
      oos         = true
    }
  }
  escalate t0_signals    >= 985
  escalate t1_embedding  >= 950
  escalate t3_local_llm  >= 900
  abstain      = "human"
  golden_set   = "eval/aph_human_loop.golden.json"
  min_accuracy = 960
}
```
