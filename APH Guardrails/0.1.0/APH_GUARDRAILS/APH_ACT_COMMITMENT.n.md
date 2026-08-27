---
section: "APH Guardrails"
name: "APH Guardrails — Act Commitment"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Act Commitment

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

This family names the obligation state a message creates for the sending
principal, independent of what the obligation is about: bound, bound-if,
bound-in-part, not bound, or no longer bound. Its most important terminal is
RECEIPT_ACKNOWLEDGED_NO_COMMITMENT — systems routinely read 'got it' as 'yes'
and manufacture obligations the human never granted, so acknowledgement is a
first-class label rather than a near-miss of agreement. It deliberately does
NOT classify subject matter, monetary value, counterparty identity, or whether
the agent holds a mandate to bind its principal at all; authority lives in the
APH mandate layer and severity lives in its own family, and any act whose
object is a calendar slot belongs to APH_ACT_SCHEDULING. Because these acts
bind and are costly to unwind, the floors here sit above a routine family's,
unresolved cases go to a human instead of a default, and the ladder stops
below t4_cloud so binding language never leaves the local box.

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
classifiers "APH_ACT_COMMITMENT" {
  description = "Classifies whether and how a message binds the principal to a general obligation"
  labels {
    COMMITMENT_UNCONDITIONAL {
      description = "Binds the principal to the obligation exactly as presented, with no stated condition, carve-out, or future decision point. A counterparty may rely on this immediately."
      examples    = ["Yes, we'll do it — you have my commitment.",
                     "Agreed to the terms as written; consider it done.",
                     "I'm signing off on this, no strings attached."]
    }
    COMMITMENT_CONDITIONAL {
      description = "Binds the principal only if one or more explicitly stated conditions hold. The conditions are named in the message and remain unresolved at the time of sending; until they resolve, no obligation is owed."
      examples    = ["We'll commit, provided the budget clears by Friday.",
                     "Yes — as long as you can deliver the data by the 10th.",
                     "I agree, on the condition that the price stays at the quoted figure."]
    }
    COMMITMENT_PARTIAL {
      description = "Binds the principal to a proper subset of what was asked and explicitly leaves the remainder uncommitted. The accepted portion is firm; the excluded portion is neither promised nor refused outright unless separately stated."
      examples    = ["I can commit to the first two deliverables, but not the third.",
                     "We'll take the 500 units now; the remaining 200 I can't promise.",
                     "Agreed on the scope, but I'm not committing to that timeline."]
    }
    COMMITMENT_REFUSED {
      description = "Refuses to bind the principal and offers no alternative terms and no later decision point. The request is closed from the sender's side."
      examples    = ["No, we won't be moving forward on this.",
                     "I'm declining the request.",
                     "That's a no from us — please don't hold anything for me."]
    }
    COMMITMENT_COUNTER_OFFERED {
      description = "Refuses the obligation as presented and states different terms the principal will be bound by if the counterparty accepts them. The counter-terms are a live offer, which separates this from COMMITMENT_REFUSED and from COMMITMENT_PARTIAL, where the original terms are accepted in part."
      examples    = ["Not at that price, but we'd commit at $12 per unit.",
                     "I can't do the full scope; I'll commit to a six-week pilot instead if you'll take it.",
                     "Counter: same terms, but delivery on the 30th rather than the 15th."]
    }
    COMMITMENT_DEFERRED {
      description = "Declines to decide now and postpones the decision to a stated later time or event, without refusing and without asking anything of the counterparty. The principal is not bound and no answer is owed before the named point."
      examples    = ["I'm not deciding today — ask me again after the board meets on the 9th.",
                     "Let's park this until Q3 planning.",
                     "Hold off; I'll have an answer once the audit closes."]
    }
    COMMITMENT_CLARIFICATION_REQUESTED {
      description = "Withholds a decision pending answers to specific questions the sender puts to the counterparty. The principal is not bound, and the next move belongs to the counterparty — unlike COMMITMENT_DEFERRED, where the sender simply waits."
      examples    = ["Before I agree — does 'support' here include weekends?",
                     "I need to know who's liable for shipping damage before I can answer.",
                     "What exactly are we signing up for? Send the scope and I'll respond."]
    }
    COMMITMENT_WITHDRAWN {
      description = "Retracts a commitment the principal previously made, releasing the principal from an obligation that was in force. Applies only where a prior commitment exists; refusing a request that was never accepted is COMMITMENT_REFUSED."
      examples    = ["I have to pull back my earlier yes — we can no longer commit.",
                     "Retracting the agreement I gave last week.",
                     "Consider my previous commitment void as of today."]
    }
    COMMITMENT_CONFIRMED {
      description = "Declares that the conditions attached to an earlier conditional or provisional commitment are now satisfied, so the obligation is firm. This is a state change from not-yet-binding to binding."
      examples    = ["The financing came through, so our conditional yes is now firm.",
                     "Conditions are met — we're bound.",
                     "You delivered the data on time, so treat our agreement as confirmed."]
    }
    COMMITMENT_REAFFIRMED {
      description = "Restates an already-firm commitment as unchanged and still in force, typically in answer to a status check. Nothing about the obligation changes, which separates this from COMMITMENT_CONFIRMED, where a conditional commitment becomes binding."
      examples    = ["Still on — nothing has changed on our end.",
                     "Confirming again: the commitment I made last month stands as-is.",
                     "Yes, we're still good for the original terms."]
    }
    RECEIPT_ACKNOWLEDGED_NO_COMMITMENT {
      description = "Confirms that the message was received and possibly understood, and creates NO obligation of any kind. A counterparty must not treat this as agreement, as a conditional agreement, or as a promise to answer by any particular time. Any downstream system that infers commitment from this label is misreading the wire value."
      examples    = ["Got it, thanks — I'll read through it.",
                     "Received and noted. To be clear, that isn't an agreement, just confirming it landed.",
                     "Understood. I'm not saying yes or no yet."]
    }
    OUT_OF_SCOPE {
      description = "The message changes nothing about the principal's obligation state. Factual reports, questions unrelated to deciding, instructions to a tool, and acts belonging to other families — notably calendar acts owned by APH_ACT_SCHEDULING — land here. This classifier must never claim a commitment terminal for such a message."
      examples    = ["Tuesday at 2pm works for the call — I'm booking it.",
                     "Here's the invoice for last month, attached.",
                     "The build finished and all tests passed."]
      oos         = true
    }
  }
  escalate t0_signals    >= 970
  escalate t1_embedding  >= 920
  escalate t3_local_llm  >= 870
  abstain      = "human"
  golden_set   = "eval/aph_act_commitment.golden.json"
  min_accuracy = 960
}
```
