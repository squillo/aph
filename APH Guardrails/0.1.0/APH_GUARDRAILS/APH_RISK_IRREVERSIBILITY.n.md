---
section: "APH Guardrails"
name: "APH Guardrails — Risk Irreversibility"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Risk Irreversibility

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

This family answers exactly one question about an act an agent has taken or
proposes to take: what is the cheapest path that returns the world to its
prior state, and who must cooperate to walk it. It is deliberately orthogonal
to how harmful the act is, how many parties it touches, whether it was
authorized, and whether it should be allowed — those are separate families
(APH_RISK_BLAST_RADIUS and the guard families), and a label here must never be
shaded by them: a trivially harmless act can be irreversible and a
catastrophic act can be one click from undone. Labels form a strict ladder
from NO_STATE_CHANGE (nothing to undo) to IRREVERSIBLE_AND_DISCLOSED (the
state cannot be restored and third parties have already observed it); when
more than one rung could be argued, the classifier MUST return the rung
furthest down that ladder, because the correct answer is the hardest reversal
path actually required, not the easiest one imaginable. This family does NOT
classify natural-language requests, questions, or opinions — only acts with an
effect on the world; anything else is OUT_OF_SCOPE.

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
classifiers "APH_RISK_IRREVERSIBILITY" {
  description = "Classifies how an already-described act can be undone if it turns out to be wrong."
  labels {
    NO_STATE_CHANGE {
      description = "The act changed no durable state anywhere, so there is nothing to reverse. Reads, queries, dry runs, simulations, and analyses whose output was not persisted. If any durable side effect exists — an audit log entry that a counterparty relies on, a rate-limit counter that gates future behaviour, a lock or reservation — this label is wrong and the act belongs to the rung matching that side effect."
      examples    = ["I read the last four invoices to answer your question; I did not write anything.",
                     "Checked the calendar for open slots on Thursday — no holds were placed.",
                     "Ran the migration in dry-run mode and discarded the output."]
    }
    REVERSIBLE_BY_ACTOR {
      description = "The acting agent can restore the prior state unilaterally, at any time, using capabilities it already holds, with no deadline and no third party's cooperation. The restored state must be equivalent to the original for every party that can observe it. Use this only when the undo is genuinely unconditional; if the undo depends on acting soon, use REVERSIBLE_WITHIN_WINDOW."
      examples    = ["I saved the draft; I can delete it again whenever you like and nothing else changes.",
                     "Added the 'needs-review' label to the ticket — removing it restores the ticket exactly.",
                     "Turned the experimental flag off for this session; flipping it back returns the previous behaviour."]
    }
    REVERSIBLE_WITHIN_WINDOW {
      description = "The acting agent can restore the prior state unilaterally, but only before a deadline, a state transition, or a retention period expires. After that boundary the act becomes at least as hard to reverse as one of the lower rungs. Use this whenever an undo path exists but is time-boxed, even if the window is long."
      examples    = ["The email is sent, but I can still recall it for the next thirty seconds.",
                     "This order can be cancelled at no cost until it enters fulfilment at 6pm tonight.",
                     "I deleted the file — it sits in trash for thirty days, after which it is gone."]
    }
    REVERSIBLE_WITH_COUNTERPARTY_CONSENT {
      description = "The prior state can be restored, but only if a specific identified counterparty agrees or acts. The agent cannot compel the reversal; the counterparty may refuse, delay, or set conditions. Use this when the blocker is a party's consent rather than an internal administrative procedure."
      examples    = ["I can release the room booking, but only if the other attendee agrees to give up the slot.",
                     "Undoing this transfer means asking the recipient to send the money back voluntarily.",
                     "The agreement can be rescinded only if the vendor countersigns the rescission."]
    }
    REVERSIBLE_VIA_ADMIN_PROCESS {
      description = "The prior state can be restored only through an out-of-band administrative, operational, or legal procedure run by someone other than the agent — a support ticket, a privileged restore, a bank recall, a regulator filing. The path exists and is expected to succeed, but it is slow, costly, or requires elevated authority the agent does not hold."
      examples    = ["Restoring the deleted account needs a support ticket and roughly three business days.",
                     "Reversing this payment means our finance team initiating a bank recall.",
                     "That table can only be brought back by a DBA restoring last night's backup."]
    }
    IRREVERSIBLE {
      description = "No practical path exists to restore the prior state: the information, funds, credential, or opportunity is gone, or the act has been committed to a system that does not accept reversal. Use this when reversal is impossible or so implausible that no responsible actor would plan on it. It says nothing about whether the act was correct — only that the actor cannot take it back."
      examples    = ["The signing key has been rotated and the old private key was destroyed; it cannot be recovered.",
                     "The funds went to an external wallet — there is no recall path once it is confirmed.",
                     "I purged the customer record under the erasure request; there is no backup left to restore from."]
    }
    IRREVERSIBLE_AND_DISCLOSED {
      description = "The act is irreversible in the sense above AND information it carried has already been observed by parties outside the principal's control, so even a perfect restoration of system state does not undo the disclosure. Choose this over IRREVERSIBLE whenever third-party observation has already occurred or must be assumed; deleting the artifact afterwards does not move the act back up the ladder."
      examples    = ["I posted the unreleased quarterly numbers to the public channel — I deleted the post, but two hundred people had already read it.",
                     "The press release went out over the wire; retracting it does not un-send it to subscribers.",
                     "The API key was pasted into a public issue; rotating it does not undo it having been read."]
    }
    OUT_OF_SCOPE {
      description = "The input does not describe an act whose reversibility can be assessed, or it asks a different question entirely — how bad the act is, who is affected, whether it is permitted, or a request for the agent to produce content. Return this rather than guessing a rung; a wrong rung here is read by a stranger's agent as a licence to proceed."
      examples    = ["Can you make that summary a couple of sentences shorter?",
                     "How much money is at stake if this goes wrong?",
                     "Check whether this user is allowed to approve the request."]
      oos         = true
    }
  }
  escalate t0_signals    >= 975
  escalate t1_embedding  >= 945
  escalate t3_local_llm  >= 905
  abstain      = "human"
  golden_set   = "eval/aph_risk_irreversibility.golden.json"
  min_accuracy = 960
}
```
