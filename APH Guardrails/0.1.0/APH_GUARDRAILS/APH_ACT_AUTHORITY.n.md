---
section: "APH Guardrails"
name: "APH Guardrails — Act Authority"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Act Authority

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

APH_ACT_AUTHORITY classifies acts that mutate the delegation graph itself —
who may act for whom, under what bounds — as opposed to any ordinary act
performed under an authority that already exists. The load-bearing boundary is
the DIRECTION of change to an existing grant: NARROW_SCOPE applies only when
the resulting permission set is a strict subset of the prior one, EXTEND_SCOPE
applies whenever any act, limit, or expiry widens, and a change that both
removes and adds is ALWAYS EXTEND_SCOPE, so the classifier can never under-
report a widening. It deliberately does NOT classify the underlying business
act (a payment, a booking, a record edit), the severity or urgency of an
authority change, or who should approve it — those are separate families. The
family is sealed and abstains to a human: an authority claim the ladder cannot
resolve must reach a person, never a default grant.

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
classifiers "APH_ACT_AUTHORITY" {
  description = "Classifies acts that change the delegation chain itself — who may act for whom, and within what bounds."
  sealed       = true
  fail_posture = "fail_closed"
  labels {
    DELEGATE_AUTHORITY {
      description = "A principal, or a party holding authority in its own right, creates a NEW delegation granting another party power to act on its behalf. There is no prior grant to the grantee for this scope; the chain gains a first link."
      examples    = ["I'm authorizing Dana's assistant agent to book travel for me through the end of the quarter.",
                     "Grant the vendor's procurement agent permission to sign purchase orders under five thousand dollars on my behalf.",
                     "You now have my authority to answer support tickets in the billing queue."]
    }
    SUB_DELEGATE_AUTHORITY {
      description = "An existing delegate passes some or all of the authority it already holds onward to a further party, lengthening the chain. The sub-delegating party RETAINS its own grant; if it does not, the act is TRANSFER_DELEGATION."
      examples    = ["I'm passing my calendar-booking authority down to the scheduling agent so it can handle this directly.",
                     "Since I hold approval rights from Priya, I'm handing a subset of them to the finance bot for this invoice run.",
                     "Appointing a downstream agent under my existing mandate to complete the onboarding steps."]
    }
    REQUEST_AUTHORITY {
      description = "A party asks to be granted authority it does not currently hold. This is a solicitation, not a grant and not an acceptance — nothing changes in the chain until the holder responds."
      examples    = ["I don't currently have permission to issue refunds — can you delegate that to me?",
                     "Requesting authority from the principal to sign the NDA on their behalf.",
                     "Please add me as an authorized agent on the shipping account so I can proceed."]
    }
    ACCEPT_DELEGATION {
      description = "The offered grantee affirmatively takes up a delegation that has been extended to it, bringing the grant into force on its side. Requires a pending offer; a grantee that solicited the grant is REQUEST_AUTHORITY until it accepts."
      examples    = ["Accepted — I'll act as your agent for the lease negotiation.",
                     "I acknowledge and take up the mandate to manage the ad budget.",
                     "Confirming receipt of the delegation; I am now operating under it."]
    }
    DECLINE_DELEGATION {
      description = "The offered grantee refuses to take up a delegation extended to it, so the grant never comes into force. Distinct from REVOKE_DELEGATION, which ends a delegation that was already live."
      examples    = ["I'm not taking on the authority to move funds; please assign it elsewhere.",
                     "Declining the delegation — this is outside what I'm willing to act on.",
                     "Thanks, but I won't be accepting agent status for this account."]
    }
    REVOKE_DELEGATION {
      description = "An existing, in-force delegation is withdrawn so that it grants nothing going forward. Applies whether the revoker is the original grantor or an upstream holder cutting a sub-delegation; a reduction that leaves any authority standing is NARROW_SCOPE, not revocation."
      examples    = ["Effective now, the assistant agent no longer has authority to send email as me.",
                     "Revoke Kim's agent from acting on the contract.",
                     "I'm terminating the mandate I gave you last month."]
    }
    TRANSFER_DELEGATION {
      description = "An existing delegation is moved from its current holder to a different holder by substitution — the new holder gains it and the original holder ceases to hold it. The chain's length is unchanged, which is what separates transfer from SUB_DELEGATE_AUTHORITY."
      examples    = ["Hand my agent authority on this account over to the new account manager's agent; I'm stepping out.",
                     "Reassign the existing delegation from the outgoing agent to its replacement.",
                     "The mandate should sit with Priya's agent from now on instead of mine."]
    }
    NARROW_SCOPE {
      description = "The bounds of an existing delegation are tightened such that the resulting permission set is a STRICT SUBSET of the prior one — fewer permitted acts, lower limits, fewer objects, or an EARLIER expiry. No act that was previously forbidden becomes permitted. If any dimension widens, the act is EXTEND_SCOPE even if other dimensions tighten."
      examples    = ["Going forward my agent may only book flights under eight hundred dollars — no hotels.",
                     "Restrict the existing delegation to read-only access on the CRM.",
                     "Shorten the mandate so it ends this Friday instead of at year-end."]
    }
    EXTEND_SCOPE {
      description = "The bounds of an existing delegation are widened — at least one newly permitted act, a raised limit, an added object, or a LATER expiry — so the resulting permission set is not a subset of the prior one. A mixed change that both adds and removes is always EXTEND_SCOPE. Note that 'extend' meaning 'hand out to someone' is DELEGATE_AUTHORITY, not this label. BOUNDARY against APH_ACT_ACCESS::GRANT_EXTEND, which a reader will otherwise conflate: the object of THIS label is the DELEGATION CHAIN — who may act for whom — and lifetime is one of its dimensions, so pushing a mandate's expiry later widens authority and lands here. The object of GRANT_EXTEND is a RESOURCE GRANT's reach: extending someone's read window on a dataset confers no power to act on anyone's behalf and belongs to that family, not this one. The two are not synonyms with the verb order flipped; they name changes to different things, and a message may legitimately produce one from each family."
      examples    = ["Add hotel booking to what my agent is already allowed to do.",
                     "Raise the spending cap on the existing delegation from five hundred to two thousand.",
                     "Push my agent's mandate out to the end of next quarter — same permitted acts, longer authority to perform them."]
    }
    ESCALATE_TO_PRINCIPAL {
      description = "The agent declines to exercise authority for this matter and refers the decision upward to its human principal or the delegation's grantor. The chain is unchanged; what moves is the decision, not the authority. NAME COLLISION, stated because both families are sealed and neither spelling can be changed: APH_HUMAN_LOOP also carries a label spelled ESCALATE_TO_PRINCIPAL, and the two sit on different axes. This one is DESCRIPTIVE — an act the agent HAS ALREADY PERFORMED, reported into the record, complete at the moment it is emitted. The routing family's is PRESCRIPTIVE — a requirement about HOW MUCH HUMAN INVOLVEMENT an act needs before it may proceed, outstanding until a human discharges it. A consumer that logs, routes, or matches on the bare string without its family qualifier will read a finished referral as an unmet obligation, or the reverse; always resolve the label family-qualified."
      examples    = ["This exceeds what I'm authorized to decide — sending it to Marcus for a human call.",
                     "I'm handing this back to my principal rather than acting on it myself.",
                     "Kicking this up to the account owner before anything gets signed."]
    }
    ASSERT_AGENCY {
      description = "A claim of currently acting on behalf of a named principal, made to establish standing to a counterparty. Nothing in the chain is created, changed, or ended — this is an assertion ABOUT an existing delegation."
      examples    = ["I'm writing on behalf of Dr. Alvarez, who has authorized me to handle her scheduling.",
                     "Acting as the authorized agent for Northwind Logistics in this thread.",
                     "For the record, I represent the buyer and have standing to negotiate these terms."]
    }
    OUT_OF_SCOPE {
      description = "The act neither changes nor asserts a delegation. Ordinary acts performed UNDER an existing authority land here — doing the work a delegation already permits is not an act ON the chain. Any claim of acting on another's behalf is ASSERT_AGENCY and never lands here, however incidentally it is phrased: an unverified agency claim is precisely what a verifier needs surfaced so it can go and check the chain. This is the expected majority outcome on live traffic."
      examples    = ["Approve the vendor invoice for twelve hundred dollars.",
                     "What time does the delegation review meeting start?",
                     "Reset the customer's password and email them the link."]
      oos         = true
    }
  }
  escalate t0_signals    >= 970
  escalate t1_embedding  >= 940
  escalate t3_local_llm  >= 900
  abstain      = "human"
  golden_set   = "eval/aph_act_authority.golden.json"
  min_accuracy = 950
}
```
