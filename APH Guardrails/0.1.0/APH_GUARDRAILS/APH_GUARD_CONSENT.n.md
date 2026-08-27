---
section: "APH Guardrails"
name: "APH Guardrails — Guard Consent"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Guard Consent

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

APH_GUARD_CONSENT reports the PROVENANCE AND CURRENT STANDING of the human
consent behind an act — the semantic twin of APH's own PrincipalSigned versus
NotaryAttested split, where EXPLICIT_CONTEMPORANEOUS is the former and
EXPLICIT_PRIOR_MANDATE the latter. Because several defects can be true at
once, labels resolve most-defective-first: a formation defect beats withdrawn,
withdrawn beats expired, expired beats purpose mismatch, purpose beats scope,
scope beats wrong-grantor, wrong-grantor beats an unverified assertion, and
any defect beats every valid form —
so a doubly-flawed act always carries the worse label and the family stays
mutually exclusive. It deliberately does NOT decide whether the act is
permitted, whether the consent was legally sufficient in any jurisdiction, or
what remedy applies when consent is missing; it states the consent fact and
policy decides the rest. Sealed, fail_closed, local_only, abstain to a human:
consent evidence is personal data, and an unavailable classifier must never be
read as permission. PRECEDENCE, stated in full because this family is sealed
and the order cannot later be amended by overlay: formation defect > withdrawn
> expired > purpose mismatch > scope mismatch > third-party grantor >
asserted-but-unverified > every valid form. NO_CONSENT_CLAIMED sits outside
that chain and applies only where no consent of any kind was ever asserted — a
consent that existed and then lapsed, was spent, or was revoked takes the
corresponding defect label instead.

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
classifiers "APH_GUARD_CONSENT" {
  description = "Classifies what kind of human consent, if any, stands behind an act, and whether that consent is still good for it."
  sealed       = true
  fail_posture = "fail_closed"
  labels {
    CONSENT_FORMATION_DEFECTIVE {
      description = "A consent was given, but the circumstances of its GIVING are defective: it was obtained under coercion, duress, or threat; the grantor showed apparent incapacity; or the grantor is believed to be a minor. This concerns how the consent was FORMED, not what it covers or whether it still stands, and it takes precedence over every other label in this family including CONSENT_WITHDRAWN — a consent that was never freely given cannot be cured by still being in force. This label records facts about the consent event and is NOT a legal determination of validity in any jurisdiction."
      examples    = ["They only agreed after I told them I would go to their manager if they refused.",
                     "He signed it but he was clearly not tracking the conversation and asked me twice what year it was.",
                     "She said yes; she also mentioned she is fourteen and using her mother's account."]
    }
    EXPLICIT_CONTEMPORANEOUS {
      description = "The human explicitly authorized THIS act, close in time to it, with the act's material terms in front of them. The strongest form; the semantic twin of an APH PrincipalSigned claim. This label asserts a FREELY GIVEN authorization by a human with apparent capacity; where the consent event itself is defective, CONSENT_FORMATION_DEFECTIVE takes precedence."
      examples    = ["I asked and Jordan just said, yes, go ahead and cancel the reservation.",
                     "The user confirmed in this session with a plain 'send it' after I read back the recipient.",
                     "Holly approved this exact charge a moment ago when I quoted her the amount."]
    }
    EXPLICIT_PRIOR_MANDATE {
      description = "The human explicitly authorized this class of act IN ADVANCE by a standing mandate that is still in force and whose terms cover this act. Explicit but not contemporaneous; the twin of an act notarized under a pre-existing grant."
      examples    = ["Standing instruction from March: renew any subscription under fifty dollars without asking.",
                     "The principal signed off in advance on all routine payroll runs, and this is one of them.",
                     "Per the mandate on file, I'm authorized to accept meetings inside this calendar window."]
    }
    IMPLIED_FROM_CONTEXT {
      description = "No explicit authorization exists for this act or its class; consent is inferred from the human's instructions, the task they assigned, or an established course of dealing. Genuine inference only — a claim of explicit consent that lacks evidence is CONSENT_ASSERTED_UNVERIFIED."
      examples    = ["She asked me to plan the whole trip, so I'm treating the airport transfer as included.",
                     "Nobody said so outright, but they've had me pay this vendor every month for a year.",
                     "They forwarded me the thread and told me to handle it, so replying is implied."]
    }
    CONSENT_ASSERTED_UNVERIFIED {
      description = "Someone asserts that the human consented, but no evidence a verifier could independently check is offered — no signature, record, transcript, or resolvable attestation. The claim may well be true; this label says only that it is unbacked."
      examples    = ["The requesting agent says its user approved this, but there's nothing behind the claim.",
                     "I'm told consent was obtained; I have no record or signature to point at.",
                     "The counterparty says the customer agreed on a phone call we can't produce."]
    }
    SCOPE_MISMATCH {
      description = "Valid, live consent from the right human exists, but its TERMS do not reach this act — wrong action, wrong object, wrong counterparty, or beyond a stated limit. Concerns WHAT was authorized; a mismatch in WHY is PURPOSE_MISMATCH."
      examples    = ["He authorized me to book the flight, not to change the return date.",
                     "Her approval covered the Q1 budget line and this charge hits Q3.",
                     "The consent is current but it names three vendors and this isn't one of them."]
    }
    PURPOSE_MISMATCH {
      description = "Valid, live consent exists and the act would fall inside its literal terms, but the act serves a DIFFERENT purpose than the one for which consent was given — a secondary use. Concerns WHY the act is being taken."
      examples    = ["They gave me the address so we could ship the order, not so we could market to them.",
                     "Consent was for troubleshooting the account, not for training a model on the transcript.",
                     "She shared the document so I could summarize it, not so I could forward it to the vendor."]
    }
    CONSENT_WITHDRAWN {
      description = "Consent covering this act existed and the human AFFIRMATIVELY revoked it before the act. Takes precedence over every other label except CONSENT_FORMATION_DEFECTIVE — expiry and any scope or purpose defect yield to withdrawal, but a consent that was never freely given outranks even its own revocation."
      examples    = ["He told me yesterday to stop acting on this, so the earlier approval is off.",
                     "The user revoked their authorization before I reached this step.",
                     "She said never mind, don't send it, after she had already approved it."]
    }
    CONSENT_EXPIRED {
      description = "Consent covering this act existed and lapsed by its own terms — a time window closed, a single-use authorization was already spent, or a condition it depended on ended — with no affirmative withdrawal by the human."
      examples    = ["The approval was good for twenty-four hours and that window has closed.",
                     "That was a one-time authorization and it was already used on the previous order.",
                     "The standing mandate lapsed at the end of the fiscal year and was never renewed."]
    }
    CONSENT_FROM_THIRD_PARTY {
      description = "Consent was given by someone other than the principal whose data, money, or authority this act touches — a manager, a family member, an administrator, or another agent. The consent may be real and even sufficient under policy, but it did not come from the affected human."
      examples    = ["Her manager approved it; the account holder herself hasn't been asked.",
                     "The spouse on the call said go ahead, but the policy is in Marco's name.",
                     "Another agent authorized this, not the human whose records it changes."]
    }
    NO_CONSENT_CLAIMED {
      description = "No human consent of any kind is asserted for this act — not explicit, not standing, not implied, not even an unbacked claim. The act stands on the agent's own judgment or on non-consent authority."
      examples    = ["Nobody has approved this; I'm proceeding on my own judgment.",
                     "There's no human in the loop on this action at all.",
                     "I have no authorization to point to for sending this."]
    }
    OUT_OF_SCOPE {
      description = "The input is not an act whose consent provenance can be assessed — legal questions about consent, drafting or discussion of consent language, product or policy talk, or any content where no act is being taken on a human's behalf. This family reports the consent behind an ACT; absence of an act belongs here, not in NO_CONSENT_CLAIMED."
      examples    = ["Does GDPR require a lawful basis for this kind of processing?",
                     "Draft a consent form for the clinical study intake packet.",
                     "Explain the difference between opt-in and opt-out in plain language."]
      oos         = true
    }
  }
  escalate t0_signals    >= 985
  escalate t1_embedding  >= 960
  escalate t3_local_llm  >= 930
  abstain      = "human"
  golden_set   = "eval/aph_guard_consent.golden.json"
  min_accuracy = 970
}
```
