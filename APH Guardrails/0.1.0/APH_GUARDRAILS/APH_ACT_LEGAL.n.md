---
section: "APH Guardrails"
name: "APH Guardrails — Act Legal"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Act Legal

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

APH_ACT_LEGAL names what an agent is DOING when the operative effect of its
message is a change in legal rights, obligations, permissions, or positions —
accepting or proposing terms, executing a confidentiality agreement, giving
notice, terminating, waiving, asserting or answering a claim, licensing,
accepting liability, or making a representation. The boundary is operative
effect, not vocabulary: summarizing law, requesting a document, or reasoning
about a contract changes nothing and is OUT_OF_SCOPE. It deliberately does not
classify acts whose operative effect is that money moves, is committed, or is
priced — those belong to APH_ACT_FINANCIAL and must return OUT_OF_SCOPE here,
so that the two families remain disjoint over one message. It also carries no
view on severity, jurisdiction, enforceability, or whether the sender was
actually authorized to bind anyone; those are separate determinations and
separate families. PRIVACY POSTURE, stated because it is a deliberate
constraint rather than an oversight: this family classifies regulated and
adversarial text, so its base is local_only with no cloud rung. The lattice
makes that the safe default direction — an overlay may restrict locality but
never relax it, and may remove a rung but never add one, so any future cloud
evaluation requires a NEW BASE VERSION that a verifier can see and refuse,
rather than arriving silently through inheritance.

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
classifiers "APH_ACT_LEGAL" {
  description = "Which non-financial legal act an agent is performing on behalf of its principal when rights or obligations change"
  labels {
    CONTRACT_TERMS_ACCEPT {
      description = "The sender assents to terms that the counterparty has put forward, intending to be bound by them as written. The terms originated on the other side; this act closes on them rather than altering them."
      examples    = ["We accept the master services agreement as drafted — treat this as our acceptance.",
                     "Agreed to your terms in version 4; no further changes from our side.",
                     "Consider it signed on our end. We're bound by clauses 1 through 19."]
    }
    CONTRACT_TERMS_PROPOSE {
      description = "The sender puts forward terms, redlines, or a counter-offer for the counterparty to consider. Nothing binds yet; the act moves the negotiation, and any counter-proposal — however small the edit — belongs here rather than under acceptance."
      examples    = ["Here's our redline: liability capped at twelve months of fees, plus a 30-day cure period.",
                     "Proposing a two-year term with mutual termination for convenience.",
                     "Counter-offer — same terms, but governing law moves to New York."]
    }
    NDA_EXECUTE {
      description = "The sender enters into a confidentiality or non-disclosure agreement, signing or countersigning so that confidentiality obligations take effect. It is separated from general contract acceptance because it is the single most commonly automated binding instrument and needs its own wire value."
      examples    = ["The mutual NDA is executed on our side — countersigned and dated today.",
                     "We're entering into the confidentiality agreement so we can share the roadmap.",
                     "Signing your non-disclosure agreement now; the three-year confidentiality period starts today."]
    }
    FORMAL_NOTICE_GIVE {
      description = "The sender delivers a notice that a contract or law provides for: notice of breach, of non-renewal, of intent, of a change in a notifiable fact, or any communication meant to start a clock or satisfy a notice requirement. The act is the delivery of notice itself; if it also ends the agreement outright, use AGREEMENT_TERMINATE."
      examples    = ["This is formal notice of breach under clause 14.2 — you have 30 days to cure.",
                     "Serving notice that we will not renew when the current term expires.",
                     "Please treat this message as our contractual notice of the change of registered address."]
    }
    AGREEMENT_TERMINATE {
      description = "The sender ends an existing agreement or relationship, for cause or for convenience, effective immediately or on a stated date. The operative effect is that the agreement stops; it is distinct from giving notice about a future termination only when the notice does not itself terminate."
      examples    = ["We are terminating the reseller agreement effective 31 October.",
                     "Consider the partnership contract ended as of today under the termination-for-cause clause.",
                     "We're exiting the agreement; obligations end once the notice period runs out."]
    }
    RIGHT_WAIVE {
      description = "The sender gives up, releases, or declines to enforce a right, remedy, protection, or defence that it holds. The effect runs against the sender's own position and is typically hard to reverse, which is why it is named separately from any concession made while proposing terms."
      examples    = ["We waive our right to arbitration on this matter.",
                     "We won't enforce the exclusivity clause for this deal — treat it as waived.",
                     "Our claim to the late-delivery remedy is released; we're not pursuing it."]
    }
    CLAIM_ASSERT {
      description = "The sender asserts a legal claim, demand, or allegation against the counterparty — breach, infringement, negligence, or entitlement to a remedy. It is the opening of an adversarial position, whether or not a forum or amount is named."
      examples    = ["We assert that your use of our trademark infringes our rights and demand you stop.",
                     "We are formally claiming under the SLA for the outage on 14 July.",
                     "You are in breach of clause 9 and we hold you responsible for the resulting harm."]
    }
    CLAIM_RESPOND {
      description = "The sender answers a claim or allegation that has been made against it — admitting, denying, defending, or stating its position. The claim originated with the counterparty; a wholesale admission of fault is LIABILITY_ACCEPT rather than a response."
      examples    = ["We deny the allegations in your letter and will defend the claim.",
                     "We admit the delay occurred but dispute that it caused the harm you describe.",
                     "Responding to your infringement claim: our position is that the existing licence covers this use."]
    }
    LICENCE_GRANT {
      description = "The sender grants permission to use property, intellectual property, data, or a mark that it controls, on stated or implied terms. The permission flows outward from the sender; obtaining or accepting someone else's licence terms is CONTRACT_TERMS_ACCEPT."
      examples    = ["You're granted a non-exclusive licence to use the dataset for internal research.",
                     "We permit you to reproduce the figures in your publication with attribution.",
                     "Consider this our authorization to use the logo in launch materials for six months."]
    }
    LIABILITY_ACCEPT {
      description = "The sender accepts fault, responsibility, or liability for an act, omission, or harm. It concedes the question of responsibility itself, which is why it is separated from CLAIM_RESPOND; any accompanying agreement to pay a sum is a distinct financial act classified by APH_ACT_FINANCIAL."
      examples    = ["We accept responsibility for the data loss and its consequences.",
                     "That was our error — we take liability for what followed.",
                     "We acknowledge fault for the missed deadline and will not contest it."]
    }
    REPRESENTATION_MAKE {
      description = "The sender makes a formal representation or warranty: an assertion of fact or of future conformity that the counterparty is invited to rely on and that carries consequences if untrue. Ordinary factual statements not offered as a basis for reliance do not belong here."
      examples    = ["We represent and warrant that the software contains no third-party code under a copyleft licence.",
                     "Confirming formally that our company is in good standing and holds all required permits.",
                     "We warrant the deliverables will conform to the specification for ninety days after acceptance."]
    }
    OUT_OF_SCOPE {
      description = "The message performs no legal act of this family. Explaining the law, asking for a document, summarizing a contract, or expressing an intention to seek advice lands here, as does any act whose operative effect is monetary — payments, refunds, invoices, quotes, and pricing belong to APH_ACT_FINANCIAL. This is the terminal for 'legal language is present but no right or obligation moves'."
      examples    = ["Authorize the 12,400 EUR wire so the settlement clears this week.",
                     "Here's a short summary of what an NDA usually covers.",
                     "Could you send me the current version of the contract to read?"]
      oos         = true
    }
  }
  escalate t0_signals    >= 980
  escalate t1_embedding  >= 960
  escalate t3_local_llm  >= 940
  abstain      = "human"
  golden_set   = "eval/aph_act_legal.golden.json"
  min_accuracy = 960
}
```
