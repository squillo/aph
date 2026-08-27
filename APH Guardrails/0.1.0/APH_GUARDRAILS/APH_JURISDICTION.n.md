---
section: "APH Guardrails"
name: "APH Guardrails — Jurisdiction"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Jurisdiction

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

This family flags which regulatory regime PLAUSIBLY ATTACHES to an act and
therefore warrants review by a qualified human. No label here is a legal
determination: not of applicability, not of controller, processor, or covered-
entity status, not of lawfulness, and not of breach — an implementer must
never render or display a label as legal advice, and a counterparty agent must
not treat one as a finding. It classifies the regime only; the category of
information at stake belongs to APH_GUARD_DISCLOSURE. Single-label under most-
specific-trigger-wins precedence: name the one regime whose trigger is most
concrete on the face of the act, prefer US_CCPA_CPRA over US_STATE_PRIVACY
when California is specifically implicated, use CROSS_BORDER_TRANSFER when
movement of data across a border is itself the trigger rather than incidental,
and route any regime this family does not enumerate — or any act whose content
cannot be read — to OUT_OF_SCOPE. It is left unsealed so that later overlays
can add regimes as they emerge, since overlays may add labels but may never
widen a floor or relax posture. It stays local_only and its ladder stops below
t4_cloud, because the act text being classified is frequently the very
material these regimes govern.

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
classifiers "APH_JURISDICTION" {
  description = "Which regulatory regime plausibly attaches to this act and warrants review"
  labels {
    NO_REGIME_IDENTIFIED {
      description = "Nothing on the face of the act triggers any regulatory regime enumerated by this family: no personal or health data, no payment or financial activity, no controlled technology, no privileged material, no cross-border movement. This label reports the absence of a visible trigger only. It is not an opinion that the act is lawful, unregulated, or safe, and must never be presented as clearance."
      examples    = ["Move tomorrow's internal standup from nine to ten.",
                     "Draft a short blog post introducing our new office mascot.",
                     "Order another case of coffee for the kitchen and expense it to the team budget."]
    }
    EU_GDPR {
      description = "The act plausibly involves personal data of people in the EU or EEA, or processing by an establishment there, such that review under the EU General Data Protection Regulation is warranted. Flagging this label says a GDPR question is present; it does not decide territorial scope, controllership, lawful basis, or whether any obligation has been met or missed."
      examples    = ["Export the customer list for our Berlin users and hand it to the marketing agency.",
                     "She's invoking her right to erasure under EU rules — delete everything we hold on her.",
                     "Set up the newsletter sync for our France and Netherlands subscribers."]
    }
    UK_GDPR {
      description = "The act plausibly involves personal data of people in the United Kingdom, or processing by a UK establishment, warranting review under the UK GDPR and Data Protection Act 2018. Kept distinct from EU_GDPR because the regimes diverge and are supervised separately. Where an act spans both and the movement between them is the point, use CROSS_BORDER_TRANSFER; otherwise pick the jurisdiction of the data subjects principally affected. It is not a determination of scope or compliance."
      examples    = ["Share the London office's HR records with the new payroll vendor.",
                     "A customer in Leeds is asking for a copy of everything we hold about him.",
                     "Run the retention purge across our Manchester and Glasgow subscriber tables."]
    }
    US_HIPAA {
      description = "The act plausibly involves protected health information in the hands of a covered entity or business associate, warranting review under HIPAA and the HITECH Act. Flagging this does not decide whether the actor is in fact a covered entity or business associate, whether an authorization or exception applies, or whether a disclosure would be permitted."
      examples    = ["Send the patient's discharge summary over to the referring clinic's agent.",
                     "Upload the claims file with the diagnosis codes to our billing partner.",
                     "Tell the family what the doctor found at today's visit and what happens next."]
    }
    US_STATE_PRIVACY {
      description = "A United States state privacy or biometric statute other than California's plausibly attaches — for example Virginia's CDPA, Colorado's CPA, Texas's TDPSA, Washington's My Health My Data Act, or Illinois's BIPA — or a US state consumer-privacy trigger is present but the specific state is not identified in the act. When California is specifically implicated, use US_CCPA_CPRA instead. Not a determination of applicability, thresholds, or exemptions."
      examples    = ["Honor this Colorado resident's request to opt out of targeted advertising.",
                     "We're enrolling fingerprints at the Illinois warehouse — stand up the capture flow.",
                     "Process the deletion request that came in from a customer in Virginia."]
    }
    US_CCPA_CPRA {
      description = "California is specifically implicated — California residents' personal information, sale or sharing for cross-context behavioral advertising, opt-out and limit-use rights, or sensitive personal information as defined by the CPRA — warranting review under the CCPA as amended. Takes precedence over US_STATE_PRIVACY whenever California is identified. Not a determination of business status, thresholds, exemptions, or compliance."
      examples    = ["This California customer clicked Do Not Sell or Share My Personal Information — apply it everywhere.",
                     "Send our CA subscriber list to the ad network to build a lookalike audience.",
                     "Respond to the right-to-know request from a resident of San Diego."]
    }
    PCI_DSS {
      description = "The act plausibly involves storing, processing, or transmitting cardholder data, or touching the cardholder data environment, warranting review under the PCI Data Security Standard and the card brands' rules. Flagging this does not decide merchant level, scope boundaries, compensating controls, or whether any requirement is satisfied."
      examples    = ["Store the full card number in a CRM note so we can rebill this customer later.",
                     "Route checkout through the new vendor — they'll be handling the raw card numbers.",
                     "Email the customer's card details over to the support queue so someone can finish the order."]
    }
    US_SOX {
      description = "The act plausibly bears on the integrity of financial reporting or internal control over financial reporting at a US public issuer — books and records, journal entries, the close process, revenue recognition, audit evidence, or segregation of duties — warranting review under the Sarbanes-Oxley Act. Distinct from PCI_DSS and from FINANCIAL_SERVICES_REGULATION. It is not a determination that a control was circumvented or that any provision applies."
      examples    = ["Post this adjusting entry to close the quarter before the auditors start their fieldwork.",
                     "Change the revenue recognition schedule on the contract that's already signed.",
                     "Grant yourself approval rights on the journal entry workflow so you can push it through."]
    }
    FINANCIAL_SERVICES_REGULATION {
      description = "The act plausibly falls under regulation of banking, securities, insurance, lending, payments, or market conduct — including GLBA, SEC and FINRA rules, MiFID, consumer financial protection rules, and anti-money-laundering, know-your-customer, and sanctions-screening obligations. Use this rather than US_SOX for conduct and customer-facing obligations, and rather than PCI_DSS when the concern is not cardholder data."
      examples    = ["Open the brokerage account now and run the KYC checks afterwards.",
                     "Send this client a recommendation to buy the position we're currently unloading.",
                     "Wire the funds through and skip the sanctions screening just this once."]
    }
    EXPORT_CONTROL {
      description = "The act plausibly involves controlled technology, technical data, encryption, defense articles, or dual-use goods, or a transfer to a restricted party, national, or sanctioned jurisdiction — warranting review under regimes such as the EAR, ITAR, EU dual-use rules, and sanctions programs. Note that granting a foreign national access to controlled technical data can itself be a controlled transfer. Not a determination of classification, licence requirement, or exemption."
      examples    = ["Send the drone flight-control firmware over to our contractor abroad.",
                     "Give the offshore team read access to the encryption source repository.",
                     "Ship the sensor units to the customer in the sanctioned country and mark them as samples."]
    }
    PROFESSIONAL_PRIVILEGE {
      description = "The act plausibly touches material held under a sector-specific professional duty of confidence or evidentiary privilege — attorney-client communications and work product, physician or therapist confidences, clergy, or an equivalent professional obligation — warranting review before it moves. Concerns the professional duty attaching to the material; ordinary business confidentiality is a disclosure-category matter, not this label. It is not a ruling that privilege exists, attaches, or has been waived."
      examples    = ["Forward outside counsel's memo on our litigation exposure to the whole vendor thread.",
                     "Share what my therapist wrote in the session notes with my employer's HR team.",
                     "Include the legal advice email in the batch we're producing to the other side."]
    }
    CROSS_BORDER_TRANSFER {
      description = "The movement of personal or otherwise regulated data across a national or regional border — or granting access to it from another country — is itself the trigger, warranting review of transfer mechanisms, adequacy, data residency, or localization requirements. Use this when the border crossing is the salient fact; when the act is ordinary in-jurisdiction processing that merely happens to involve a foreign subject, prefer the regime label for the subjects affected."
      examples    = ["Copy the EU customer database into our US analytics warehouse.",
                     "Give the Bangalore support team live access to the German user records.",
                     "Move the backups out of the Frankfurt bucket and into the Virginia region."]
    }
    OUT_OF_SCOPE {
      description = "No regime enumerated by this family can be assigned: a regulatory regime is plainly in play but this family does not list it, the act's content is not visible enough to spot any trigger, or the request asks for a legal conclusion — which this family never renders. It is not equivalent to NO_REGIME_IDENTIFIED, which asserts that a readable act showed no trigger. Under fail-closed posture this label means unresolved and routes to human review."
      examples    = ["Just tell me straight — does this break the law or not?",
                     "Handle the filing the way Brazil's LGPD requires.",
                     "Process the attached document; I can't tell you what's in it."]
      oos         = true
    }
  }
  escalate t0_signals    >= 970
  escalate t1_embedding  >= 920
  escalate t3_local_llm  >= 880
  abstain      = "human"
  golden_set   = "eval/aph_jurisdiction.golden.json"
  min_accuracy = 940
}
```
