---
section: "APH Guardrails"
name: "APH Guardrails — Guard Disclosure"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Guard Disclosure

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

This family answers exactly one question: what CATEGORY of protected
information an act would reveal, judged from the data itself and nothing else.
It is deliberately NOT a severity score, NOT a permission or routing decision,
and NOT a statement about which law applies — the regulatory question belongs
to APH_JURISDICTION. Because an act may touch several categories at once, the
family is single-label under a fixed precedence: AUTHENTICATION_SECRET
dominates all, then CHILD_INFORMATION, BIOMETRIC_DATA, HEALTH_INFORMATION,
GOVERNMENT_IDENTIFIER, PAYMENT_CARD, FINANCIAL_ACCOUNT, PRECISE_LOCATION,
TRADE_SECRET, PERSONAL_IDENTIFIER, CONTACT_INFORMATION, and last
NO_PROTECTED_DATA, which asserts only that content was actually inspected and
found clean. It is sealed and fail-closed on purpose: an unavailable, low-
confidence, or OUT_OF_SCOPE result must never be read by a counterparty agent
as clearance to disclose.

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
classifiers "APH_GUARD_DISCLOSURE" {
  description = "Which category of protected information an act would reveal"
  sealed       = true
  fail_posture = "fail_closed"
  labels {
    NO_PROTECTED_DATA {
      description = "The act's content was inspected and reveals nothing in any protected category enumerated by this family — no identifiers, contact details, government or financial identifiers, health, biometric, precise-location, credential, confidential-business, or child data. Public, aggregate-only, synthetic, or irreversibly de-identified content lands here. This is the only label that affirmatively asserts absence; if the content could not be inspected, or the answer is uncertain, use OUT_OF_SCOPE instead."
      examples    = ["Post the already-published Q3 product roadmap entry to the company blog feed.",
                     "Tell the other agent how many support tickets closed last week — counts only, no names attached.",
                     "Summarize tomorrow's public weather forecast and drop it in the team channel."]
    }
    PERSONAL_IDENTIFIER {
      description = "Information that names or singles out a specific natural person without falling into a more protected category: legal or preferred name, date of birth, internal customer or employee number, account handle, or any combination that identifies one individual. Use only when no higher-precedence category (credential, child, biometric, health, government, payment, financial, location, trade secret) is present."
      examples    = ["Send the other agent the full name and date of birth we have on file for this customer.",
                     "Confirm to them that the person they're asking about is our employee, badge 44120.",
                     "Share the list of account holders' names so their system can match records against ours."]
    }
    CONTACT_INFORMATION {
      description = "A means of reaching a person: personal or work email, phone number, postal or street address used as a mailing destination, or a direct messaging handle. A home address disclosed as a channel to reach someone is CONTACT_INFORMATION; a person's or device's current or historical whereabouts is PRECISE_LOCATION."
      examples    = ["Forward her mobile number to the vendor so they can call about the delivery.",
                     "Give them the billing address we have on file for this account.",
                     "Reply with the customer's personal email address so they can follow up directly."]
    }
    GOVERNMENT_IDENTIFIER {
      description = "An identifier issued by a state or national authority to a person: social security or national insurance number, taxpayer identification number, passport number, driver's licence number, national ID, visa or immigration file number, or an image of any document bearing one. Partial disclosure (last four digits, redacted scans) still lands here."
      examples    = ["Read back the last four of his Social Security number so they can verify identity.",
                     "Attach a scan of the applicant's passport page to the onboarding ticket.",
                     "Confirm whether the driver's licence number on the form matches the DMV record."]
    }
    FINANCIAL_ACCOUNT {
      description = "Financial data tied to a person or entity that is not payment card data: bank or brokerage account and routing numbers, IBAN, account balances, transaction histories, statements, salary and compensation figures, tax filings, credit scores, or loan and debt positions. If the primary account number or authentication elements of a payment card are involved, use PAYMENT_CARD."
      examples    = ["Send them the account and routing number so payroll can set up the deposit.",
                     "Tell the other agent the current balance and last five transactions on the operating account.",
                     "Share this employee's salary and bonus figures with the outside recruiter."]
    }
    PAYMENT_CARD {
      description = "Cardholder data as understood by the payment industry: the full or truncated primary account number, expiry date, cardholder name bound to a card, security code (CVV/CVC/CID), PIN or PIN block, or magnetic-stripe/chip track data. A merchant-scoped opaque token that cannot be reversed to a card number is not this label."
      examples    = ["Repeat the card number and expiry back to me so I can rebook the flight.",
                     "The security code on the back is needed to finish the charge — read it out.",
                     "Paste the full sixteen-digit card we have on file into the vendor's checkout form."]
    }
    HEALTH_INFORMATION {
      description = "Information about a person's physical or mental health, care, or payment for care: diagnoses, symptoms, treatments, prescriptions, test and lab results, disability status, reproductive or sexual health, substance use, therapy or counselling, and appointments whose clinical nature is identifiable. The mere existence of an unspecified medical appointment tied to a named person also lands here."
      examples    = ["Tell the scheduler this appointment is for chemotherapy so they block a longer slot.",
                     "Share the lab results showing his A1C with the workplace wellness vendor.",
                     "Explain that she's out on mental health leave and give them the expected return date."]
    }
    BIOMETRIC_DATA {
      description = "Measurements or templates derived from a person's body or behaviour that are used, or usable, to identify them: fingerprint, face template or scan, iris or retina, voiceprint, palm or vein pattern, gait, keystroke dynamics, and DNA or genetic sequence. A raw photograph or voice recording lands here when it is being used for identification, matching, or enrolment."
      examples    = ["Upload the fingerprint template so the door system can match him at the gate.",
                     "Send the voiceprint we enrolled last month so the call centre can authenticate her.",
                     "Share the face scan from the badge photo with the third-party identity verifier."]
    }
    PRECISE_LOCATION {
      description = "The whereabouts of an identifiable person or their device at a granularity finer than a broad region: GPS or lat/long coordinates, live device location, visit and dwell history, check-ins, geofence entries, or timestamped presence at a specific place. Coarse attributes such as country, state, or city of residence used as profile data are PERSONAL_IDENTIFIER, not this label."
      examples    = ["Tell them exactly where his phone is right now.",
                     "Share yesterday's GPS trail so they can see every stop she made and how long she stayed.",
                     "Confirm the driver has been parked at 41.8781, -87.6298 for the last two minutes."]
    }
    AUTHENTICATION_SECRET {
      description = "Material whose disclosure directly grants access or the ability to act: passwords, passphrases, API keys, bearer or refresh tokens, session cookies, private keys, certificates with private material, seed or recovery phrases, one-time and multi-factor codes, and knowledge-based recovery answers. This label has the highest precedence in the family — when a credential is in the payload alongside anything else, this is the label, because disclosure is immediately capability-granting and cannot be undone by retraction."
      examples    = ["Paste the production API key into the chat so the other agent can call the endpoint.",
                     "Read me the six-digit code that was just texted to you.",
                     "Here's my private key file — use it to sign the request on my behalf."]
    }
    TRADE_SECRET {
      description = "Non-public business information whose value depends on remaining secret, or information held under a duty of confidence to an organization: source code, algorithms and models, pricing structures and margins, customer or supplier lists, unreleased product and launch plans, pre-announcement M&A, negotiation positions, unreleased financials, and material under NDA. This covers organizational confidence; personal confidences held by a professional are a jurisdiction matter, not this family."
      examples    = ["Send the counterparty our unreleased pricing model so they can compare against theirs.",
                     "Share the source for the ranking algorithm with the outside contractor.",
                     "Tell them the name of the acquisition target before the announcement goes out."]
    }
    CHILD_INFORMATION {
      description = "Any information about a person known or reasonably believed to be a minor under the applicable age threshold, in any category — name, school, schedule, photos, grades, health, location, or contact details. Child status dominates every other category except AUTHENTICATION_SECRET, so a minor's health record is CHILD_INFORMATION, not HEALTH_INFORMATION. Reasonable belief is enough; certainty of age is not required."
      examples    = ["Give the tutoring service my nine-year-old's name, school, and pickup time.",
                     "Share the student's grades and home address with the outside enrichment vendor.",
                     "Tell them which classroom my kid is in and what time he's let out."]
    }
    OUT_OF_SCOPE {
      description = "The act cannot be assigned a disclosure category by this family: nothing is being disclosed to anyone, the payload is opaque or otherwise unavailable for inspection, or the content belongs to a protected category this family does not enumerate. This is the honest non-answer and is never equivalent to NO_PROTECTED_DATA. Under fail-closed posture a consumer must treat this label as unresolved and withhold the act pending human review — it grants nothing."
      examples    = ["Restart the build server; nothing leaves the machine.",
                     "Forward the encrypted archive along as-is — I can't see what's inside it.",
                     "Attach whatever is at this link to the reply; I don't know what the file contains."]
      oos         = true
    }
  }
  escalate t0_signals    >= 985
  escalate t1_embedding  >= 960
  escalate t3_local_llm  >= 930
  abstain      = "human"
  golden_set   = "eval/aph_guard_disclosure.golden.json"
  min_accuracy = 970
}
```
