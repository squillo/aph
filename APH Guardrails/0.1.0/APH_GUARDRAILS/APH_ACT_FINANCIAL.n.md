---
section: "APH Guardrails"
name: "APH Guardrails — Act Financial"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Act Financial

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

APH_ACT_FINANCIAL names what an agent is DOING when the operative effect of
its message is that money moves, is committed to move, or is priced. The
boundary is effect, not topic: discussing, reporting, or forecasting money is
not a financial act, and only the sender's own act is classified — never the
recipient's expected response. It does not classify the effect an act has on
legal rights — accepting contract terms, executing an NDA, giving notice,
waiving a right — which is APH_ACT_LEGAL's subject. EVALUATION IS INDEPENDENT,
stated because the earlier wording invited the opposite reading and the
failure it produced is silent: families are evaluated SEPARATELY over the same
message, and OUT_OF_SCOPE here means THIS family's operative effect is absent,
never that another family owns the message. A settlement is the worked case:
'We accept responsibility for the outage and will wire 50,000 in settlement'
carries a payment label from this family AND LIABILITY_ACCEPT from
APH_ACT_LEGAL, returned in parallel. A reader who treats either family's
OUT_OF_SCOPE as a hand-off gets two out-of-scope verdicts on the single most
consequential message either family will ever see, and concludes that no
financial act and no legal act occurred. It also does not encode
amount, currency, severity, authority, or routing — a payment of one cent and
a payment of one million share the label PAYMENT_AUTHORIZE, and everything
else is a separate family's job. PRIVACY POSTURE, stated because it is a
deliberate constraint rather than an oversight: this family classifies
regulated and adversarial text, so its base is local_only with no cloud rung.
The lattice makes that the safe default direction — an overlay may restrict
locality but never relax it, and may remove a rung but never add one, so any
future cloud evaluation requires a NEW BASE VERSION that a verifier can see
and refuse, rather than arriving silently through inheritance.

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
classifiers "APH_ACT_FINANCIAL" {
  description = "Which financial act an agent is performing on behalf of its principal when money moves, is committed, or is priced"
  labels {
    PAYMENT_AUTHORIZE {
      description = "The sender authorizes or instructs that a specific payment be made from funds it controls or is empowered to commit. The operative effect is that money leaves the principal's side. Use this only when the instruction is to actually pay, not merely to approve a document as correct."
      examples    = ["Go ahead and pay the March hosting bill from the operating account.",
                     "I approve the wire of 12,400 EUR to Kestrel Logistics — release it today.",
                     "Authorized. Charge the card on file for the remaining balance."]
    }
    PAYMENT_REQUEST {
      description = "The sender asks a counterparty to pay a sum, without issuing a formal invoice record. No money moves by this act alone. If the act creates or transmits an invoice document or invoice identifier, use INVOICE_ISSUE instead."
      examples    = ["Please remit the outstanding 3,200 USD by Friday.",
                     "We're asking your team to send payment for the work completed in Q2.",
                     "Could you settle what's owed on the shared account this week?"]
    }
    REFUND_ISSUE {
      description = "The sender returns, or commits to return, money it has already received from the counterparty, in whole or in part. Distinguished from PAYMENT_AUTHORIZE by direction and provenance: a refund reverses a prior collection rather than settling a new obligation."
      examples    = ["Refund the customer the full 149.00 they paid on the 3rd.",
                     "We're returning your deposit; it should be back on the original card within five days.",
                     "Process a 60% credit back for the nights that were cancelled."]
    }
    CHARGE_DISPUTE {
      description = "The sender contests a charge or transaction that has already been made against it, asserting it is unauthorized, duplicated, or incorrect. This is an adversarial act against an existing debit, not a request for a favourable refund; if the sender is simply asking the counterparty to voluntarily return money, that counterparty's act would be REFUND_ISSUE."
      examples    = ["I'm disputing the 89.00 charge from 12 August — I never authorized it.",
                     "We are contesting this transaction with our bank as fraudulent.",
                     "Open a chargeback on the duplicate debit from last month."]
    }
    INVOICE_ISSUE {
      description = "The sender creates or transmits a formal invoice: an identified, itemized demand for payment under stated terms. The presence of an invoice record, number, or stated payment terms is what separates this from PAYMENT_REQUEST."
      examples    = ["Invoice 2026-0417 is attached — 8,500 USD, net 30.",
                     "I've raised this month's retainer bill and sent it to your accounts team.",
                     "Issuing our invoice for the September engagement now, due on receipt."]
    }
    INVOICE_APPROVE {
      description = "The sender approves a received invoice or bill as valid and payable, clearing it for a payment run. This act validates a document; it does not itself instruct that money move. If the same message also orders the payment out, the operative effect is payment and PAYMENT_AUTHORIZE applies."
      examples    = ["Invoice 2026-0417 is approved for payment; code it to the marketing budget.",
                     "I've signed off on the vendor's bill — it can go into the next payment run.",
                     "Checked and approved as correct; release it to accounts payable."]
    }
    QUOTE_PROVIDE {
      description = "The sender states a price or estimate at which it is willing to supply goods or services, as an offer the counterparty may accept or decline. The sender is the one naming the number and is not yet bound to a transaction."
      examples    = ["Our price for the 200-unit run would be 14,000 USD, valid for 30 days.",
                     "Here's an estimate: roughly 40 hours at 180 an hour.",
                     "We can quote you 2,400 a month for the enterprise tier."]
    }
    QUOTE_ACCEPT {
      description = "The sender accepts a price or estimate previously offered by the counterparty, binding itself to that price. The number originated with the other side; the sender's act is assent to it."
      examples    = ["We accept your quote of 14,000 USD for the 200-unit run.",
                     "That estimate works for us — proceed on those numbers.",
                     "Yes to the 2,400-a-month tier; consider the quote accepted."]
    }
    PURCHASE_ORDER_ISSUE {
      description = "The sender issues a purchase order or equivalent buying commitment against stated goods, quantities, and terms. It differs from QUOTE_ACCEPT in that it creates a procurement instrument of the sender's own, which invoices will later be matched against."
      examples    = ["Raising PO 88231 against your quote — 200 units at 70 each.",
                     "Our purchase order is issued; please reference it on every invoice.",
                     "I'm putting the order through for the annual licences on the agreed terms."]
    }
    PRICE_TERMS_AGREE {
      description = "The sender agrees a price, rate, discount, or other monetary term as a standing basis for future transactions, outside the issuance or acceptance of a specific quote or order. The operative content is the number or the formula, not a particular purchase. BOUNDARY against APH_ACT_LEGAL::CONTRACT_TERMS_ACCEPT: this label names assent to the NUMBER — what a unit costs, what the rate is, how the discount computes. That label names assent to the INSTRUMENT — being bound by a set of terms as written. A signed agreement that fixes a rate does both, and per the independence rule above it returns both labels, one from each family. Neither is the other's fallback: agreeing a rate in a message that binds nobody to anything is this label alone."
      examples    = ["Agreed — 12% off list on any order above 500 units.",
                     "We'll lock the rate at 165 an hour for the next twelve months.",
                     "Deal on the 5% early-payment discount."]
    }
    RECURRING_CHARGE_ESTABLISH {
      description = "The sender sets up, or consents to, a repeating charge, subscription, standing order, direct-debit mandate, or auto-pay arrangement. The distinguishing feature is that a single act authorizes an open-ended series of future debits rather than one payment."
      examples    = ["Set up the monthly subscription at 99 a month starting 1 October.",
                     "Please put us on a standing direct debit for the quarterly fee.",
                     "Enrol this account in auto-pay on the card ending 4417."]
    }
    RECURRING_CHARGE_CANCEL {
      description = "The sender cancels, stops, or declines to renew an existing recurring charge, subscription, mandate, or auto-renewal, ending the series of future debits. It concerns only the recurring authorization; it makes no claim about money already taken."
      examples    = ["Cancel our subscription effective at the end of this billing period.",
                     "Please stop the direct debit — do not take next month's payment.",
                     "Turn off auto-renewal on the annual plan."]
    }
    OUT_OF_SCOPE {
      description = "The message performs no financial act of this family: no money moves, is committed, is priced, or is disputed. Reporting balances, acknowledging receipt, forecasting spend, or merely discussing money lands here. This terminal asserts ONLY that this family's operative effect is absent — it is never a hand-off, and it says nothing about what another family will return for the same message. A message that accepts contract terms and nothing else is OUT_OF_SCOPE here because no money moved, not because the legal family claimed it; a message that does both returns a label from each."
      examples    = ["Our current account balance is 42,110 USD as of this morning.",
                     "Let's move the budget review meeting to Thursday.",
                     "We accept the confidentiality terms as drafted."]
      oos         = true
    }
  }
  escalate t0_signals    >= 985
  escalate t1_embedding  >= 965
  escalate t3_local_llm  >= 945
  abstain      = "human"
  golden_set   = "eval/aph_act_financial.golden.json"
  min_accuracy = 960
}
```
