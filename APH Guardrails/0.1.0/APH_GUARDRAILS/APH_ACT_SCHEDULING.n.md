---
section: "APH Guardrails"
name: "APH Guardrails — Act Scheduling"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Act Scheduling

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

This family gives two agents from different organizations a shared, resolvable
name for what a message DOES to a point in time on a calendar: offer it, take
it, refuse it, hold it, move it, kill it, or hand it to someone else. The
boundary is the object of the act — if the thing being created, altered, or
released is a scheduled slot, it is scheduling; a general obligation with no
time-slot object belongs to APH_ACT_COMMITMENT. It deliberately does NOT
classify subject matter, meeting importance, urgency, attendee identity,
whether the sending agent holds a mandate to bind its principal, or what the
receiving system should do next — authority, severity, and routing are
separate families. Two labels here are easily conflated and are split on
purpose: naming a replacement slot the sender will honor
(TIME_COUNTER_PROPOSED) is a live, acceptable offer, while merely describing
open windows (TIME_DECLINED_WITH_AVAILABILITY, AVAILABILITY_PROVIDED) binds
nothing.

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
classifiers "APH_ACT_SCHEDULING" {
  description = "Classifies what a message does to a calendar commitment between two parties"
  labels {
    TIME_PROPOSED {
      description = "Offers one or more specific times for a meeting that is not yet scheduled. The sender will honor any offered time if the counterparty accepts it, so acceptance alone completes the commitment. No prior proposal is being answered."
      examples    = ["Would Tuesday the 14th at 2pm Pacific work for the quarterly review?",
                     "I can do either Wednesday morning or Friday after 3 — pick whichever suits you and I'll take it.",
                     "Putting forward next Monday at 09:30 for the kickoff."]
    }
    TIME_ACCEPTED {
      description = "Accepts a specific time the counterparty previously proposed, converting that proposal into a firm commitment for the sender's principal. This is the canonical 'accept meeting time' act. No new time is introduced and no condition is attached."
      examples    = ["Tuesday at 2pm works — I'm booking it.",
                     "Accept the meeting time as proposed.",
                     "Yes, Thursday 10:00 Eastern is confirmed on my side."]
    }
    TIME_DECLINED {
      description = "Refuses a proposed time and offers nothing in its place: no alternative slot, no availability window, no request to keep looking. The scheduling exchange ends unless the counterparty restarts it."
      examples    = ["I can't make Tuesday at 2, sorry.",
                     "That slot doesn't work for me.",
                     "Declining the Friday invite — I won't be available."]
    }
    TIME_COUNTER_PROPOSED {
      description = "Rejects the proposed time and names one or more specific replacement times the sender will honor if accepted. The replacement is a live offer, so the counterparty accepting it completes the commitment with no further exchange. Distinguished from TIME_DECLINED_WITH_AVAILABILITY, which names no bindable slot."
      examples    = ["Tuesday doesn't work, but I can hold Wednesday at 2pm instead — say the word and it's booked.",
                     "Instead of Friday morning, let's do Thursday at 4pm Pacific.",
                     "Not 9am. I'll take 11am the same day if you'll take it."]
    }
    TIME_DECLINED_WITH_AVAILABILITY {
      description = "Refuses the proposed time and describes general availability, constraints, or preferred windows that are NOT themselves acceptable-as-stated offers. The counterparty cannot complete a booking from this message alone; a further proposal is still required."
      examples    = ["Tuesday's out for me. I'm generally open later that week, though nothing firm yet.",
                     "Can't do the 14th; my afternoons after the 20th tend to be clearer.",
                     "That won't work — mornings are usually better, but I'd have to check before naming a slot."]
    }
    TIME_HELD_TENTATIVE {
      description = "Places a provisional, explicitly non-binding hold on a specific slot. The slot is reserved against competing bookings but the principal is not committed to attend, and the hold either lapses or is later confirmed."
      examples    = ["Pencil me in for Thursday at 3 — tentative until I hear back from legal.",
                     "I'll hold Wednesday 10am provisionally, not confirmed.",
                     "Marking the 14th as a soft hold for now."]
    }
    TIME_HOLD_CONFIRMED {
      description = "Converts an existing tentative hold on a specific slot into a firm commitment. Applies only where a prior hold exists; a first-time firm acceptance of someone else's proposal is TIME_ACCEPTED."
      examples    = ["The tentative hold on Thursday 3pm is now firm.",
                     "Converting Wednesday's pencil-in to a confirmed booking.",
                     "Legal cleared it — the hold on the 14th is confirmed."]
    }
    MEETING_RESCHEDULE_REQUESTED {
      description = "Seeks to move an already-confirmed commitment to a different time, naming one or more replacement times. The original commitment remains in force until the counterparty accepts the move; this act alone cancels nothing."
      examples    = ["Something came up — can we move Thursday's review to Friday at the same time?",
                     "I need to shift our confirmed 2pm to next week; Tuesday or Wednesday would work.",
                     "Requesting we push the standing sync from the 3rd to the 10th."]
    }
    MEETING_CANCELLED {
      description = "Terminates an existing scheduled commitment with no replacement time offered and no rebooking sought in this message. The slot is released for both parties."
      examples    = ["Cancel Thursday's review; we don't need it.",
                     "I'm calling off tomorrow's call — no replacement needed.",
                     "Please drop the 2pm from the calendar entirely."]
    }
    ATTENDANCE_DELEGATED {
      description = "States that the principal will not personally attend a scheduled commitment and names a substitute who will attend instead. The meeting and its time are unchanged and remain committed."
      examples    = ["I can't attend Thursday, but Priya will go in my place.",
                     "Sending my deputy to the 2pm — the meeting stands.",
                     "I'm out that day; Marco has the context and will cover for me."]
    }
    AVAILABILITY_REQUESTED {
      description = "Asks the counterparty to disclose their open times. No time is offered, accepted, or refused, and no slot is reserved on either side."
      examples    = ["What does your calendar look like next week?",
                     "Send me a few times that work on your end.",
                     "Are you free any afternoon between the 10th and the 14th?"]
    }
    AVAILABILITY_PROVIDED {
      description = "Discloses the principal's open or blocked times without offering any specific slot as bindable and without refusing a prior proposal. Informational only: selecting a window from this message does not create a commitment."
      examples    = ["I'm open Tuesday and Thursday afternoons, and Friday before noon.",
                     "Here's my free/busy for next week: mornings are booked, after 2pm is clear.",
                     "Generally available the week of the 20th except Wednesday."]
    }
    OUT_OF_SCOPE {
      description = "The message performs no act on a calendar commitment. Meeting-adjacent talk that neither offers, accepts, refuses, holds, moves, releases, delegates, nor discloses times lands here, as does every non-scheduling act. This classifier must never claim a scheduling terminal for such a message."
      examples    = ["What's the agenda for the review?",
                     "Here are the notes from yesterday's meeting.",
                     "Approve the $40,000 purchase order."]
      oos         = true
    }
  }
  escalate t0_signals    >= 940
  escalate t1_embedding  >= 860
  abstain      = "clarify"
  golden_set   = "eval/aph_act_scheduling.golden.json"
  min_accuracy = 920
}
```
