---
section: "APH Guardrails"
name: "APH Guardrails — Act Data Mutation"
version: "0_1_0"
copyright: "(2020-present) Scott Wyatt, Squillo Inc. - All Rights Reserved"
license: "Apache-2.0 (file contents). N Lang itself is proprietary to Squillo Inc. and is commercially licensable only through Squillo Inc."
---
# APH Guardrails — Act Data Mutation

> **Copyright (2020-present) Scott Wyatt, Squillo Inc. — All Rights Reserved.**
> N Lang is a proprietary language of Squillo Inc.; commercial use of the
> language, compiler, runtime, and Snapp tooling is licensable only through
> Squillo Inc. — <https://squillo.com/nlang>. The contents of this file are
> published under the Apache License 2.0 (see `LICENSE` at the repository
> root); that grant covers this file, not the N Lang language or toolchain.

This family names what an act DOES to a system of record so that a receiving
agent can decide, before any bytes change, whether the APH envelope in hand
actually covers it. The boundary is record state: an act is classified by the
SHAPE of the change — which records it touches, whether the prior value
survives, and whether structure or instance data moves — never by who asked,
how risky it is, or whether it ought to be permitted. It deliberately does NOT
classify changes to who may reach a record (that is APH_ACT_ACCESS), nor
message sends, payments, scheduling, or approval-workflow steps; severity and
routing are separate families. READ_ONLY_QUERY is carried here on purpose, so
a stranger's agent can assert 'this envelope covers a read and nothing more'
in the same vocabulary it would use to assert a purge. RESIDUAL RULE, which
closes a hole the precedence language would otherwise carry: this family is
open to overlays, an overlay may ADD a label, and an added label sits nowhere
in the precedence relations above — so a rule stated only over the enumerated
set is uncomputable for it, and the permissive reading wins by default.
Therefore any label not named in those relations ranks at the LEAST-REVERSIBLE
position for precedence, and a consumer that receives a label it does not
recognize MUST NOT treat the act as a read, as recoverable, or as
single-record. Two facts hold regardless of any label a later overlay adds: an
act whose target set is selected by predicate rather than enumerated is a bulk
act, and an act that leaves no recoverable copy is a permanent deletion. No
overlay-added label may claim a message carrying either fact.

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
classifiers "APH_ACT_DATA_MUTATION" {
  description = "Classifies what an act does to state in a system of record: which records change, and how reversibly."
  labels {
    RECORD_CREATE {
      description = "Brings a new record into existence in a system of record. The act asserts no prior record for this subject; if the act is conditional on an existing record being updated instead, it is not this label. Applies to exactly one new record — creating many records from a selection or feed is BULK_UPDATE only if it edits existing rows, otherwise repeated RECORD_CREATE acts."
      examples    = ["Create a new customer record for Aurora Dental Group with billing contact ops@auroradental.example.",
                     "Add Marcus Webb to the CRM as a lead from the trade show list.",
                     "File a new support ticket about the failed nightly export and attach the error log."]
    }
    RECORD_FIELD_UPDATE {
      description = "Changes one or more named fields on a single, already-identified existing record, leaving every unnamed field at its current value. This is the partial-patch case. If the act clears or overwrites fields it did not name, it is RECORD_REPLACE; if the target is a set selected by filter rather than one identified record, it is BULK_UPDATE."
      examples    = ["Change the shipping address on order 88213 to the Portland warehouse.",
                     "Set the account's renewal date to March 14 and leave everything else exactly as it is.",
                     "Update just the phone number on Dana's contact card — the rest of it is still correct."]
    }
    RECORD_REPLACE {
      description = "Overwrites a single existing record wholesale, so that fields absent from the incoming payload are cleared or reset rather than preserved. The record's identity survives; its prior contents do not. If the replacement source is an earlier revision of the same record, RECORD_RESTORE takes precedence."
      examples    = ["Overwrite the whole product entry with the payload from the new catalog feed.",
                     "Replace the existing policy document record with this version; anything not present in it should be cleared.",
                     "Swap the entire vendor profile for the one in the attached JSON — this is not a partial patch."]
    }
    RECORD_SOFT_DELETE {
      description = "Removes a single record from active use while retaining it in a recoverable state — archive, trash, tombstone, or a deleted flag. Reversal is expected to be possible by the same system without restoring from an external backup. If the act requires that no recoverable copy remain, it is RECORD_HARD_DELETE."
      examples    = ["Archive the closed opportunity so it drops out of the active pipeline but still shows up in reporting.",
                     "Mark the duplicate contact as deleted; we can undo it if I turn out to be wrong.",
                     "Move that campaign to the trash — it should stay recoverable for thirty days."]
    }
    RECORD_HARD_DELETE {
      description = "Irreversibly destroys a single record, including any recoverable copy the system holds, such that the prior value cannot be produced again. Erasure requests, purges, and 'permanently, no backup' deletions land here. This label asserts irreversibility; when the act's reversibility is genuinely undetermined, the classifier must abstain rather than choose between this label and RECORD_SOFT_DELETE."
      examples    = ["Purge the applicant's file permanently — this is a GDPR erasure request.",
                     "Delete ledger row 4471 for good; no backup copy of it should survive anywhere.",
                     "Wipe the test tenant's record completely so that it cannot be restored later."]
    }
    RECORD_MERGE {
      description = "Collapses two or more existing records into one surviving identity, retiring the others and consolidating their contents or references. The distinguishing fact is that record identities are reduced in number. If the act only copies fields between records while both survive, it is RECORD_FIELD_UPDATE."
      examples    = ["Merge the duplicate accounts for Northwind Logistics into the one with the older ID.",
                     "Combine these two contact records — keep the newer email and roll the activity history together.",
                     "Fold the sandbox customer entry into the production one and retire the duplicate."]
    }
    RECORD_SPLIT {
      description = "Divides one existing record into two or more records, increasing the number of record identities and distributing the original's contents or references among them. The original may survive as one of the results or be retired."
      examples    = ["Split the combined household account into a separate record for each spouse.",
                     "Break the bundled invoice into one invoice per project code.",
                     "Separate that merged supplier entry back into the two legal entities it came from."]
    }
    RECORD_RESTORE {
      description = "Returns a record to a previously captured state: reverting to an earlier revision, or undeleting a record that was soft-deleted. The authority for the new contents is the record's own history, which is what separates this from RECORD_REPLACE. Restoring a set selected by filter rather than one identified record is still this label only if the set is enumerated; a predicate-selected mass revert is BULK_UPDATE."
      examples    = ["Roll the pricing sheet back to the version from before Tuesday's import.",
                     "Undelete the client record we archived last week — it was the wrong one.",
                     "Restore revision 12 of the onboarding checklist; the current one lost the compliance steps."]
    }
    BULK_CREATE {
      description = "Brings a set of new records into existence from a source the act names rather than from enumerated content — an import, a feed, a generated range, or a copy of a queried set — so the exact number created is not fixed by the act itself. Takes precedence over RECORD_CREATE whenever the created set is source-selected rather than spelled out, for the same reason the other bulk labels take precedence: the blast radius, not the operation, is the fact a verifier needs. If the act edits rows that already exist it is BULK_UPDATE, and if it both imports and overwrites on conflict it is BULK_UPDATE, because the destructive half governs."
      examples    = ["Import every contact from that CSV into the customer table.",
                     "Create a draft invoice for each account that closed a deal this quarter.",
                     "Copy all of last year's active projects into the new workspace as fresh records."]
    }
    BULK_UPDATE {
      description = "Applies a change to a set of records selected by predicate, filter, or query rather than by enumerated identity, so the exact number of affected records is not fixed by the act itself. Takes precedence over the single-record update labels whenever the target is predicate-selected. If the bulk act deletes rather than edits, it is BULK_DELETE; if it alters the record type rather than the rows, it is SCHEMA_CHANGE; if it only brings new records into existence, it is BULK_CREATE."
      examples    = ["Set the region to EMEA on every account whose billing country is in the EU.",
                     "Re-tag all tickets older than ninety days as stale across the whole queue.",
                     "Apply the new tax rate to each open invoice that hasn't been sent out yet."]
    }
    BULK_DELETE {
      description = "Deletes a set of records selected by predicate, filter, or query rather than by enumerated identity, whether the deletion is recoverable or permanent. Takes precedence over RECORD_SOFT_DELETE and RECORD_HARD_DELETE whenever the target is predicate-selected, because the blast radius, not the reversibility, is the operative fact for a verifier."
      examples    = ["Remove every lead that hasn't been touched since 2023 from the pipeline.",
                     "Purge all event logs older than the retention window across all tenants.",
                     "Delete the entire batch we imported this morning — that source file was wrong."]
    }
    SCHEMA_CHANGE {
      description = "Alters the structure or definition of records rather than the contents of any particular record: adding, renaming, retyping, or dropping a field; adding or removing an index or constraint; running a structural migration. Takes precedence over the data labels even when the change rewrites existing rows as a side effect."
      examples    = ["Add an optional 'preferred pronouns' field to the patient profile type.",
                     "Change the order total column from integer cents to decimal and migrate the existing rows.",
                     "Create an index on created_at so the weekly reports stop timing out."]
    }
    READ_ONLY_QUERY {
      description = "Retrieves, counts, checks, or reports on records without changing any stored state. Nothing in the system of record differs after the act except access logging. This label exists so that a read can be asserted positively and narrowly on the wire; an act that reads in order to then write is classified by the write it performs, not by this label."
      examples    = ["How many open invoices does Northwind have right now?",
                     "Pull the last five support tickets for this account so I can read through them.",
                     "Check whether a record already exists for this email address before doing anything else."]
    }
    OUT_OF_SCOPE {
      description = "The act is not a change to, or a read of, state in a system of record. Communication sends, permission and sharing changes, payments, scheduling, approvals, and physical-world actions terminate here rather than being forced into a mutation label."
      examples    = ["Send the signed contract over to the client's counsel by email.",
                     "Give the auditor read access to the ledger for the next week.",
                     "Move our Thursday standup to 9:30 and let the team know."]
      oos         = true
    }
  }
  escalate t0_signals    >= 970
  escalate t1_embedding  >= 930
  escalate t3_local_llm  >= 900
  abstain      = "human"
  golden_set   = "eval/aph_act_data_mutation.golden.json"
  min_accuracy = 960
}
```
