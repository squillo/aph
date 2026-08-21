<!--
The checklist below is CONTRIBUTING.md's review rules made visible at the
moment they apply. Delete lines that do not apply to this PR — an unchecked
irrelevant box reads the same as an unmet requirement.
-->

## What this changes

<!-- One paragraph. If this lands an RFC, link the RFC issue — the design
conversation belongs there, and this description can stay short. -->

## Which surface

- [ ] **Normative** (MUST/SHALL text, wire shape, algorithm set, state machines, error codes) — needs **two maintainer approvals** and a version bump, or a dated in-place revision under the pre-production exception
- [ ] **Published vectors / schemas** — bytes other implementations test against; regenerated through the generators, never text-edited
- [ ] **Non-normative docs / implementation only** — one approval

## The record

- [ ] Dated revision entry added to `CHANGELOG.md` (required for anything normative or vector-touching)
- [ ] Every commit carries `Signed-off-by:` (DCO — `git commit -s`)
- [ ] If example envelopes' field set changed: `examples/*.json` updated and the conformance suite is green
- [ ] Counts and enumerations that this change moves (example counts, "N bindings", coverage lists) were found by sweep and updated — a stale count is a defect
