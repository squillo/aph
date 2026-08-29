# Contributing to APH

Contributions to the APH specification, examples, and tests are welcome via pull request.

## Process

- Pull requests target the `main` branch.
- Every commit MUST carry a `Signed-off-by:` line (Developer Certificate of Origin). Configure with `git commit -s`.
- Maintainers from Squillo, Inc. review and merge.
- For substantive discussion, open a GitHub issue before opening a PR so the design conversation lives in the issue tracker. Three issue forms carry the process: **RFC** for any change to normative text (the request-for-change entry point — problem, proposal, compatibility, security, in that order), **Erratum** for spec text that is simply wrong, and **Conformance disagreement** for an implementation that disagrees with a published artifact. Review routing is codified in `.github/CODEOWNERS`; the PR template restates the approval bar at the moment it applies. Accepted (and rejection-worthy) RFCs land as numbered documents in [`rfcs/`](rfcs/README.md) — the issue holds the conversation, the document holds the decision.

## Scope

This repository carries the APH **specification**, **example envelopes**, **conformance tests**, the **N Lang type Snapp** under `APH Spec/`, and the **reference Rust implementation** under `interpreters/rust/`. Other implementations (SDKs in other languages, notary services, channel-adapter integrations) live in separate repositories and are not in scope here.

## Spec changes

- Changes to the on-wire envelope shape, the set of permitted signature algorithms, the protocol state machines, or any other normative MUST/SHALL clause require a pull request, two maintainer approvals, and a version bump.
  - *Enforcement status, kept honest:* branch protection on `main` currently requires **one** approving review plus Code Owners review plus the always-run status checks, because the maintainer roster cannot yet satisfy a two-review quorum — a setting that demanded two would be an overclaim the platform cannot deliver. The required count moves to two in the same change that names a second maintainer in `.github/CODEOWNERS`. **Ruled 2026-08-29: the seat is held DELIBERATELY — the project runs solo within the Squillo organization for now.** This is a standing decision, not a pending search; RFC Decision blocks cite it rather than implying a candidate hunt is underway, and the ruling is revisited when the ruling-maker revisits it. Maintainer direct pushes remain possible (`enforce_admins` off); that exemption now ends when the solo ruling does, since the versioning exception below closed with the 0.1 cut.
- **Pre-production exception — CLOSED 2026-08-29 by the 0.1 cut**, before its original expiry trigger (the first wire-asserting external adopter) fired. While it was in force: APH had no such adopters, so a correction to a design defect landed **in place** in the current draft rather than forking a version — one specification a reader can trust, instead of two they must reconcile. Such a change still requires the pull request and the two approvals; what it skips is the version bump. It MUST be recorded as a dated revision entry in `CHANGELOG.md` and in the spec's revision banner. **The exception is now closed**: the spec left draft at v0.1.0 final (2026-08-29), and the versioning rules below apply without exception from that cut — chosen deliberately ahead of the adopter trigger rather than discovered after it.
  - *What "depends on the wire format" means, made precise by the first downstream report ([#1](https://github.com/squillo/aph/issues/1)).* The test is whether a wire change would **break** them or merely **cost them a documentation edit**. A consumer that defines its own terms by CITATION to a section here — and mints, parses, verifies, and asserts nothing — is a documentation-only consumer: a correction costs them an edit, and the exception survives. The exception expires when someone outside ships an artifact that **asserts wire facts**: code that mints, parses, or verifies an envelope; a schema or receipt carrying `aphVersion`, `attestationMode`, `bodySha256`, or an `APH_E*` code as data; or conformance vectors containing real envelope bytes. That distinction is not a loophole — it is the difference between a dependency that a fix repairs and one that a fix strands.
  - *What we ask of consumers, so this is never discovered after the fact:* tell us **before** you ship anything that asserts wire facts, not after. The first downstream consumer made exactly that commitment and it is the pattern we will ask of the next one — an exception that expires on an event nobody reports is an exception that expired silently. And **gate what you mint**: `your-minter | aph validate --json -` fails your build on a refusal and names the field, the value, and the closed set that refused it, so a disagreement with the wire format surfaces in your own CI rather than in an issue weeks later. The recipe is in [README.md](README.md#gate-your-own-envelopes-in-your-own-ci).
- Patch-level edits (typographical fixes, clarifications that do not change conformance) require one maintainer approval.
- Any change that alters the example envelopes' field set must also update the example JSON files in `examples/` to remain valid against the revised spec.

## Versioning

The protocol number follows [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html):

- A breaking change to the envelope wire shape, the role set, or the state machines bumps the MINOR version while the protocol is in the `0.x` series (for example `0.1.0` → `0.2.0`), and bumps the MAJOR version once the protocol reaches `1.0.0`.
- A **new optional field** bumps the MINOR version at `1.x` and above, and the PATCH at `0.x`. This is the genuinely backward-compatible case: a verifier that has not updated ignores the field and reaches the same verdict it reached before.
- A **new value in one of §7.1's closed vocabularies** — a channel kind, a content class — bumps the MINOR version at every series, `0.x` included, matching §7.1.5's own statement that new channel kinds are "additive in 0.x minor versions". *(Corrected 2026-08-28: this line previously grouped closed-vocabulary values with new optional fields and assigned both the PATCH at `0.x`, which contradicted the specification and understated the change.)*
  - The two are not the same event, and grouping them was the defect. A new optional field is additive for everyone. A new closed-vocabulary value is additive for the PRODUCER and **refusing** for any consumer that has not updated: §7.1's closed sets require a verifier to reject a value it does not recognize, and since the reference implementation models them as types, that rejection happens at strict parse — before the protocol's own error vocabulary is reachable. Which is why `aph validate --json` reports it as `reason: "closed_set"` — carrying the offending value and the whole allowed set — and never as an `APH_E` code: there is no code below step 1 to report ([README.md](README.md#reading-the-verdict-from-a-build)). An addition that turns a working verifier into a refusing one is not a patch, whatever else it is.
  - Which is why such a change also owes a **producer rule**: a producer MUST NOT emit a new closed-vocabulary value until it has reason to believe the recipient understands it. Without one, adding any value is a flag day for every deployed verifier. The AgentCard extension declaration (§10.1) is the existing discovery mechanism for that belief.
- A clarification, typographical fix, or example correction bumps the PATCH version.

The version of the protocol is reflected both in the `aphVersion` envelope field and in the spec document filename (`spec/aph-0.1.md`, and `spec/aph-0.2.md` when that version exists). There is one spec document per protocol version — never an amendment document alongside it.

## Code of conduct

We expect respectful, professional collaboration. See the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) for guidance on community expectations.
