# Contributing to APH

Contributions to the APH specification, examples, and tests are welcome via pull request.

## Process

- Pull requests target the `main` branch.
- Every commit MUST carry a `Signed-off-by:` line (Developer Certificate of Origin). Configure with `git commit -s`.
- Maintainers from Squillo, Inc. review and merge.
- For substantive discussion, open a GitHub issue before opening a PR so the design conversation lives in the issue tracker. Three issue forms carry the process: **RFC** for any change to normative text (the request-for-change entry point — problem, proposal, compatibility, security, in that order), **Erratum** for spec text that is simply wrong, and **Conformance disagreement** for an implementation that disagrees with a published artifact. Review routing is codified in `.github/CODEOWNERS`; the PR template restates the approval bar at the moment it applies.

## Scope

This repository carries the APH **specification**, **example envelopes**, **conformance tests**, the **N Lang type Snapp** under `APH Spec/`, and the **reference Rust implementation** under `interpreters/rust/`. Other implementations (SDKs in other languages, notary services, channel-adapter integrations) live in separate repositories and are not in scope here.

## Spec changes

- Changes to the on-wire envelope shape, the set of permitted signature algorithms, the protocol state machines, or any other normative MUST/SHALL clause require a pull request, two maintainer approvals, and a version bump.
  - *Enforcement status, kept honest:* branch protection on `main` currently requires **one** approving review plus Code Owners review plus the always-run status checks, because the maintainer roster cannot yet satisfy a two-review quorum — a setting that demanded two would be an overclaim the platform cannot deliver. The required count moves to two in the same change that names a second maintainer in `.github/CODEOWNERS`. Maintainer direct pushes remain possible (`enforce_admins` off) while the project is pre-adoption; that exemption ends on the same trigger as the versioning exception above.
- **Pre-production exception, in force until the first external adopter.** APH has no external adopters, so a correction to a design defect lands **in place** in the current draft rather than forking a version — one specification a reader can trust, instead of two they must reconcile. Such a change still requires the pull request and the two approvals; what it skips is the version bump. It MUST be recorded as a dated revision entry in `CHANGELOG.md` and in the spec's revision banner. **This exception expires the moment someone outside this repository depends on the wire format**, after which the versioning rules below apply without exception.
- Patch-level edits (typographical fixes, clarifications that do not change conformance) require one maintainer approval.
- Any change that alters the example envelopes' field set must also update the example JSON files in `examples/` to remain valid against the revised spec.

## Versioning

The protocol number follows [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html):

- A breaking change to the envelope wire shape, the role set, or the state machines bumps the MINOR version while the protocol is in the `0.x` series (for example `0.1.0` → `0.2.0`), and bumps the MAJOR version once the protocol reaches `1.0.0`.
- A backward-compatible addition (a new optional field, a new channel binding, a new content class) bumps the MINOR version at `1.x` and above, and the PATCH at `0.x`.
- A clarification, typographical fix, or example correction bumps the PATCH version.

The version of the protocol is reflected both in the `aphVersion` envelope field and in the spec document filename (`spec/aph-0.1.md`, and `spec/aph-0.2.md` when that version exists). There is one spec document per protocol version — never an amendment document alongside it.

## Code of conduct

We expect respectful, professional collaboration. See the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) for guidance on community expectations.
