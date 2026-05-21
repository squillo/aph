# Contributing to APH

Contributions to the APH specification, examples, and tests are welcome via pull request.

## Process

- Pull requests target the `main` branch.
- Every commit MUST carry a `Signed-off-by:` line (Developer Certificate of Origin). Configure with `git commit -s`.
- Maintainers from Squillo, Inc. review and merge.
- For substantive discussion, open a GitHub issue before opening a PR so the design conversation lives in the issue tracker.

## Scope

This repository carries the APH **specification**, **example envelopes**, and **conformance tests**. Reference implementations (SDKs, notary services, channel-adapter integrations) live in separate repositories and are not in scope here. A pull request that adds implementation code to this repo will be redirected to the appropriate implementation repository.

## Spec changes

- Changes to the on-wire envelope shape, the set of permitted signature algorithms, the protocol state machines, or any other normative MUST/SHALL clause require a pull request, two maintainer approvals, and a version bump.
- Patch-level edits (typographical fixes, clarifications that do not change conformance) require one maintainer approval.
- Any change that alters the example envelopes' field set must also update the example JSON files in `examples/` to remain valid against the revised spec.

## Versioning

The protocol number follows [Semantic Versioning 2.0](https://semver.org/spec/v2.0.0.html):

- A breaking change to the envelope wire shape, the role set, or the state machines bumps the MINOR version while the protocol is in the `0.x` series (for example `0.1.0` → `0.2.0`), and bumps the MAJOR version once the protocol reaches `1.0.0`.
- A backward-compatible addition (a new optional field, a new channel binding, a new content class) bumps the MINOR version at `1.x` and above, and the PATCH at `0.x`.
- A clarification, typographical fix, or example correction bumps the PATCH version.

The version of the protocol is reflected both in the `aphVersion` envelope field and in the spec document filename (`spec/aph-0.1.md`, `spec/aph-0.2.md`, …).

## Code of conduct

We expect respectful, professional collaboration. See the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) for guidance on community expectations.
