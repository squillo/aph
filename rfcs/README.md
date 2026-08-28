# APH RFCs — the design record

This directory is the durable half of the request-for-change process. The
[RFC issue form](../.github/ISSUE_TEMPLATE/rfc.yml) is where a change is
*proposed* and discussed; this directory is where an *accepted* design lands
as a numbered document — and where a rejected one leaves its reasoning, which
is often worth more than an acceptance.

The two halves deliberately hold different things, so they cannot drift: the
issue holds the CONVERSATION (alternatives raised, objections, revisions);
the document here holds the DECISION as accepted, in its final form. Where
they disagree, the document is what was accepted, and the issue is history.

## Lifecycle

1. **Propose** — open an [RFC issue](../../issues/new?template=rfc.yml).
   Problem first, proposal second, compatibility and security stated. A
   change without a named problem is a preference.
2. **Discuss** — in the issue. Maintainers and any implementer affected.
3. **Decide** — a maintainer marks the issue accepted or rejected, with the
   reasoning in the thread.
4. **Record** — an accepted RFC lands here as `NNNN-short-name.md` via pull
   request (next number, zero-padded to four digits), together with any
   normative change it drives; the CHANGELOG's dated revision entry cites the
   RFC number. A rejected RFC MAY land here too when the reasoning deserves a
   findable home — marked `Status: Rejected`, because the strongest argument
   against re-litigating a decision is the record of why it was made.
5. **Implement** — spec text and implementations move under the normal
   review rules ([CONTRIBUTING.md](../CONTRIBUTING.md)); the RFC document is
   the design's record, never a second normative source. Where an RFC and
   the specification disagree, the specification wins and the RFC is
   historical.

Start from [`0000-template.md`](0000-template.md). The template's sections
mirror the issue form's required fields on purpose — an RFC that survived the
issue stage already has every section drafted.

## Index

| RFC | Title | Status |
|---|---|---|
| [0001](0001-rotation-attestation.md) | Signed rotation attestation (v0.2 candidate) | Draft |
| [0002](0002-service-act-channel.md) | A service-act channel binding | Draft |
| [0003](0003-audience-and-single-use.md) | Audience binding and single-use envelopes | Draft |
