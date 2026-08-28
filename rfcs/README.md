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

   A change request also arrives, in practice, as an **implementer report** —
   someone who hit the problem while building against the spec, writing it up
   where they found it rather than on our form. That is a proposal and is
   treated as one; a maintainer opens the issue on their behalf so the
   discussion has a public home. An implementer who took the trouble to
   report a real defect should not also have to learn our intake.
2. **Discuss** — in the issue. Maintainers and any implementer affected.
3. **Decide** — a maintainer accepts or rejects, and the decision is recorded
   in **the RFC document's own `Decision` block**: the date, who decided,
   what was decided, and any limitation the decision was made under.

   The document is where the decision lives because a `Status:` word with no
   reasoning beside it is not a record — it is an assertion, and a reader who
   later asks *why* has nowhere to look. Where an issue exists it holds the
   conversation and the decision is cross-linked; where one does not, the
   block is still the record and says so.
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

**A note on the RFCs numbered below 0006.** They were written before this
directory had an issue practice, and none of them has an issue thread: they
arrived as implementer reports or as design work done in place, and were
decided the same way. Their `Decision` blocks say so explicitly rather than
implying a deliberation that did not happen. Issues are opened for RFCs from
0006 onward. This note stays until it stops being true, because a process
document that describes a practice nobody followed is the same defect as a
specification guarantee that lives only in prose.

## Index

| RFC | Title | Status |
|---|---|---|
| [0001](0001-rotation-attestation.md) | Signed rotation attestation (v0.2 candidate) | Draft |
| [0002](0002-service-act-channel.md) | A service-act channel binding | **Accepted** |
| [0003](0003-audience-and-single-use.md) | Audience binding and single-use envelopes | Draft |
| [0004](0004-vendor-extension-channel-kind.md) | A vendor-extension arm for `ChannelKind` | Rejected |
| [0005](0005-recipient-class.md) | Recipient class: who is on the other end of the medium | Draft |
| [0006](0006-published-guardrail-vocabularies.md) | Published guardrail vocabularies: meaning as a resolvable third party | Draft |
| [0007](0007-in-app-channel-kind.md) | A channel kind for an in-application messaging surface | **Accepted** |
