# Registration drafts

Prepared IANA registration **requests** for the two identifiers APH v0.1 uses
by convention. Spec §13 names both; these files are the documents §13 promises.

| File | Registry | Requests |
|---|---|---|
| `uri-scheme-aph.md` | Uniform Resource Identifier (URI) Schemes | Provisional registration of the `aph` scheme, on the six-field template in RFC 7595 §7.4 (the procedure that consumes it is §7.2) |
| `dns-underscored-aph.md` | Underscored and Globally Scoped DNS Node Names | A `TXT` entry for `_notary`, per RFC 8552 §4.1.1 — which is the label APH §8.4.5's `_aph._notary.<domain>` actually registers, for the reason below |

## Nothing here is registered

**Submission is pending and the exposure is unchanged.** A draft is not a
registration: until the entries appear in the IANA registries, APH does not
own either name, a later assignment to another party forces APH to move, and
every surface that states that risk keeps stating it, unedited. These files
exist so that submitting is a decision rather than a project; they do not
advance the status by themselves.

**Submitting is a human act, and deliberately not automated.** Both processes
want a real identity — RFC 7595 §4 requires contact information identifying
the registrant and §7.4 requires a change controller; the RFC 8552 entry
carries no contact field but the submission still needs a requester. Each file
marks those fields **OPERATOR-FILLS** and leaves them empty. An absent contact
blocks submission; an invented one gets submitted.

## The surfaces that carry this status

Enumerated rather than remembered, because the flip happens twice — once now
(deferred → drafted) and once when IANA acts (drafted → the registry citation)
— and a half-swept repository claims two things about the same name. **Six
surfaces state the registration status of these two identifiers. All six now
carry the drafted wording; the sweep is closed.**

| Surface | Wording today |
|---|---|
| `spec/aph-0.1.md` §13 — the URI-scheme and DNS-underscore paragraphs | drafted, submission pending |
| `spec/aph-0.1.md` Appendix B — the registration Future Work bullet | drafted, not submitted; names both files and carries the open DNS naming question |
| `README.md` (repository root), Status section | drafted, not submitted |
| `spec/operations.md` §6 — the intro paragraph and both table rows | drafted, not submitted |
| `spec/security-considerations.md` — the out-of-scope entry for APH's own identifiers | drafted, submission pending; stays an open item |
| `skills/spec/SKILL.md` — "Unregistered conventions an adopter inherits" | drafted, submission pending; warns against rounding up to "registered" |

None of the six changed what it says about the **risk**, because the risk did
not change: each described the exposure correctly before and describes it
identically now. What moved is the **action**, from deferred to drafted, and
nothing else moved with it.

Three of them had been stale in a sharper way than wording and were corrected
first. They did not merely *say* "deferred" — they attributed the deferral **to
§13**: `operations.md` §6 said "§13 defers exactly **two** to v0.2",
`skills/spec/SKILL.md` said "the two §13 actually defers to v0.2", and
`security-considerations.md` said "registration deferred to v0.2 (§13)". §13
had stopped saying that, so each was a false statement about a section of this
specification rather than merely old news, and a reader following the
cross-reference found the opposite of what was promised.

Appendix B had been stale by omission instead of by contradiction: it described
the registration fairly but named no draft and left the DNS request out
entirely, while the adjacent key-rotation bullet already named its own design
draft. It now names both files and inherits the `_notary` naming question,
which is a wire-shape decision and therefore genuinely future work.

**When IANA acts, all six flip again** — drafted → the registry citation. That
second flip is what this table exists for; it is not a record of a finished
job.

`CHANGELOG.md` also contains the phrase in dated historical entries; those are
records of what was true then and are left alone.

## Read the findings, not just the templates

Neither file is only a filled-in form. Each carries the objections a reviewer
will raise, because a request that gets bounced was not ready:

- **`aph://` uses the `//` form**, so a generic RFC 3986 parser reads
  `extensions` as an authority. Harmless only because §13 forbids
  dereferencing — the opacity rule is the mitigation, not the syntax.
- **RFC 8552 registers the underscored label closest to the root**, which for
  `_aph._notary.<domain>` is `_notary`, not `_aph`. That inverts the DKIM
  shape §13 cites as precedent. `_aph` is not separately registrable, but it
  does not need to be: RFC 8552 §2 gives each registered global name "a
  distinct, subordinate namespace", so registering `_notary` carries `_aph`
  with it. The same rule is the request's weak point — `_notary` is a generic
  noun, and the first party to file owns the namespace `_aph` lives in.
  Whether to keep the name or invert it to `_notary._aph` is an open
  wire-shape question left to the specification owner, and the DNS file
  refuses to decide it.

Each file opens with a pre-submission checklist ending in the same step: when
an entry appears, flip every surface in the table above, and delete the
checklist.
