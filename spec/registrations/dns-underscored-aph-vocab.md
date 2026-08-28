# Underscored DNS Node Name Registration — APH vocabulary publication

**STATUS: DRAFT. NOT SUBMITTED. NOT REGISTERED.**

This is a prepared registration *request* for the IANA "Underscored and
Globally Scoped DNS Node Names" registry established by RFC 8552 §4.1,
covering the DNS name APH §8.5.1 publishes vocabulary digests at. Writing it
changes nothing: the label is reserved by convention and stays that way until
a human submits this request and the designated expert acts. A draft is not a
registration.

It is the **second** such request from this project, and the sibling —
`dns-underscored-aph.md`, covering `_notary` — carries the full working of
RFC 8552's subordinate-label rule. That reasoning is not repeated here; §1
below states only what differs, and a reader meeting this registry for the
first time should read the sibling first.

---

## 1. Why this is a SECOND registration and not an addendum to the first

This is the finding that shaped the request, and it was nearly missed.

RFC 8552 registers the underscored label **closest to the root**. For the
deployed key-publication name that is `_notary`:

```
_aph._notary.<domain>
```

Read toward the root that is `<domain>` → `_notary` → `_aph`.

The vocabulary name has the same two-label shape and the same subordinate
`_aph`, but a different label in the registrable position:

```
_aph._vocab.<domain>
```

Read the same way: `<domain>` → `_vocab` → `_aph`. **The registrable label is
`_vocab`, and it is a different label from `_notary`.** A registry entry names
one label; holding `_notary` grants the subordinate namespace beneath
`_notary`, and grants nothing at all beneath `_vocab`. So this needs its own
entry, its own expert review, and its own uniqueness check.

An earlier draft of RFC 0006 asserted the opposite — that the vocabulary name
would cost "one line in the same registration". That was wrong, and it is
recorded here rather than quietly fixed because the error had a deadline: it
was cheap to correct before the sibling request was submitted and would have
been expensive to discover afterward, when the namespace shape was already
committed.

**The alternative that was considered and declined.** Naming the surfaces
`_notary._aph.<domain>` and `_vocab._aph.<domain>` would put `_aph` in the
registrable position, so ONE registration of `_aph` would carry every present
and future subordinate name — a cleaner namespace, and one registration rather
than two. It was declined because `_aph._notary` is already published in live
DNS and shipped in released code, and reversing the label order would break a
deployed discovery surface to tidy a registry request. The consistency of the
two published names is worth more than the saved entry.

---

## 2. The registration request

```
RR Type:     TXT
_NODE NAME:  _vocab
Reference:   APH v0.1 specification, section 8.5.1 (vocabulary digest
             publication). Published at github.com/squillo/aph.
```

**Requester for IANA correspondence and expert review:** OPERATOR-FILLS.
Deliberately empty — the registry entry carries no contact field, but the
submission needs a human, and naming one here without their agreement would be
worse than leaving it blank.

**Supporting statement for the expert.** RFC 8552 §4.1.5 asks the expert to
confirm the details are "sufficiently clear, precise, and complete" and that
the combination of name, RR type and details is unique in the table. What the
reference defines:

- **Name form.** `_aph._vocab.<domain>`, where `<domain>` is the registrable
  domain of the vocabulary's publisher. One subordinate label, `_aph`, fixed
  as a literal — not a selector, not a version, not any other varying token.
  It is the same subordinate label the sibling request uses, which is the
  point: both APH discovery surfaces sit under one project-scoped label, in
  positions the registry treats independently.
- **Record content.** A single TXT string carrying a semicolon-separated
  tag-list, aligned with DKIM's tag-list syntax (RFC 6376 §3.6.1) for operator
  familiarity, and identical in shape to the sibling's. Required tags: `v`
  (version literal `APHv1`), `n` (vocabulary name), `ver` (vocabulary
  version), `h` (the published bundle's integrity digest, in the
  Subresource-Integrity form `sha256-<base64>`). No optional tags in v0.1.
- **Multiplicity.** Multiple TXT records MAY coexist at the same name, one per
  published vocabulary or version. Resolvers select on `n` and `ver` together
  and MUST refuse rather than guess when two records claim the same `n`+`ver`
  pair with different digests — ambiguity about which bytes a name refers to
  is treated as corruption, not as a choice.
- **Size.** A record MUST fit a single 255-byte character-string. This is a
  constraint the specification imposes on itself rather than one the registry
  imposes: a digest split across strings would require a concatenation rule,
  and a concatenation rule that two implementations read differently is an
  interop defect that surfaces only between strangers.
- **Uniqueness.** No existing entry in the registry uses `_vocab`. The
  registrant must re-confirm this at submission time, and should note that
  `_vocab` is a generic English word — if the expert considers it too generic
  for a globally scoped name, this project would rather be told at review than
  hold a label another protocol has a better claim to.

---

## 3. What holding `_vocab` does and does not grant

Per RFC 8552 §2, a registered global underscored node name owns a distinct
subordinate namespace. So registering `_vocab` grants `_aph._vocab` and any
future name APH defines beneath `_vocab`, exactly as registering `_notary`
grants `_aph._notary`.

It grants nothing beneath `_notary`, and holding `_notary` grants nothing
beneath `_vocab`. The two entries are independent, and a reader of either
request should not infer the other has been made.

**Neither entry is a claim on `_aph` itself.** As the sibling request works
through in its §3, `_aph` is not separately registrable — APH defines no
record directly at `_aph.<domain>` — and does not need to be. §13's
reservation of `_aph` is honoured derivatively, as a consequence of holding
the labels above it, and a standalone `_aph` request would be the wrong
instrument rather than a missing one.

---

## 4. Submission is user-owned

Nothing here is submitted by tooling. The sequence is the sibling's: a human
re-confirms uniqueness against the live registry, fills the requester, sends
the request to IANA, and only then may §13 describe `_vocab` as registered
rather than drafted. Until the designated expert acts, the label is
unregistered and the name is not APH's — and the specification says so in
those words.
