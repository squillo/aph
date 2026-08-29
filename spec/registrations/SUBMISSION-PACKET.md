# Submission packet — the three registrations, one sitting

**STATUS: PREPARED 2026-08-29. NOT SUBMITTED.** Submission is user-owned by
each draft's own terms; this file exists so the sitting takes minutes, not an
afternoon. Each draft below remains the source of truth for its request body
— this packet holds only the sequencing, the re-checks, and the blanks.

The spec is v0.1.0 FINAL (cut 2026-08-29), so every request now cites a
frozen document rather than a moving draft.

## The one blank in all three

**Requester** (name + email for IANA correspondence and expert review):
deliberately empty in every draft — fill at send time. All three may name the
same person.

## 1. `aph://` — provisional URI scheme (RFC 7595)

- **Request body:** [`uri-scheme-aph.md`](uri-scheme-aph.md) §2 (the
  completed template). Its §1 "Before submitting" is the checklist; do it in
  order.
- **Re-checks at send time:** the scheme is still absent from the
  [IANA URI Schemes registry](https://www.iana.org/assignments/uri-schemes);
  the trademark note in its §"Trademark" is confirmed.
- **Optional first:** circulate to `uri-review@ietf.org` (RFC 7595 §7.2
  RECOMMENDS four weeks; provisional registration does not require it — the
  draft's §1.3 states the tradeoff; sending without it is a legitimate
  choice for a provisional entry).
- **Send to:** `iana@iana.org`, subject:
  `Provisional URI scheme registration request: aph`

## 2. `_notary` — underscored node name (RFC 8552 §4.1)

- **Request body:** [`dns-underscored-aph.md`](dns-underscored-aph.md) §5
  (the entry) with §§1–4 as the expert's supporting statement. Its §6
  "Before submitting" is the checklist.
- **Re-check at send time:** no `_notary` row for RR type TXT in the
  [Underscored and Globally Scoped DNS Node Names registry](https://www.iana.org/assignments/dns-parameters).
- **Send to:** `iana@iana.org`, subject:
  `Underscored DNS node name registration request: _notary (TXT)`

## 3. `_vocab` — underscored node name (RFC 8552 §4.1), SECOND entry

- **Request body:** [`dns-underscored-aph-vocab.md`](dns-underscored-aph-vocab.md)
  §2 with §§1 and 3 as the supporting statement. Read its §1 before sending:
  it is a SECOND registration, not an addendum, and the request itself
  explains why.
- **Re-checks at send time:** no `_vocab` row for RR type TXT in the same
  registry; and note to the expert, as the draft already does, that
  `_vocab` is a generic English word — if the expert considers it too
  generic, this project would rather be told at review.
- **Send to:** `iana@iana.org`, subject:
  `Underscored DNS node name registration request: _vocab (TXT)`

## After sending

For each acknowledged registration, flip the corresponding §13 row in
`spec/aph-0.1.md` from *drafted* to *submitted* (and later *registered*) as a
dated erratum — status rows describing external registries are records of
fact, not normative changes, so they move without a version bump. Until the
designated expert acts, the labels remain unregistered and the specification
keeps saying so.
