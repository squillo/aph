# Underscored DNS Node Name Registration — APH key publication

**STATUS: DRAFT. NOT SUBMITTED. NOT REGISTERED.**

This is a prepared registration *request* for the IANA "Underscored and
Globally Scoped DNS Node Names" registry established by RFC 8552 §4.1,
covering the DNS name APH v0.1 §8.4.5 publishes notary public keys at.
Writing it changes nothing: the labels are reserved by convention and stay
that way until a human submits this request and the designated expert acts.
A draft is not a registration.

The registry entry itself carries no contact field — RFC 8552 §4.1.1 defines
exactly three, and none of them is an identity. The *submission* still needs a
requester for IANA correspondence and for the expert review exchange, and that
is marked **OPERATOR-FILLS** below and left empty on purpose.

---

## 1. What RFC 8552 registers — and the finding that follows

The registry (RFC 8552 §4.1) "includes any DNS node name that begins with the
underscore character ... and is the underscored node name closest to the
root", and operates under Expert Review. RFC 8552 §1.3 defines that name — the
*global* underscored node name — as "the one that is closest to the root of
the DNS hierarchy", which in ordinary presentation order is "the rightmost
name beginning with an underscore". §2 then rules the others out of the table
in as many words: a subordinate name "is meaningful only within the scope of
the global underscored node name. Therefore, they are ignored by this
'Underscored and Globally Scoped DNS Node Names' registry."

APH v0.1 §8.4.5 publishes at:

```
_aph._notary.<domain>
```

Read toward the root that is `<domain>` → `_notary` → `_aph`. **The label
closest to the root is `_notary`, not `_aph`.** The entry RFC 8552 requires
for the deployed name is therefore `TXT` / `_notary`, and `_aph` sits in the
subordinate position — the position a DKIM selector or a TLSA port number
occupies — which the registry does not carry.

This is worth stating plainly because it inverts the shape of the precedents
§13 cites:

| Published name | Label closest to root | Registry entry | Subordinate label |
|---|---|---|---|
| `<selector>._domainkey.<domain>` (DKIM, RFC 6376) | `_domainkey` | TXT `_domainkey` | the selector |
| `_dmarc.<domain>` (DMARC, RFC 7489) | `_dmarc` | TXT `_dmarc` | none |
| `_<port>._tcp.<domain>` (TLSA, RFC 6698) | `_tcp` | TLSA `_tcp` | the port label |
| `_aph._notary.<domain>` (APH §8.4.5) | `_notary` | TXT `_notary` — this request | `_aph` |

DKIM, DMARC and TLSA all put the protocol-or-registry-owned token closest to
the root and vary the label beneath it. APH puts the generic token closest to
the root and the protocol token beneath it. §4 below treats that as the open
question it is; it is not decided in this file.

---

## 2. The entry requested (RFC 8552 §4.1.1)

RFC 8552 §4.1.1 defines three fields: RR Type, `_NODE NAME` (recorded in
lowercase, "to simplify name comparisons"), and Reference — the specification
that "defines a record type and its use under this _Node Name". It also
requires "a separate registry entry" for *each* RR TYPE used with a node name.
APH §8.4.5 publishes key material in TXT and nothing else, so exactly one
entry is requested; a future revision that put another RR TYPE at the same
name would file a second entry, not amend this one.

```
RR Type:     TXT
_NODE NAME:  _notary
Reference:   APH v0.1 specification, section 8.4.5 (DNS TXT — DKIM-style
             publication). Published at github.com/squillo/aph.
```

**Supporting statement for the expert.** RFC 8552 §4.1.5 asks the expert to
confirm that "the details for creating the registry entry are sufficiently
clear, precise, and complete" and that the combination of name, RR type and
details is unique in the table. What the reference defines:

- **Name form.** `_aph._notary.<domain>`, where `<domain>` is the registrable
  domain of the notary's `did:web` identifier, or the domain operationally
  controlled by the notary operator where there is no `did:web`. One
  subordinate label, `_aph`, fixed as a literal — it is not a selector, a
  port number, or any other varying token.
- **Record content.** A single TXT string carrying a semicolon-separated
  tag-list, aligned with DKIM's tag-list syntax (RFC 6376 §3.6.1) for operator
  familiarity. Required tags `v` (version literal `APHv1`), `alg` (`ed25519`
  or `p256`), `k` (public key bytes, base64url per RFC 7515 §2, unpadded).
  Optional tags `did`, `kid`, `notBefore`, `notAfter`.
- **Multiplicity.** Multiple TXT records MAY coexist at the same name, one per
  active key; verifiers iterate all returned records, select by `kid`, and
  validate the `notBefore`/`notAfter` window before attempting signature
  verification.
- **Uniqueness.** No existing entry in the registry uses `_notary`; the
  registrant must re-confirm this at submission time (§6 step 1).

---

## 3. `_aph` is not separately registrable — and does not need to be

Spec §13 states that v0.1 "reserves the underscore-prefixed labels `_aph` and
`_aph._notary` by convention". The deployed name carries two underscored
labels, and that reservation names one of them plus the compound of both — so
three things, which the registry treats three different ways: one directly,
one not at all, one derivatively.

- `_notary` — **registrable directly**, as §2.
- `_aph._notary` — **not a registry entry at all.** RFC 8552 registers single
  labels, not compound names; the compound is described inside the reference,
  not registered as a name.
- `_aph` — **not separately registrable, and it does not need to be.** RFC
  8552 §4.1.1 requires the Reference to be the specification defining "a
  record type and its use *under this _Node Name*". APH defines no record at
  `_aph.<domain>`, so a standalone request would carry an RR type with nothing
  behind it and should fail §4.1.5's "clear, precise, and complete" test. But
  the registry already grants what the reservation is reaching for, one level
  up: §2 assigns "definition and registration of subordinate underscored node
  names" to "the specification that creates the global underscored node name
  registry entry", and states that "each registered global underscored node
  name owns a distinct, subordinate namespace". Registering `_notary` *carries*
  `_aph` with it. The subordinate label is APH's to define by the registry's
  own rule, and a second entry would be the wrong instrument, not a missing
  one.

Two things follow, and the second is the one to carry into §4.

**§13's reservation of `_aph` is honoured, but derivatively.** It is a
consequence of holding `_notary`, never an independent claim on the label, and
a speculative standalone entry filed to hold the name would be name-squatting
through a registry that reviews explicitly for completeness — it would deserve
the rejection it got.

**The dependency runs the wrong way for APH.** Because subordinate namespaces
belong to whoever holds the global name, the first party to register `_notary`
owns the namespace `_aph` sits in. Losing that label to another filer would
not merely cost APH a name it had reserved; it would leave APH's subordinate
label inside a namespace another specification controls. That is the real
stake in §4, and it is larger than a naming preference.

---

## 4. `_notary` is the weak point of this request — stated, not hidden

`_notary` is a generic English noun with no protocol affiliation. Any other
protocol that wants a notary-shaped DNS branch wants the same label, and the
first one to file gets it — along with, per §3, the subordinate namespace
`_aph` lives in. APH is asking the registry for a common word, and asking it
to be the foundation of a namespace, in the same entry.

RFC 8552 §4.1.5 scopes the expert's job narrowly — entry adequacy and
uniqueness, explicitly *not* a technical quality judgement on the referenced
specification — so there is no sentence in RFC 8552 that forbids a generic
name. The instinct is written down in the neighbouring registry's guidelines
instead; RFC 7595 §3.8, on URI scheme names, says schemes "SHOULD NOT use
names that are either very general purpose or associated in the community with
some other application or protocol". No such rule binds this request. The
reviewer reading it is the same kind of reviewer.

Two options, **for the specification owner, not decided here:**

**(a) Submit as drafted.** Request `TXT` / `_notary`. Matches every record
APH has published, matches the live deployment, costs nothing, and carries the
generic-name objection into expert review where it may or may not survive.

**(b) Invert the name in a specification revision** to
`_notary._aph.<domain>`, making the registered entry `TXT` / `_aph` — the DKIM
shape exactly, protocol token closest to the root, category label beneath it.
It answers both halves of the objection at once: `_aph` is an initialism no
other specification is competing for, and under §2's subordinate-namespace
rule APH would own the namespace rather than renting a label inside one — the
`_notary` beneath it becomes APH's to define, as `_aph` is under option (a).
The cost is a wire change: every published TXT record moves, every verifier's
query name changes, and a v0.1 verifier querying `_aph._notary` finds nothing
at a notary that has moved. §8.4.6's no-downgrade rule bounds the blast radius
— *absence* at the DNS surface advances the resolution sequence rather than
failing it, so a v0.1 verifier degrades to `did:web` instead of refusing a
good envelope — which makes this a discovery-coverage loss rather than a
verification outage. It is still a break, and v0.1's own §8.4.7 rotation
overlap has no equivalent mechanism for moving a *name*.

Deciding between them is a wire-shape question with live published records
behind it, which is why this file records the finding and stops. Option (a) is
what §2 is written as, because it is what is deployed; if (b) is chosen, §2's
`_NODE NAME` becomes `_aph` and everything else in this document survives
unchanged.

---

## 5. What a collision costs (unchanged by this draft)

Unchanged from `operations.md` §6 and the README, and repeated here so a
reader who arrives at this file first is not misled by its optimism:

- **A foreign record at a colliding name is not a misparse risk.** A
  conformant parser refuses any record whose `v` tag is not `APHv1` (§8.4.5
  step 3a), so an unrelated record at the same name is ignored rather than
  read as a key. Publishing a foreign key there is not a way to make a
  verifier accept it.
- **The real cost is name ownership.** If the label is later assigned
  elsewhere, APH moves and every published record is reissued.
- **Nothing here affects whether an envelope verifies.** Key discovery is one
  input to verification; registration status is not an input to anything.

---

## 6. Before submitting

1. **Check the registry** for an existing entry under the label being
   requested. Uniqueness of the name/RR-type combination is explicitly in the
   expert's scope (RFC 8552 §4.1.5), so a collision found late is found by
   the reviewer.
2. **Settle §4 first.** The request names one label and the (a)/(b) decision
   changes which one. Submitting (a) and then choosing (b) means withdrawing
   an entry.
3. **Fix the Reference to something citable, and check it against the harder
   requirement.** RFC 8552 §4.1.1 wants the specification that defines the
   use, but §4.1 adds a MUST the field name does not advertise: "The required
   Reference for an entry MUST have a stable resolution to the organization
   controlling that registry entry." A repository URL under an account that
   can be renamed, transferred or deleted resolves stably only as long as
   nobody does any of those. Cite a specific commit or release tag rather than
   a branch so the reference names bytes that do not move, and be ready for
   the expert to ask what makes the *location* durable.
4. **Fill OPERATOR-FILLS:** the requester's name and working contact
   information, for IANA correspondence and the expert review exchange. This
   draft does not supply one — an invented contact is worse than a missing
   one, because a missing one blocks submission.
5. **Submit to IANA** and expect the §4 question to come back. Have the answer
   ready rather than discovering it during review.
6. **When the entry appears**, flip every surface that carries the status to
   the registry citation, and delete this section. The surfaces are enumerated
   once, in `README.md` in this directory, because a partial sweep is how a
   repository ends up claiming two different things about the same name.
