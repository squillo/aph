# Provisional URI Scheme Registration — `aph`

**STATUS: DRAFT. NOT SUBMITTED. NOT REGISTERED.**

This is a prepared registration *request* for the `aph` URI scheme, written
against the template in RFC 7595 §7.4 and the guidelines in RFC 7595 §3 and
§4. Writing it changes nothing about the scheme's standing. `aph://` is a
convention in APH v0.1 and stays one until a human submits this request and
IANA acts on it; spec §13, `operations.md` §6 and the README say so and
continue to say so. A draft is not a registration.

**Submission is deliberately not automated.** RFC 7595 §4 requires contact
information identifying the registrant and §7.4 requires a change controller.
Both are identity claims, and no tooling in this repository is permitted to
invent one — an absent contact blocks submission, an invented contact gets
submitted. The two fields are marked **OPERATOR-FILLS** and left empty on
purpose.

---

## 1. Before submitting

1. **Check the registry first.** RFC 7595 §7.2 step 1: look for an existing
   `aph` entry in the IANA "Uniform Resource Identifier (URI) Schemes"
   registry. Provisional registration requires that "there must not already
   be an entry with the same scheme name" (RFC 7595 §4). If `aph` is taken,
   this request cannot proceed under this name and the protocol changes its
   scheme — see §3.9 below for why that is survivable.
2. **Fill both OPERATOR-FILLS fields** with a real person and working contact
   information.
3. **Optionally circulate to `uri-review@ietf.org`.** RFC 7595 §7.2 attaches
   the four-week review step to *permanent* registrations; a provisional
   request is not required to go through it. Sending it anyway costs nothing
   and surfaces an objection before IANA does.
4. **Submit to `iana@iana.org`** (RFC 7595 §7.2 step 4). Where the request is
   provisional and no entry already exists under the name, IANA adds it under
   First Come First Served.
5. **When the entry appears**, flip every surface that carries the status to
   the registry citation, and delete this section. The surfaces are enumerated
   once, in `README.md` in this directory, because a partial sweep is how a
   repository ends up claiming two different things about the same name.

---

## 2. The registration template (RFC 7595 §7.4)

RFC 7595 §7.4 defines exactly six fields — scheme name, status,
applications/protocols, contact, change controller, references. This block is
the whole submission; everything in §3 below is supporting material that
answers the RFC 7595 §3 guidelines, which §4 asks a provisional request to
address but which the template itself does not carry as fields.

RFC 7595 §8.1 is the registration request for the `example` scheme, written
on this template, and is the worked model: six labelled fields and nothing
else, several of them a single line (its `Contact:` is literally `N/A`). If a
reviewer wants the §3 material, it is in this document to hand over; it does
not belong inside the template block.

```
Scheme name:
  aph

Status:
  Provisional

Applications/protocols that use this scheme name:
  The APH (Agent per Human) notarization protocol uses "aph:" URIs as
  protocol-level identifiers, compared as opaque literals and never
  dereferenced. APH v0.1 defines exactly one such identifier:

    aph://extensions/notarization/v1

  which is the extension URI an agent declares in its Agent2Agent (A2A)
  AgentCard under capabilities.extensions to advertise that its outbound
  messages carry APH notarization envelopes (APH v0.1 §10.1 and the
  companion document a2a-extension.md). The same string also names the
  A2A message metadata key the envelope itself travels under. A receiving
  agent's only defined operation on the URI, in either position, is
  equality against the published constant.

Contact:
  OPERATOR-FILLS — a named individual with working email address. This
  draft does not supply one; see the note at the top of this file.

Change controller:
  OPERATOR-FILLS — the organization maintaining the APH specification,
  with contact information. The specification names Squillo, Inc. as the
  maintainer of the v0.1 draft; the registration still needs a named
  contact at that organization rather than the organization alone.

References:
  APH v0.1 specification, sections 10.1 (A2A composition) and 13 (IANA
  Considerations), and the companion document a2a-extension.md section 2
  (Extension URI). Published at github.com/squillo/aph.

  Note for the registrant: RFC 7595 §7.4 does not require a permanent,
  citable specification for a provisional registration. The APH v0.1
  specification is a public draft under active change control and is
  cited here as the definition of the scheme's current use, not as a
  stable standard. Cite a specific commit or release tag rather than a
  branch, so the reference names bytes that do not move.
```

---

## 3. Supporting material — the RFC 7595 §3 guidelines

RFC 7595 §4 asks a provisional request to meet the §3.8 name syntax, to give
contact information, and to include clear security considerations per §3.7;
where the other §3 guidelines are not met, it asks that "the differences and
reasons SHOULD be noted". All nine — §3.1 through §3.9 — are answered below in
the RFC's own order, so a reviewer can check them off without reading the
protocol first.

**Guidelines, not fields.** §3's nine subsections are not template entries:
§7.4 carries six fields and none of them is a §3 heading, so this material has
nowhere to live inside the template block. That split is what changed between
RFC 4395 and RFC 7595 — RFC 4395 §5.4's eleven-field template carried
`Interoperability considerations` (and syntax, semantics, encoding) as fields
of the form, while its guideline section ran §2.1–§2.8 and stopped at scheme
name considerations. RFC 7595 cut the template to six fields and moved that
material into the guidelines, where it is §3.9. A reviewer working from the
older shape will look for these as fields and should look here instead.

### 3.1 Demonstrable, new, long-lived utility

APH identifiers name protocol features — currently a single extension
declaration — inside documents that already carry URIs from many schemes. The
utility claimed is *distinguishability*: an A2A AgentCard's extension list is
a set of URIs from unrelated protocols, and an APH-scoped namespace lets a
recipient recognize an APH declaration without a registry lookup or a
substring heuristic.

**Stated honestly:** this is a modest claim. The same job could be done by an
`https:` URI under a domain the protocol controls, and APH's own roadmap
records that intent — a2a-extension.md §6 anticipates a parallel
`https://w3id.org/aph/v1` identifier in v0.2, with `aph://` retained as an
alias. The provisional status is therefore the right status: the scheme is in
use and is not proposed as a permanent addition to the URI namespace on the
strength of one identifier.

### 3.2 Syntactic compatibility — and the `//` finding

`aph` conforms to the `scheme` production of RFC 3986 §3.1: three US-ASCII
ALPHA characters, registered lowercase, no `.` (RFC 7595 §3.8 forbids a `.`
except in a reversed-domain private-use name).

The scheme-specific part is where a reviewer should look. The one published
identifier is written in the `//` form:

```
aph://extensions/notarization/v1
```

Under RFC 3986 §3, `//` introduces an **authority** component. A generic
RFC 3986 parser therefore reads `extensions` as the authority (and, in the
common case, as a host name) and `/notarization/v1` as the path. `extensions`
is not a host and no APH implementation ever resolves it — §3.4 below is the
rule that makes this safe — but the parse is what a generic parser produces,
and a reviewer will see it.

**Why the form is not being changed here:** a scheme designed fresh for
identifiers that are never resolved would use the opaque form
`aph:extensions/notarization/v1`, with no `//` and therefore no authority to
mis-read. APH v0.1 ships the `//` form as a single pinned string constant
(a2a-extension.md §2 requires implementations to declare it as one constant
and forbids constructing it from substrings at call sites), it is deployed,
and this registration documents what exists rather than what would be tidier.
Correcting the form is a wire change to a signed-adjacent constant and belongs
to a specification revision, not to a registration document.

### 3.3 Well defined

The syntax of the scheme-specific part is not open-ended in v0.1: the
specification defines one literal identifier and requires it to be treated as
a constant. There is no grammar for third parties to mint `aph:` URIs, and no
part of the identifier is derived from user, host or session data.

### 3.4 Definition of operations

**There are none, and that is the point.** APH v0.1 §13 states the rule
normatively: implementations MUST treat `aph://` URIs as opaque identifiers
and MUST NOT attempt to dereference them as URLs. a2a-extension.md §2 repeats
it: the URI "is not dereferenceable, and verifiers MUST NOT attempt to resolve
it. It serves as a stable discriminator only."

The only defined operation is byte-string equality against the published
constant. No retrieval, no update, no deletion, and no resolution protocol is
defined or implied. The posture is the one `urn:` takes — an identifier with
no resolution mechanism — rather than the one `http:` takes.

### 3.5 Context of use

Confined, and documented as confined — but in **two** positions, not one, and
a reviewer reading the specification straight through meets the second one
first. The single identifier appears as:

1. **The `uri` member of an `AgentExtension` object** in an A2A AgentCard's
   `capabilities.extensions` array. This is the normatively specified
   position: APH v0.1 §10.1 and a2a-extension.md §2–§5 define the declaration,
   the byte-equality comparison, and the discovery flow that scans for it.
2. **The metadata key an A2A message carries the envelope under.** APH v0.1
   §1.1.1 describes an A2A message carrying its APH envelope "as extension
   metadata under the URI-namespaced key". This position is *narrated in a
   worked example rather than normatively specified* — v0.1 defines no
   required shape for it, because A2A owns that container. Stated here because
   the registration should describe where the string actually turns up, and a
   reviewer who finds a use the request did not mention stops trusting the
   request.

In both positions the URI is a key or a discriminator, never a target. It does
not appear in the APH notarization envelope's signed content in either case —
which is what keeps §3.9's "registration changes no wire behaviour" true — it
is not user-facing, and it is not published in hypertext for humans to follow.
The applications and protocols cited are A2A (transport) and APH itself.

### 3.6 Internationalization and character encoding

Not applicable in the way it usually is. The scheme-specific part of the one
defined identifier is US-ASCII, fixed by the specification, and never derived
from user input — so there is no text to internationalize, no percent-encoding
decision to get wrong, and no IRI-to-URI mapping to specify. If a future
revision defines a *family* of `aph:` identifiers rather than one constant,
this section stops being trivially satisfiable and the registration should be
updated at the same time.

### 3.7 Clear security and privacy considerations

RFC 3986 §7's general URI considerations apply. Three are specifically live
for this scheme, and one of them is the reason the scheme is safe at all.

- **Reliable parsing / spoofing (RFC 3986 §7.6, §7.4).** The `//` form invites
  a generic parser to read `extensions` as a host (§3.2 above). The mitigation
  is the opacity rule in §3.4, not the syntax: nothing in APH resolves the
  URI, so no host lookup, no connection and no certificate check is ever
  performed against that token. An implementation that *did* dereference an
  `aph://` URI would be non-conformant, and the failure mode it would create
  — attempting a network operation against an attacker-influenced token — is
  exactly what the MUST NOT in §13 forecloses.
- **Rare IP address formats / malicious construction (RFC 3986 §7.4).** Not
  reachable. The identifier is a pinned constant compared for equality; there
  is no code path in which an inbound string becomes a request target.
- **Sensitive information (RFC 3986 §7.5) and privacy.** The identifier is a
  fixed public constant. It carries no user identifier, no session token, no
  host the user contacted, and no protocol state. Its presence in an
  AgentCard discloses exactly one fact: that the advertising agent claims APH
  support. That is the disclosure the declaration exists to make.

**Local, non-protocol risk worth stating:** registering a system-wide handler
for `aph://` on an end-user operating system may collide with unrelated
software that has claimed the same scheme informally. That risk is a property
of the desktop handler registry, not of APH, and it is the risk this
provisional registration reduces — an entry in the IANA registry is how a
second party discovers the name is spoken for.

### 3.8 Scheme name considerations

- **Syntax:** conforms to RFC 3986 §3.1, registered lowercase, contains no
  `.`.
- **Short but distinguished:** `aph` is the initialism of the protocol name
  (Agent per Human) and is three characters. RFC 7595 §3.8 asks for names
  that are "short but also sufficiently descriptive and distinguished to
  avoid problems". A three-letter name in a shared namespace is genuinely
  contended, and the §1 registry check is the whole mitigation.
- **Not general-purpose, not grandiose:** RFC 7595 §3.8 warns against names
  that are "very general purpose", "associated in the community with some
  other application or protocol", or "overly general or grandiose". `aph` is
  an initialism with no general-language meaning and makes no universality
  claim.
- **Trademark:** the registrant should confirm before submitting that the
  three-letter string carries no mark that would create a rights problem in
  IETF specifications (RFC 7595 §3.8, citing RFC 5378 §3.4). This draft makes
  no such determination.
- **Service name correspondence:** APH defines no service name, so RFC 7595
  §3.8's "if a scheme name has a one-to-one correspondence with a service
  name, then the names SHOULD be the same" does not bind. If APH ever
  registers a service name, it should be `aph`.

### 3.9 Interoperability considerations

RFC 7595 §3.9 asks for "any details regarding the scheme that might impact
interoperability" — it names proprietary encodings and version
incompatibilities as the shapes to watch for. APH has neither, and the reason
is worth stating rather than answering "none":

- **Registration does not change any wire behaviour.** No envelope verifies
  differently before or after IANA acts. Both positions in §3.5 are outside
  the envelope's signed content — a declaration in an AgentCard, and a
  transport metadata key beside the envelope — so an implementation that has
  never heard of the registry produces identical verdicts.
- **A non-APH consumer's correct behaviour is to ignore it.** An A2A agent
  reading an AgentCard extension list is expected to skip URIs it does not
  recognize; an unrecognized `aph:` URI is a declaration of a capability the
  reader does not implement, which is the ordinary case.
- **Generic URI libraries handle the string without special support.** It
  parses under RFC 3986 with the caveat in §3.2 (an authority component that
  is not a host). Equality comparison — the only operation — is
  case-sensitive on the scheme-specific part; the scheme name itself is
  case-insensitive per RFC 3986 §3.1 and is always emitted lowercase.
- **The v0.2 alias plan.** a2a-extension.md §6 anticipates a parallel
  `https://w3id.org/aph/v1` identifier with `aph://` retained as an alias. A
  provisional registration is compatible with that outcome: if the `https:`
  form becomes primary, the provisional entry is updated or withdrawn rather
  than stranded.

---

## 4. What this document does not do

It does not register anything. Until the entry appears in the IANA registry,
`aph://` is used by convention only, the name is not owned, and a later
assignment of `aph` to another party would force APH to change its extension
URI. That exposure is unchanged by the existence of this draft. Every surface
in this repository that states the exposure still states it, unedited and in
the same words — the drafts moved the *registration action* from deferred to
drafted, and moved nothing else. `README.md` in this directory enumerates
those surfaces, so that the second flip — drafted → the registry citation,
when IANA acts — sweeps all of them rather than some.
