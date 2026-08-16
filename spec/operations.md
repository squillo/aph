# APH Operator Runbook

> Companion to `spec/aph-0.1.md` and `spec/security-considerations.md`, and
> **non-normative**. Where this document and the specification disagree, the
> specification wins and this document is the defect. It describes what an
> operator of a Notary Service has to hold, what happens when each of those
> things is lost, and the procedures that make the losses survivable.

Everything here is written against one constraint, stated first so that no
procedure below can quietly violate it:

**The human's authority is the root, the keys stay on the operator's own
machine, and no third party is required for the protocol to work.** A
mitigation that hands custody to a custodian, or that inserts a service the
protocol then depends on, defeats what APH is for. Where an option below
would do that, it is named and declined with the reason rather than left out.

---

## 1. What a Notary Service operator holds

Four things, and it is worth separating them because only one is a secret and
a different one is the actual root of authority:

1. **The notary signing keypair — private half.** Signs the notary proof on
   every envelope, the `notarySignature` on every mandate, and the revocation
   status list credential (§8.4.1, §6.3.3.3).
2. **Control of the domain named in the notary's `did:web`.** The registrar
   account, the DNS zone, and the TLS certificate for the origin serving
   `/.well-known/did.json`.
3. **Durable revocation state** — which Delegation Mandates are revoked, and
   each mandate's permanent index in the status list (§6.3.3.6).
4. **The published surfaces themselves** — the DID Document, any DNS TXT
   record at `_aph._notary.<domain>`, and the status list credential at the
   derived endpoint.

**Item 2, not item 1, is the root of the publication surface's authority.**
Both discovery mechanisms are anchored in domain ownership: §8.4.4's trust
model is the TLS certificate chain, §8.4.5's is the DNS resolution chain.
Neither is authenticated by the notary's signing key. Whoever controls the
domain can publish a new key; nobody else can, whatever key they hold.

That asymmetry is what makes §3 below survivable, and it is also why §3.3 is
the most important paragraph in this document.

**What the operator does not hold: any human principal's key.** A Notary
Service never sees one (§8.4). Every consequence in this document is bounded
by that fact — a notary in trouble is a notary that cannot witness, never a
notary that can speak for a human.

---

## 2. Losing the signing key

The case: the machine holding the private key is lost, wiped, or its key
store becomes unreadable, and no copy exists. This is not a compromise — see
`security-considerations.md` §3.1 for that — it is an availability and
continuity event.

### 2.1 What it costs

- **No new envelopes and no new mandates.** Nothing can be notarized until a
  key the verifiers accept is signing again.
- **The revocation transport stops within minutes, and it stops loudly.**
  §6.3.3.3 requires the status list credential to be re-issued at an interval
  no greater than 120 seconds, and a verifier MUST refuse one issued more
  than 300 seconds ago plus 60 seconds of skew. The last published document
  therefore ages out roughly six minutes after the key goes away, and from
  that moment every envelope carrying a `credentialStatus` is refused with
  `APH_E008` by every conformant verifier (§6.3.3.4 case 2). This is the
  sharpest edge of the loss: a fleet-wide refusal arriving on a six-minute
  fuse, from an outage whose only symptom before that is silence. §5 exists
  to put a number on that fuse before it burns.
- **Pinning verifiers see a mismatch.** A recipient that pinned the key under
  §8.4.8 will warn on the replacement, and will keep accepting the old key
  until it re-pins.

### 2.2 What it does not cost

- **Nothing already signed becomes invalid.** Those signatures are genuine
  and stay genuine. As long as the old PUBLIC key remains published, every
  envelope ever issued under it still verifies — which is exactly what
  §8.4.7 step 4's further-visibility window is for.
- **No human's authority is touched.** Principal keys live on the humans'
  own devices. In a `PrincipalSigned` envelope the authorization layer — the
  layer that actually proves consent — is unaffected; what stopped is the
  witness.
- **The identity is not lost, provided item 2 of §1 survives.** Domain
  control lets you publish a replacement key. Seed loss is a rotation you
  did not schedule, not an erasure.

### 2.3 The coupling that turns a recoverable loss into an unrecoverable one

**If the registrar and DNS credentials live in the same store as the signing
key, then losing that store loses both, and the identity is genuinely
unrecoverable.** No key escrow scheme fixes this, because the missing
capability is not cryptographic — it is the ability to publish at all.

This is the cheapest and largest mitigation in this document, and it costs no
cryptography whatsoever:

- Keep the registrar account, the DNS API credentials and the TLS issuance
  path recoverable **independently** of the machine that holds the signing
  key — a different credential store, different recovery contacts, different
  second factor.
- Verify the separation by testing the recovery path for the domain, not by
  believing it. An untested account-recovery path is a claim, not a control.

Do this before anything in §3 or §4. The procedures below assume domain
control survives; if it does not, they do not apply.

---

## 3. Pre-authorized rotation (RECOMMENDED)

### 3.1 The mechanism

§8.4.7 already specifies publishing two keys at once, as the overlap window
of a planned rotation. Pre-authorized rotation is that same mechanism used
defensively, with one change: the second key is published **before it is
needed, and stays published**.

1. Generate a SUCCESSOR keypair on different media from the primary, and keep
   its private half off the signing host entirely.
2. Publish BOTH public keys, continuously — two `verificationMethod` entries
   in the DID Document (both listed in `assertionMethod`), and/or two TXT
   records at `_aph._notary.<domain>` distinguished by `kid`.
3. Give the successor a **distinct `kid` from day one**, and make the SIGNER
   emit that fragment in `proof.verificationMethod`. The `kid` on the published
   record is only half of it, and alone it is the half that does nothing: a
   fragment is what names one key unambiguously, and naming one key is what
   lets promotion happen without editing the published document. Without it,
   two published keys are two candidates and the resolver's answer order
   chooses between them — see §3.4 step 3, which is why that step precedes
   every publication step.
4. Keep signing with the PRIMARY. The successor is published and unused.

### 3.2 Why this is a recovery mechanism and not a recovery plan

Because verifiers already accept the successor, promotion is a change to what
the operator SIGNS with, not to what the world can READ. At the moment of the
incident there is no document to edit, no DNS change to propagate, no cache
to wait out, and nothing that has to be done with a key that no longer
exists. A plan that begins "publish a new key" is a plan whose first step
takes as long as DNS and verifier caches take; this one has already taken it.

**On the phrase "pre-signed by the current key".** APH v0.1 defines no signed
rotation statement, and neither publication surface is key-authenticated
(§1). The successor is therefore pre-*authorized* by having been published
under the operator's domain control while the primary was healthy — which is
the same authority that publishes every APH key. Saying it is "signed by the
old key" would overstate what the wire actually carries. A signed rotation
attestation is a reasonable v0.2 question; it is not something to assume in
v0.1.

### 3.3 What it costs, stated plainly

- **Two keys can sign for this identity for the whole period, not for a
  30-day window.** Compromise of either forges notary proofs.
  `security-considerations.md` §3.1 bounds what that is worth — a stolen
  notary key still cannot forge a human's authorization — but the exposure
  is genuinely doubled in time, and the mitigation is discipline: the
  successor's private half never touches the signing host until promotion.
- **A `kid` fragment on every proof stops being advisory and becomes
  mandatory.** §8.4.7 bounds the ambiguity of two-keys-published to a 30-day
  overlap window, after which one key is retired and the question disappears
  on its own; publishing a successor permanently makes the ambiguity permanent
  too. A signer that omits the fragment therefore converts continuity
  insurance into a verification outage — total on `did:web`, intermittent on
  DNS TXT. §3.4 step 3 is where that cost is paid, and it is paid before any
  publication.

  The pairing runs both ways, and the second half is easier to miss: once
  proofs name a `kid`, every PUBLISHED TXT record must carry one too. The tag
  is optional in §8.4.5, so an existing single-key record probably omits it,
  and a record naming no `kid` cannot satisfy a request for a specific one.
  Reissue the primary's record with its own `kid` before publishing the
  successor's (§3.4 step 5) — otherwise DNS TXT stops answering for the
  primary while looking perfectly healthy, because §8.4.6 simply advances to
  `did:web`.
- **An unexercised successor is an untested backup.** Wrong bytes, a
  forgotten passphrase, unreadable media — all discovered at the worst
  moment. §3.6 is not optional.
- **Pinning verifiers see two keys.** That is the intended §8.4.8 behaviour
  and is why the specification tells a pinning verifier to validate against
  both the pinned and the published key.
- **`did:web`-only operators lose historical resolution on removal.** Per
  §8.4.7, retirement on `did:web` is removal, and there is no dated form. An
  operator who needs envelopes signed under a retired key to keep resolving
  must also publish DNS TXT, where `notAfter` expresses it.

### 3.4 Runbook A — establish a successor

Do this once, while everything is healthy.

1. Generate the successor keypair on a machine or removable medium separate
   from the signing host. Never copy the private half to the signing host.
2. Record the successor's `kid`, its algorithm, and its public key bytes
   somewhere you can read without either machine.
3. **Before publishing a second key anywhere, confirm the SIGNER emits the
   fragment.** Notarize a throwaway envelope and check that its
   `proof.verificationMethod` ends in `#<kid>` naming the primary. This is a
   precondition of steps 4 and 5, not a nicety, because with two keys published
   and no fragment to choose by the two mechanisms fail in two different ways
   and neither is acceptable: `did:web` resolution refuses outright with
   `APH_E014` — the document declines to guess among several keys, by design —
   while a DNS TXT verifier has no `kid` to filter on and takes the FIRST
   record valid at that instant, in whatever order the resolver happened to
   answer. So the DID path is a total outage and the TXT path is an
   intermittent one, where roughly half the answers resolve the successor's
   public key against a primary-signed envelope and refuse. Both fail closed
   and no wrong key is ever accepted, but this is an outage the continuity
   mechanism itself would have caused, and the intermittent half is the
   expensive kind to diagnose. §8.4.7 bounds this ambiguity to a 30-day overlap
   window; a successor published permanently makes it permanent, which is what
   turns the fragment from advice into a prerequisite.
4. Add the successor's public key to the published DID Document as a second
   `verificationMethod`, and add it to `assertionMethod`.
5. If you publish DNS TXT, first make sure the PRIMARY's existing record
   carries its own `kid` tag, then add a second record at the same name
   carrying the successor's. Leave `notAfter` unset on both while both are
   current.

   **Reissuing the primary's record is the step people skip, and skipping it
   is silent.** The `kid` tag is optional in §8.4.5 and the single-key example
   printed there omits it, so an established deployment's record very likely
   has none. Once step 3's fragment is in place, a verifier asks for one
   specific `kid`; a record that names none is not a match for that request,
   so the primary's key stops being selectable the moment the successor
   appears. The failure is invisible from outside: §8.4.6 simply advances to
   `did:web` and everything keeps verifying, so step 6's end-to-end check
   still passes and `dig` still shows both keys. A verifier that asks for DNS
   TXT specifically gets `APH_E014` instead — you have quietly dropped from
   two publication mechanisms to one.
6. Confirm from a machine with no relationship to the notary that both keys
   resolve — `curl` the well-known URL, `dig +short TXT _aph._notary.<domain>`
   — and that a freshly notarized envelope still verifies end to end through
   the §8.4.6 order. **Both keys resolving is not the check**: two keys resolve
   perfectly well in exactly the broken state step 3 describes, which is why
   that step cannot be deferred to here. Resolution from your own network
   proves less than you think.
7. Store the successor's private half on media that will not be lost together
   with the primary. Two locations that burn down together are one location.
8. Schedule the rehearsal in §3.6.

### 3.5 Runbook B — promote the successor

The primary is gone. Domain control survives (if it does not, see §2.3).

1. **Confirm the primary is unrecoverable** before promoting. Promotion is
   not reversible in any useful sense: you will have consumed the spare.
2. Bring the successor's private half onto the signing host and configure the
   service to sign with it. The published surfaces need **no change** for
   verification to work — this is the property §3.2 bought.
3. **Re-issue the status list credential immediately.** This is the first
   thing to do after the signer is live, not the last: it is the surface with
   the six-minute fuse (§2.1), and until a freshly signed document is served
   every status-carrying envelope is being refused.
4. Verify from outside: fetch a freshly notarized envelope's key through the
   §8.4.6 resolution order and check that its `verificationMethod` fragment
   matches the successor's `kid`.
5. **Generate a new successor and run Runbook A again.** You now have one key
   and no spare, which is the state §3 exists to avoid.
6. Retire the lost key per §3.7 — deliberately and later, not in the same
   change.

### 3.6 Runbook C — rehearse

Quarterly, or whenever the successor's storage medium or passphrase changes.
The rehearsal is the step that converts §3.4 from a belief into a control.

1. Load the successor's private half on a scratch host — not the signing
   host.
2. Sign an arbitrary test payload with it.
3. Verify that signature against the public key **as published**, resolved
   through the §8.4.6 order rather than from a local copy. Resolving locally
   tests your filesystem; resolving through discovery tests what a stranger
   would see.
4. Confirm the successor's `kid` matches the published entry.
5. Wipe the scratch host. Record the date of the rehearsal, not the outcome
   alone — an undated rehearsal cannot be shown to have happened recently.

Never rehearse by promoting. A rehearsal that changes the active signing key
is a rotation, and it consumes the spare it was meant to test.

### 3.7 Runbook D — retire a lost or superseded key

1. On DNS TXT, set the retired key's `notAfter` to a timestamp inside the
   overlap window and **leave the record published** — §8.4.7 step 4
   recommends a further year of visibility so verifiers checking older
   envelopes can still resolve the historical key.
2. On `did:web`, retirement is removal (§8.4.7). Remove the entry only when
   you accept that envelopes signed under it stop resolving against the
   document. If that matters, publish DNS TXT as well and remove the DID
   Document entry there.
3. Do not remove the retired entry in the same change that promotes the
   successor. Two independent changes fail independently.

---

## 4. Threshold split of the seed — available, deliberately not implemented here

An operator MAY split the signing seed into *n* shares such that any *k* of
them reconstruct it, using an **audited external tool of their own choosing**,
and keep every share themselves. It is a legitimate option and it composes
with §3 rather than competing with it.

**What it buys, precisely.** No single medium is sufficient to reconstruct
the key, and the loss of up to *n − k* shares is survivable. Unlike a
rotation, it restores the SAME key, so nothing published has to change and
no verifier has to re-pin.

**What it costs.**

- Reconstruction puts the whole seed in one place on one machine at one
  moment. That machine and that moment have to be trusted completely.
- Shares must be placed so that they cannot be lost together and cannot be
  gathered by one adversary. Those two requirements pull in opposite
  directions, and the placement is the entire security of the scheme.
- It protects the key, not the identity. If the shares are lost too, you are
  back to §3 — which is why a threshold split is not a substitute for a
  published successor.

**Why this repository does not implement it.** APH's reference
implementation ships no secret-sharing code, and adding one would be
hand-rolled cryptography in the highest-consequence place available: a
subtly wrong sharing scheme does not fail loudly, it leaks the key to anyone
holding fewer than *k* shares, and the operator finds out never. Choosing an
audited implementation is a decision an operator makes with their own threat
model; publishing an unaudited one inside a protocol library would make that
decision for them, badly.

**The decision to escrow at all — and in what form — is the operator's.**
Nothing in APH requires it. This section exists so the option is visible and
its costs are stated, not to recommend it.

---

## 5. Publication cadence: make the deadline visible

The freshness bound of §6.3.3.3 is correct in direction and silent in
arrival. A publisher that quietly stops does not degrade; it works, and works,
and then every verifier in the world refuses at once. The mitigation is to
watch the deadline approach.

### 5.1 The two deadlines

Both are measured from the published document's own `validFrom`:

| Line | When | Who it binds | What it means |
|---|---|---|---|
| Republish deadline | `validFrom + 120s` | the publisher (§6.3.3.3 MUST) | **The alarm.** You are late. Nothing is refused yet. |
| Refusal cliff | `validFrom + 300s + 60s` skew | every verifier (§6.3.3.3 MUST) | **The outage.** Every status-carrying envelope is now refused with `APH_E008`. |

The three numbers are `STATUS_REPUBLISH_INTERVAL_SECONDS` (120),
`STATUS_MAX_AGE_SECONDS` (300), and `STATUS_CLOCK_SKEW_SECONDS` (60) in
`aph-core`'s `credential_status` module. The gap between the two lines —
360s − 120s = **240 seconds, four minutes** — is the entire warning window,
and it only helps someone who is looking at it. Size alerting off that
subtraction rather than off the phrasing: if a revision moves either bound,
the arithmetic on this page has to be redone with it.

### 5.2 The external monitor

The document is public, machine-readable, and carries its own issuance
instant, so the check needs nothing this repository has to ship:

```sh
ENDPOINT=https://notary.example.com/.well-known/aph-status.json
AGE=$(curl -fsS "$ENDPOINT" | jq -r '(now - (.validFrom | fromdateiso8601)) | floor')
# warn at 120, page at 300 — the cliff is 360, and arriving there is too late
[ "$AGE" -gt 120 ] && echo "APH status list is ${AGE}s old: republish overdue"
```

Run it from **outside** your own infrastructure. A monitor sharing a failure
domain with the publisher goes quiet at exactly the moment it is needed, and
silence reads as health.

### 5.3 The in-process reading

A publisher built on `aph-core` reads the same two distances from the
document it is about to serve, without re-deriving either bound:

```rust
let credential = aph_core::parse_status_list_credential(&document)?;
let alarm = credential.seconds_until_republish_due(now)?; // negative once late
let cliff = credential.seconds_until_stale(now)?;          // negative once refused
```

Both are pure functions of the document and the instant you pass; `aph-core`
reads no clock of its own. Negative is a distance, not an error — a monitor
needs "how late am I", not only "too late". The interval itself is
`aph_core::credential_status::STATUS_REPUBLISH_INTERVAL_SECONDS`, so a
publisher never copies the number out of prose.

### 5.4 When the alarm fires

1. Check whether the SIGNER is alive before checking whether the publisher
   is. The commonest cause of a stale list is that the key is unreachable —
   locked key store, expired session, revoked credential — and that failure
   presents identically to a broken upload.
2. Re-issue and publish. Publishing an unchanged bitstring is fine and
   expected; what expires is the document's age, not its content.
3. If the signer cannot be revived within the warning window, treat it as
   §2 and consider Runbook B.

### 5.5 The other silent deadline: key validity

A DNS TXT record carrying `notAfter` has the same shape of failure — the key
is accepted until it is not, and the arrival is silent. Monitor it the same
way:

```sh
dig +short TXT _aph._notary.notary.example.com
```

Alarm on `notAfter` approaching with no successor record present. On
`did:web` there is no dated form to watch (§8.4.7): validity is presence, so
the thing to monitor is that the document still resolves and still contains
the `kid` you are signing with.

---

## 6. Unregistered conventions an operator inherits

APH v0.1 uses several identifiers that are **conventions rather than
registrations**. Four of them can change what an adopter's software does, and
each carries a different kind of risk. Their statuses differ and the
difference matters when you tell your own users what is coming: §13 defers
exactly **two** to v0.2 — the `aph://` scheme and the `_aph` / `_aph._notary`
labels. The media type it declines outright rather than defers, naming the
registered `application/vc+ld+json` as the conformant choice. The JSON-LD
context §13 does not mention at all; §7.1.1 requires it and nothing currently
serves it.

| Identifier | Status | What a collision would cost |
|---|---|---|
| `_aph._notary.<domain>` DNS label | Reserved by convention; IANA underscored-node-name registration deferred to v0.2 | A foreign record at the same name is **not** a misparse risk — a conformant parser refuses any record whose `v` tag is not `APHv1`, so it is ignored rather than read as a key. The real cost is name ownership: if `_aph` is later assigned elsewhere, APH moves and every published record is reissued. |
| `aph://` URI scheme | Used by convention; registration deferred to v0.2 | APH itself is safe by construction: §13 requires these URIs be treated as opaque and never dereferenced. The risk is local — registering a system-wide handler for `aph://` may collide with unrelated software. |
| `application/aph+ld+json` media type | Unregistered; the registered `application/vc+ld+json` is the conformant choice | Low. Conformant verifiers MUST accept both, so an operator who emits only the registered type carries no risk at all. |
| `https://w3id.org/aph/v1` JSON-LD context | Required in every envelope's `@context` (§7.1.1), and not currently served | Tooling that dereferences JSON-LD contexts will fail to fetch it. Verifiers that treat `@context` as a pinned literal — the shape APH expects — are unaffected. |

Two more are unregistered and inert, listed so the enumeration is complete
rather than convenient: the JWS protected-header `typ` value `aph+jws`
(§8.2), which is matched as a literal and never resolved; and the
`urn:aph:schema:0.1:*` `$id` values on `spec/schemas/*.schema.json`, which
are URNs precisely so that no tool tries to fetch them.

None of these affects whether an envelope verifies. All of them affect what
an adopter should promise their own users about stability before v0.2.

---

## 7. Pre-flight checklist

Before a Notary Service issues its first credential that anyone else relies
on:

- [ ] The registrar, DNS and TLS recovery paths are independent of the
      machine holding the signing key (§2.3) — and have been tested, not
      assumed.
- [ ] A successor key exists, is published alongside the primary, has its own
      `kid`, and its private half is not on the signing host (§3.4).
- [ ] The signing configuration emits `proof.verificationMethod` with a
      `#<kid>` fragment naming the signing key, **checked on a real envelope
      before a second key was published anywhere** (§3.4 step 3) — two
      published keys with no fragment to choose by is a verification outage,
      not an ambiguity.
- [ ] Every published DNS TXT record carries its own `kid` tag — the
      PRIMARY's as well as the successor's (§3.4 step 5). The tag is optional
      in §8.4.5, so a record predating this checklist probably lacks one, and
      a record naming no `kid` cannot answer a request for a specific one.
      Omitting this drops you to one publication mechanism without any
      symptom, since §8.4.6 advances to `did:web` on its own.
- [ ] The successor has been rehearsed at least once, and the date recorded
      (§3.6).
- [ ] Both published keys resolve from a network with no relationship to the
      notary — **and a freshly notarized envelope verifies end to end**, which
      the resolution check alone does not establish.
- [ ] The status list republish job runs at an interval below 120 seconds,
      and an external monitor alarms on the document's age (§5.2).
- [ ] Revocation state is durable across a restart of the issuing process.
      A revocation that does not survive a restart is not a revocation.
- [ ] Status list indices are allocated permanently and are never reused
      (§6.3.3.6) — reuse silently re-points stored envelopes at an unrelated
      mandate.
- [ ] Whatever this deployment promises about the four identifiers in §6 is
      what §6 actually says.
