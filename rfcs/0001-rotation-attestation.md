# RFC 0001 — Signed Key-Rotation Attestation (v0.2 candidate)

- **Status:** Accepted 2026-08-29 — implemented in the v0.2 delta
  (`spec/aph-0.2.md` §5) and the reference (`aph-core::rotation`).
  Written ahead of the RFC process existing; adopted as RFC 0001 when this
  directory was created, because it was already an RFC in everything but
  the number.
- **Spec sections touched:** the v0.2 delta §5 (the statement, its
  verification, its publication property); §8.4 is unchanged in v0.1.0.

> **NON-NORMATIVE, and not part of APH v0.1.** Nothing in this document
> changes `spec/aph-0.1.md`. No field described here may be emitted by a
> conformant v0.1 producer, and no verifier is required to look for one. This
> is a design proposal written down so that it can be argued with before it is
> specified — where it and the specification appear to disagree, the
> specification is right and this document is a proposal that has not been
> accepted yet.
>
> It is deliberately written to be **refutable**: every claim about what the
> mechanism buys is paired with the case where it buys nothing.

Everything below is written against the constraint `operations.md` opens with,
quoted here so that no proposal in this document can quietly violate it:

> **The human's authority is the root, the keys stay on the operator's own
> machine, and no third party is required for the protocol to work.** A
> mitigation that hands custody to a custodian, or that inserts a service the
> protocol then depends on, defeats what APH is for.

§8 below checks each proposal against that sentence, one clause at a time.

---

## 1. The problem, in one sentence

**Domain control alone publishes notary keys.**

Both discovery mechanisms are anchored in domain ownership and neither is
authenticated by the notary's signing key: §8.4.4's trust model is the TLS
certificate chain, §8.4.5's is the DNS resolution chain, and
`security-considerations.md` §3.6 states the consequence outright — "what
actually determines recoverability is control of the domain, not possession of
the key." `operations.md` §1 says the same thing from the operator's side:
item 2, not item 1, is the root of the publication surface's authority.

That property is what makes APH deployable — a notary needs no registry, no
enrolment, and no relationship with any verifier — and it is also the gap. An
adversary who obtains the publication surface **without** obtaining the signing
key can introduce a brand-new key that every conformant verifier accepts as
this identity's key, with no prior relationship required and nothing to
contradict it. Concretely, that adversary is: whoever takes over the registrar
account, whoever hijacks the zone, whoever obtains a certificate for the origin,
or the shared platform that serves `/.well-known/did.json` for an operator who
does not own the zone (the §8.4.7 case of an identity publishing only
`did:web`).

`operations.md` §2.3 already tells the operator to keep those credentials
recoverable independently of the key store. That is a control the operator
asserts and a verifier cannot check. A signed rotation attestation is the same
separation made **checkable by the verifier**.

---

## 2. The statement

### 2.1 Shape

A rotation attestation is a small JSON object in which the **current** key
makes one claim: *this named successor is mine.*

```json
{
  "aphVersion": "0.2",
  "type": "AphRotationAttestation",
  "id": "urn:uuid:5f0e6d4a-2b71-4c0f-9c3e-0a1b2c3d4e5f",
  "subject": "did:web:notary.example.com",
  "predecessor": "did:web:notary.example.com#k1",
  "successor": {
    "kid": "k2",
    "alg": "EdDSA",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "notBefore": "2027-01-01T00:00:00Z",
    "notAfter": "2029-01-01T00:00:00Z"
  },
  "created": "2026-08-16T12:00:00Z",
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:web:notary.example.com#k1",
    "created": "2026-08-16T12:00:00Z",
    "proofValue": "<placeholder — illustrative, not a test vector>"
  }
}
```

**The `proofValue` above is a placeholder**, following the convention §7.3.1
states for the spec's worked examples: those blocks are illustrative and their
signature values are not test vectors. The two keys are illustrative in the
same way — `#k1`, the speaker, is the spec's own `did:web` example key, and the
successor is a second public key used only to keep the `k1`/`k2` pair distinct
across §2.1 and §3.1. Both are **public** halves and authorize nothing. This
document contains no private key material of any kind, and a real vector — if
this design is accepted — belongs in `examples/` alongside the others, minted
through the reference implementation's own signing path from published test
seeds.

### 2.2 Why each field is inside the signed bytes

| Field | Why it must be covered by the signature |
|---|---|
| `subject` | Names the identity the statement is about. Without it, an attestation minted under one identity could be lifted and served at another identity's surface by anyone who could obtain both — the same replay class §7.1.7.1 closes by binding an embedded mandate's `humanPrincipalDid` / `agentDid` / `id` to the envelope carrying it. |
| `predecessor` | Names the *speaker* as a DID URL including the `#kid` fragment. A verifier chains on this value, so it cannot be inferred from where the record was found. |
| `successor.kid` | The fragment a later `proof.verificationMethod` will carry. `operations.md` §3.1 step 3 already makes this fragment load-bearing; here it is also the join key of the chain. |
| `successor.publicKeyMultibase` | The key bytes themselves. Naming a `kid` without the bytes would let whoever controls publication bind that `kid` to a key of their choosing, which is the attack this whole mechanism exists to stop. |
| `successor.notBefore` / `notAfter` | The activation bounds: the window in which a verifier may accept the successor as this identity's signing key. Same meaning and same RFC 3339 form as the §8.4.5 tags of the same name, so an operator learns one vocabulary. |
| `created` | Orders two attestations naming the same `predecessor` (see §6 on why ordering alone is not a defence). |
| `id` | A stable name for the statement, so a future retraction or an operator's records can refer to exactly one attestation. |

**One vocabulary trap, named because it will bite someone.** `successor.alg`
uses §8.1's JWS algorithm names (`EdDSA`, `ES256`), because this object is JSON
signed the way an envelope is signed. The §8.4.5 TXT `alg` tag uses
`ed25519` / `p256`. Both spellings already exist in v0.1 and a v0.2 verifier
reading both surfaces must map between them. This draft does not unify them —
changing the TXT tag would break every published record — but a v0.2
specification should state the mapping in one place rather than leaving each
implementation to rediscover it.

### 2.3 Canonicalization and signature — zero new cryptography

The statement is signed exactly the way everything else in APH is signed. No
new algorithm, no new canonicalization, no new proof format:

- **Canonical bytes**: RFC 8785 JCS over the statement with the `proof` block
  **present and complete except for its own `proofValue`, which is set to the
  empty string `""`** — §7.2.1's lone-proof base, the same rule a single notary
  proof on an envelope already follows. The statement is not a chain, so none
  of §7.2.1's two-proof cases apply.

  **"Minus" is not "empty", and §8.2 already says so in those words.** An
  implementation that *removes* the `proofValue` member rather than emptying it
  produces different canonical bytes, and therefore a signature no conformant
  verifier reproduces. It is repeated here because §8.2 records that earlier
  drafts of this protocol got it wrong, and a new v0.2 statement is a fresh
  chance to get it wrong the same way.
- **Proof formats**: §8.2's, unchanged — `DataIntegrityProof` with
  `eddsa-jcs-2022` or `ecdsa-jcs-2019`, or `JsonWebSignature2020`.
- **Algorithms**: §8.1's set, unchanged — `EdDSA` and `ES256`.

A verifier that can already check an envelope proof can check a rotation
attestation with no new primitive. That is the point: the mechanism is a new
*statement*, not new *cryptography*.

### 2.4 The VC-shaped alternative, considered and declined

The obvious alternative is to make the attestation a W3C Verifiable
Credential, reusing the envelope machinery wholesale. It is declined for one
concrete reason: a VC invites a `credentialStatus`, and §6.3.3's status
machinery carries a **freshness bound** — a status list credential older than
five minutes MUST NOT be accepted. §6 below argues that a rotation attestation
must have the opposite property. An object shaped like a VC, whose most natural
extension point is the one thing it must not have, is a shape that misleads.

---

## 3. Publication

The statement is published on **both** §8.4 surfaces. Neither is required; an
operator publishing one publishes the attestation there.

### 3.1 `did:web` — a property in the DID Document (PRIMARY PROPOSAL)

The attestation rides in the same document as the key it attests to:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:notary.example.com",
  "verificationMethod": [
    {
      "id": "did:web:notary.example.com#k1",
      "type": "Multikey",
      "controller": "did:web:notary.example.com",
      "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoVTwBaPaeT1KhFmkV"
    },
    {
      "id": "did:web:notary.example.com#k2",
      "type": "Multikey",
      "controller": "did:web:notary.example.com",
      "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    }
  ],
  "assertionMethod": [
    "did:web:notary.example.com#k1",
    "did:web:notary.example.com#k2"
  ],
  "https://w3id.org/aph/v1#rotationAttestation": [
    { "…the §2.1 statement, verbatim, including its proof…" }
  ]
}
```

**Why this is the primary proposal: atomicity.** The successor key entry and
the attestation naming it land in one write. There is no window in which the
key is published and the statement is not — which is precisely the window a
verifier requiring continuity would refuse in, and precisely the window an
operator would introduce by publishing two things in two places.

**Two costs, stated.**

1. **The JSON-LD term.** A property key that is a bare token
   (`aphRotationAttestation`) is undefined against the `did:v1` context and a
   JSON-LD-processing resolver may drop it. The full-URI key form shown above
   survives expansion without needing a context definition — but
   `https://w3id.org/aph/v1` is an identifier APH does not serve, which
   `operations.md` §6 already enumerates with its consequence: tooling that
   dereferences JSON-LD contexts fails to fetch it, and verifiers treating
   `@context` as a pinned literal are unaffected. The URI works as a key
   whether or not it dereferences; an adopter should still know it does not.
2. **It perturbs a document §8.4.7 deliberately kept plain.** §8.4.7 states
   that the DID Document schema gains no per-key validity metadata, so that the
   document stays a plain DID Document any conformant `did:web` resolver can
   read. An added top-level property is a smaller intrusion than added
   per-key metadata — the `verificationMethod` entries themselves are
   untouched, so a resolver that ignores the property reads exactly the
   document it reads today — but it is the same category of decision and
   deserves the same scrutiny.

**Marked alternative: a derived sibling document.**
`https://<origin>/.well-known/aph-rotation.json`, with the origin **derived**
from the notary's `did:web` under §8.4.4 step 2 — the same derivation §6.3.3.2
already uses for the status endpoint, and derived for the same reason: whoever
gets to name the host that answers a question gets to choose the answer. This
keeps the DID Document untouched and settles the JSON-LD question by not asking
it. It costs a second fetch and re-opens the atomicity window above. **If the
JSON-LD term question does not resolve cleanly, this is the option to take.**

### 3.2 DNS TXT — a record at a child name

```
_rotation._aph._notary.notary.example.com.  IN  TXT  (
  "v=APHv1; t=rotation; att="
  "eyJhbGciOiJFZERTQSJ9.eyJhcGhWZXJzaW9uIjoiMC4yIiwiY3JlYXRlZCI6…"
  "…<remaining characters of the compact JWS>" )
```

Two tags beyond `v`:

- `t=rotation` — the record type discriminator, so this record is never
  mistaken for a key record.
- `att` — a **compact JWS (RFC 7515 §3.1)** whose payload is the RFC 8785 JCS
  serialization of the §2.1 statement, signed by the predecessor key.

**Why the payload travels rather than being reconstructed.** The alternative —
spelling the statement's fields out as tags (`from=k1; to=k2; k=…`) and having
the verifier rebuild the canonical JSON to check the signature — is smaller on
the wire and worse in every other way. It creates a second canonicalization
surface, and two implementations that must agree byte-for-byte on how to
rebuild a document from a tag-list is exactly how you get two conformant-looking
implementations that never interoperate. The record carries the bytes that were
signed: do not re-derive what you can carry. §7.2.1 opens on the same note —
ambiguity in a canonicalization base is how interoperability dies — and §8.2's
"minus is not empty" correction is the record of that ambiguity costing real
interoperability once already, over a single JSON member.

**The b64:false quirk of §8.2 does NOT apply here, deliberately.** §8.2's
`JsonWebSignature2020` proofs are *detached* — the payload is the document the
verifier already holds. A TXT record is the only place these bytes exist, so
the payload must be present and base64url-encoded in the ordinary RFC 7515 way.
RFC 7797's unencoded-payload form would also forbid a `.` in the payload, and
JSON can contain one.

**Why a child name rather than a new tag on the existing key record.**
`_rotation._aph._notary.<domain>` is a strict child of the key name, so the key
RRset is byte-identical to what it is today and a v0.1 verifier never sees the
new record at all. That separation is not cosmetic. §8.4.5 requires `v`, `alg`
and `k` and rejects a record missing any of them; this record carries `v`, `t`
and `att`, so at the KEY name it would be a malformed APH record **by
construction** rather than by accident.

The same-name alternative is *probably* safe — the reference implementation
ignores unrecognized tags (DKIM's tolerance, and its parser has a
forward-compatibility test pinning exactly that) and skips a record it cannot
parse beside a valid one — but §8.4.5 states neither rule normatively, and
§8.4.6 says a published-and-failed mechanism MUST reject the envelope rather
than advance. An implementation reading those together as "a malformed
neighbour is a failure" would turn a v0.2 publication into a v0.1 verification
outage. The child name means the question is never asked. See §9.3: v0.2
should state the ignore rule anyway, because every future extension needs it.

**Size.** A TXT character-string is capped at 255 octets; longer values are
split across concatenated character-strings, which is what the parentheses
above show and what DKIM already does for long keys. An Ed25519 attestation
lands in the high hundreds of octets once base64url expansion is counted — the
exact figure moves with the identifiers the statement carries, so treat it as
an order of magnitude and not a measurement. Either way the RRset exceeds the
bare 512-octet UDP limit and requires EDNS0 or TCP fallback. Both are
universally deployed,
but an operator whose resolver path truncates will see this fail, and an
implementation must not treat a truncated answer as a malformed record.

### 3.3 Retention, chains, and bounds

Rotations compose: `k1 → k2 → k3`. A verifier holding a pin on `k1` and meeting
an envelope signed by `k3` needs both attestations to be resolvable, so:

- **Attestations are retained, not replaced.** The publication surface carries
  every attestation still needed to chain from any key a verifier might
  plausibly still hold — the same obligation §8.4.7 step 4 already states for
  retired *keys* ("keep the record visible for a further window, RECOMMENDED
  1 year"), extended to the statements about them.
- **A verifier MUST bound the chain it will walk.** The chain is
  attacker-influenced input and is walked before any verdict, so an unbounded
  walk is a denial-of-service surface — the same reasoning §7.1.7.1 gives for
  rejecting an oversized envelope (RECOMMENDED 64 KiB) *before* canonicalizing
  it: work done on unauthenticated input is bounded first.
- **Cycles and dangling links are refused**, in the vocabulary v0.1 already
  uses for proof chains — §8.3.1 step 1e rejects a linkage that is "missing,
  dangling, or cyclic", and §7.1.11 requires every link to resolve to a member
  of the same chain. Applied here: a `predecessor` naming a key that is not
  published, or a chain that revisits a key, is invalid rather than merely
  unhelpful.

---

## 4. What it adds over §8.4.7's bare overlap

**An attacker who controls the publication surface but NOT the current key can
no longer introduce a successor.**

That sentence is the entire motivation, and it is worth restating what it
replaces. §8.4.7 rotates by publishing two keys side by side for an overlap
window; the successor is authorized by **appearing**, and appearing is
something domain control alone accomplishes (§1 above). So today the same
attacker publishes a key of their choosing and every conformant verifier
accepts it. With the attestation, a verifier applying the continuity rule
requires a successor to have been **named by its predecessor**, not merely
**served from the same origin**. The bar for introducing a key rises from
*domain OR key* to *domain AND key*.

Three consequences worth naming separately:

1. **It makes `operations.md` §2.3's separation checkable.** That section tells
   an operator to keep registrar credentials, DNS API credentials and the TLS
   issuance path recoverable independently of the signing key. Today that is a
   control the operator asserts and nobody can verify. Under this mechanism, the
   separation is what an attacker has to defeat *twice*, and a verifier can tell.

2. **It gives §8.4.8's pin mismatch an answer.** Today, a pinning verifier that
   sees a published key differing from its pinned copy has no way to distinguish
   *the operator rotated* from *someone took the origin*; §8.4.8 can only say
   warn, try both, and fail if both fail. The attestation is exactly that
   distinguisher: a mismatch whose published key chains to the pin is a
   rotation, and one that does not is a takeover. §9.2 specifies the behaviour.

3. **It makes "pre-authorized rotation" mean what it sounds like.**
   `operations.md` §3.2 and `security-considerations.md` §5.1 both go out of
   their way to say the successor is pre-*authorized* by domain control, and
   that calling it "signed by the old key" would overstate what the wire
   carries. Under this mechanism the wire carries it, and the careful phrasing
   can be retired — for v0.2 operators only, and only where they publish it.

---

## 5. What it cannot add

### 5.1 A stolen current key signs a rotation too

An attacker holding the current private key mints a valid attestation naming
their own successor. The signature is genuine. Nothing in the statement
distinguishes it from the operator's own.

If that attacker *also* controls publication, they install the successor and the
mechanism has bought nothing against them. If they do not, they hold a valid
attestation nobody serves — which is the one case where the mechanism helps,
and it is the mirror image of the case in §4.

**The backstop is `security-considerations.md` §3.1, and it does not move.** A
leaked notary key is bounded: the notary never holds the principal's key, so
the attacker **cannot forge an authorization**. A `PrincipalSigned` envelope
dies at the principal proof (`APH_E011`), which the attacker cannot produce; a
`NotaryAttested` envelope carrying an embedded mandate dies at the mandate's
`principalSignature`. The residual risk is unchanged and remains exactly what
§3.1 names: a `NotaryAttested` envelope with **no** embedded mandate, in which
nothing the human signed is present — which is why §7.1.7.1 says to embed the
mandate and why a recipient MAY refuse an envelope that omits it.

The rotation attestation does not widen that bound and does not narrow it. It
is a mechanism about **which key is this identity's**, not about **what a key
can say**.

### 5.2 A verifier with no memory gains nothing

This is the claim most likely to be oversold, so it is stated as bluntly as
possible.

An attacker who takes the domain of an identity a verifier has **never seen
before** simply publishes a genesis key and no attestation at all. The verifier
has nothing to chain *from*, so there is nothing to check, and it accepts —
exactly as it does today. The attacker does not have to defeat the mechanism;
they decline to participate in it, and a first-contact verifier cannot tell the
difference between an identity that never rotated and an identity that was
reset.

**The property is therefore realized by a verifier with memory, and only
there.** Memory already exists in v0.1 in three forms, and the attestation
gives all three something to do:

- a pin under §8.4.8,
- a resolved key cached under `security-considerations.md` §5's guidance (TTL
  no longer than the longest plausible rotation overlap),
- an out-of-band record an operator or a compliance system already keeps.

The honest summary: **this mechanism upgrades continuity for verifiers that
remember. It does nothing for first contact.** §7 says the same thing from the
other end.

Corroboration from a third party — a transparency log, DNSSEC validation
promoted from warning to requirement, certificate-transparency monitoring of
the origin — would extend memory to verifiers that have none. Each is
compatible with this design and none may be made mandatory; §8 explains why.

### 5.3 It is not a recovery from key loss

If the key is gone and no attestation was minted while it lived, none can ever
be minted. `security-considerations.md` §3.6 is unchanged: APH offers no
protocol-level recovery from loss, and adding one would mean a custodian.

What changes is the value of doing it in advance, which is the argument
`operations.md` §3 already makes for pre-authorized rotation. Under v0.1 the
advance work buys *availability* — no document to edit at the worst moment.
Under this mechanism it also buys *authenticated continuity*, and it buys it
only if the attestation was minted before the loss.

### 5.4 It does not authenticate the publication surface generally

Everything else served from that surface is still domain-anchored: the DID
Document's other properties, the derived status endpoint, the TLS certificate
itself. This mechanism authenticates exactly one claim — the predecessor →
successor link — and claims no more.

### 5.5 The threat table

| Attacker holds | v0.1 | With the attestation |
|---|---|---|
| Publication surface only; verifier has **no** memory of this identity | New key accepted | **Unchanged** — attacker publishes a genesis key and no attestation; nothing to chain from |
| Publication surface only; verifier holds a pin or a live cache | Mismatch: warn, try both, no way to tell rotation from takeover | **Refused** — the published key does not chain to the remembered one. This is the gain. |
| Current private key only | Can sign envelopes, bounded by §3.1; cannot introduce a key, because publication is domain-anchored | **Unchanged** — can mint an attestation, cannot publish it |
| Both | Full control of the identity; §3.1's bound is the only backstop | **Unchanged** |

---

## 6. Retracting a rotation

The naive design is a "revocation attestation" signed by the predecessor. It
fails in the one case that matters, and the failure is structural rather than
fixable: **if the predecessor key is what was stolen, the attacker's attestation
and the operator's retraction are signed by the same key**, and a verifier
cannot rank them. Ordering by `created` does not help — the attacker writes
whatever timestamp they like. A key cannot be used to un-say something the
holder of that key said.

**What actually works is the publication surface, and it works for free.**

**Proposal: continuity is checked against what is currently published, and
withdrawal is un-publication.** An attestation the operator stops serving is
not resolvable, so a verifier that requires the attestation to be *present* —
not merely to have once existed — gets retraction from domain control with no
new mechanism. This is the presence-based model §8.4.7 already defines for
`did:web` retirement ("retirement IS removal"), applied to statements instead
of keys.

**The consequence, stated plainly because it is a deliberate asymmetry:**
**key control is required to ADD a successor; domain control is sufficient to
REMOVE one.** That is the right split. The failure you must not have is a
stolen key silently becoming the identity — so adding is guarded by the key.
The failure you can live with is an operator who has lost the domain also losing
the ability to withdraw — because `security-considerations.md` §3.6 already
says that operator has lost the identity outright, and no mechanism in this
document repairs that.

**Two alternatives, marked and declined for the first cut.**

- **A `notAfter` on the attestation itself**, so an unwithdrawn statement
  expires. Declined as the default: it puts a liveness obligation on the
  continuity path. Re-minting before the bound passes requires the *current*
  key — which, in the scenario this whole mechanism exists for, is the key that
  is gone. §6.3.3.3's five-minute freshness bound is correct for a status list
  precisely because a live signer is what a status list asserts; a rotation
  attestation asserts a durable historical fact and **must remain verifiable
  after the predecessor key is dead**. Available to operators who want a bounded
  window and accept the obligation; not the default.
- **An explicit retracted-attestation list** at the derived endpoint. This
  rebuilds §6.3.3 — a fetch, an issuer binding, a freshness question — to solve
  a problem un-publication already solves. Recorded so that the next person to
  propose it finds the reason it was not taken.

---

## 7. Genesis: the first key has no predecessor

The first key an identity ever publishes has nothing to sign for it. Nothing
can. This is not a gap to be closed later; it is the shape of the problem.

**Bootstrap stays domain-anchored. The attestation upgrades CONTINUITY, not
GENESIS.**

A verifier meeting an identity for the first time trusts the TLS certificate
chain (§8.4.4) or the DNS resolution chain (§8.4.5), exactly as in v0.1. What
changes is the *second* key and every key after it. An identity's genesis key
is as trustworthy as its domain, forever, and no amount of subsequent chaining
improves it retroactively — a chain is only as good as its anchor, and this
anchor is a domain.

Three corollaries worth being explicit about:

1. **§5.2 is the same fact from the other side.** A verifier with no memory is
   always at first contact, so it is always in the genesis case.
2. **An attacker who takes the domain can always reset to genesis** by
   publishing a fresh key with no attestation. Only a verifier that remembers
   the identity's previous state can tell that a reset happened. A v0.2
   specification could let an identity *declare* that it always chains — but
   whoever holds the publication surface also holds that declaration and would
   delete it, so the declaration would have to be remembered too, which is the
   same requirement wearing a different hat.
3. **Anchoring genesis is a different problem** and is the one a transparency
   log or a registry would address. Both are out of scope here for the reason
   §8 gives.

---

## 8. The spirit constraint, checked clause by clause

> **The human's authority is the root, the keys stay on the operator's own
> machine, and no third party is required for the protocol to work.** A
> mitigation that hands custody to a custodian, or that inserts a service the
> protocol then depends on, defeats what APH is for.

- **The human's authority is the root.** Untouched. This mechanism is entirely
  about which key belongs to a *notary*, and `security-considerations.md` §3.1's
  bound — a notary key cannot forge a human's authorization — is neither
  strengthened nor weakened by it (§5.1).
- **The keys stay on the operator's own machine.** The attestation is minted by
  the operator's current key on the operator's own machine, and it contains the
  successor's **public** half only. `operations.md` §3.4 step 1's rule — the
  successor's private half never touches the signing host until promotion — is
  unchanged and unaffected. Nothing in this document asks any key to move.
- **No third party is required.** Both publication surfaces are the operator's
  own: their DNS zone, their web origin. There is no log, no registry, no
  directory, no notary-of-notaries, and nothing to enrol with. A verifier needs
  no relationship with anyone.

**The one place this constraint does real work is §5.2's corroboration
paragraph.** A transparency log genuinely would extend the property to
first-contact verifiers. It is therefore the tempting thing to require — and
requiring it would insert a service the protocol then depends on, in the exact
words of the constraint. **Any such corroborator stays OPTIONAL.** A verifier
that consults one is applying local policy; a verifier that does not remains
fully conformant.

---

## 9. Migration

### 9.1 Additive by construction

**A verifier that ignores the attestation reaches exactly the verdict it
reaches today, for every envelope.** This is a design rule, not an observation,
and the shapes in §3 are chosen to satisfy it:

- No field is added to, removed from, or reinterpreted in any §8.4.5 key
  record. The rotation record lives at a child name a v0.1 verifier never
  queries.
- No `verificationMethod` entry changes. A resolver that ignores an unknown
  top-level property reads the same document it reads today.
- No published example, fixture, or signature changes. Nothing in this design
  touches envelope bytes.
- No new algorithm and no new canonicalization (§2.3), so a v0.2 verifier needs
  no new primitive and a v0.1 verifier needs no change at all.

**Absence is not failure, and the §8.4.6 rule applies here in the same shape.**
A v0.1 operator publishes no attestations; an identity that has never rotated
has none to publish. A verifier finding no attestation has learned that the
mechanism is *not offered*, not that a check *failed*.

**Requiring attested continuity is POLICY, and must not be the v0.2 default.**
A verifier MAY require it, in the shape §8.3.1 step 10 already gives to local
policy and §7.1.7's `attestationMode` gives to `APH_E012`: a deliberate,
declared refusal to accept the weaker claim. Making it the default would turn
every v0.1 operator's next rotation into a fleet-wide outage — the mechanism
would break the deployments it exists to protect.

### 9.2 A pinning verifier's behaviour, specified

§8.4.8 today: on pinned-vs-published mismatch, SHOULD warn, SHOULD validate
against both, MUST treat failure against both as fatal. Under this design, a
pinning verifier that finds an attestation behaves as follows.

| What is published | Behaviour |
|---|---|
| Published key **equals** the pin | Unchanged from v0.1. No attestation is consulted; there is no mismatch to explain. |
| Mismatch, and the published key **chains to the pin** by a valid attestation (directly or through a bounded chain, §3.3) | The mismatch is **explained**. The verifier SHOULD re-pin to the successor and accept. This is the case §8.4.8 cannot currently distinguish, and it is the one that makes pinning survivable across a planned rotation. |
| Mismatch, and the published key **does not chain to the pin** | The verifier MUST NOT silently re-pin. It SHOULD refuse and surface the reason. Validating against the pinned key alone remains available for envelopes signed while that key was current — the pinned key has not become invalid, it has become unexplained. |
| Mismatch, and **no attestation is published at all** | v0.1 behaviour, unchanged: warn, validate against both, fatal if both fail. The verifier has learned nothing new, and must not treat absence as a failed check (§9.1). |

This also settles §8.4.7's re-pin obligation on `did:web`, where retirement is
removal and an old key becomes unresolvable once removed: a pinning verifier
re-pins during the overlap window *because the attestation told it what to
re-pin to*, rather than because an operator remembered to tell it.

### 9.3 What a v0.2 specification would have to add

This draft deliberately allocates nothing. The list is what an editor would
owe:

1. **A sixteenth error code.** A continuity refusal is none of the fifteen.
   It is not `APH_E001` — the signature verified fine, against a key the
   verifier declines to accept. It is not `APH_E014` — something *is*
   published. It is not `APH_E012` — that is attestation *mode*, a different
   axis entirely. Working name only: `NotaryKeyContinuityUnproven`. §11 is
   v0.1's closed set of fifteen and this draft does not extend it.
2. **The unrecognized-tag rule, stated normatively.** §8.4.5 says records with
   missing required tags or a wrong `v` are rejected and says nothing about
   tags it does not know. The reference implementation already ignores them,
   DKIM (RFC 6376 §3.2) already requires it, and every future extension needs
   it. §3.2 routes around the question; the rule should be written down anyway.
3. **The algorithm-name mapping** between §8.1's `EdDSA`/`ES256` and §8.4.5's
   `ed25519`/`p256`, in one place (§2.2).
4. **The JSON-LD term decision** for §3.1's DID Document property, or the
   switch to the derived sibling document.
5. **A published vector.** If this is accepted, `examples/` gains a real signed
   attestation minted through the reference implementation's own signing path
   and byte-compared by conformance, exactly as the repo's signed vectors
   already are — from public test seeds, re-derivable by anyone, with no
   secret material.
6. **A retention recommendation** for attestations, parallel to §8.4.7 step 4's
   further-visibility window for keys.

---

## 10. Open questions

Recorded honestly rather than resolved, because a draft that answers everything
is a draft nobody argued with.

- **Is §5.2 fatal to the value proposition?** The mechanism helps verifiers
  that remember and no one else. If real deployments overwhelmingly re-resolve
  from scratch every time, the attestation is machinery serving a population of
  approximately zero, and the honest answer would be to promote §8.4.8 pinning
  first and revisit this afterwards. **This should be decided before the
  mechanism is specified, not after.**
- **Should a successor be able to attest to its own predecessor** (a
  counter-signature, so the chain is verifiable in both directions)? It would
  prove the successor's holder consented to the role, which matters if a
  predecessor could otherwise name a key its holder does not control. It also
  requires the successor's private half to sign at a moment `operations.md`
  §3.4 says it should be nowhere near a signing host, and the rehearsal in §3.6
  is where that could be folded in without violating the rule.
- **What does an attestation mean for `did:key`?** Nothing, and §8.4.3 is why:
  the identifier *carries its own public key bytes*, so the identity IS the key
  and a rotated `did:key` is simply a different identifier. There is no
  document to republish and nothing for a successor to succeed to. An
  attestation naming a `did:key` successor would be a
  statement about a different identity, and v0.2 should refuse it rather than
  leave it undefined.
- **Multiple concurrent successors.** An operator may legitimately publish two
  successors (two media, two recovery paths). Nothing above forbids it, and the
  chain walk in §3.3 becomes a tree walk. The bound is the same; the wording
  is not, and someone has to write it.
- **Does the DNS TXT surface earn its complexity here?** §3.2's record runs to
  several hundred octets and needs EDNS0 or TCP, where the key record is one
  comfortable string.
  If in practice every operator publishing rotation attestations also publishes
  `did:web`, the TXT half is cost with no coverage. The counter-argument is
  §8.4.5's own: DNS survives when the origin does not.


## Decision

**Accepted 2026-08-29**, by the sole maintainer — the standing arrangement
recorded in CONTRIBUTING.md and `rfcs/README.md` (deliberately solo within
the Squillo organization), which Decision blocks cite instead of
re-litigating.

Implemented the same day, post-cut discipline intact: v0.1.0 untouched,
everything lands in the v0.2 delta. What exists now:

- **`spec/aph-0.2.md` §5** — the normative statement: all-required
  camelCase members, the successor carrying its own key bytes (the
  kid-without-bytes attack named and closed), §8.1 JWS alg spellings, the
  lone-proof JCS signing base, publication under
  `https://w3id.org/aph/v1#rotationAttestation`.
- **`aph-core::rotation`** — `RotationAttestation`/`RotationSuccessor`
  (strict serde), `sign_rotation_attestation`,
  `verify_rotation_attestation`: every structural rule checked before the
  signature, every refusal `APH_E024` naming the failed rule.
- **`APH_E024 RotationAttestationInvalid`** — the taxonomy's twenty-fourth
  code, in the enum census.
- **`spec/schemas/rotation-attestation.schema.json`** — the statement's
  schema, proof shape shared with the envelope's by reference, welded to
  the committed vector in CI.
- **`examples/v0.2/rotation_attestation.json`** — a signed,
  byte-pinned vector minted with the RFC 8032 test key.

Of §9's open questions: the `did:key` refusal is IMPLEMENTED as argued
(the identity IS the key; a rotated `did:key` is a different identifier);
counter-signatures, concurrent successors, and the TXT carriage remain
open for a later revision — none blocks the mechanism shipped.
