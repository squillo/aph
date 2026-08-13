# APH v0.2 — The Principal Signs

**Status:** `v0.2.0-draft`. This document is an **amendment** to
[`aph-0.1.md`](./aph-0.1.md), not a replacement. Every section of v0.1 that
this document does not modify remains in force, and v0.1 section numbers are
cited throughout. Read v0.1 first; read this for what changed and why.

---

## 0. Why this amendment exists

v0.1 contains a contradiction between its prose and its wire format.

Two normative statements promise that the human principal may sign directly:

> §1.1 — "The issuing authority is the human principal… The human's
> signature (**directly** or transitively via the Notary Service capturing
> explicit attestation) is the root of every APH credential."

> §3.1 — "Every notarized message binds to a verifiable signature derived
> from a key held by the human principal (**directly via the principal's
> key**, or transitively via the Notary Service's key after explicit human
> attestation)."

The v0.1 wire format cannot express the direct mode. `proof` is a single
object whose `verificationMethod` names the **Notary Service's** key (§7.1.11);
`DelegationMandate` and `CommunicationMandate` each carry exactly one
signature field, `notarySignature`, which §6.1 requires to verify against
the notary's published verification method. No field anywhere carries a
signature made by the principal's own key.

The consequence is precise and consequential. A v0.1 verifier learns:

> *A notary asserts that this human authorized this action.*

It does not learn:

> *This human authorized this action.*

v0.2 closes that gap. It does not weaken v0.1 — v0.1 envelopes remain
valid, and the mode they express is given a name so a verifier can tell the
two apart.

## 0.1 What this changes about the Notary Service

Under v0.1, the notary holds the key that matters, so a notary can forge an
authorization for any principal it serves. Every mitigation for that is
custody engineering: hardware modules, per-principal isolation,
non-extractable keys.

Under v0.2 `PrincipalSigned` mode, the notary never holds the principal's
key and therefore **cannot forge an authorization at all**. Its compromise
costs availability and metadata, never a forged credential.

That single change is what makes the Notary Service deployable as ordinary
infrastructure. A notary becomes a **witness and policy engine that anyone
may host**, and the question a verifier asks about it stops being *"do I
trust this operator with a key"* and becomes *"is this running the software
the protocol published"* — a supply-chain question, answered by §15.

---

## 1. Summary of changes

| Change | v0.1 | v0.2 | Section |
|---|---|---|---|
| Envelope proof | single object, notary's key | **proof chain**: principal proof + notary countersignature | §2 |
| Attestation strength | not expressed | **`policy.attestationMode`**, closed enum | §3 |
| Delegation Mandate | `notarySignature` only | adds **`principalSignature`** | §4 |
| Principal key discovery | unspecified | `did:key` carries the key **in the envelope**; `did:web`/DNS TXT for rotatable identities | §5 |
| Notary trust anchor | operator reputation | **k-of-3 code attestation** over reproducible builds | §15 |
| `aphVersion` | `"0.1"` | `"0.2"` when a principal proof is present | §7 |

---

## 2. The proof chain (amends §7.1.11)

v0.2 uses the W3C Verifiable Credentials 2.0 Data Integrity **proof chain**.
This is not a new APH construct; multiple proofs on one credential, ordered
so that a later proof covers an earlier one, is a facility the data model
already defines. APH v0.2 constrains it to exactly two roles.

`proof` MAY therefore be either a single object (v0.1 form, still valid) or
an **array** of proof objects. When it is an array:

| Position | `proofPurpose` | `verificationMethod` | Covers |
|---|---|---|---|
| 1 — **principal proof** | `assertionMethod` | the principal's DID URL | the envelope with all `proofValue`s emptied |
| 2 — **notary proof** | `authentication` | the notary's DID URL | the envelope **including the complete principal proof** |

The principal proof is the authorization. Its absence means no party proved
the human agreed to anything.

The notary proof is a **countersignature**. Because it covers the principal
proof, a notary cannot detach a principal's signature and re-attach it to a
different envelope, nor substitute a different authorization beneath its own
signature. It attests three things and no more: that policy was evaluated,
when the decision occurred, and that the notary observed **this exact**
principal proof.

Verifiers MUST verify the proofs in chain order. A notary proof that
verifies over a principal proof that does not itself verify is worthless,
and accepting it would be the defect the chain exists to prevent.

### 2.1 Canonicalization for each proof

The §7.2 rule extends unchanged in substance and is stated exactly here,
because ambiguity in a canonicalization base is how interoperability dies:

- **Principal proof.** JCS-canonicalize the envelope with **every**
  `proofValue` in the chain set to the empty string `""`.
- **Notary proof.** JCS-canonicalize the envelope with the principal
  proof's `proofValue` **present and complete**, and the notary proof's own
  `proofValue` set to `""`.

The empty-string convention (rather than removing the member) is normative
in v0.2 for both proofs, settling the question v0.1 §7.2 left open.

---

## 3. `policy.attestationMode` (adds to §7.1.7)

A closed enum, REQUIRED in v0.2 envelopes:

| Value | Proofs | What a recipient may conclude |
|---|---|---|
| `PrincipalSigned` | principal + notary | **This human authorized this action.** |
| `NotaryAttested` | notary only | *A notary asserts* this human authorized this action. |

`NotaryAttested` is the v0.1 behavior, retained deliberately: on a device
where the principal has no separable key, or in a hardware profile where
signing is delegated to a secure element the application cannot address as
a principal, it remains the honest description of what happened.

**No silent downgrade.** A verifier that requires `PrincipalSigned` and
receives `NotaryAttested` MUST refuse. It MUST NOT accept the weaker claim
and report success, for the same reason §8.4.6 forbids falling back from a
stronger key-discovery mechanism to a weaker one: an attacker who can defeat
the weak path will always present the weak path.

A v0.2 envelope omitting `attestationMode` is malformed. A v0.1 envelope
(`aphVersion` `"0.1"`) omitting it is `NotaryAttested` by definition.

---

## 4. `DelegationMandate.principalSignature` (adds to §6.1)

Standing authority is the highest-value document in the protocol: one
signature grants an agent the ability to act for hours or days. It is
therefore the document that most needs the principal's own signature.

| Field | Type | Required | Description |
|---|---|---|---|
| `principalSignature` | string | in `PrincipalSigned` mode | Multibase signature by the **principal's** key over the JCS-canonical form of this struct MINUS **both** `principalSignature` and `notarySignature`. |

`notarySignature` is unchanged and still covers the form minus itself, with
`principalSignature` **present**. The ordering mirrors §2: the notary
countersigns what the principal signed.

A Communication Mandate MAY carry a `principalSignature` on the same terms.
In the `AskEveryTime` flow it SHOULD, since the human is present by
definition; in the standing-delegation flow the principal's authority is
already evidenced by the parent Delegation Mandate.

---

## 5. Principal key discovery (amends §8.4)

The §8.4 mechanisms apply to principal keys unchanged, with one property
worth stating plainly because it removes a whole class of deployment work:

**A `did:key` principal needs no lookup.** In `did:key`, the public key
**is** the identifier. When `credentialSubject.humanPrincipal.id` is a
`did:key`, the verifying key is already present in the envelope, and a
recipient verifies the principal proof with **no network access, no
publication, and no prior relationship**. This is the recommended default
for individual principals.

The trade-off is equally plain and MUST be documented wherever `did:key` is
recommended: **a `did:key` principal cannot rotate its key.** The key is the
name; changing the key changes the principal's identity. Principals
requiring rotation — organizations, long-lived service identities — MUST use
`did:web` or DNS TXT publication, which carry `kid` and therefore support
overlapping keys during rotation (§8.4.5, §8.4.7).

---

## 6. Verification steps (amends §8.3)

Insert after v0.1 step 1 (strict parse):

1a. **Read `attestationMode`.** If the verifier's policy requires
    `PrincipalSigned`, refuse now on any other value (§3). Do not proceed
    and discover the weakness later.

1b. **Resolve the principal's key.** For a `did:key` principal, decode it
    from the identifier — offline. Otherwise resolve per §8.4.

1c. **Verify the principal proof** over the §2.1 principal base. Failure is
    `APH_E001`. A verifier MUST NOT continue to the notary proof on
    failure: the notary proof cannot rescue an unauthorized envelope.

v0.1 steps 2 through 9 then proceed for the **notary proof**, unchanged.

Add after v0.1 step 9:

10. **Attestation policy (OPTIONAL).** A verifier MAY require that the
    notary advertise a code attestation valid under §15 and refuse
    otherwise. This is policy, not protocol: a verifier that does not check
    it is still conformant.

---

## 7. Versioning

An envelope carrying a principal proof MUST set `aphVersion` to `"0.2"`.
An envelope with a single notary proof MAY remain `"0.1"` indefinitely; it
is not deprecated. A v0.2 verifier MUST accept both. A v0.1 verifier
encountering `"0.2"` MUST reject it per §8.3 step 7 rather than attempt a
partial verification — which is exactly what the version pin is for.

---

## 15. Notary Code Attestation

> Numbered §15 because v0.1 §12 is Security Considerations; §15 appends
> after v0.1 §14 References.

A Notary Service that cannot forge authorizations (§0.1) may be hosted by
anyone. That raises a different question: **is this notary running the
software the protocol published?** §15 answers it with a supply-chain
attestation rather than a key-custody claim.

### 15.1 The authority

The APH protocol authority publishes attestations under a **k-of-3
threshold**: three holder keys, of which any **two** valid signatures
constitute a valid attestation. Two is chosen deliberately — one lost key
must not halt releases, and one compromised key must not be able to ship
alone.

The three authority public keys are published through the §8.4 mechanisms
like any other APH key material, and are subject to §8.4.7 rotation with
overlap.

### 15.2 The subject

An attestation is over a **content digest of a reproducible build** of a
notary release: the artifact, not a version string. A version string is a
claim about an artifact; a digest is the artifact.

### 15.3 What a notary advertises

A notary MAY declare the attested digest it is running in
`credentialSubject.notarization.notaryService`, last-position additive:

| Field | Type | Required | Description |
|---|---|---|---|
| `attestedDigest` | string | no | Content digest of the attested release this notary reports running. |
| `attestationUri` | string | no | Where the k-of-3 attestation for that digest may be fetched. |

### 15.4 Reuse, not invention

Attestation format, transparency logging, and provenance vocabulary SHOULD
reuse existing supply-chain standards — Sigstore, in-toto attestations, and
SLSA provenance — rather than defining an APH-specific schema. APH's
contribution here is the k-of-3 authority and the binding into
`notaryService`, not a new signature envelope.

### 15.5 The limit, stated normatively

**An attestation proves what code was published. It does not prove what
code is running.**

Absent hardware-backed remote attestation, a notary operator can publish an
attested digest and execute something else. §15 therefore raises the cost of
operating a malicious notary and narrows the population of plausible ones;
it does not make a remote notary honest.

Implementations MUST NOT present an attestation as a guarantee of honest
execution. Any user-facing surface that renders an attestation badge MUST
convey this limit. A design or interface that implies otherwise is
non-conformant with this section.

This is also why `PrincipalSigned` matters more than attestation: the
principal proof is verified by mathematics, and needs no assumption about
what a remote process is running.

---

## Appendix: Errata to v0.1

- **E-1.** §1.1 and §3.1 describe a direct-principal-signature mode that
  the v0.1 wire format cannot express. Readers of v0.1 should understand
  those sentences as describing intent fulfilled in v0.2 §2. In v0.1, every
  credential is `NotaryAttested`.
- **E-2.** §7.2 leaves open whether a signer removes `proof.proofValue` or
  sets it to the empty string. v0.2 §2.1 settles this normatively as the
  empty string, for every proof in the chain. The reference implementation
  has always behaved this way.
- **E-3.** §4 states that v0.1 "assumes a local notary holding the human's
  signing key." Under v0.2 `PrincipalSigned` this is no longer the case, and
  the remote-notary profile §4 anticipates becomes safe without the
  multi-signature escrow §4 suggests, because the principal's signature —
  not the notary's custody — is what carries the authorization.
