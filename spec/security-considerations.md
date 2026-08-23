# APH Security Considerations

> Companion to `spec/aph-0.1.md`. Describes the threat model APH defends
> against, what it intentionally does NOT defend against, and operational
> guidance for implementers.

## 1. Threat Model

APH is a per-message attestation protocol. It binds a single outbound
message — identified by its body hash, channel, recipient addressing, and
agent identity — to a human principal whose key material is controllable
and verifiable by recipients across vendor and trust boundaries. The
protocol's central design assumption is that **a signature made by the
human's own key** demonstrates that the named human authorized the named
message on the named channel within the named time window — carried either
as the principal proof of a `PrincipalSigned` envelope, or as the
`principalSignature` on the Delegation Mandate embedded in a
`NotaryAttested` one (§7.1.7.1). A notary signature alone demonstrates that
a notary *asserts* this, which is a weaker claim and must never be reported
as the stronger one.

The protocol operates in an adversarial environment in which any of the
sending agent, the transit network, intermediary relays, and the
recipient's own infrastructure may be controlled by an attacker. APH's
crypto chain (RFC 8785 canonical JSON plus RFC 7515 detached JWS) is
intended to remain meaningful in the presence of all such adversaries
short of a compromise of the Notary Service's signing key or the human's
device.

APH does NOT attempt to defend against threats that target the human's
device, the human's judgment, the channel's transport security, or the
correctness of the recipient's address resolution. Those concerns are
left to the device's operating system, the human's training, the
channel's existing transport security mechanisms (TLS, end-to-end
encryption), and the recipient's identity infrastructure (DNS, MX,
contact resolution). Sections §2 and §3 enumerate the threat split
precisely.

## 2. In-scope threats (APH defends against these)

### 2.1 Replay

Threat: an attacker captures a valid APH envelope and replays it later,
potentially in a different conversation, hoping the recipient will accept
the message as freshly authorized.

Mitigation: every envelope carries a `validFrom` / `validUntil` time
window and a unique `id` (UUID v4 in the canonical encoding). Recipients
MUST reject envelopes presented outside the time window. Recipients
SHOULD additionally maintain a short-lived dedup cache keyed on the
envelope `id` so a single envelope cannot be presented twice within its
validity window. Time windows are bound at notarization time and SHOULD
be on the order of minutes, not hours.

### 2.2 Tampering with the message body

Threat: an agent (or any intermediary on the transit path) modifies the
outbound message body after the human approved it, then forwards the
modified body alongside the unmodified envelope.

Mitigation: the envelope's `communication.bodySha256` field commits the
human's authorization to specific body bytes. Recipients MUST compute
SHA-256 of the body they received and reject the envelope if the digest
does not match the field's value. The `bodySize` field is advisory and
defends against trivial truncation attacks where the digest computation
could be confused by length ambiguity.

### 2.3 Mandate forgery

Threat: an attacker synthesizes a `DelegationMandate` or
`CommunicationMandate` without involving any Notary Service, then
presents it alongside a self-prepared envelope.

Mitigation, in two layers. **The human's layer:** a `DelegationMandate`
carries `principalSignature`, made by the human's own key over the
canonical mandate minus both signature fields (§6.1). An attacker who does
not hold the human's key cannot produce it, and a recipient checks it
directly — against a `did:key` principal, with no lookup at all. **The
notary's layer:** the envelope's proof (the single proof of a
`NotaryAttested` envelope, or the countersigning second proof of a chain)
is signed with a key bound via `verificationMethod` to a DID controlled by
the Notary Service, and verified against the key published in that
service's DID document or DNS TXT record (§8.4).

Either layer failing is fatal: an envelope whose notary proof does not
verify MUST be rejected (`APH_E001`), and an embedded mandate whose
`principalSignature` does not verify MUST be rejected (`APH_E011`). Note
the asymmetry that matters — **only the human's layer proves authorization**.
A recipient that verifies the notary proof alone has confirmed provenance,
not consent.

### 2.4 Channel impersonation

Threat: an attacker takes an envelope notarized for one channel (for
example a Slack reply to a private channel) and re-presents it on a
different channel (for example a public email blast), hoping the
recipient on the second channel will accept the message as authorized.

Mitigation: the `channel.kind` field and the channel-specific
`recipientAddressing` sub-object are inside the signed payload. Channel
adapters on the recipient side MUST validate that the channel they are
operating on matches the envelope's `channel.kind` and that the
addressing fields match the actual delivery context (workspace and
channel for Slack, recipient address for email, and so on). An envelope
whose `channel.kind` does not match the adapter's channel MUST be
rejected.

### 2.5 Algorithm downgrade and `alg: none`

Threat: an attacker presents an envelope whose JWS protected header
declares `alg: none`, or declares an unsupported weak algorithm, hoping
the recipient's JWS library will accept the envelope without verifying a
real signature.

Mitigation: recipients MUST reject any envelope whose protected-header
`alg` is not in the supported set. The supported set in v0.1 is exactly
`ES256` and `EdDSA`; `alg: none` MUST be rejected regardless of any
other consideration. Implementers SHOULD select a JWS library that
allows the application to pin the accepted algorithm set; libraries that
default to a permissive accept-list MUST be configured restrictively
before use.

### 2.6 Attestation-mode downgrade

Threat: an attacker presents a `NotaryAttested` envelope — or simply omits
`attestationMode`, which means `NotaryAttested` (§7.1.7) — to a recipient
whose policy expects the human's own signature, hoping the recipient
verifies whatever proof it finds and reports the result as "the human
authorized this." This is structurally identical to §2.5's algorithm
downgrade and strictly more consequential: `alg: none` costs a signature
check, this costs the entire authorization claim.

Mitigation: a verifier that requires `PrincipalSigned` MUST read
`attestationMode` FIRST and refuse anything else with `APH_E012`, before
doing any verification work (§8.3.1 step 1a). It MUST NOT infer the mode
from the shape of `proof`, and MUST NOT accept a chain whose principal
proof fails on the strength of a valid notary countersignature. A verifier
that accepts both modes MUST render them differently to a human: *"Alice
signed this"* and *"Alice's notary says Alice approved this"* are different
sentences, and collapsing them into one badge is the defect this section
exists to prevent.

## 3. Out-of-scope threats (APH does NOT defend against)

### 3.1 Compromised Notary Service signing key

A leaked notary key is serious but **bounded**, and the bound is the point
of the trust model. The notary never holds the principal's key, so an
attacker holding a leaked notary key **cannot forge an authorization**:

- Against a `PrincipalSigned` envelope, they can produce a valid
  countersignature over an envelope the human never signed — and a verifier
  rejects it at the principal proof (`APH_E011`), which the attacker cannot
  produce.
- Against a `NotaryAttested` envelope carrying an embedded mandate, they
  hit the same wall at the mandate's `principalSignature`.
- Against a `NotaryAttested` envelope carrying **no** embedded mandate, they
  can issue arbitrary envelopes under the human's name, because in that
  shape nothing the human signed is present. **This is the residual risk,
  and it is why §7.1.7.1 says to embed the mandate and why a recipient MAY
  refuse an envelope that omits it.**

What a leaked key always costs: availability (an attacker can flood), and
metadata (envelopes reveal who messaged whom, when, on which channel).
Operators MUST still run key management accordingly — hardware-backed
storage where available, restricted signing-service attack surface, planned
rotation (§8.4.7) — and §6.3.3 now specifies the revocation transport (a
W3C Bitstring Status List v1.0 profile), so a withdrawn mandate becomes
observable to third-party recipients without a key rotation. Note the
limit of that transport against THIS threat: the status list is published
by the notary and signed by the notary's key, so an attacker holding that
key can publish a list too. Revocation status defends against a
compromised *mandate*, not against a compromised *notary key*; for the
latter the answer remains rotation under §8.4.7. The design goal is not
that a notary is never compromised; it is that a compromised notary cannot
put words in a human's mouth.

### 3.2 Compromised Human Principal device

If the human's device is compromised at a level that lets the attacker
trigger the local Notarization Service to issue mandates, every envelope
the attacker produces will be cryptographically valid. APH cannot detect
this. OS-level device security (full-disk encryption, secure boot,
hardware-backed key storage, user authentication on every consent prompt)
is the boundary. Implementations SHOULD make the consent prompt
operationally distinct from background activity so a compromised
attacker cannot silently approve sends, but a sufficiently capable
attacker who controls the device will defeat that defense.

### 3.3 Recipient phishing and address misresolution

APH proves who authorized the outbound message. It does NOT prove the
recipient's address was correctly resolved on the sender's side. If an
agent is tricked into sending a notarized message to the wrong address —
through a typo, a homograph attack, or a DNS hijack — APH cannot detect
the misrouting. DNS security extensions, recipient verification (for
example a known-recipient cache on the sender side), and channel-level
trust signals (verified domains in chat platforms, DMARC for email) are
the appropriate mitigations.

### 3.4 Social engineering of the human

If the human approves a malicious message — because a phishing prompt
deceived them, or because the agent's UI misrepresented the message body
— APH will faithfully notarize the bad message. APH is not a
content-moderation protocol. Implementers SHOULD render the preview
lines and the recipient addressing prominently in the consent prompt so
the human can detect mismatches between the message they intend to
authorize and the message the agent is actually preparing.

### 3.5 Channel-level transport security

APH does NOT replace TLS or end-to-end encryption on the transport
channel. APH binds the message to the human; transport confidentiality
and integrity remain the responsibility of the channel adapter and its
transport. An envelope sent over plaintext SMTP is just as readable to a
network attacker as the message body itself.

### 3.6 Loss of the Notary Service signing key

§3.1 covers a key an attacker has. This covers a key nobody has: the store
holding the private half is lost, wiped, or becomes unreadable, and no copy
exists. APH offers no protocol-level recovery, and adding one would mean a
custodian — which is precisely the dependency the trust model exists to
avoid.

The consequences split cleanly, and the split is worth stating because the
frightening half is not the one operators expect:

- **Nothing already signed is invalidated.** Those signatures remain genuine
  and remain verifiable for as long as the corresponding PUBLIC key stays
  published, which is what §8.4.7 step 4's further-visibility window is for.
- **No human's authority is affected.** The notary never held a principal
  key, so the authorization layer of a `PrincipalSigned` envelope is
  untouched. What stopped is the witness.
- **The revocation transport fails within minutes, fleet-wide.** §6.3.3.3
  requires the status list credential to be re-issued at least every 120
  seconds and refuses one older than 300 seconds plus 60 seconds of skew. A
  signer that goes away therefore takes every status-carrying envelope with
  it about six minutes later, refused with `APH_E008` by every conformant
  verifier. This is fail-closed behaving exactly as designed, and it is the
  reason key loss is an incident measured in minutes rather than in the days
  a re-publication would take.

**What actually determines recoverability is control of the domain, not
possession of the key.** Both discovery mechanisms are anchored in domain
ownership — §8.4.4 in the TLS chain, §8.4.5 in DNS — and neither is
authenticated by the notary's signing key. An operator who retains domain
control can publish a replacement key; an operator who loses the registrar
credentials alongside the signing key has lost the identity outright, and no
escrow scheme repairs that, because the missing capability is publication
rather than signing.

Two operator-side mitigations, both compatible with the trust model and
neither required by it: a **pre-authorized rotation** (a successor key
generated and published in advance under §8.4.7's overlap, so recovery never
needs the lost key) and separating the domain-control credentials from the
key store. `operations.md` §2 and §3 carry the mechanism and the procedures.

### 3.7 Denial of service against a publication surface

An attacker who can stop a notary's status list from being republished — or
who can make its origin unreachable — causes every conformant verifier to
refuse every envelope that carries a `credentialStatus` (§6.3.3.4 case 2).
APH does not defend against this, and the exposure is deliberate: §6.3.3.4
explains why an attacker who can make the status check *fail* must not
thereby get to choose that it is *skipped*. Availability is traded for the
guarantee that a revoked mandate cannot be laundered back into acceptance.

What follows for an operator is that publication liveness is a security
property and not merely an uptime one, and that its failure is silent until
it is total. The window between the 120-second republish obligation and the
360-second refusal cliff is the only warning, so it has to be watched
deliberately rather than inferred from peers refusing. `operations.md` §5
carries the two deadlines and a monitor that reads them from the published
document itself.

## 4. Algorithm requirements

Implementations of APH 0.1 MUST support the following JWS algorithms:

- `ES256` — ECDSA using the NIST P-256 curve and SHA-256 (RFC 7518). This
  algorithm is REQUIRED for interoperability with AP2-shaped tooling and
  for recipients whose verifier libraries derive from existing W3C VC
  Data Model 2.0 deployments.
- `EdDSA` — Edwards-curve Digital Signature Algorithm with the Ed25519
  curve (RFC 8032). This algorithm is REQUIRED for compact signatures and
  for deployments whose human-principal device keys are Ed25519.

Implementations MUST reject the `none` algorithm. Implementations SHOULD
reject any algorithm not listed above; future drafts (v0.2 and beyond)
MAY extend the set after a coordinated rollout in which recipients
update first and senders follow. The supported set is closed; ad-hoc
extension on a per-deployment basis is NOT permitted because doing so
would defeat cross-vendor verification.

## 5. Key management guidance

Notary Service signing keys SHOULD be stored in hardware-backed key
storage where available — TPM 2.0, Apple Secure Enclave, Android
StrongBox, or a network HSM. Software-only key storage is acceptable for
v0.1 prototyping but creates a single-process compromise as the failure
boundary. Production deployments SHOULD plan a path to hardware-backed
storage before the protocol moves beyond pilot use.

DIDs used for the `issuer`, `humanPrincipal.id`, and `agent.id` fields
SHOULD resolve to durable, controllable key material. `did:key` and
`did:web` are RECOMMENDED for v0.1 because they have wide library
support and the verification method is unambiguous from the DID
document. Other DID methods (`did:ion`, `did:plc`, `did:peer`) MAY be
used where the deployment already has tooling for them; verifiers MUST
be configured with the DID method resolvers they expect to encounter.

Rotation: implementations SHOULD support multiple active verifying keys
per DID document so a deployment can roll its signing key without a
flag day. During rotation, recipients accept any of the currently
published verifying keys; the Notary Service issues new envelopes under
the new key, and after a configurable overlap window the old key is
removed from the DID document. §8.4.7 specifies the overlap normatively,
including how it is expressed on each publication mechanism; what remains
for v0.2 is a maximum overlap window and a recommended notification
mechanism for downstream recipients.

Verification keys on the recipient side SHOULD be cached with a TTL no
longer than the longest plausible rotation overlap window so a
recipient does not continue to accept envelopes signed under a key that
the issuer has withdrawn.

### 5.1 Key continuity: pre-authorized rotation

Storing a key well is not the same as surviving its loss, and §3.6 shows the
loss case has a six-minute fuse. The mitigation that fits the trust model —
no custodian, no key leaving the operator's control, no service the protocol
then depends on — is to use §8.4.7's overlap mechanism defensively:

Generate a SUCCESSOR keypair now, on media separate from the signing host,
and publish its public half alongside the primary's **continuously**, with a
distinct `kid` — and configure the SIGNER to emit that `kid` as the fragment
of `proof.verificationMethod` before publishing anything, because that is the
half of the pairing which does the work. Two published keys and a
fragment-less DID URL leave a verifier no way to choose, and the §8.4.6
mechanisms resolve that differently: a DID Document declines to guess among
several keys and the resolution refuses, while a DNS TXT verifier takes the
first record valid at that instant, in whatever order it was answered. Both
fail closed, so no wrong key is accepted, but the resulting verification
outage is self-inflicted by the continuity mechanism — and §8.4.7's 30-day
bound on that ambiguity does not apply to a successor published permanently.
Keep signing with the primary. Because verifiers already
resolve and accept the successor, recovery becomes a change to what the
operator signs with rather than a change to what the world can read — no
document edit, no DNS propagation, no cache to wait out, and nothing that
must be done with a key that no longer exists.

Two honest costs. **Two keys can sign for the identity for the whole period**,
not just during a 30-day rotation window, so the exposure §3.1 bounds is
doubled in duration; the discipline that answers it is keeping the successor's
private half off the signing host until promotion. **An unexercised successor
is an untested backup** — it must be rehearsed against the key *as published*,
or its first use is also its first test. `operations.md` §3 carries the
procedures, including the rehearsal.

Note what this mechanism does NOT claim. APH v0.1 defines no signed rotation
statement, and neither publication surface is authenticated by the notary's
key (§3.6). A successor is pre-*authorized* by having been published under
the operator's domain control while the primary was healthy — the same
authority that publishes every APH key — and describing it as "signed by the
old key" would overstate what the wire carries.

### 5.2 Threshold split of the seed

An operator MAY split the signing seed into *n* shares of which any *k*
reconstruct it, holding every share themselves, using an audited external
implementation of their own choosing. It buys a property rotation does not:
no single medium reconstructs the key, loss of up to *n − k* shares is
survivable, and because the SAME key is restored, nothing published changes
and no verifier re-pins.

It also costs what rotation does not: reconstruction assembles the whole seed
on one machine at one moment, and the shares must be placed so they cannot be
lost together yet cannot be gathered by one adversary — two requirements that
pull against each other, and in which the placement is the entire security of
the scheme. It protects the key, not the identity: if the shares are lost too,
the operator is back to §5.1, which is why the two are complementary rather
than alternatives.

**This specification's reference implementation deliberately ships no
secret-sharing code.** A subtly wrong sharing scheme does not fail loudly —
it leaks the key to a holder of fewer than *k* shares and the operator never
learns — so shipping an unaudited one inside a protocol library would make a
threat-model decision on the operator's behalf, badly. The decision to escrow
at all, and in what form, is the operator's; nothing in APH requires it.

## 6. Privacy considerations

The APH envelope inherently reveals: the human principal's DID
(`humanPrincipal.id`), the agent's DID and AgentCard URI (`agent.id`,
`agent.agentCardUri`), the channel kind (`channel.kind`), the channel
addressing fields, and a SHA-256 hash of the body plus a preview
(typically three to five lines). For most deployments this is the
intended disclosure surface because the recipient legitimately needs to
identify both the human and the agent. For privacy-sensitive
deployments, this disclosure surface may be larger than desired.

For privacy-sensitive deployments, the envelope MAY be delivered via the
SD-JWT-VC profile (see the main spec, §10.4). Under that profile the
recipient receives only the disclosed claims; undisclosed claims remain
unrecoverable from the wire form. A recipient that only needs to know
"the named human consented to send a message on this channel" can be
given a selectively-disclosed envelope that omits the preview, the
preview line count, and any cross-link references.

The `communication.bodySha256` field is a SHA-256 hash; for very short
bodies (one or two characters of low-entropy content) brute-force
preimage recovery is computationally trivial. Bodies SHOULD carry at
least sixteen bytes of entropy for the hash to be meaningful as a
confidentiality boundary; typical message bodies easily exceed this.
Implementers SHOULD NOT rely on the body hash for confidentiality of the
message body — the hash is a binding mechanism, not an encryption
mechanism.

### 6.1 Revocation status is a phone-home, and APH did not previously have one

The revocation transport (§6.3.3) introduces a disclosure this protocol
did not make before this revision, and it is worth naming plainly rather
than leaving an implementer to discover it in a traffic capture.

Every check in §8.3 before step 8a is offline or resolves key material
that is cacheable for hours. Step 8a is different: a recipient checking
status makes a TLS connection **to the issuing notary's own host**, and
it makes that connection at the moment of verification. The notary
therefore learns that *someone at this IP address is verifying an
envelope right now* — a fact it previously could not observe at all,
because a recipient with a cached key never had to contact it. Repeated
across a correspondence, the timing series describes when a particular
recipient reads messages from a particular principal.

Two properties bound the disclosure, and one aggravates it:

- **A bitstring list gives herd privacy.** The verifier fetches the WHOLE
  list, not one mandate's entry, so the fetch does not reveal which
  mandate is being checked. That is the reason a bitstring is preferable
  here to a per-mandate status endpoint, and it is a reason the choice of
  vintage is a privacy decision and not only an interoperability one.
- **The freshness bound is short, so caching helps less than usual.**
  §6.3.3.3 caps a cached list at five minutes and RECOMMENDS a 60-second
  TTL. A recipient that verifies frequently therefore phones home
  frequently. The bound is deliberate — a stale answer is the failure the
  transport exists to remove — but it trades privacy for currency, and
  the trade is made explicitly here rather than silently.
- **The origin is derived, so the recipient cannot be steered.** §6.3.3.2
  binds the fetch to an origin derived from the notary's own `did:web`
  and refuses a cross-origin `statusListCredential` unfetched. A verifier
  therefore cannot be turned into a probe against a host of the sender's
  choosing — the privacy cost is paid to the notary that already knows
  the mandate exists, and to nobody else.

Mitigations available to a privacy-sensitive recipient: fetch the list on
a schedule rather than on demand (accepting the freshness bound as an
upper limit rather than a target), route the fetch through a shared
egress or a caching proxy so the notary sees one aggregate client rather
than each recipient, or decline to check status and accept the residual
risk — which remains conformant only for envelopes carrying no
`credentialStatus`, since §6.3.1 item 3 makes the check a MUST when one
is present.

One implementation note that is a correctness matter and not only a
privacy one: `statusListIndex` is a **string**, never a JSON number
(§6.3.3.6). A runtime that widens it into a floating-point value silently
rounds indices past 2^53 and then reads the wrong bit — reporting another
mandate's revocation state as this one's, with no parse error anywhere.
This is the same float-widening hazard that removed structured-value
passing from the wasm binding, and it is why the wire type is a string.

## 7. Deferred / out-of-scope

The following topics are intentionally NOT addressed in APH v0.1 and are
tracked for later drafts or for other specifications:

- Status for anything other than a Delegation Mandate. §6.3.3 landed the
  revocation transport for withdrawn mandates (a W3C Bitstring Status
  List v1.0 profile). It does NOT cover a compromised notary key: a list
  the compromised key itself signs is worth nothing against its holder,
  so key-level compromise is still answered by rotation (§8.4.7), and
  a status mechanism for keys remains future work.
- Formal cryptographic protocol analysis. v0.1 relies on the documented
  security properties of its underlying primitives (RFC 8785, RFC 7515,
  RFC 7518, RFC 8032). A formal analysis of the composed protocol
  remains future work.
- Quantum-resistant algorithm set. v0.1 fixes ES256 and EdDSA, both of
  which are vulnerable to a sufficiently large quantum computer. A
  post-quantum algorithm set will be defined when the relevant IETF
  algorithm registrations stabilize.
- Hardware attestation linkage. The envelope does not currently carry a
  TPM attestation, an Apple App Attest assertion, an Android Play
  Integrity verdict, or any analogous device-binding signal. A future
  draft MAY add an optional `deviceAttestation` block so a recipient can
  evaluate the device's posture in addition to the human's consent.
- Transparency log integration. APH envelopes MAY in a future draft be
  written to a Sigstore Rekor-style transparency log for tamper-evident
  audit; v0.1 does not specify the binding.
- Coordinated multi-party consent. v0.1 attests one human per envelope.
  Group consent (M-of-N approvals from a set of humans) is left to a
  future draft.
- IANA registration of APH's own identifiers. Two are used by CONVENTION in
  v0.1, with complete registration requests drafted and submission pending
  (§13; `spec/registrations/`): the `aph://` URI scheme and the `_aph` /
  `_aph._notary` underscored DNS labels. This stays an open item because
  drafted is not registered — neither name is APH's until IANA acts, and the
  exposure below is exactly what it was before the drafts existed. A distinct
  APH media type is NOT among them — §13 declines it outright rather than
  drafting one, registering none, naming the already-registered
  `application/vc+ld+json` as the conformant choice, and requiring verifiers
  to accept the unregistered `application/aph+ld+json` as well. Neither
  unregistered name affects whether an envelope verifies — a conformant TXT
  parser refuses any record whose `v` tag is not `APHv1`, so a foreign record
  at a colliding name is ignored rather than misread — but an adopter should
  know which names this protocol does not yet own. `operations.md` §6
  enumerates every unregistered identifier, including the unserved
  `https://w3id.org/aph/v1` JSON-LD context, with the consequence of each.
- A signed key-rotation statement. §8.4.7 rotates by publishing two keys, and
  the authority to publish is domain control rather than key control (§3.6).
  A rotation attestation signed by the outgoing key — which would let a
  verifier check that a successor was named by its predecessor rather than
  merely served from the same origin — is a v0.2 question, and now has a
  non-normative design draft: `rfcs/0001-rotation-attestation.md` (RFC 0001). The
  draft's own honesty notes apply here too — a stolen current key signs a
  rotation as readily as the operator does, and the mechanism upgrades
  continuity, not genesis.
