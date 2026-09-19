# APH Guardrails — a shared vocabulary for what agents ask of each other

**Status: alpha.** The label sets are complete and internally reviewed; the
accuracy gates are not yet backed by published corpora (see *Honest scope*).

When one agent tells another "accept the meeting time" or "update the customer
record," both sides need an answer to what that phrase *means* — and neither
counterparty should be the one who decides. This Snapp is that answer: a
shared, versioned, independently resolvable vocabulary of classifiers that two
agents from different organizations can both point at. It applies the same
trust move the APH protocol makes for notary keys — resolve from something
public that neither party controls — one layer up, to meaning.

## What is here

Sixteen classifier families, 184 labels, in three tiers plus a routing output:

- **Acts** — what the agent is asking for: scheduling, commitment, data
  mutation, access, financial, legal, and the delegation chain itself.
- **Guards** — sealed, fail-closed gates: consent standing, the hard safety
  floor, channel-injection detection, and protected-data disclosure.
- **Risk** — irreversibility, blast radius, urgency-as-claimed, and which
  regulatory regime plausibly attaches.
- **Routing** — `APH_HUMAN_LOOP`, the output the other fifteen feed: how much
  human involvement this act requires before an agent may proceed.

Each family is one literate `.n.md` file under `APH_GUARDRAILS/`, declared in
`APH_GUARDRAILS/mod.n.md` (declaration order is load order; an undeclared file
never loads). The `how/overlays/` recipes document the extension model.

## Extending it

The first entry for a namespace is the base; every later entry is a
tighten-only overlay. A contributor may add a label, raise a confidence floor,
remove a rung, restrict privacy locality, or harden a fail posture — and may
never do the reverse. Violations are loud load refusals, never silent clamps.
Six families are **sealed** and refuse all overlays: authority, consent,
safety, injection, disclosure, and human-loop. For those, the only change
path is a new base version a verifier can see and choose.

## Honest scope

Three limits, stated so they cannot be discovered later:

1. **The accuracy gates are declarations of intent.** Every family names a
   `golden_set` path under `eval/` and a `min_accuracy` between 920 and 980.
   The corpora do not ship yet, so the gates assert what a conforming
   evaluation must clear — they are not yet evidence that anything clears it.
2. **The seals are authored intent.** Whether `sealed = true` is enforced is a
   property of the consuming runtime's fold, not of these bytes. Verify your
   engine refuses overlays against sealed specs before relying on the seal.
3. **The wire binding is designed; adoption is young.** An APH envelope
   carries these labels in `credentialSubject.actClassification`
   (spec §7.1.12): family-qualified as `FAMILY/LABEL` — a bare label is a
   strict-parse rejection — as a set across families, citing this
   vocabulary by `{name, version, digest}`. Publication and resolution
   ride spec §8.5 (`_aph._vocab.<domain>`, digest-pinned, absent advances
   / corrupt refuses). The blessed citation for this bundle (ruled
   2026-08-31, superseding the same-day alpha.1 blessing):
   `name = "aph_guardrails"`, `version = "0.1.0"`,
   `digest = "sha256-iTJRGKxirtZFmyDmoGPdPyRzIevrjVddmWhMnCa6Od0="` —
   SHA-256 over the fetched artifact bytes (SRI-style, RFC 0010) of the
   compiled bundle `snapp/aph_guardrails@0.1.0.json`, which is also the
   machine-readable registry of the 184 labels and the artifact the
   reference repository's freshness weld regenerates from these sources
   on every test run. (The bundle's internal `@snapp.integrity` string
   has no protocol meaning — RFC 0010.) The superseded
   `aph_guardrails@0.1.0-alpha.1.json` stays in-repo, frozen, for
   citations already minted against it
   (`sha256-DhTpa6O6GraKyoUFz91imP6f9gBYkXAVvDiqwRo2W60=` over its
   bytes).
   Emission stays version-gated (§7.1.12): do not emit toward a recipient
   not known to understand the field. What remains genuinely young:
   published TXT records and deployed consumers.

## Relationship to the APH protocol

The sibling Snapp (`APH Spec/`) defines the **wire**: envelopes, mandates,
signatures, key discovery. This Snapp defines **meaning**, and versions
independently, because a wire format is stable by obligation while a
vocabulary grows continuously. Binding them to one version number would force
one to move at the other's pace.
