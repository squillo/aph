---
description: Validate an APH NotarizationEnvelope with the reference CLI and report a verdict with spec-grounded diagnosis
argument-hint: <path/to/envelope.json | raw envelope JSON>
---

Validate the APH NotarizationEnvelope given in: $ARGUMENTS

1. **Resolve the input.** If the argument is a path to a JSON file, use it as-is
   (make it absolute). If it is raw JSON, write it to a scratch file first. If it
   is empty, ask which envelope to validate (the golden fixtures live at
   `${CLAUDE_PLUGIN_ROOT}/examples/*.json`).

2. **Run the reference structural check.** From the working directory
   `${CLAUDE_PLUGIN_ROOT}/interpreters/rust`, run:

   ```
   cargo run -q -p aph-cli -- validate <absolute-path-to-envelope>
   ```

   Scope: the CLI performs a STRICT STRUCTURAL PARSE ONLY
   (`deny_unknown_fields` against the canonical wire types). It does NOT verify
   the signature, the `validFrom`/`validUntil` time window, the algorithm
   allow-list, or the body hash — those are spec §8.3 steps 2–8 and the CLI
   implements only step 1.

3. **If the CLI rejects the envelope, diagnose the parse failure precisely**
   (`spec/aph-0.1.md`):
   - The envelope parser is strict (`deny_unknown_fields`) — an unknown or
     missing envelope-level field is fatal (§7.1, §8.3 step 1). Compare
     field-by-field against the §7.1 tables. Exception:
     `channel.recipientAddressing` sub-fields are opaque (§7.4).
   - Unrecognized channel kind: check the closed enum (§7.1.5); `google_chat`
     (snake_case) is the normative spelling per the §7.1.5 erratum.

4. **Then perform the checks the CLI does not run, by hand**, and report each
   as a separate line item using the APH error taxonomy (§11):
   - Time window: `validFrom <= now <= validUntil` with ~60s skew (§8.3
     step 6); expired is `APH_E003`.
   - Algorithm: only `ES256` and `EdDSA` are allowed; `alg: none` is always
     rejected — `APH_E010` (§8.1). Check `proof.cryptosuite` /
     JWS header against §8.2.
   - Body hash format: `communication.bodySha256` must be 64 lowercase hex
     (§7.1.6); an actual mismatch against recomputed body bytes is `APH_E009`
     (recomputation is only possible when you have the body).
   - Signature (`APH_E001` envelope-level, `APH_E006` mandate-level): NOT
     verifiable here without resolving the notary key (§8.4). Note: the repo
     example fixtures carry placeholder `proofValue`s that are not real
     signatures, so cryptographic verification of them is impossible by design.

5. **Fallback when the CLI is unavailable** (workspace missing, build broken):
   perform the structural checks by hand against the knowledge in the
   `/aph:spec` skill (`skills/spec/SKILL.md`): required top-level fields,
   `@context` order (`https://www.w3.org/ns/credentials/v2` then
   `https://w3id.org/aph/v1`), both `type` entries, `aphVersion == "0.1"`, the
   six `credentialSubject` objects, closed enums (channel kind, contentClass,
   policy decision), `bodySha256` format, `validFrom < validUntil`, and a
   well-formed `proof` block.

6. **Report the verdict** with its scope stated explicitly — e.g.
   `VALID (structural strict-parse; time window checked; signature and body
   hash NOT verified)` or `INVALID`, the precise reason, the APH error code
   when one applies, and the spec section reference (`spec/aph-0.1.md` §N) so
   the user can read the normative text. Never report an unqualified `VALID`:
   this command does not perform cryptographic verification.
