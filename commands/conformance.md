---
description: Run the APH reference conformance suite and summarize pass/fail per suite, mapping failures to spec sections
argument-hint: [optional cargo test filter]
---

Run the APH conformance suite and report results.

1. **Run the tests.** From the working directory
   `${CLAUDE_PLUGIN_ROOT}/interpreters/rust`, run:

   ```
   cargo test
   ```

   If a filter was provided in `$ARGUMENTS`, append it: `cargo test $ARGUMENTS`.
   This covers the workspace default members: `aph-core`, `aph-conformance`, and
   `aph-cli`.

2. **Summarize pass/fail grouped by suite**, not as one flat list:
   - golden envelope fixtures (canonical envelope shapes)
   - contract tests (validation rules, closed enums, strict parsing)
   - channel-binding specs (per-channel `recipientAddressing` shapes)
   - repo examples round-trip (`examples/*.json` parsed with strict schema)
   - two-party exchange (a stranger admitted through the §8.4.6 chain, then
     four refusals each asserting its own error code)
   - three-party relay (verifier-identity independence across Alice → Bob →
     Carol, with Bob in both roles)
   - cross-notary revocation (the published, signature-verified status list
     across a trust boundary; forged and replayed lists refused)

   Give totals per suite (passed/failed/ignored) and name each failing test.

3. **Map every failure to the spec** (`spec/aph-0.1.md`) so it is actionable:
   - envelope shape / missing or unknown fields → §7.1 (strict
     `deny_unknown_fields` parsing; `recipientAddressing` opaque per §7.4)
   - canonicalization or signature bytes → §7.2 (JCS, strip `proof.proofValue`)
   - algorithms / proof formats → §8.1–§8.2 (`eddsa-jcs-2022`,
     `ecdsa-jcs-2019`, detached JWS `aph+jws`)
   - key discovery → §8.4 (`did:key`, DNS TXT `_aph._notary`, `did:web`)
   - flow transitions → §9 (both state machines; violations are `APH_E002`)
   - error-code mismatches → §11 (closed set `APH_E001`..`APH_E015`)
   - mandate rules → §6 (validity windows, `allowedChannels`, single-use
     Communication Mandates)
   - channel-kind naming failures → `google_chat` (snake_case) is normative
     per the §7.1.5 erratum; `googleChat` in stale spec copies is superseded
   - multi-party exchange failures → §8.3/§8.3.1 (the recipient verification
     order) and §8.4.6 (discovery order — absence ADVANCES the chain, failure
     REFUSES on the spot; a downgrade past a failing mechanism is the exact
     defect the two-party no-downgrade test exists to catch)
   - cross-notary revocation failures → §6.3.3 (status endpoint derived from
     the issuer's own `did:web` host, same-origin binding, the signed list,
     freshness) — a `not_revoked` verdict from an unverified or foreign list
     is a security failure, never a fixture problem

4. **Report** an overall verdict (all green / N failures), the per-suite
   breakdown, and for each failure: test name, likely root cause, and the spec
   section to read. If the build itself fails, report the compile error instead
   and do not guess at test results.
