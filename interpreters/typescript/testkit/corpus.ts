/**
 * The published `examples/` corpus, and the verdict this implementation is
 * expected to return for each file.
 *
 * The table below is the comparison harness's contract. Two properties are
 * asserted by `test/corpus.test.ts` and both matter:
 *
 *  1. every row's file, when present on disk, produces the stated verdict;
 *  2. every `*.json` on disk has a row.
 *
 * Property 2 is why this file states no TOTAL. A count in prose goes stale the
 * moment a vector lands and nothing catches it; a bidirectional coverage check
 * fails loudly instead, naming the file nobody classified. Vectors this
 * repository publishes but has not committed yet are therefore listed as
 * `optional` rows rather than left out — a row that describes a file not yet
 * minted is a plan; a file with no row is a hole.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';

import type { AphErrorCode } from '../src/errors.js';

/**
 * Finds the repository root by looking for two files that only exist there.
 *
 * Walking up beats a relative path built from `import.meta.url`: the compiled
 * tests sit at a different depth than the sources, and a hard-coded `../../..`
 * silently resolves somewhere wrong the first time the layout moves.
 */
function findRepoRoot(): URL {
  let candidate = new URL('../', import.meta.url);
  for (let depth = 0; depth < 8; depth += 1) {
    if (
      existsSync(new URL('examples/README.md', candidate)) &&
      existsSync(new URL('spec/aph-0.1.md', candidate))
    ) {
      return candidate;
    }
    candidate = new URL('../', candidate);
  }
  throw new Error(
    'could not locate the APH repository root above ' +
      `${import.meta.url} (looked for examples/README.md beside spec/aph-0.1.md)`,
  );
}

export const REPO_ROOT: URL = findRepoRoot();
export const EXAMPLES_DIR: URL = new URL('examples/', REPO_ROOT);

export function exampleUrl(fileName: string): URL {
  return new URL(fileName, EXAMPLES_DIR);
}

export function exampleExists(fileName: string): boolean {
  return existsSync(exampleUrl(fileName));
}

/** The file's TEXT, because §7.1.7.1's byte bound applies to bytes, not to a parsed value. */
export function readExample(fileName: string): string {
  return readFileSync(exampleUrl(fileName), 'utf8');
}

/** Every `*.json` in `examples/`, enumerated from disk rather than remembered. */
/**
 * The corpus INVENTORY, which lives in the corpus directory and is not itself
 * a vector. Every enumerator skips it by name: it is the one file in
 * `examples/*.json` that would fail envelope parsing for the honest reason
 * that it was never an envelope.
 */
export const MANIFEST_FILE = 'manifest.json';

export function listExampleFiles(): string[] {
  return readdirSync(EXAMPLES_DIR)
    .filter((name) => name.endsWith('.json') && name !== MANIFEST_FILE)
    .sort();
}

/**
 * What this implementation must decide about one corpus file.
 *
 *  - `admit` — full §8.3 verification succeeds.
 *  - `refuse` — full §8.3 verification fails with exactly `code`.
 *  - `offline-proofs-only` — the file's notary key does not travel inside the
 *    document and this implementation never fetches, so no key can be handed
 *    in and the assertion is narrowed to what is checkable without one:
 *    strict parse, proof structure, and every proof whose `verificationMethod`
 *    is a `did:key` and therefore carries its own key. Narrower than `admit`,
 *    and honest about which half is unchecked.
 */
export type CorpusVerdict =
  | { readonly kind: 'admit' }
  | { readonly kind: 'refuse'; readonly code: AphErrorCode }
  | { readonly kind: 'offline-proofs-only' };

export interface CorpusRow {
  readonly file: string;
  /**
   * False for a vector this repository publishes that is not committed yet;
   * the harness skips the row until the file appears on disk.
   */
  readonly required: boolean;
  readonly verdict: CorpusVerdict;
  /** WHY this file is in the corpus — what a verifier learns from getting it right. */
  readonly proves: string;
}

/**
 * SEVEN of the eight shape-only fixtures share a verdict and a reason, so they
 * share this builder: seven copies of the same sentence would be seven places
 * to update when the reason changes. The eighth,
 * `slack_new_with_extensions_envelope.json`, is spelled out as its own row
 * below because it reaches the same verdict while proving something extra.
 *
 * `APH_E001` rather than a parse error is the whole point of these rows. Their
 * `proofValue` strings are illustrative multibase, and their notary is a
 * `did:key` whose bytes this verifier decodes offline — so the document parses,
 * the structure checks out, and the SIGNATURE is what fails. A verifier that
 * reported these as malformed would be failing at step 1 and calling it step 5.
 */
function shapeOnlyFixture(file: string, channel: string): CorpusRow {
  return {
    file,
    required: true,
    verdict: { kind: 'refuse', code: 'APH_E001' },
    proves:
      `strict parse of the ${channel} recipient-addressing shape (§7.4, opaque sub-fields), ` +
      'the single-object proof carriage of §7.1.11, and that an illustrative proofValue is ' +
      'refused as a SIGNATURE failure and not as a malformed document',
  };
}

export const CORPUS: readonly CorpusRow[] = [
  shapeOnlyFixture('slack_reply_envelope.json', 'Slack thread-reply'),
  shapeOnlyFixture('email_reply_envelope.json', 'email reply'),
  shapeOnlyFixture('discord_dm_envelope.json', 'Discord direct-message'),
  shapeOnlyFixture('teams_channel_envelope.json', 'Teams channel-post'),
  shapeOnlyFixture('whatsapp_envelope.json', 'WhatsApp'),
  shapeOnlyFixture('google_chat_envelope.json', 'Google Chat space'),
  shapeOnlyFixture('imessage_envelope.json', 'iMessage'),
  {
    file: 'act_classification_envelope.json',
    required: true,
    verdict: { kind: 'refuse', code: 'APH_E001' },
    proves:
      '§7.1.12 `actClassification` parses in the INDEPENDENT implementation — the ' +
      'family-qualified labels and the pinned vocabulary reference — and that carrying ' +
      'the claim does not change the verdict, which stays the shape-only signature ' +
      'refusal. The digest is the shipped guardrail bundle\'s own, so this fixture also ' +
      'proves the two artifacts agree on what that bundle is called',
  },
  {
    file: 'audience_bound_envelope.json',
    required: true,
    verdict: { kind: 'refuse', code: 'APH_E001' },
    proves:
      '§7.1.13 `audience` parses in the INDEPENDENT implementation — the named ' +
      'recipient and the open-membered `channelBinding` with its closed `kind` — and ' +
      'that carrying it does not change the verdict, which stays the shape-only ' +
      'signature refusal reached BEFORE step 5a. The step 5a gate itself is pinned on ' +
      'minted envelopes in the roundtrip suite, where a real signature lets the ' +
      'pipeline reach it',
  },
  {
    file: 'slack_new_with_extensions_envelope.json',
    required: true,
    verdict: { kind: 'refuse', code: 'APH_E001' },
    proves:
      'all three §7.5 registered extensions parse — `appleAurAcceptance`, ' +
      '`linkedMandate.ap2SignedPayloadB64`, and `linkedMandate.vaultMutation` with its ' +
      'internally-tagged `kind` and snake_case interior (§7.5.3) — and that the extensions ' +
      'do not change the verdict, which stays the shape-only signature refusal',
  },
  {
    file: 'principal_signed_envelope.json',
    required: true,
    verdict: { kind: 'admit' },
    proves:
      'THE (→) CROSS-VERIFICATION: four real Ed25519 signatures made by the reference ' +
      'implementation verify here — both envelope proofs over their §7.2.1 bases (the ' +
      'principal base being the ONE-ELEMENT ARRAY form) and both §6.1 mandate signatures — ' +
      'plus the §7.1.11 chain linkage, the §7.2.1 issuance order, and the §7.1.7.1 ' +
      'mandate-to-envelope bindings',
  },
  {
    file: 'ts_minted_envelope.json',
    // Minted by `scripts/mint_ts_envelope.ts`; materialized at landing time.
    required: false,
    verdict: { kind: 'admit' },
    proves:
      'THE (←) CROSS-VERIFICATION ARTIFACT, read back by its own producer: this file is ' +
      'minted by this implementation and verified by the Rust reference in ' +
      "`ts_minted_cross_verify.rs`. Its row here closes the loop on the producer's side, so " +
      'a mint that drifts from this verifier fails before it ever reaches cargo',
  },
  {
    file: 'es256_signed_envelope.json',
    required: false,
    verdict: { kind: 'offline-proofs-only' },
    proves:
      'the `ecdsa-jcs-2019` MUST-support path of §8.1 against a vector this implementation ' +
      'did not mint. Narrowed to offline proofs because the vector post-dates this table and ' +
      "its notary key is not knowable here; the principal proof's did:key carries its own",
  },
  {
    file: 'detached_jws_envelope.json',
    required: false,
    verdict: { kind: 'offline-proofs-only' },
    proves:
      'the `JsonWebSignature2020` carriage of §8.2 — the fixed protected header, `b64:false` ' +
      'with `crit:["b64"]`, and the empty payload segment — against a vector this ' +
      'implementation did not mint. Narrowed for the same reason as the ES256 row',
  },
];
