/**
 * WHY THIS FILE EXISTS: the comparison harness. Every published example gets
 * this implementation's verdict compared against a committed expectation, so
 * "the TypeScript agrees with the Rust" is a table a reviewer can read rather
 * than a claim in a report. `testkit/corpus.ts` holds the table and the WHY for
 * each row.
 *
 * WHAT IT PINS: the stated verdict for every row present on disk, AND — the
 * half that is easy to leave out — that no `*.json` in `examples/` lacks a row.
 * That second direction is deliberately a COVERAGE check rather than a count:
 * the corpus grows, and a number written into prose is a fact that rots
 * silently in every place someone forgot to look. A file nobody classified
 * fails here and names itself.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { AphError } from '../src/errors.js';
import { isDidKey } from '../src/didkey.js';
import { parseEnvelope } from '../src/parse.js';
import { verifyProofStructure } from '../src/structure.js';
import { verifyEnvelope, verifyProofAt } from '../src/verify.js';
import { proofsOf, type EnvelopeProof } from '../src/types.js';
import type { SuppliedKeys } from '../src/verify.js';
import { CORPUS, exampleExists, listExampleFiles, readExample } from '../testkit/corpus.js';
import {
  GOLDEN_EVALUATION_INSTANT,
  GOLDEN_FILE,
  goldenSuppliedKeys,
} from '../testkit/golden.js';
import { TS_MINTED_EVALUATION_INSTANT, TS_MINTED_FILE } from '../testkit/ts_minted.js';

/**
 * The instant each file is evaluated at. Every published envelope carries its
 * own 24-hour window, so one shared constant would put half the corpus outside
 * it — and a verifier that read the wall clock would pass today and fail next
 * year, which is the whole reason `now` is a parameter.
 */
function evaluationInstant(file: string): string {
  return file === TS_MINTED_FILE ? TS_MINTED_EVALUATION_INSTANT : GOLDEN_EVALUATION_INSTANT;
}

/**
 * Keys supplied per file. Only the Rust golden needs any: its notary is a
 * `did:web`. Everything else in the corpus resolves offline, which is the
 * property that makes a corpus checkable by a stranger.
 */
function suppliedKeys(file: string): SuppliedKeys | undefined {
  return file === GOLDEN_FILE ? goldenSuppliedKeys() : undefined;
}

for (const row of CORPUS) {
  test(`corpus: ${row.file} — ${row.verdict.kind}`, async (t) => {
    if (!exampleExists(row.file)) {
      assert.equal(
        row.required,
        false,
        `${row.file} is a REQUIRED corpus row and is missing from examples/`,
      );
      t.skip(
        `${row.file} is not on disk yet — an optional row for a vector this repository ` +
          `publishes that is not committed yet. It proves: ${row.proves}`,
      );
      return;
    }

    const text = readExample(row.file);
    const options = {
      now: evaluationInstant(row.file),
      keys: suppliedKeys(row.file),
    };

    if (row.verdict.kind === 'admit') {
      const verified = await verifyEnvelope(text, options);
      assert.ok(verified.envelope.id.length > 0);
      return;
    }

    if (row.verdict.kind === 'refuse') {
      const expected = row.verdict.code;
      try {
        await verifyEnvelope(text, options);
      } catch (error) {
        if (!(error instanceof AphError)) {
          assert.fail(`${row.file} must be refused with a §11 code, got ${String(error)}`);
        }
        assert.equal(error.code, expected);
        return;
      }
      assert.fail(`${row.file} was ADMITTED but the table expects ${expected}`);
      return;
    }

    // `offline-proofs-only`: parse and structure must hold, and every proof
    // whose key travels inside its own identifier must verify. The rest is
    // unchecked and the row says so.
    const envelope = parseEnvelope(text);
    verifyProofStructure(envelope);
    const proofs = proofsOf(envelope);
    let checked = 0;
    for (let index = 0; index < proofs.length; index += 1) {
      const proof = proofs[index] as EnvelopeProof;
      if (!isDidKey(proof.verificationMethod)) continue;
      assert.equal(
        await verifyProofAt(envelope, index, {}),
        true,
        `${row.file} proof ${index} names a did:key and must verify offline`,
      );
      checked += 1;
    }
    assert.ok(
      checked > 0,
      `${row.file} has no did:key proof, so this row checks nothing — give it an admit or ` +
        'refuse verdict with the key it needs',
    );
  });
}

test('every example on disk has a row in the corpus table', () => {
  // The direction that catches the thing a count never does: a vector landing
  // in `examples/` with nobody having decided what this implementation should
  // say about it.
  const classified = new Set(CORPUS.map((row) => row.file));
  const unclassified = listExampleFiles().filter((file) => !classified.has(file));
  assert.deepEqual(
    unclassified,
    [],
    `these files are in examples/ with no corpus row: ${unclassified.join(', ')}`,
  );
});

test('every corpus row states WHY its file is in the corpus', () => {
  // A row with no reason is a row nobody can maintain: the next person cannot
  // tell whether a changed verdict is a regression or a correction.
  for (const row of CORPUS) {
    assert.ok(row.proves.length > 40, `${row.file} has no meaningful WHY`);
  }
});
