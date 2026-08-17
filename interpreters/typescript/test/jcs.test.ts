/**
 * WHY THIS FILE EXISTS: RFC 8785 canonicalization decides which bytes a
 * signature covers, so a divergence here is invisible until two
 * implementations refuse each other's signatures with no clue why. These tests
 * pin the three rules that actually differ between plausible implementations —
 * member ordering, number serialization, and string escaping — before any
 * signature is involved, so a canonicalization bug is reported as a
 * canonicalization bug.
 *
 * WHAT THEY PIN: RFC 8785 §3.2.3 UTF-16 code-unit member ordering (including
 * across the BMP boundary), §3.2.2.3 ECMAScript number serialization, §3.2.2.2
 * escaping, and that the output is UTF-8 bytes.
 *
 * WHERE THE EXPECTATIONS LIVE: not here. `testkit/jcs_vectors.json` is the
 * table, and this file is one of TWO runners over it — the other drives the
 * same rows through the same compiled code under a second ECMAScript engine,
 * from cargo (`interpreters/rust/aph-js-harness`). Keeping the expectations in
 * a file with no language in it is what makes "two engines agree" a checkable
 * claim instead of two hand-written suites that drifted. Add a row there and
 * both engines assert it; add it here and only one does.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { canonicalize, canonicalizeToBytes, type JsonValue } from '../src/jcs.js';
import { REPO_ROOT } from '../testkit/corpus.js';

/** One row of the shared table's `canonicalize` section. */
interface CanonicalizeCase {
  readonly name: string;
  /** WHY the row exists; shown as the assertion message when it fails. */
  readonly pins: string;
  /** The input's JSON TEXT, parsed by whichever engine is running. */
  readonly json: string;
  /** The expected canonical output text, byte for byte. */
  readonly canonical: string;
}

/** One row of the shared table's `refuse` section. */
interface RefuseCase {
  readonly name: string;
  readonly pins: string;
  /** A closed tag, because JSON has no literal for a non-finite number. */
  readonly nonFinite: string;
  readonly errorName: string;
}

interface JcsVectorTable {
  readonly canonicalize: readonly CanonicalizeCase[];
  readonly refuse: readonly RefuseCase[];
}

/**
 * Resolved from the repository root rather than from this file's compiled
 * location. The compiled tests sit at a different depth than the sources, so a
 * hard-coded `../../..` is the thing that silently resolves somewhere wrong the
 * first time the layout moves; `testkit/corpus.ts` already solved this by
 * probing upward for two files that only exist at the root.
 */
const TABLE = JSON.parse(
  readFileSync(new URL('interpreters/typescript/testkit/jcs_vectors.json', REPO_ROOT), 'utf8'),
) as JcsVectorTable;

/**
 * The closed tag set the `refuse` rows name. It exists because JSON cannot
 * carry NaN or an infinity — encoding them as an expression the runner would
 * evaluate would put executable text in a data file, so the table names them
 * and each runner maps the name.
 */
const NON_FINITE: Readonly<Record<string, number>> = {
  NaN: Number.NaN,
  Infinity: Number.POSITIVE_INFINITY,
  '-Infinity': Number.NEGATIVE_INFINITY,
};

test('the shared table is populated and every case name is distinct', () => {
  // Guards against a vacuous suite two ways. A table that failed to load would
  // iterate zero rows below and pass while proving nothing; and two rows with
  // the same name would report as one test, so a regression could hide behind
  // its twin in either runner's output.
  assert.ok(TABLE.canonicalize.length > 0, 'the canonicalize section of the shared table is empty');
  assert.ok(TABLE.refuse.length > 0, 'the refuse section of the shared table is empty');
  const names = [
    ...TABLE.canonicalize.map((row) => row.name),
    ...TABLE.refuse.map((row) => row.name),
  ];
  assert.equal(new Set(names).size, names.length, 'two rows in the shared table share a name');
});

for (const row of TABLE.canonicalize) {
  test(`RFC 8785: ${row.name}`, () => {
    // `JSON.parse` rather than a literal, so the row's INPUT is the same bytes
    // in both runners and the value each engine holds is built by that engine.
    assert.equal(canonicalize(JSON.parse(row.json) as JsonValue), row.canonical, row.pins);
  });
}

for (const row of TABLE.refuse) {
  test(`RFC 8785: ${row.name}`, () => {
    const value = NON_FINITE[row.nonFinite];
    assert.equal(
      typeof value,
      'number',
      `the table names an unknown nonFinite tag: ${row.nonFinite}`,
    );
    assert.throws(() => canonicalize(value as JsonValue), { name: row.errorName }, row.pins);
  });
}

test('canonicalizeToBytes emits UTF-8, which is the encoding a signature covers', () => {
  // NOT in the shared table, and the omission is the point: `TextEncoder` is a
  // host API rather than an ECMAScript one, so the second engine has to be
  // handed one — and a row asserted against a supplied encoder would be
  // measuring the harness, not the implementation. The engine-sensitive half of
  // canonicalization is entirely inside `canonicalize`, which the table covers.
  //
  // U+00E9 is one UTF-16 code unit and TWO UTF-8 bytes (0xC3 0xA9). An
  // implementation that signed UTF-16 would produce a different length here.
  const bytes = canonicalizeToBytes(String.fromCodePoint(0xe9) as JsonValue);
  assert.deepEqual([...bytes], [0x22, 0xc3, 0xa9, 0x22]);
});
