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
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalize, canonicalizeToBytes, type JsonValue } from '../src/jcs.js';

/**
 * Control characters are built rather than typed. A raw C0 byte in a source
 * file is invisible to a reviewer and trips this repository's
 * invisible-character census; `String.fromCharCode` says exactly which code
 * point is meant.
 */
function chars(...codes: number[]): string {
  return String.fromCharCode(...codes);
}

test('RFC 8785 §3.2.3 orders members by UTF-16 code unit, not by insertion or locale', () => {
  assert.equal(canonicalize({ b: 1, a: 2, C: 3 } as JsonValue), '{"C":3,"a":2,"b":1}');
  // A locale-aware comparator sorts "a" before "C" in several locales. The
  // uppercase letter MUST come first: its code unit is 0x43 against 0x61.
  assert.equal(canonicalize({ a: 1, C: 2 } as JsonValue), '{"C":2,"a":1}');
});

test('RFC 8785 §3.2.3 ordering is by UTF-16 code units, so a surrogate pair sorts above the BMP', () => {
  // "a" is 0x0061, the euro sign is 0x20AC, and the emoji is the surrogate
  // pair 0xD83D 0xDE02. This pins that the pair is compared by its LEADING
  // surrogate, which is what "UTF-16 code units" means.
  const bmp = chars(0x20ac);
  const astral = String.fromCodePoint(0x1f602);
  const value = { [astral]: 3, [bmp]: 2, a: 1 } as JsonValue;
  assert.equal(canonicalize(value), `{"a":1,"${bmp}":2,"${astral}":3}`);
});

test('RFC 8785 §3.2.3 sorting recurses into nested objects and never reorders arrays', () => {
  const value = { z: { b: 1, a: 2 }, list: [{ y: 1, x: 2 }, 3] } as JsonValue;
  assert.equal(canonicalize(value), '{"list":[{"x":2,"y":1},3],"z":{"a":2,"b":1}}');
});

test('RFC 8785 §3.2.2.3 serializes numbers as ECMAScript Number::toString does', () => {
  assert.equal(canonicalize(1 as JsonValue), '1');
  // A trailing ".0" is not part of the ECMAScript form, and an implementation
  // that emitted one would sign different bytes for the same value.
  assert.equal(canonicalize(1.0 as JsonValue), '1');
  assert.equal(canonicalize(-0 as JsonValue), '0');
  assert.equal(canonicalize(0.1 as JsonValue), '0.1');
  assert.equal(canonicalize(1e21 as JsonValue), '1e+21');
  assert.equal(canonicalize(1e-7 as JsonValue), '1e-7');
  assert.equal(canonicalize(-1.5 as JsonValue), '-1.5');
});

test('a non-finite number is refused rather than coerced to null', () => {
  // JSON.stringify turns NaN and Infinity into `null`, silently changing the
  // bytes a signature covers. Refusing is the only safe answer.
  assert.throws(() => canonicalize(Number.NaN as JsonValue), TypeError);
  assert.throws(() => canonicalize(Number.POSITIVE_INFINITY as JsonValue), TypeError);
});

test('RFC 8785 §3.2.2.2 escapes only what must be escaped, and non-ASCII stays literal', () => {
  assert.equal(canonicalize('a"b\\c' as JsonValue), '"a\\"b\\\\c"');
  assert.equal(canonicalize('\b\t\n\f\r' as JsonValue), '"\\b\\t\\n\\f\\r"');
  // The rest of the C0 range takes the \u00xx form with LOWERCASE hex.
  assert.equal(canonicalize(chars(0x01, 0x1f) as JsonValue), '"\\u0001\\u001f"');
  // Nothing above 0x1F is escaped: the canonical form carries the character
  // itself and the UTF-8 encoding carries the bytes. 0x7F (DELETE) is not a C0
  // control and RFC 8785 leaves it alone — a plausible mistake, so it is pinned.
  const del = chars(0x7f);
  assert.equal(canonicalize(del as JsonValue), `"${del}"`);
  const accented = String.fromCodePoint(0xe9, 0x1f602);
  assert.equal(canonicalize(accented as JsonValue), `"${accented}"`);
});

test('the canonical form of the JSON literals and containers has no insignificant whitespace', () => {
  const value = { a: null, b: true, c: false, d: [], e: {} } as JsonValue;
  assert.equal(canonicalize(value), '{"a":null,"b":true,"c":false,"d":[],"e":{}}');
});

test('canonicalizeToBytes emits UTF-8, which is the encoding a signature covers', () => {
  // U+00E9 is one UTF-16 code unit and TWO UTF-8 bytes (0xC3 0xA9). An
  // implementation that signed UTF-16 would produce a different length here.
  const bytes = canonicalizeToBytes(String.fromCodePoint(0xe9) as JsonValue);
  assert.deepEqual([...bytes], [0x22, 0xc3, 0xa9, 0x22]);
});
