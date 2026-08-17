/**
 * The module the second engine evaluates. It is the ONLY JavaScript this
 * harness supplies, and it deliberately implements nothing.
 *
 * Every function below is a thin adapter: parse a JSON request, call the
 * compiled TypeScript, serialize the answer as JSON. No protocol rule, no
 * canonicalization, no comparison, and no expectation lives here — the
 * expectations are in `interpreters/typescript/testkit/jcs_vectors.json`, which
 * the node suite reads too, and the comparison happens on the Rust side where a
 * mismatch can be printed with both engines' output. A driver that decided
 * anything would be a third implementation of the thing under test.
 *
 * WHY THE BOUNDARY IS JSON TEXT IN BOTH DIRECTIONS: the same rule every binding
 * in this repository follows. The envelope's `proof` member is an untagged
 * union whose arm is decided by position, so a value that crosses a host
 * boundary as an object lets a second deserializer decide which arm it is.
 * Text keeps that decision inside the implementation under test.
 *
 * SCOPE: the crypto-free core only — canonicalization, strict parse, proof
 * structure, and the error taxonomy. Nothing here imports `verify.js`,
 * `mint.js`, `signers.js` or `webcrypto.js`: the implementation's cryptography
 * is SubtleCrypto by design, a language engine has none, and supplying one from
 * the host would mean this harness had opinions about signatures. Those paths
 * stay gated under the runtime that has WebCrypto.
 */

import { canonicalize } from './dist/src/jcs.js';
import { APH_ERROR_CODES, APH_ERROR_VARIANTS } from './dist/src/errors.js';
import { parseEnvelope } from './dist/src/parse.js';
import { declaredAttestationMode, verifyProofStructure } from './dist/src/structure.js';

/**
 * Reduces a thrown value to the facts the Rust side asserts on.
 *
 * `code` and `path` are read when present because they are the two things the
 * taxonomy actually promises: `AphError` carries the §11 code, `AphParseError`
 * carries the JSON path of the member that failed. A harness that reported only
 * a message would turn "refused with the right code" into a string match.
 */
function describe(thrown) {
  if (thrown === null || typeof thrown !== 'object') {
    return { name: 'NonErrorThrow', message: String(thrown) };
  }
  const described = {
    name: String(thrown.name === undefined ? 'Error' : thrown.name),
    message: String(thrown.message === undefined ? '' : thrown.message),
  };
  if (typeof thrown.code === 'string') described.code = thrown.code;
  if (typeof thrown.path === 'string') described.path = thrown.path;
  return described;
}

/**
 * The three non-finite doubles, named rather than written.
 *
 * JSON has no literal for any of them, so the shared table names them with a
 * closed tag and each runner maps the tag. The alternative — an expression the
 * runner evaluates — would put executable text in a data file read by two
 * engines, which is a larger hole than the three constants are worth.
 */
const NON_FINITE = {
  NaN: Number.NaN,
  Infinity: Number.POSITIVE_INFINITY,
  '-Infinity': Number.NEGATIVE_INFINITY,
};

function hasTag(tag) {
  // `in` would also match anything inherited from Object.prototype, so a table
  // row naming "toString" would silently resolve to a function.
  return Object.prototype.hasOwnProperty.call(NON_FINITE, tag);
}

/**
 * Canonicalizes every row of the shared table's `canonicalize` section.
 *
 * The WHOLE table text crosses, unmodified, and the section is selected here —
 * so neither side re-encodes the other's data on the way in. The row's input
 * likewise crosses as its JSON TEXT and is parsed by THIS engine, because the
 * property under test is what this engine does with the double it built itself;
 * handing the value across pre-decoded would fold the host's number conversion
 * into the result.
 */
export function canonicalizeCases(tableJson) {
  const rows = JSON.parse(tableJson).canonicalize;
  const results = [];
  for (const row of rows) {
    try {
      results.push({ name: row.name, canonical: canonicalize(JSON.parse(row.json)) });
    } catch (thrown) {
      results.push({ name: row.name, threw: describe(thrown) });
    }
  }
  return JSON.stringify(results);
}

/** Runs the shared table's `refuse` section: the non-finite values that have no JSON form. */
export function refuseCases(tableJson) {
  const rows = JSON.parse(tableJson).refuse;
  const results = [];
  for (const row of rows) {
    if (!hasTag(row.nonFinite)) {
      results.push({ name: row.name, unknownTag: String(row.nonFinite) });
      continue;
    }
    try {
      results.push({ name: row.name, canonical: canonicalize(NON_FINITE[row.nonFinite]) });
    } catch (thrown) {
      results.push({ name: row.name, threw: describe(thrown) });
    }
  }
  return JSON.stringify(results);
}

/**
 * Strict-parses one envelope's TEXT and reports what the crypto-free half of
 * §8.3 decides about it.
 *
 * `canonicalStable` re-canonicalizes the canonical form and compares. It is not
 * a cross-engine claim — the shared table carries those — but it is the cheap
 * property that catches a formatter which is not a fixed point on real protocol
 * documents, where the numbers are byte counts and latencies rather than the
 * table's chosen edges.
 */
export function inspectEnvelope(requestJson) {
  const request = JSON.parse(requestJson);
  let envelope;
  try {
    envelope = parseEnvelope(request.text);
  } catch (thrown) {
    return JSON.stringify({ parsed: false, parseError: describe(thrown) });
  }

  const result = { parsed: true, declaredMode: declaredAttestationMode(envelope) };
  try {
    result.structureMode = verifyProofStructure(envelope);
  } catch (thrown) {
    result.structureError = describe(thrown);
  }

  const once = canonicalize(JSON.parse(request.text));
  result.canonicalStable = canonicalize(JSON.parse(once)) === once;
  return JSON.stringify(result);
}

/**
 * The §11 taxonomy as the module itself declares it.
 *
 * Returned rather than asserted here so the Rust side can check the two
 * declarations against each other. No count crosses: the codes are enumerated
 * and the checks are derived from the enumeration, because a number in a test
 * is a second place to update when the set changes.
 */
export function errorTaxonomy() {
  return JSON.stringify({ codes: APH_ERROR_CODES, variants: APH_ERROR_VARIANTS });
}
