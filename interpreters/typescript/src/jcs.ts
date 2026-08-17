/**
 * RFC 8785 — JSON Canonicalization Scheme (JCS).
 *
 * This is PROTOCOL logic, not cryptography: it decides which bytes a signature
 * covers (spec §7.2). It is written here rather than taken from a package
 * because the whole point of this implementation is that a second party
 * derived the byte sequence from the specification alone.
 */

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };

/**
 * RFC 8785 §3.2.2.3 defers number serialization to ECMAScript's
 * `Number::toString`, which is exactly what `String(n)` performs — so the
 * platform already implements this rule and reimplementing it could only
 * introduce a divergence. Non-finite values have no JSON form at all and are
 * refused rather than coerced to `null` the way `JSON.stringify` would, since
 * a silently nulled number changes the bytes a signature covers.
 */
function serializeNumber(value: number, path: string): string {
  if (!Number.isFinite(value)) {
    throw new TypeError(`RFC 8785: ${path} is not a finite number (${String(value)})`);
  }
  // String(-0) is "0", which is the value RFC 8785 requires; noted because the
  // sign of negative zero surviving into the canonical form would be a defect.
  return String(value);
}

/**
 * RFC 8785 §3.2.2.2 string escaping is character-for-character the escaping
 * `JSON.stringify` already performs on a lone string: the two-character forms
 * for `"` `\` and the five named control characters, `\u00xx` with lowercase
 * hex for the remaining C0 range, and every other code point emitted literally
 * as UTF-8. Delegating to the platform here is reuse of a rule, not of a
 * library, and it removes the likeliest hand-rolled escaping bug.
 */
function serializeString(value: string): string {
  return JSON.stringify(value);
}

function canonicalizeValue(value: JsonValue, path: string, out: string[]): void {
  if (value === null) {
    out.push('null');
    return;
  }
  switch (typeof value) {
    case 'boolean':
      out.push(value ? 'true' : 'false');
      return;
    case 'number':
      out.push(serializeNumber(value, path));
      return;
    case 'string':
      out.push(serializeString(value));
      return;
    default:
      break;
  }

  if (Array.isArray(value)) {
    out.push('[');
    for (let i = 0; i < value.length; i += 1) {
      if (i > 0) out.push(',');
      canonicalizeValue(value[i] as JsonValue, `${path}[${i}]`, out);
    }
    out.push(']');
    return;
  }

  if (typeof value === 'object') {
    const record = value as JsonObject;
    // RFC 8785 §3.2.3 sorts members by the UTF-16 code units of their names.
    // The default comparator of Array#sort compares strings with `<`, which IS
    // UTF-16 code-unit order — using a locale-aware comparator here would sort
    // "Z" before "a" in some locales and produce bytes no other implementation
    // reproduces.
    const keys = Object.keys(record).sort();
    out.push('{');
    for (let i = 0; i < keys.length; i += 1) {
      const key = keys[i] as string;
      if (i > 0) out.push(',');
      out.push(serializeString(key));
      out.push(':');
      canonicalizeValue(record[key] as JsonValue, `${path}.${key}`, out);
    }
    out.push('}');
    return;
  }

  throw new TypeError(`RFC 8785: ${path} holds a value with no JSON form`);
}

/** The canonical text. Callers that sign or verify want {@link canonicalizeToBytes}. */
export function canonicalize(value: JsonValue): string {
  const out: string[] = [];
  canonicalizeValue(value, '$', out);
  return out.join('');
}

/**
 * The canonical UTF-8 bytes — the sequence a signature actually covers.
 * `TextEncoder` always emits UTF-8, which is RFC 8785 §3.2's required encoding.
 */
export function canonicalizeToBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}
