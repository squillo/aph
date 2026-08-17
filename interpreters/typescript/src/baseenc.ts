/**
 * Byte encodings the protocol carries: multibase base58btc (spec §6.1, §8.2 —
 * every `proofValue` and mandate signature) and base64url (RFC 7515 JWS parts
 * and RFC 7517 JWK members).
 *
 * These are transport encodings, not cryptography: they map bytes to
 * characters and back with no secret and no algebra.
 */

/**
 * The Bitcoin base58 alphabet. Its distinguishing property is what it OMITS —
 * `0`, `O`, `I`, `l` — so a transcribed signature cannot silently change value
 * through a homoglyph.
 */
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const BASE58_INDEX: ReadonlyMap<string, number> = new Map(
  Array.from(BASE58_ALPHABET, (character, position) => [character, position]),
);

/** Multibase prefix for base58btc (multibase table: `z`). */
export const MULTIBASE_BASE58BTC_PREFIX = 'z';

export function base58btcEncode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Big-endian base conversion by repeated division over a digit buffer. A
  // BigInt would be shorter but loses the leading-zero count, and a leading
  // zero byte is significant here: it is the multicodec prefix's high byte in
  // some did:key encodings.
  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      carry += (digits[i] as number) << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = '';
  // Each leading zero byte encodes as one leading '1' — the base58btc rule that
  // makes the encoding length-preserving for zero-prefixed inputs.
  for (let i = 0; i < bytes.length && bytes[i] === 0; i += 1) out += '1';

  // `digits` is little-endian and was seeded with a single zero so the division
  // loop had somewhere to carry into. That seed is an ARTIFACT: emitting it
  // would append a spurious '1' that the leading-zero loop has already written,
  // so the magnitude's high-order zero digits are dropped here. Only an
  // all-zero input reaches this with nothing left, and for that input the
  // leading-'1' run is already the complete encoding.
  let top = digits.length - 1;
  while (top > 0 && digits[top] === 0) top -= 1;
  if (top > 0 || digits[0] !== 0) {
    for (let i = top; i >= 0; i -= 1) out += BASE58_ALPHABET[digits[i] as number];
  }
  return out;
}

export function base58btcDecode(text: string): Uint8Array {
  if (text.length === 0) return new Uint8Array(0);

  const bytes: number[] = [0];
  for (const character of text) {
    const value = BASE58_INDEX.get(character);
    if (value === undefined) {
      throw new TypeError(`base58btc: "${character}" is not in the base58btc alphabet`);
    }
    let carry = value;
    for (let i = 0; i < bytes.length; i += 1) {
      carry += (bytes[i] as number) * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const leadingZeros: number[] = [];
  for (let i = 0; i < text.length && text[i] === '1'; i += 1) leadingZeros.push(0);

  // Mirror of the encoder: strip the accumulator's seed. Leading zero BYTES are
  // carried by the '1' characters and counted above; a high-order zero left in
  // the accumulator is the seed, and keeping it would decode "1" to two zero
  // bytes instead of one.
  let top = bytes.length - 1;
  while (top > 0 && bytes[top] === 0) top -= 1;
  const magnitude = top === 0 && bytes[0] === 0 ? [] : bytes.slice(0, top + 1);
  return Uint8Array.from([...leadingZeros, ...magnitude.reverse()]);
}

/** `z<base58btc>` — the multibase form every `proofValue` in this protocol uses. */
export function multibaseEncode(bytes: Uint8Array): string {
  return MULTIBASE_BASE58BTC_PREFIX + base58btcEncode(bytes);
}

/**
 * Decodes a multibase string, refusing any base but base58btc. Accepting a
 * second base would mean two spellings of the same signature, and §7.2's
 * whole argument is that two spellings of the same bytes is how interop dies.
 */
export function multibaseDecode(text: string): Uint8Array {
  if (!text.startsWith(MULTIBASE_BASE58BTC_PREFIX)) {
    throw new TypeError(
      `multibase: expected a base58btc value (prefix "z"), got "${text.slice(0, 1)}"`,
    );
  }
  return base58btcDecode(text.slice(1));
}

const BASE64URL_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const BASE64URL_INDEX: ReadonlyMap<string, number> = new Map(
  Array.from(BASE64URL_ALPHABET, (character, position) => [character, position]),
);

/** RFC 4648 §5 base64url, unpadded — the form RFC 7515 and RFC 7517 both use. */
export function base64urlEncode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] as number;
    const b1 = i + 1 < bytes.length ? (bytes[i + 1] as number) : undefined;
    const b2 = i + 2 < bytes.length ? (bytes[i + 2] as number) : undefined;

    out += BASE64URL_ALPHABET[b0 >> 2];
    out += BASE64URL_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    if (b1 === undefined) break;
    out += BASE64URL_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    if (b2 === undefined) break;
    out += BASE64URL_ALPHABET[b2 & 0x3f];
  }
  return out;
}

export function base64urlDecode(text: string): Uint8Array {
  const clean = text.replace(/=+$/, '');
  const out = new Uint8Array(Math.floor((clean.length * 6) / 8));
  let bits = 0;
  let accumulator = 0;
  let written = 0;
  for (const character of clean) {
    const value = BASE64URL_INDEX.get(character);
    if (value === undefined) {
      throw new TypeError(`base64url: "${character}" is not a base64url character`);
    }
    accumulator = (accumulator << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[written] = (accumulator >> bits) & 0xff;
      written += 1;
    }
  }
  return out.subarray(0, written);
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new TypeError('hex: odd-length input');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new TypeError(`hex: "${hex.slice(i * 2, i * 2 + 2)}" is not hex`);
    out[i] = byte;
  }
  return out;
}

/** Constant-shape byte comparison for test assertions and hash comparison. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}
