/**
 * The cryptography seam. EVERY hash and EVERY signature operation in this
 * implementation goes through SubtleCrypto; nothing here implements a curve, a
 * hash, or a field operation. What this module DOES implement is encoding
 * plumbing — SPKI wrapping, JWK assembly, DER/P1363 signature conversion —
 * which is byte formatting, not algebra.
 *
 * The one place that boundary is easy to cross is P-256 point decompression:
 * `did:key` carries a COMPRESSED SEC1 point and WebCrypto's `raw` EC import is
 * specified for the UNCOMPRESSED form. Recovering the y coordinate means a
 * modular square root over the curve's prime field — so instead of computing
 * it, the compressed point is wrapped in a SubjectPublicKeyInfo and handed to
 * the platform, which decompresses it inside the same implementation that will
 * verify with it.
 */

import { base64urlEncode } from './baseenc.js';
import type { KeyAlgorithm } from './didkey.js';

function subtle(): SubtleCrypto {
  const webcrypto = (globalThis as { crypto?: Crypto }).crypto;
  if (!webcrypto?.subtle) {
    throw new Error(
      'WebCrypto (globalThis.crypto.subtle) is unavailable. This implementation requires ' +
        'Node 20 or newer, where SubtleCrypto exposes Ed25519 and ECDSA P-256.',
    );
  }
  return webcrypto.subtle;
}

/** SHA-256 over arbitrary bytes — spec §7.1.6 `bodySha256` and §8.3 step 8. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await subtle().digest('SHA-256', bytes as unknown as BufferSource);
  return new Uint8Array(digest);
}

/**
 * The fixed DER prelude of a P-256 SubjectPublicKeyInfo: SEQUENCE { OID
 * id-ecPublicKey (1.2.840.10045.2.1), OID prime256v1 (1.2.840.10045.3.1.7) }.
 * Twenty-one bytes, identical for every P-256 public key.
 */
const P256_SPKI_ALGORITHM_IDENTIFIER = Uint8Array.from([
  0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
  0xce, 0x3d, 0x03, 0x01, 0x07,
]);

/**
 * Wraps a SEC1 point (compressed 33 bytes or uncompressed 65) in SPKI DER.
 * Both forms fit in short-form DER lengths — 57 and 89 content bytes — so the
 * long-form length encoding is unconstructible here and is not implemented.
 */
function p256SpkiFromPoint(point: Uint8Array): Uint8Array {
  if (point.length !== 33 && point.length !== 65) {
    throw new TypeError(
      `P-256: SEC1 point must be 33 (compressed) or 65 (uncompressed) bytes, got ${point.length}`,
    );
  }
  const bitStringLength = 1 + point.length; // one leading byte counts the unused bits: zero.
  const contentLength = P256_SPKI_ALGORITHM_IDENTIFIER.length + 2 + bitStringLength;
  const out = new Uint8Array(2 + contentLength);
  out[0] = 0x30;
  out[1] = contentLength;
  out.set(P256_SPKI_ALGORITHM_IDENTIFIER, 2);
  out[2 + P256_SPKI_ALGORITHM_IDENTIFIER.length] = 0x03;
  out[3 + P256_SPKI_ALGORITHM_IDENTIFIER.length] = bitStringLength;
  out[4 + P256_SPKI_ALGORITHM_IDENTIFIER.length] = 0x00;
  out.set(point, 5 + P256_SPKI_ALGORITHM_IDENTIFIER.length);
  return out;
}

export async function importEd25519PublicKey(rawPublicKey: Uint8Array): Promise<CryptoKey> {
  return subtle().importKey(
    'raw',
    rawPublicKey as unknown as BufferSource,
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
}

/**
 * Imports an Ed25519 signing key from an RFC 8032 seed plus its public key.
 *
 * WebCrypto has no `raw` import for private OKP keys, and its JWK form
 * requires `x` (the public key) alongside `d` (the seed). Both halves of every
 * test key used here are printed together in RFC 8032 §7.1, so supplying the
 * public half costs nothing and buys a check: signing with this key and
 * verifying under the RFC's published public key proves the pair was assembled
 * correctly rather than merely accepted.
 */
export async function importEd25519PrivateKey(
  seed: Uint8Array,
  publicKey: Uint8Array,
): Promise<CryptoKey> {
  return subtle().importKey(
    'jwk',
    { kty: 'OKP', crv: 'Ed25519', d: base64urlEncode(seed), x: base64urlEncode(publicKey) },
    { name: 'Ed25519' },
    false,
    ['sign'],
  );
}

export async function importP256PublicKey(sec1Point: Uint8Array): Promise<CryptoKey> {
  return subtle().importKey(
    'spki',
    p256SpkiFromPoint(sec1Point) as unknown as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
}

/**
 * Imports a P-256 signing key from its published scalar and public coordinates.
 *
 * There is no key-GENERATION counterpart here, deliberately. WebCrypto's ECDSA
 * is randomized — SubtleCrypto exposes no RFC 6979 deterministic mode — so an
 * ES256 artifact this implementation mints cannot be byte-pinned whatever key
 * it uses, and a generated key would buy nothing while adding a second way for
 * private material to exist. Every P-256 key here is the published RFC 6979
 * Appendix A.2.5 sample.
 */
export async function importP256PrivateKey(
  d: Uint8Array,
  x: Uint8Array,
  y: Uint8Array,
): Promise<CryptoKey> {
  return subtle().importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      d: base64urlEncode(d),
      x: base64urlEncode(x),
      y: base64urlEncode(y),
    },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
}

export async function signEd25519(key: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await subtle().sign({ name: 'Ed25519' }, key, message as unknown as BufferSource),
  );
}

export async function verifyEd25519(
  key: CryptoKey,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  return subtle().verify(
    { name: 'Ed25519' },
    key,
    signature as unknown as BufferSource,
    message as unknown as BufferSource,
  );
}

/** Returns the IEEE P1363 (raw r||s) form SubtleCrypto produces natively. */
export async function signEs256(key: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await subtle().sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      message as unknown as BufferSource,
    ),
  );
}

export async function verifyEs256(
  key: CryptoKey,
  signatureP1363: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  return subtle().verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    signatureP1363 as unknown as BufferSource,
    message as unknown as BufferSource,
  );
}

const P256_COORDINATE_BYTES = 32;

/**
 * Converts an ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` ECDSA signature to
 * the fixed-width r||s form SubtleCrypto verifies.
 *
 * Two encodings of the same signature exist in the wild and this implementation
 * has to read both: RFC 7518 §3.4 mandates the fixed-width form for the JWS
 * `ES256` algorithm, while some deployed signers (including seams that predate
 * the JWS profile) emit DER inside the JWS signature part. Accepting both
 * widens the DECODER, never the algorithm set — the same (r, s) pair either
 * verifies or does not, whichever way it was spelled — but it does mean a
 * `proofValue` is not byte-unique, so a producer should emit only the
 * RFC 7518 form. {@link p1363ToDer} exists for the reverse direction.
 */
export function derToP1363(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30) throw new TypeError('ECDSA DER: expected a SEQUENCE tag');
  let offset = 2;
  if ((der[1] as number) & 0x80) {
    // Long-form length: the low bits count the length bytes that follow.
    offset = 2 + ((der[1] as number) & 0x7f);
  }
  const readInteger = (): Uint8Array => {
    if (der[offset] !== 0x02) throw new TypeError('ECDSA DER: expected an INTEGER tag');
    const length = der[offset + 1] as number;
    const value = der.subarray(offset + 2, offset + 2 + length);
    offset += 2 + length;
    return value;
  };
  const r = readInteger();
  const s = readInteger();

  const out = new Uint8Array(P256_COORDINATE_BYTES * 2);
  const place = (value: Uint8Array, at: number): void => {
    // DER integers are signed and minimally encoded: strip a leading zero that
    // exists only to keep the value positive, then right-align into 32 bytes.
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start += 1;
    const trimmed = value.subarray(start);
    if (trimmed.length > P256_COORDINATE_BYTES) {
      throw new TypeError('ECDSA DER: integer wider than a P-256 coordinate');
    }
    out.set(trimmed, at + (P256_COORDINATE_BYTES - trimmed.length));
  };
  place(r, 0);
  place(s, P256_COORDINATE_BYTES);
  return out;
}

export function p1363ToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== P256_COORDINATE_BYTES * 2) {
    throw new TypeError(`ECDSA P1363: expected ${P256_COORDINATE_BYTES * 2} bytes`);
  }
  const encodeInteger = (value: Uint8Array): number[] => {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start += 1;
    const trimmed = [...value.subarray(start)];
    // A DER INTEGER is signed: a high bit set would read as negative, so a
    // zero byte is prepended to keep the value positive.
    if (((trimmed[0] as number) & 0x80) !== 0) trimmed.unshift(0x00);
    return [0x02, trimmed.length, ...trimmed];
  };
  const body = [
    ...encodeInteger(raw.subarray(0, P256_COORDINATE_BYTES)),
    ...encodeInteger(raw.subarray(P256_COORDINATE_BYTES)),
  ];
  return Uint8Array.from([0x30, body.length, ...body]);
}

/**
 * Normalizes an ECDSA signature of either encoding to the P1363 form
 * SubtleCrypto expects. The 64-byte length is the discriminator: a DER
 * signature over P-256 is 70-72 bytes and always opens with 0x30.
 */
export function normalizeEcdsaSignature(signature: Uint8Array): Uint8Array {
  if (signature.length === P256_COORDINATE_BYTES * 2) return signature;
  return derToP1363(signature);
}

/** Public key material as it travels through this implementation: bytes plus its curve. */
export interface PublicKeyMaterial {
  readonly algorithm: KeyAlgorithm;
  /** Ed25519: 32 raw bytes. P-256: a SEC1 point, compressed or uncompressed. */
  readonly keyBytes: Uint8Array;
}

export async function importPublicKey(material: PublicKeyMaterial): Promise<CryptoKey> {
  return material.algorithm === 'Ed25519'
    ? importEd25519PublicKey(material.keyBytes)
    : importP256PublicKey(material.keyBytes);
}
