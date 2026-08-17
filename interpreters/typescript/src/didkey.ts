/**
 * `did:key` decoding and encoding (spec §8.4.3).
 *
 * `did:key` is the one publication mechanism that is fully offline: the key
 * bytes travel inside the identifier. That property is what lets this
 * implementation verify a principal proof with no network at all, which is
 * the boundary this implementation keeps: envelopes arrive as bytes, keys and
 * `now` arrive as parameters, and nothing here ever fetches.
 */

import { base58btcDecode, base58btcEncode, bytesEqual } from './baseenc.js';

export type KeyAlgorithm = 'Ed25519' | 'P256';

export interface DecodedDidKey {
  readonly algorithm: KeyAlgorithm;
  /** Ed25519: the 32 raw public key bytes. P-256: the 33-byte compressed SEC1 point. */
  readonly keyBytes: Uint8Array;
}

/**
 * Multicodec prefixes as they appear ON THE WIRE, i.e. unsigned-varint encoded.
 *
 * Spec §8.4.3 prints "0xed01 indicates Ed25519; 0x1200 indicates P-256" — but
 * those two numbers are written to different conventions. `ed01` is already the
 * varint form of multicodec code 0xed. `1200` is the multicodec CODE for
 * p256-pub, whose unsigned-varint form is 0x80 0x24, and that is what a
 * `did:key` string actually carries (which is why P-256 dids read `zDn...`
 * while Ed25519 dids read `z6Mk...`). This implementation follows the
 * multicodec registry and the W3C did:key registration. If a published APH
 * vector ever disagrees, that is a spec-versus-vector disagreement worth
 * filing under README's Reporting section rather than silently accommodating.
 */
const MULTICODEC_ED25519_PUB = Uint8Array.from([0xed, 0x01]);
const MULTICODEC_P256_PUB = Uint8Array.from([0x80, 0x24]);

const ED25519_PUBLIC_KEY_BYTES = 32;
const P256_COMPRESSED_POINT_BYTES = 33;

/** Strips the `#fragment` of a DID URL, leaving the DID that identifies the subject. */
export function didOf(verificationMethod: string): string {
  const hash = verificationMethod.indexOf('#');
  return hash === -1 ? verificationMethod : verificationMethod.slice(0, hash);
}

export function isDidKey(didOrUrl: string): boolean {
  return didOf(didOrUrl).startsWith('did:key:z');
}

export function decodeDidKey(didOrUrl: string): DecodedDidKey {
  const did = didOf(didOrUrl);
  if (!did.startsWith('did:key:')) {
    throw new TypeError(`did:key: "${did}" is not a did:key identifier`);
  }
  const multibase = did.slice('did:key:'.length);
  if (!multibase.startsWith('z')) {
    throw new TypeError(`did:key: "${did}" is not multibase base58btc (expected a "z" prefix)`);
  }
  const decoded = base58btcDecode(multibase.slice(1));

  if (bytesEqual(decoded.subarray(0, 2), MULTICODEC_ED25519_PUB)) {
    const keyBytes = decoded.subarray(2);
    if (keyBytes.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new TypeError(
        `did:key: Ed25519 key is ${keyBytes.length} bytes, expected ${ED25519_PUBLIC_KEY_BYTES}`,
      );
    }
    return { algorithm: 'Ed25519', keyBytes: new Uint8Array(keyBytes) };
  }

  if (bytesEqual(decoded.subarray(0, 2), MULTICODEC_P256_PUB)) {
    const keyBytes = decoded.subarray(2);
    if (keyBytes.length !== P256_COMPRESSED_POINT_BYTES) {
      throw new TypeError(
        `did:key: P-256 key is ${keyBytes.length} bytes, expected ${P256_COMPRESSED_POINT_BYTES} ` +
          '(compressed SEC1)',
      );
    }
    return { algorithm: 'P256', keyBytes: new Uint8Array(keyBytes) };
  }

  throw new TypeError(
    `did:key: multicodec prefix 0x${[...decoded.subarray(0, 2)]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')} is neither Ed25519 nor P-256 (spec §8.4.3 names only those two)`,
  );
}

function encodeDidKey(prefix: Uint8Array, keyBytes: Uint8Array): string {
  const payload = new Uint8Array(prefix.length + keyBytes.length);
  payload.set(prefix, 0);
  payload.set(keyBytes, prefix.length);
  return `did:key:z${base58btcEncode(payload)}`;
}

/**
 * Derives the `did:key` for a raw Ed25519 public key. The minting path derives
 * every identifier from key material rather than carrying a literal, so a
 * fixture cannot claim a DID its own key does not produce.
 */
export function encodeDidKeyEd25519(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new TypeError(`did:key: Ed25519 public key must be ${ED25519_PUBLIC_KEY_BYTES} bytes`);
  }
  return encodeDidKey(MULTICODEC_ED25519_PUB, publicKey);
}

export function encodeDidKeyP256(compressedPoint: Uint8Array): string {
  if (compressedPoint.length !== P256_COMPRESSED_POINT_BYTES) {
    throw new TypeError(
      `did:key: P-256 public key must be ${P256_COMPRESSED_POINT_BYTES} bytes (compressed SEC1)`,
    );
  }
  return encodeDidKey(MULTICODEC_P256_PUB, compressedPoint);
}

/**
 * The `did:key` convention for a verification method: the DID with its own
 * multibase suffix as the fragment, as printed throughout spec §8.4.3 and in
 * every published example.
 */
export function didKeyVerificationMethod(did: string): string {
  return `${did}#${did.slice('did:key:'.length)}`;
}
