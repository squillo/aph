/**
 * PUBLISHED test key material, and nothing else.
 *
 * Every private scalar in this file is printed in an RFC. They authorize
 * nothing, they are re-derivable by anyone, and they exist so that a reader who
 * does not trust this repository can check every byte against the document it
 * came from. No key that is not a published test vector appears anywhere in
 * this package.
 *
 *  - Ed25519: RFC 8032 §7.1 TEST 1, TEST 2 and TEST 3 — seed, public key,
 *    message and signature, so the constants can be checked against their own
 *    RFC by signing and comparing rather than by trusting this file.
 *  - P-256: RFC 6979 Appendix A.2.5 ("ECDSA, 256 Bits (Prime Field)"), the
 *    sample key `x` with its public point `U = xG`. A P-256 scalar cannot be a
 *    repeated-byte fake the way an Ed25519 seed can — every 32 bytes is a valid
 *    Ed25519 seed, while a P-256 scalar must lie below the group order — so a
 *    published one is the only honest option.
 */

import { hexToBytes } from '../src/baseenc.js';
import {
  importEd25519PrivateKey,
  importEd25519PublicKey,
  importP256PrivateKey,
  importP256PublicKey,
  type PublicKeyMaterial,
} from '../src/webcrypto.js';

export interface Ed25519TestVector {
  /** Which of RFC 8032 §7.1's numbered cases this is. */
  readonly name: string;
  readonly seed: Uint8Array;
  readonly publicKey: Uint8Array;
  /** The RFC's own message and signature, for a known-answer check. */
  readonly message: Uint8Array;
  readonly signature: Uint8Array;
}

function ed25519Vector(
  name: string,
  seedHex: string,
  publicHex: string,
  messageHex: string,
  signatureHex: string,
): Ed25519TestVector {
  return {
    name,
    seed: hexToBytes(seedHex),
    publicKey: hexToBytes(publicHex),
    message: hexToBytes(messageHex),
    signature: hexToBytes(signatureHex),
  };
}

/** RFC 8032 §7.1 TEST 1 — the empty-message case. */
export const RFC8032_TEST_1 = ed25519Vector(
  'RFC 8032 §7.1 TEST 1',
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  '',
  'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e' +
    '39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
);

/**
 * RFC 8032 §7.1 TEST 2 — the HUMAN PRINCIPAL throughout this repository's
 * corpus, including `examples/principal_signed_envelope.json`.
 */
export const RFC8032_TEST_2 = ed25519Vector(
  'RFC 8032 §7.1 TEST 2',
  '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
  '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
  '72',
  '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f' +
    '3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
);

/** RFC 8032 §7.1 TEST 3 — the NOTARY throughout this repository's corpus. */
export const RFC8032_TEST_3 = ed25519Vector(
  'RFC 8032 §7.1 TEST 3',
  'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
  'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
  'af82',
  '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67' +
    'f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
);

export const ED25519_VECTORS: readonly Ed25519TestVector[] = [
  RFC8032_TEST_1,
  RFC8032_TEST_2,
  RFC8032_TEST_3,
];

/**
 * RFC 6979 Appendix A.2.5, the NIST P-256 sample key.
 *
 * `d` is the RFC's `x`; `qx`/`qy` are its `Ux`/`Uy`. The RFC prints the public
 * point because the key is a sample: nothing about it is secret and nothing is
 * authorized by holding it.
 *
 * Note what this key does NOT buy. RFC 6979 specifies DETERMINISTIC ECDSA, but
 * SubtleCrypto implements the randomized algorithm and exposes no way to ask
 * for a deterministic nonce — so a signature made here with this key differs on
 * every run even though the key does not. The key is fixed so the DID and the
 * public point are stable; the signature is not pinnable and no artifact signed
 * with it is committed.
 */
export const RFC6979_A25_P256 = {
  name: 'RFC 6979 Appendix A.2.5 (NIST P-256, SHA-256) sample key',
  d: hexToBytes('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721'),
  qx: hexToBytes('60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6'),
  qy: hexToBytes('7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299'),
} as const;

/**
 * The compressed SEC1 form of the RFC 6979 A.2.5 public point — the shape a
 * `did:key` carries (spec §8.4.3).
 *
 * Compression is a byte selection, not a curve operation: keep x, and record
 * the parity of y in the prefix (0x02 even, 0x03 odd). Decompression is the
 * direction that needs a modular square root, and this implementation never
 * performs it — it hands the compressed point to SubtleCrypto inside an SPKI
 * wrapper instead (see `src/webcrypto.ts`).
 */
export const RFC6979_A25_P256_COMPRESSED: Uint8Array = Uint8Array.from([
  (RFC6979_A25_P256.qy[RFC6979_A25_P256.qy.length - 1] as number) % 2 === 0 ? 0x02 : 0x03,
  ...RFC6979_A25_P256.qx,
]);

export async function ed25519SigningKey(vector: Ed25519TestVector): Promise<CryptoKey> {
  return importEd25519PrivateKey(vector.seed, vector.publicKey);
}

export async function ed25519VerifyingKey(vector: Ed25519TestVector): Promise<CryptoKey> {
  return importEd25519PublicKey(vector.publicKey);
}

export function ed25519KeyMaterial(vector: Ed25519TestVector): PublicKeyMaterial {
  return { algorithm: 'Ed25519', keyBytes: vector.publicKey };
}

export async function p256SigningKey(): Promise<CryptoKey> {
  return importP256PrivateKey(RFC6979_A25_P256.d, RFC6979_A25_P256.qx, RFC6979_A25_P256.qy);
}

/**
 * There is no `p256KeyMaterial` sibling to {@link ed25519KeyMaterial}, and the
 * absence is the point: every P-256 party in this suite is named by a
 * `did:key`, which carries its own bytes, so nothing ever needs to be SUPPLIED
 * for one. The Ed25519 helper exists solely because the published golden's
 * notary is a `did:web`.
 */
export async function p256VerifyingKey(): Promise<CryptoKey> {
  return importP256PublicKey(RFC6979_A25_P256_COMPRESSED);
}
