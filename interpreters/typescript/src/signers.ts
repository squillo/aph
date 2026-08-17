/**
 * Concrete {@link Signer}s over the §8.2 proof formats.
 *
 * Each takes an already-imported `CryptoKey`, so no private key material passes
 * through this module and where a key came from — a keychain, a device, a
 * published test vector — is the caller's business. Every signature is produced
 * by SubtleCrypto; the code here only encodes what SubtleCrypto returns.
 */

import { base64urlEncode, multibaseEncode } from './baseenc.js';
import type { Signer } from './mint.js';
import type { Cryptosuite } from './types.js';
import { signEd25519, signEs256 } from './webcrypto.js';

/** `eddsa-jcs-2022` — multibase base58btc over the raw 64-byte Ed25519 signature. */
export function ed25519DataIntegritySigner(key: CryptoKey, verificationMethod: string): Signer {
  return {
    verificationMethod,
    proofType: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    async encodeProofValue(canonical: Uint8Array): Promise<string> {
      return multibaseEncode(await signEd25519(key, canonical));
    },
  };
}

/**
 * `ecdsa-jcs-2019` — multibase base58btc over the fixed-width r||s signature.
 *
 * SubtleCrypto's ECDSA already returns the IEEE P1363 form the W3C cryptosuite
 * fixes, so nothing is converted here. Note what that costs: WebCrypto has no
 * RFC 6979 deterministic mode, so a value produced by this signer is DIFFERENT
 * on every run and an artifact carrying it cannot be byte-pinned. That is why
 * the committed cross-implementation artifact is Ed25519 and the ES256 path is
 * covered by verifying a published vector plus a mint-then-verify self-test.
 */
export function es256DataIntegritySigner(key: CryptoKey, verificationMethod: string): Signer {
  return {
    verificationMethod,
    proofType: 'DataIntegrityProof',
    cryptosuite: 'ecdsa-jcs-2019',
    async encodeProofValue(canonical: Uint8Array): Promise<string> {
      return multibaseEncode(await signEs256(key, canonical));
    },
  };
}

const JWS_ALGORITHM_OF: Readonly<Record<Cryptosuite, 'EdDSA' | 'ES256'>> = {
  'eddsa-jcs-2022': 'EdDSA',
  'ecdsa-jcs-2019': 'ES256',
};

/**
 * `JsonWebSignature2020` — the §8.2 compact detached JWS.
 *
 * The protected header is fixed by §8.2: `alg`, `kid`, `typ: aph+jws`,
 * `cty: vc+ld+json`, `b64: false`, `crit: ["b64"]`. With `b64:false` RFC 7797
 * makes the signing input `BASE64URL(header) || "." || <raw payload bytes>` —
 * the payload is NOT re-encoded — and that is the form this signer produces.
 * The verifier additionally tolerates signers that base64url-encode the payload
 * anyway; a producer should not, because two spellings of the same signing
 * input make a `proofValue` non-unique.
 */
export function detachedJwsSigner(
  key: CryptoKey,
  verificationMethod: string,
  cryptosuite: Cryptosuite,
): Signer {
  const alg = JWS_ALGORITHM_OF[cryptosuite];
  const header = base64urlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        alg,
        kid: verificationMethod,
        typ: 'aph+jws',
        cty: 'vc+ld+json',
        b64: false,
        crit: ['b64'],
      }),
    ),
  );
  return {
    verificationMethod,
    proofType: 'JsonWebSignature2020',
    async encodeProofValue(canonical: Uint8Array): Promise<string> {
      const prefix = new TextEncoder().encode(`${header}.`);
      const signingInput = new Uint8Array(prefix.length + canonical.length);
      signingInput.set(prefix, 0);
      signingInput.set(canonical, prefix.length);
      const signature =
        alg === 'EdDSA' ? await signEd25519(key, signingInput) : await signEs256(key, signingInput);
      // RFC 7515 §A.5 detached serialization: the payload segment is empty.
      return `${header}..${base64urlEncode(signature)}`;
    },
  };
}
