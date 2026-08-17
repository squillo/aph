/**
 * `examples/principal_signed_envelope.json` — the (→) half of the
 * cross-verification bar — and the one piece of configuration verifying it
 * requires.
 *
 * That configuration is the point of this module rather than an inconvenience.
 * The golden's notary is `did:web:notary.squillo.com#key-1`, and a `did:web`
 * key does NOT travel inside the identifier: it is published at a
 * `.well-known` document a verifier fetches (§8.4.4). This implementation
 * never fetches, so the key arrives as a parameter — and the parameter has to
 * come from somewhere a reader can check. It comes from RFC 8032 §7.1 TEST 3,
 * which `examples/README.md` and the repository README both name as the
 * notary's seed.
 */

import type { SuppliedKeys } from '../src/verify.js';

import { RFC8032_TEST_3, ed25519KeyMaterial } from './vectors.js';

export const GOLDEN_FILE = 'principal_signed_envelope.json';

/** The DID URL the golden's notary proof names. */
export const GOLDEN_NOTARY_VERIFICATION_METHOD = 'did:web:notary.squillo.com#key-1';

/**
 * An instant inside the golden's `validFrom`..`validUntil` window
 * (2026-05-21T00:00:00Z .. 2026-05-22T00:00:00Z). A constant, because a
 * verifier that read the wall clock would pass today and fail in 2027.
 */
export const GOLDEN_EVALUATION_INSTANT = '2026-05-21T12:00:00Z';

/**
 * The keys a verifier must be handed to check the golden end to end. The
 * principal is deliberately NOT here: it is a `did:key`, it carries its own
 * bytes, and `resolveVerifyingKey` refuses to let a supplied entry shadow the
 * strongest anchor the protocol has.
 */
export function goldenSuppliedKeys(): SuppliedKeys {
  return { [GOLDEN_NOTARY_VERIFICATION_METHOD]: ed25519KeyMaterial(RFC8032_TEST_3) };
}
