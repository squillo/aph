/**
 * APH v0.1 — an independent TypeScript implementation.
 *
 * SCOPE, stated honestly and up front:
 *  - It shares no code with the reference Rust implementation. It was written
 *    from `spec/aph-0.1.md` and the published example envelopes. It is NOT an
 *    independent TEAM: the same authors wrote both, so what this proves is that
 *    the specification is implementable twice, not that it survives a stranger.
 *    The invitation to outside implementers stands and is the missing half.
 *  - It parses bytes and NEVER fetches. §8.4 key discovery and §6.3.3's status
 *    fetch are network acts, so keys and `now` arrive as parameters. That is
 *    the same boundary the reference draws around its core.
 *  - Every hash and every signature runs through SubtleCrypto. Nothing here
 *    implements a curve or a digest. RFC 8785 canonicalization IS implemented
 *    here, because deciding which bytes a signature covers is protocol logic.
 */

export { canonicalize, canonicalizeToBytes } from './jcs.js';
export type { JsonObject, JsonValue } from './jcs.js';

export {
  APH_ERROR_CODES,
  APH_ERROR_VARIANTS,
  AphError,
  AphKeyUnavailableError,
  AphParseError,
} from './errors.js';
export type { AphErrorCode } from './errors.js';

export {
  base58btcDecode,
  base58btcEncode,
  base64urlDecode,
  base64urlEncode,
  bytesEqual,
  bytesToHex,
  hexToBytes,
  multibaseDecode,
  multibaseEncode,
} from './baseenc.js';

export {
  decodeDidKey,
  didKeyVerificationMethod,
  didOf,
  encodeDidKeyEd25519,
  encodeDidKeyP256,
  isDidKey,
} from './didkey.js';
export type { DecodedDidKey, KeyAlgorithm } from './didkey.js';

export { parseEnvelope, parseDelegationMandate } from './parse.js';
export { serializeEnvelope, serializeEnvelopeDocument } from './serialize.js';
export {
  mandateSigningBase,
  mandateSigningBaseWithMembersEmptied,
  proofBase,
} from './bases.js';
export {
  declaredAttestationMode,
  requireAttestationMode,
  verifyProofStructure,
} from './structure.js';

export {
  checkCredentialStatus,
  resolveVerifyingKey,
  verifyBodyHash,
  verifyEmbeddedMandate,
  verifyEnvelope,
  verifyProofAt,
} from './verify.js';
export type { SuppliedKeys, VerifiedEnvelope, VerifyOptions } from './verify.js';

export {
  mintNotaryAttestedEnvelope,
  mintPrincipalSignedEnvelope,
  signDelegationMandate,
} from './mint.js';
export type { PreparedEnvelope, ProofMetadata, Signer } from './mint.js';

export {
  detachedJwsSigner,
  ed25519DataIntegritySigner,
  es256DataIntegritySigner,
} from './signers.js';

export {
  importEd25519PrivateKey,
  importEd25519PublicKey,
  importP256PrivateKey,
  importP256PublicKey,
  sha256,
} from './webcrypto.js';
export type { PublicKeyMaterial } from './webcrypto.js';

export * from './types.js';
