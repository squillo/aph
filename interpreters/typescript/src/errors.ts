/**
 * APH error taxonomy (spec §11) and the two failure kinds that deliberately
 * carry NO §11 code.
 *
 * §11 is a CLOSED set of sixteen protocol-level codes. Two things that can go
 * wrong in this implementation are outside it, and inventing a code for either
 * would widen a set the specification closed:
 *
 *  - a strict-parse failure at §8.3 step 1. §11 has no parse code; the spec
 *    says "reject", names no variant, and a verifier that reported a malformed
 *    document as, say, APH_E001 would send an operator to inspect key material
 *    over a typo. `AphParseError` carries the JSON path of the offending
 *    member instead.
 *  - a verification method this verifier was never given the key for. §8.4
 *    discovery is out of scope here (this implementation parses bytes and
 *    never fetches), so nothing was queried and nothing was found absent —
 *    APH_E014 means a surface ANSWERED and published no key, which is a
 *    different fact. `AphKeyUnavailableError` is a caller-configuration
 *    failure, not a protocol verdict.
 */

/**
 * The sixteen codes of §11, enumerated rather than counted. The `as const`
 * tuple is the enumeration: `APH_ERROR_CODES.length` is derived from it, so a
 * code added here cannot leave a stated count stale.
 */
export const APH_ERROR_CODES = [
  'APH_E001', // InvalidEnvelopeSignature
  'APH_E002', // InvalidFlowTransition
  'APH_E003', // MandateExpired
  'APH_E004', // RoleViolation
  'APH_E005', // ChannelNotAllowed
  'APH_E006', // NotarySignatureInvalid
  'APH_E007', // HumanAuthenticationRequired
  'APH_E008', // NotaryServiceUnreachable
  'APH_E009', // EnvelopeBodyHashMismatch
  'APH_E010', // UnsupportedAlgorithm
  'APH_E011', // PrincipalSignatureInvalid
  'APH_E012', // AttestationModeRefused
  'APH_E013', // ProofChainInvalid
  'APH_E014', // NotaryKeyNotPublished
  'APH_E015', // MandateRevoked
  'APH_E016', // MandateRequired — unrooted authority: §9.2 with no mandate at all
] as const;

export type AphErrorCode = (typeof APH_ERROR_CODES)[number];

/** §11 variant names, kept beside the codes so a message can name both. */
export const APH_ERROR_VARIANTS: Readonly<Record<AphErrorCode, string>> = {
  APH_E001: 'InvalidEnvelopeSignature',
  APH_E002: 'InvalidFlowTransition',
  APH_E003: 'MandateExpired',
  APH_E004: 'RoleViolation',
  APH_E005: 'ChannelNotAllowed',
  APH_E006: 'NotarySignatureInvalid',
  APH_E007: 'HumanAuthenticationRequired',
  APH_E008: 'NotaryServiceUnreachable',
  APH_E009: 'EnvelopeBodyHashMismatch',
  APH_E010: 'UnsupportedAlgorithm',
  APH_E011: 'PrincipalSignatureInvalid',
  APH_E012: 'AttestationModeRefused',
  APH_E013: 'ProofChainInvalid',
  APH_E014: 'NotaryKeyNotPublished',
  APH_E015: 'MandateRevoked',
  APH_E016: 'MandateRequired',
};

/** A protocol-level refusal carrying one of the sixteen §11 codes. */
export class AphError extends Error {
  readonly code: AphErrorCode;

  constructor(code: AphErrorCode, detail: string) {
    super(`${code} (${APH_ERROR_VARIANTS[code]}): ${detail}`);
    this.name = 'AphError';
    this.code = code;
  }
}

/**
 * §8.3 step 1 strict-parse failure. `path` is the JSON path of the member that
 * caused it, because "unknown field" without a name is unactionable to the
 * producer who has to fix it.
 */
export class AphParseError extends Error {
  readonly path: string;

  constructor(path: string, detail: string) {
    super(`strict parse failed at ${path}: ${detail}`);
    this.name = 'AphParseError';
    this.path = path;
  }
}

/** No key was supplied for a verification method this verifier cannot decode offline. */
export class AphKeyUnavailableError extends Error {
  readonly verificationMethod: string;

  constructor(verificationMethod: string) {
    super(
      `no verifying key available for ${verificationMethod}: it is not a did:key ` +
        '(which decodes offline, spec §8.4.3) and no key was supplied for it. This ' +
        'implementation performs no §8.4 discovery — keys arrive as parameters.',
    );
    this.name = 'AphKeyUnavailableError';
    this.verificationMethod = verificationMethod;
  }
}

export function aphError(code: AphErrorCode, detail: string): AphError {
  return new AphError(code, detail);
}
