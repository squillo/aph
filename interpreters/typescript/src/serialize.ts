/**
 * Emitting an envelope as JSON text.
 *
 * Note what this is NOT: it is not canonicalization. RFC 8785 decides which
 * bytes a signature covers (see `jcs.ts`); this decides what a published file
 * looks like. Keeping them in separate modules is deliberate — an
 * implementation that emitted canonical bytes as its file format would be
 * correct and unreadable, and one that signed its pretty-printed form would be
 * readable and wrong.
 */

import type { NotarizationEnvelope } from './types.js';

/** Compact, single-line JSON — the wire form for a transport with a length budget. */
export function serializeEnvelope(envelope: NotarizationEnvelope): string {
  return JSON.stringify(envelope);
}

/**
 * The published-file form used throughout `examples/`: two-space indentation
 * and a trailing newline. Pinned as a function rather than left to each call
 * site because a byte-identity test compares against it.
 */
export function serializeEnvelopeDocument(envelope: NotarizationEnvelope): string {
  return `${JSON.stringify(envelope, null, 2)}\n`;
}
