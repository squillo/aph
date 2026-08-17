/**
 * Mints `examples/ts_minted_envelope.json` — the (←) half of the
 * cross-verification bar.
 *
 * Run it with `npm run mint` after `npm run build`. It is idempotent: the
 * fixture is entirely constants and Ed25519 is deterministic, so a second run
 * writes the same bytes. `test/ts_minted_artifact.test.ts` is the tripwire that
 * says so — if the committed file and a fresh mint ever differ, the signing
 * path moved and the artifact is stale.
 *
 * The script REFUSES TO PUBLISH what it cannot verify. Minting and verifying
 * are separate code paths here (`src/mint.ts` builds the bases forward;
 * `src/verify.ts` rebuilds them from the finished document), so a self-check
 * before writing catches the one class of bug that would otherwise ship: an
 * artifact whose §7.2.1 bases are self-consistently WRONG. It would still be
 * caught later, by the Rust cross-verify test — but at the cost of a committed
 * file and a red gate, rather than a non-zero exit here.
 */

import { writeFileSync } from 'node:fs';
import process from 'node:process';

import { serializeEnvelopeDocument } from '../src/serialize.js';
import { verifyEnvelope } from '../src/verify.js';
import { exampleUrl } from '../testkit/corpus.js';
import {
  TS_MINTED_BODY,
  TS_MINTED_EVALUATION_INSTANT,
  TS_MINTED_FILE,
  buildTsMintedEnvelope,
} from '../testkit/ts_minted.js';

async function main(): Promise<void> {
  const envelope = await buildTsMintedEnvelope();
  const document = serializeEnvelopeDocument(envelope);

  // Verified from the SERIALIZED TEXT, not from the in-memory object: text is
  // what the Rust side will read, and a round-trip through JSON is where a
  // number widening or a key-order assumption would show up.
  const verified = await verifyEnvelope(document, {
    now: TS_MINTED_EVALUATION_INSTANT,
    requireMode: 'PrincipalSigned',
    bodyBytes: new TextEncoder().encode(TS_MINTED_BODY),
  });
  if (!verified.bodyHashChecked || !verified.embeddedMandateChecked) {
    throw new Error(
      'refusing to publish: the self-check did not exercise both the §8.3 step 8 body hash ' +
        'and the §7.1.7.1 embedded mandate, so the artifact would ship less than it claims',
    );
  }

  const target = exampleUrl(TS_MINTED_FILE);
  writeFileSync(target, document, 'utf8');
  process.stdout.write(
    `wrote ${TS_MINTED_FILE} (${new TextEncoder().encode(document).length} bytes), ` +
      `verified as ${verified.attestationMode} at ${TS_MINTED_EVALUATION_INSTANT}\n`,
  );
}

await main().catch((error: unknown) => {
  process.stderr.write(`mint failed: ${String(error)}\n`);
  process.exitCode = 1;
});
