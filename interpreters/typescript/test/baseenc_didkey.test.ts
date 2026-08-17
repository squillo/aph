/**
 * WHY THIS FILE EXISTS: base58btc and `did:key` are where an independent
 * implementation can be self-consistently wrong. A broken encoder that is also
 * a broken decoder round-trips perfectly and produces identifiers no other
 * implementation resolves. The cure is to check against something this
 * implementation did not produce: the DID strings inside the PUBLISHED corpus.
 *
 * WHAT THEY PIN: RFC 4648 §5 base64url against its own published vectors, the
 * base58btc leading-zero rule, multibase's refusal of any base but base58btc,
 * and — the load-bearing one — that deriving a `did:key` from the RFC 8032
 * §7.1 TEST 2 public key reproduces the principal DID printed in
 * `examples/principal_signed_envelope.json`.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  base58btcDecode,
  base58btcEncode,
  base64urlDecode,
  base64urlEncode,
  bytesEqual,
  bytesToHex,
  hexToBytes,
  multibaseDecode,
  multibaseEncode,
} from '../src/baseenc.js';
import { decodeDidKey, didKeyVerificationMethod, didOf, encodeDidKeyEd25519, isDidKey } from '../src/didkey.js';
import { parseEnvelope } from '../src/parse.js';
import { GOLDEN_FILE } from '../testkit/golden.js';
import { readExample } from '../testkit/corpus.js';
import { RFC8032_TEST_2, RFC8032_TEST_3 } from '../testkit/vectors.js';

const ASCII = new TextEncoder();

test('RFC 4648 §5 base64url matches the RFC test vectors, unpadded', () => {
  assert.equal(base64urlEncode(ASCII.encode('')), '');
  assert.equal(base64urlEncode(ASCII.encode('f')), 'Zg');
  assert.equal(base64urlEncode(ASCII.encode('fo')), 'Zm8');
  assert.equal(base64urlEncode(ASCII.encode('foo')), 'Zm9v');
  assert.equal(base64urlEncode(ASCII.encode('foob')), 'Zm9vYg');
  assert.equal(base64urlEncode(ASCII.encode('fooba')), 'Zm9vYmE');
  assert.equal(base64urlEncode(ASCII.encode('foobar')), 'Zm9vYmFy');
});

test('base64url uses the URL-safe alphabet and tolerates padding on the way in', () => {
  // 0xFB 0xFF encodes as "-_" in base64url where standard base64 writes "+/".
  // A decoder that accepted only the standard alphabet would reject valid JWS
  // segments; §8.2's proofValue is base64url throughout.
  assert.equal(base64urlEncode(Uint8Array.from([0xfb, 0xff])), '-_8');
  assert.deepEqual([...base64urlDecode('-_8')], [0xfb, 0xff]);
  // RFC 7515 forbids emitting padding but a producer that adds it is still
  // decodable; dropping it costs nothing and refusing would be gratuitous.
  assert.deepEqual([...base64urlDecode('Zm9v')], [...base64urlDecode('Zm9v==')]);
});

test('base58btc preserves leading zero bytes as leading "1" characters', () => {
  // The rule matters because the multicodec prefix of a did:key can begin with
  // a zero byte; an encoder that treated the input as one big integer would
  // silently drop it and produce a DID that decodes to a shorter key.
  assert.equal(base58btcEncode(Uint8Array.from([0x00, 0x00, 0x01])), '112');
  assert.deepEqual([...base58btcDecode('112')], [0x00, 0x00, 0x01]);
  assert.equal(base58btcEncode(new Uint8Array(0)), '');
  // The all-zero payload is the case where a naive digit buffer emits one '1'
  // too many and its decoder produces one zero byte too many — self-consistent,
  // and wrong against every other base58btc implementation. Both directions are
  // pinned because a bug present in both round-trips and hides.
  assert.equal(base58btcEncode(Uint8Array.from([0x00])), '1');
  assert.equal(base58btcEncode(Uint8Array.from([0x00, 0x00])), '11');
  assert.deepEqual([...base58btcDecode('1')], [0x00]);
  assert.deepEqual([...base58btcDecode('11')], [0x00, 0x00]);
});

test('base58btc round-trips arbitrary bytes, including a full 64-byte signature width', () => {
  const bytes = Uint8Array.from({ length: 64 }, (_unused, index) => (index * 37) % 256);
  assert.ok(bytesEqual(base58btcDecode(base58btcEncode(bytes)), bytes));
});

test('multibase accepts base58btc and refuses every other base', () => {
  const bytes = hexToBytes('deadbeef');
  const encoded = multibaseEncode(bytes);
  assert.ok(encoded.startsWith('z'));
  assert.ok(bytesEqual(multibaseDecode(encoded), bytes));
  // "m" is multibase base64. Accepting it would mean two spellings of the same
  // signature, which is exactly what §7.2 argues destroys interoperability.
  assert.throws(() => multibaseDecode('m3q2-7w'), TypeError);
});

test('hex helpers round-trip and reject malformed input', () => {
  assert.equal(bytesToHex(hexToBytes('00ff10')), '00ff10');
  assert.throws(() => hexToBytes('abc'), TypeError);
  assert.throws(() => hexToBytes('zz'), TypeError);
});

test('a did:key derived from RFC 8032 TEST 2 reproduces the PUBLISHED principal DID', () => {
  // The whole point of the file. If base58btc or the multicodec prefix were
  // wrong, this implementation would still round-trip its own DIDs and would
  // resolve nobody else's. The published corpus is the outside check.
  const envelope = parseEnvelope(readExample(GOLDEN_FILE));
  const derived = encodeDidKeyEd25519(RFC8032_TEST_2.publicKey);
  assert.equal(derived, envelope.credentialSubject.humanPrincipal.id);
  assert.equal(derived, envelope.issuer);
});

test('did:key decoding recovers the exact public key bytes the identifier carries', () => {
  for (const vector of [RFC8032_TEST_2, RFC8032_TEST_3]) {
    const did = encodeDidKeyEd25519(vector.publicKey);
    const decoded = decodeDidKey(did);
    assert.equal(decoded.algorithm, 'Ed25519');
    assert.ok(bytesEqual(decoded.keyBytes, vector.publicKey), `${vector.name} did not round-trip`);
  }
});

test('a verification method is the DID plus its own multibase suffix, and didOf strips it', () => {
  const did = encodeDidKeyEd25519(RFC8032_TEST_2.publicKey);
  const method = didKeyVerificationMethod(did);
  assert.equal(method, `${did}#${did.slice('did:key:'.length)}`);
  assert.equal(didOf(method), did);
  assert.ok(isDidKey(method));
  // A did:web is not offline-resolvable and must not be mistaken for one.
  assert.equal(isDidKey('did:web:notary.squillo.com#key-1'), false);
  assert.equal(didOf('did:web:notary.squillo.com#key-1'), 'did:web:notary.squillo.com');
});

test('did:key refuses a multicodec prefix §8.4.3 does not name', () => {
  // 0xec01 is x25519-pub: a real multicodec, and not a signing key. Accepting
  // it would mean importing a key agreement key as a verification key.
  const notASigningKey = base58btcEncode(
    Uint8Array.from([0xec, 0x01, ...RFC8032_TEST_2.publicKey]),
  );
  assert.throws(() => decodeDidKey(`did:key:z${notASigningKey}`), TypeError);
});
