import { babyjubjub } from '@noble/curves/misc.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import { Buffer } from 'node:buffer';
import { __TESTS, Point, pedersenHash } from '../pedersen.js';
import PEDERSEN_VEC from './vectors/pedersen.json' with { type: 'json' };

describe('pedersen', () => {
  it('basic', () => {
    for (const k in PEDERSEN_VEC) {
      const msg = hexToBytes(k);
      const exp = hexToBytes(PEDERSEN_VEC[k]);
      // console.log('MSG', k);
      deepStrictEqual(pedersenHash(msg), exp);
      // console.log('----');
    }
  });
  it('point codec', () => {
    const points = [
      babyjubjub.Point.BASE,
      babyjubjub.Point.BASE.negate(),
      babyjubjub.Point.BASE.multiply(2n),
      babyjubjub.Point.BASE.multiply(2n).negate(),
    ];
    for (const p of points) {
      const enc = Point.encode(p);
      const before = Uint8Array.from(enc);
      deepStrictEqual(Point.encode(Point.decode(enc)), before);
      deepStrictEqual(enc, before);
    }
    const buf = Buffer.from(Point.encode(babyjubjub.Point.BASE.negate()));
    const before = Uint8Array.from(buf);
    deepStrictEqual(Point.encode(Point.decode(buf)), before);
    deepStrictEqual(Uint8Array.from(buf), before);
  });
  it('bounds the persistent generator cache without changing long-message digests', () => {
    const msg = Uint8Array.from({ length: 257 * 25 }, (_, i) => i & 255);
    const expected = hexToBytes('c08635ac0917bd3fd741ea06d7aecec557b1087babb8f5fda224e8a2dbe9ee1c');
    deepStrictEqual(pedersenHash(msg), expected);
    deepStrictEqual(__TESTS.pointCacheSize(), __TESTS.maxCachedPoints);
    deepStrictEqual(pedersenHash(msg), expected);
    deepStrictEqual(__TESTS.pointCacheSize(), __TESTS.maxCachedPoints);
  });
});
it.runWhen(import.meta.url);
