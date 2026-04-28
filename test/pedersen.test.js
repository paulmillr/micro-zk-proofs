import { hexToBytes } from '@noble/hashes/utils.js';
import { babyjubjub } from '@noble/curves/misc.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import { Buffer } from 'node:buffer';
import { Point, pedersenHash } from '../pedersen.js';
import PEDERSEN_VEC from './vectors/pedersen.json' with { type: 'json' };

describe('pedersen', () => {
  should('basic', () => {
    for (const k in PEDERSEN_VEC) {
      const msg = hexToBytes(k);
      const exp = hexToBytes(PEDERSEN_VEC[k]);
      // console.log('MSG', k);
      deepStrictEqual(pedersenHash(msg), exp);
      // console.log('----');
    }
  });
  should('point codec', () => {
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
});
should.runWhen(import.meta.url);
