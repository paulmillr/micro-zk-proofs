import { hexToBytes } from '@noble/hashes/utils';
import { describe, should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import { pedersenHash } from '../pedersen.js';
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
});
should.runWhen(import.meta.url);
