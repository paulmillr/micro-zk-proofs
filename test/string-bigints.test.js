import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import { stringBigints } from '../index.js';

describe('stringBigints', () => {
  should('roundtrip unsigned bigint leaves', () => {
    const value = {
      a: 0n,
      b: [1n, { c: 2n }],
      d: null,
    };
    deepStrictEqual(stringBigints.decode(stringBigints.encode(value)), value);
  });
  should('preserve non-unsigned decimal strings', () => {
    deepStrictEqual(stringBigints.decode({ a: '-1', b: ['1.0', '0x10', 'word'] }), {
      a: '-1',
      b: ['1.0', '0x10', 'word'],
    });
  });
  should('reject negative bigint leaves on encode', () => {
    throws(() => stringBigints.encode({ a: 1n, b: [-1n] }), /expected non-negative bigint/);
  });
});
should.runWhen(import.meta.url);
