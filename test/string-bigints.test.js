import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import { stringBigints } from '../index.js';

const nested = (leaf, depth) => {
  let value = leaf;
  for (let i = 0; i < depth; i++) value = [value];
  return value;
};

describe('stringBigints', () => {
  it('roundtrip unsigned bigint leaves', () => {
    const value = {
      a: 0n,
      b: [1n, { c: 2n }],
      d: null,
    };
    deepStrictEqual(stringBigints.decode(stringBigints.encode(value)), value);
  });
  it('preserves non-canonical unsigned decimal strings', () => {
    deepStrictEqual(stringBigints.decode({ a: '-1', b: ['01', '00', '1.0', '0x10', 'word'] }), {
      a: '-1',
      b: ['01', '00', '1.0', '0x10', 'word'],
    });
  });
  it('reject negative bigint leaves on encode', () => {
    throws(() => stringBigints.encode({ a: 1n, b: [-1n] }), /expected non-negative bigint/);
  });
  it('bounds encode and decode nesting depth without overflowing the stack', () => {
    let decoded = stringBigints.decode(nested('1', 256));
    for (let i = 0; i < 256; i++) decoded = decoded[0];
    deepStrictEqual(decoded, 1n);

    throws(
      () => stringBigints.decode(nested('1', 3000)),
      /maximum bigint conversion depth exceeded \(256\)/
    );
    throws(
      () => stringBigints.encode(nested(1n, 257)),
      /maximum bigint conversion depth exceeded \(256\)/
    );
  });
  it('rejects cyclic encode and decode values while allowing shared subtrees', () => {
    const cyclicArray = [];
    cyclicArray.push(cyclicArray);
    throws(() => stringBigints.decode(cyclicArray), /cyclic bigint conversion value/);

    const cyclicObject = {};
    cyclicObject.self = cyclicObject;
    throws(() => stringBigints.encode(cyclicObject), /cyclic bigint conversion value/);

    const shared = { value: '1' };
    deepStrictEqual(stringBigints.decode({ a: shared, b: shared }), {
      a: { value: 1n },
      b: { value: 1n },
    });
  });
  it('preserves sparse arrays and own __proto__ fields', () => {
    const sparse = [];
    sparse.length = 2;
    sparse[1] = '1';
    const decodedSparse = stringBigints.decode(sparse);
    deepStrictEqual(0 in decodedSparse, false);
    deepStrictEqual(decodedSparse[1], 1n);

    const value = Object.fromEntries([
      ['__proto__', '1'],
      ['value', '2'],
    ]);
    const decoded = stringBigints.decode(value);
    deepStrictEqual(Object.getPrototypeOf(decoded), Object.prototype);
    deepStrictEqual(Object.hasOwn(decoded, '__proto__'), true);
    deepStrictEqual(decoded.__proto__, 1n);
    deepStrictEqual(decoded.value, 2n);
  });
});
it.runWhen(import.meta.url);
