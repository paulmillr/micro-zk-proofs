import { bn254 } from '@noble/curves/bn254.js';
import { babyjubjub } from '@noble/curves/misc.js';
import { keccakprg } from '@noble/hashes/sha3-addons.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import bench from '@paulmillr/jsbt/bench.js';
import { deepStrictEqual } from 'node:assert';
import * as zkp from '../index.js';
import * as mimcsponge from '../mimcsponge.js';
import { pedersenHash, Point } from '../pedersen.js';
import { generateWitness } from '../witness.js';
import circuitSum from '../test/vectors/sum-circuit.json' with { type: 'json' };

const prg = (seed) => {
  const p = keccakprg();
  p.addEntropy(utf8ToBytes(seed));
  return (len) => p.randomBytes(len);
};

const msg = Uint8Array.from({ length: 128 }, (_, i) => i);
const point = Point.encode(babyjubjub.Point.BASE.multiply(123n));
const witnessForSum = generateWitness(circuitSum);
const groth16 = zkp.buildSnark(bn254).groth;
const setup = groth16.setup(circuitSum, prg('groth16-setup'));
const witness = witnessForSum({ a: '33', b: '34' });
const proof = await groth16.createProof(setup.pkey, witness, prg('groth16-proof'));
deepStrictEqual(groth16.verifyProof(setup.vkey, proof), true);

console.log('# Primitives');
await bench('mimcsponge.multiHash x8', () =>
  mimcsponge.multiHash([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n])
);
await bench('pedersenHash 128B', () => pedersenHash(msg));

console.log('# Groth16');
await bench('generateWitness sum', () => witnessForSum({ a: '33', b: '34' }));
await bench('setup sum', () => groth16.setup(circuitSum, prg('groth16-setup-bench')));
await bench('createProof sum', () =>
  groth16.createProof(setup.pkey, witness, prg('groth16-proof-bench'))
);
await bench('verifyProof sum', () => deepStrictEqual(groth16.verifyProof(setup.vkey, proof), true));
