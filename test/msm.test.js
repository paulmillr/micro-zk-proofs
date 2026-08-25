import { bn254 } from '@noble/curves/bn254.js';
import { keccakprg } from '@noble/hashes/sha3-addons.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, rejects } from 'node:assert';
import * as zkp from '../index.js';
import * as msm from '../msm.js';
import { generateWitness } from '../witness.js';
import circuitSum from './vectors/sum-circuit.json' with { type: 'json' };

const prg = (seed) => {
  const p = keccakprg();
  p.addEntropy(utf8ToBytes(seed));
  const randomBytes = (len) => p.randomBytes(len);
  return randomBytes;
};

describe('MSM', () => {
  it('Basic', async () => {
    const { methods, terminate } = msm.initMSM();
    const res = await methods.bn254_msmG1([
      { scalar: 1n, point: bn254.G1.Point.BASE },
      { scalar: 2n, point: bn254.G1.Point.BASE },
    ]);
    deepStrictEqual(res.equals(bn254.G1.Point.BASE.multiply(3n)), true);
    terminate();
  });

  it('supports opt-in side-channel hardening', async () => {
    const calls = [];
    const backend = async (input) => {
      calls.push(input);
      return bn254.G1.Point.ZERO;
    };
    const points = [bn254.G1.Point.BASE, bn254.G1.Point.BASE];
    const scalars = [0n, 1n];

    const optimized = msm.modifyArgs(bn254.fields.Fr, bn254.G1.Point, backend);
    await optimized(points, scalars);
    deepStrictEqual(
      calls[0].map(({ scalar }) => scalar),
      [1n]
    );

    const hardened = msm.modifyArgs(bn254.fields.Fr, bn254.G1.Point, backend, {
      hardenSideChannel: true,
    });
    await hardened(points, scalars);
    deepStrictEqual(
      calls[1].map(({ scalar }) => scalar),
      [0n, 1n]
    );
    await rejects(() => hardened(points, [0n, bn254.fields.Fr.ORDER]), /invalid scalar at index 1/);
  });

  // TODO: split benchmarking into separate test/bench.ts file
  it('proof', async () => {
    const randomBytesSetup = prg('groth16-setup');
    const { methods, terminate } = msm.initMSM();

    const groth16 = zkp.buildSnark(bn254).groth;
    const setup = groth16.setup(circuitSum, randomBytesSetup);
    const witness = generateWitness(circuitSum, { unsafeAllowJsEvalCircuit: true })({
      a: '33',
      b: '34',
    });
    const zeroWitness = generateWitness(circuitSum, { unsafeAllowJsEvalCircuit: true })({
      a: '0',
      b: '0',
    });
    const hardenedInputs = [];
    const hardenedGroth = zkp.buildSnark(bn254, {
      G1msm: async (input) => {
        hardenedInputs.push(input.map(({ scalar }) => scalar));
        return bn254.G1.Point.ZERO;
      },
      G2msm: async (input) => {
        hardenedInputs.push(input.map(({ scalar }) => scalar));
        return bn254.G2.Point.ZERO;
      },
      hardenSideChannel: true,
    }).groth;
    await hardenedGroth.createProof(setup.pkey, zeroWitness, prg('groth16-hardened-proof'));
    deepStrictEqual(hardenedInputs[0], zeroWitness);

    const randomBytesProof1 = prg('groth16-proof');

    let start = Date.now();
    const proof = await groth16.createProof(setup.pkey, witness, randomBytesProof1);
    // console.log(`\nProof generation, no workers: ${Date.now() - start}ms`);
    start = Date.now();
    deepStrictEqual(groth16.verifyProof(setup.vkey, proof), true);
    // console.log(`Proof verification, no workers: ${Date.now() - start}ms`);

    const groth16msm = zkp.buildSnark(bn254, {
      G1msm: methods.bn254_msmG1,
      G2msm: methods.bn254_msmG2,
    }).groth;
    const randomBytesProof2 = prg('groth16-proof');

    start = Date.now();
    const proof2 = await groth16msm.createProof(setup.pkey, witness, randomBytesProof2);
    // console.log(`Proof generation, with workers: ${Date.now() - start}ms`);
    start = Date.now();
    deepStrictEqual(groth16.verifyProof(setup.vkey, proof), true);
    // console.log(`Proof verification, with workers: ${Date.now() - start}ms`);
    deepStrictEqual(proof, proof2);
    // console.log();
    terminate();
  });
});

it.runWhen(import.meta.url);
