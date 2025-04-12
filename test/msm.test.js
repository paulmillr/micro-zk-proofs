import { bn254 } from '@noble/curves/bn254';
import { keccakprg } from '@noble/hashes/sha3-addons';
import { describe, should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import * as zkp from '../index.js';
import * as msm from '../msm.js';
import { generateWitness } from '../witness.js';
import circuitSum from './vectors/circuit_sum.json' with { type: 'json' };

const prg = (seed) => {
  const p = keccakprg().feed(seed);
  const randomBytes = (len) => p.fetch(len);
  return randomBytes;
};

describe('MSM', () => {
  should('Basic', async () => {
    const { methods, terminate } = msm.initMSM();
    const res = await methods.bn254_msmG1([
      { scalar: 1n, point: bn254.G1.ProjectivePoint.BASE },
      { scalar: 2n, point: bn254.G1.ProjectivePoint.BASE },
    ]);
    deepStrictEqual(res.equals(bn254.G1.ProjectivePoint.BASE.multiply(3n)), true);
    terminate();
  });

  should('proof', async () => {
    const randomBytesSetup = prg('groth16-setup');
    const { methods, terminate } = msm.initMSM();

    const groth16 = zkp.buildSnark(bn254).groth;
    const setup = groth16.setup(circuitSum, randomBytesSetup);
    const witness = generateWitness(circuitSum)({ a: '33', b: '34' });
    const randomBytesProof1 = prg('groth16-proof');

    let start = Date.now();
    const proof = await groth16.createProof(setup.pkey, witness, randomBytesProof1);
    console.log(`\nProof generation, no workers: ${Date.now() - start}ms`);
    start = Date.now();
    deepStrictEqual(groth16.verifyProof(setup.vkey, proof), true);
    console.log(`Proof verification, no workers: ${Date.now() - start}ms`);

    const groth16msm = zkp.buildSnark(bn254, {
      G1msm: methods.bn254_msmG1,
      G2msm: methods.bn254_msmG2,
    }).groth;
    const randomBytesProof2 = prg('groth16-proof');

    start = Date.now();
    const proof2 = await groth16msm.createProof(setup.pkey, witness, randomBytesProof2);
    console.log(`Proof generation, with workers: ${Date.now() - start}ms`);
    start = Date.now();
    deepStrictEqual(groth16.verifyProof(setup.vkey, proof), true);
    console.log(`Proof verification, with workers: ${Date.now() - start}ms`);
    deepStrictEqual(proof, proof2);
    console.log();
    terminate();
  });
});

should.runWhen(import.meta.url);
