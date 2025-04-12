import { bn254 } from '@noble/curves/bn254';
import * as zkp from 'micro-zk-proofs';
import * as zkpWitness from 'micro-zk-proofs/witness.js';
import { deepStrictEqual } from 'node:assert';
import { default as calc } from './output/sum_test_js/witness_calculator.cjs';

import { readFileSync } from 'node:fs';
import { dirname, join as pjoin } from 'node:path';
import { fileURLToPath } from 'node:url';
const _dirname = dirname(fileURLToPath(import.meta.url));
const read = (...paths) => readFileSync(pjoin(_dirname, ...paths));

console.log('# wasm circom v2');
(async () => {
  const input = { a: '33', b: '34' };
  // 1. setup
  const coders = zkpWitness.getCoders(bn254.fields.Fr);
  const setupWasm = zkp.bn254.groth.setup(
    coders.getCircuitInfo(read('output', 'sum_test.r1cs'))
  );
  // 2.1: generate witness
  // NOTE: circom generates zero-deps witness calculator from wasm.
  // In theory we can do small wasm runtime for it, but it depends on compiler version and can change!
  const c = await calc(read('output', 'sum_test_js', 'sum_test.wasm'));
  const binWitness = await c.calculateBinWitness(input, true);
  const wtns = await c.calculateWTNSBin(input, true);
  const witness0 = coders.binWitness.decode(binWitness);
  const witness1 = coders.WTNS.decode(wtns).sections[1].data; // Or using WTNS circom format
  deepStrictEqual(witness0, witness1);
  // 2.2: generate proof
  console.log('creating proof');
  const proofWasm = await zkp.bn254.groth.createProof(setupWasm.pkey, witness0);
  console.log('created proof', proofWasm);
  // 3: validate proof
  console.log('verifying proof');
  deepStrictEqual(
    zkp.bn254.groth.verifyProof(setupWasm.vkey, proofWasm),
    true
  );
})();
