import { bn254 } from '@noble/curves/bn254';
import * as zkp from 'micro-zk-proofs';
import * as zkpMsm from 'micro-zk-proofs/msm.js';
import * as zkpWitness from 'micro-zk-proofs/witness.js';
import { deepStrictEqual } from 'node:assert';
import sumCircuit from './sum-circuit.json' with { "type": "json" };

const input = { a: '33', b: '34' };
// 2. setup
const setupJs = zkp.bn254.groth.setup(sumCircuit);
// Generate using circom_old circuit
// NOTE: we have this small util to remove dependencies on snarkjs for witness generation
// 3. generate witness
const witnessJs = zkpWitness.generateWitness(sumCircuit)(input);
//deepStrictEqual(witness0, witnessJs); // -> will fail, because we have different constrains!
// 4. create proof
const proofJs = await zkp.bn254.groth.createProof(setupJs.pkey, witnessJs);
console.log('proof created, signals:', proofJs.publicSignals)
// 4. verify proof
deepStrictEqual(
  zkp.bn254.groth.verifyProof(setupJs.vkey, proofJs),
  true
);
console.log('proof is valid');

// Fast, parallel proofs
(async () => {
  console.log('testing fast parallel proofs, using web workers');
  // bonus: use workers for performance
  const msm = zkpMsm.initMSM();
  const groth16 = zkp.buildSnark(bn254, {
    G1msm: msm.methods.bn254_msmG1,
    G2msm: msm.methods.bn254_msmG2,
  }).groth;
  // 2.2: generate proof
  const proofJs2 = await groth16.createProof(setupJs.pkey, witnessJs);
  console.log('proof created, signals:', proofJs2.publicSignals)
  // 3: validate proof
  deepStrictEqual(
    groth16.verifyProof(setupJs.vkey, proofJs2),
    true
  );
  console.log('proof is valid');
  msm.terminate();
})();