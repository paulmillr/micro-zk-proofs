import * as zkp from 'micro-zk-proofs';
import { deepStrictEqual } from 'node:assert';

import { readFileSync } from 'node:fs';
import { dirname, join as pjoin } from 'node:path';
import { fileURLToPath } from 'node:url';
const _dirname = dirname(fileURLToPath(import.meta.url));
const read = (...paths) => readFileSync(pjoin(_dirname, ...paths));

console.log('# wasm circom v1');
(async () => {
  const bigjson = (path) => zkp.stringBigints.decode(
    JSON.parse(read('wasmsnark', 'example', 'bn128', path))
  );
  const pkey = bigjson('proving_key.json');
  const vkey = bigjson('verification_key.json');
  const witness = bigjson('witness.json');
  const oldProof = bigjson('proof.json');
  const oldProofGood = bigjson('proof_good.json');
  const oldProofGood0 = bigjson('proof_good0.json');
  const oldPublic = bigjson('public.json');
  // Generate proofs
  console.log('creating proof');
  const proofNew = await zkp.bn254.groth.createProof(pkey, witness);
  console.log('created proof', proofNew);
  console.log('verifying proof');
  deepStrictEqual(
    zkp.bn254.groth.verifyProof(vkey, proofNew),
    true
  );
  const { publicSignals } = proofNew;
  // Verify proofs
  console.log('verifying proof 2');
  deepStrictEqual(zkp.bn254.groth.verifyProof(vkey, { proof: oldProof, publicSignals }), true);
  console.log('verifying proof 3');
  deepStrictEqual(zkp.bn254.groth.verifyProof(vkey, { proof: oldProofGood, publicSignals }), true);
  console.log('verifying proof 4');
  deepStrictEqual(zkp.bn254.groth.verifyProof(vkey, { proof: oldProofGood0, publicSignals }), true);
  console.log('all proofs were correct')
})();