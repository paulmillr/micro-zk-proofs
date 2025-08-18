import { bn254 } from '@noble/curves/bn254.js';
import { keccakprg } from '@noble/hashes/sha3-addons.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import * as zkp from '../index.js';
import { stringBigints } from '../index.js';
import { generateWitness } from '../witness.js';
import setupRandomTest from './vectors/setup_random.json' with { type: 'json' };
import setupStaticTest from './vectors/setup_static.json' with { type: 'json' };
import circuitSum from './vectors/sum-circuit.json' with { type: 'json' };
import { utf8ToBytes } from '@noble/hashes/utils.js';

const prg = (seed) => {
  const p = keccakprg();
  p.addEntropy(utf8ToBytes(seed));
  const randomBytes = (len) => p.randomBytes(len);
  return randomBytes;
};

const groth16 = zkp.buildSnark(bn254, { unsafePreserveToxic: true }).groth;

describe('noble', () => {
  describe('bn254', () => {
    describe('groth16', () => {
      should('basic', async () => {
        const randomBytes = (len) => new Uint8Array(len).fill(1);
        const setup = groth16.setup(circuitSum, randomBytes);
        deepStrictEqual(
          JSON.stringify(stringBigints.encode(setup)),
          JSON.stringify(setupStaticTest)
        );
        const val = 454086624460063511464984254936031011189294057512315937409637584344757371137n;
        deepStrictEqual(setup.toxic, {
          t: val,
          kalfa: val,
          kbeta: val,
          kgamma: val,
          kdelta: val,
        });
        const witness = generateWitness(circuitSum)({ a: '33', b: '34' });
        // prettier-ignore
        deepStrictEqual(witness, stringBigints.decode(["1","67","34","33","1","0","0","0","0","1","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","1","0","0","0","1","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","1","1","0","0","0","0","1","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]));

        const { proof, publicSignals } = await groth16.createProof(
          setup.pkey,
          witness,
          randomBytes
        );
        deepStrictEqual(proof, {
          pi_a: [
            3285035260889746104269284885820959442939907139548638959681943825690516278084n,
            2648855993656388559870646626249292876382348938139221541891130660154575844129n,
            1n,
          ],
          pi_b: [
            [
              2884204507407545728585046607224796787171398942257281444495943819562788725171n,
              7348364896924769428895483116243070710467194897401429504770182973984372916499n,
            ],
            [
              14676251046053368433988358093582281063969472597337985366682989541917672422486n,
              927598236072292312839274706827882937289295505812680507424758151344165459291n,
            ],
            [1n, 0n],
          ],
          pi_c: [
            1185032209584230159114824061889183767799331180319151045756468713254194095245n,
            21836773498038157726269317010434915919598895376705098659117058907794803649352n,
            1n,
          ],
          protocol: 'groth',
        });
        deepStrictEqual(publicSignals, [67n, 34n]);
        const { proof: proof2, publicSignals: publicSignals2 } = await groth16.createProof(
          setup.pkey,
          witness,
          randomBytes
        );
        deepStrictEqual(proof2, proof);
        deepStrictEqual(publicSignals2, publicSignals);
        deepStrictEqual(groth16.verifyProof(setup.vkey, { proof, publicSignals }), true);
      });
      should('rng', async () => {
        const randomBytes = prg('groth16');
        const setup = groth16.setup(circuitSum, randomBytes);
        deepStrictEqual(
          JSON.stringify(stringBigints.encode(setup)),
          JSON.stringify(setupRandomTest)
        );
        const witness = generateWitness(circuitSum)({ a: '33', b: '34' });
        const proof = await groth16.createProof(setup.pkey, witness, randomBytes);
        deepStrictEqual(groth16.verifyProof(setup.vkey, proof), true);
      });
    });
  });
});
should.runWhen(import.meta.url);
