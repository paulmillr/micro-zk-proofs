import { bls12_381 } from '@noble/curves/bls12-381.js';
import { bn254 } from '@noble/curves/bn254.js';
import { keccakprg } from '@noble/hashes/sha3-addons.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, rejects, throws } from 'node:assert';
import * as zkp from '../index.js';
import { stringBigints } from '../index.js';
import { generateWitness } from '../witness.js';
import setupRandomTest from './vectors/setup_random.json' with { type: 'json' };
import setupStaticTest from './vectors/setup_static.json' with { type: 'json' };
import circuitSum from './vectors/sum-circuit.json' with { type: 'json' };

const prg = (seed) => {
  const p = keccakprg();
  p.addEntropy(utf8ToBytes(seed));
  const randomBytes = (len) => p.randomBytes(len);
  return randomBytes;
};

const groth16 = zkp.buildSnark(bn254, { unsafePreserveToxic: true }).groth;
const smallCircuit = { nVars: 2, nPubInputs: 0, nOutputs: 0, constraints: [[{}, {}, {}]] };

describe('noble', () => {
  describe('bn254', () => {
    describe('groth16', () => {
      it('basic', async () => {
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
        const witness = generateWitness(circuitSum, { unsafeAllowJsEvalCircuit: true })({
          a: '33',
          b: '34',
        });
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
      it('rejects non-canonical and malformed proofs without throwing', async () => {
        const randomBytes = (len) => new Uint8Array(len).fill(1);
        const setup = groth16.setup(circuitSum, randomBytes);
        const witness = generateWitness(circuitSum, { unsafeAllowJsEvalCircuit: true })({
          a: '33',
          b: '34',
        });
        const valid = await groth16.createProof(setup.pkey, witness, randomBytes);
        deepStrictEqual(groth16.verifyProof(setup.vkey, valid), true);

        const scaled = structuredClone(valid);
        scaled.proof.pi_a = scaled.proof.pi_a.map(
          (value) => (BigInt(2) * value) % bn254.fields.Fp.ORDER
        );
        deepStrictEqual(groth16.verifyProof(setup.vkey, scaled), false);

        const reduced = structuredClone(valid);
        reduced.proof.pi_a[0] += bn254.fields.Fp.ORDER;
        deepStrictEqual(groth16.verifyProof(setup.vkey, reduced), false);

        for (const pi_a of [[1n, 1n, 1n], valid.proof.pi_a.slice(1), ['1', 1n, 1n]]) {
          const malformed = structuredClone(valid);
          malformed.proof.pi_a = pi_a;
          deepStrictEqual(groth16.verifyProof(setup.vkey, malformed), false);
        }

        const malformedG2 = structuredClone(valid);
        malformedG2.proof.pi_b[0] = [malformedG2.proof.pi_b[0][0]];
        deepStrictEqual(groth16.verifyProof(setup.vkey, malformedG2), false);

        const nonCanonicalSignal = structuredClone(valid);
        nonCanonicalSignal.publicSignals[0] += bn254.fields.Fr.ORDER;
        deepStrictEqual(groth16.verifyProof(setup.vkey, nonCanonicalSignal), false);
        deepStrictEqual(groth16.verifyProof(setup.vkey, null), false);
      });
      it('rng', async () => {
        const randomBytes = prg('groth16');
        const setup = groth16.setup(circuitSum, randomBytes);
        deepStrictEqual(
          JSON.stringify(stringBigints.encode(setup)),
          JSON.stringify(setupRandomTest)
        );
        const witness = generateWitness(circuitSum, { unsafeAllowJsEvalCircuit: true })({
          a: '33',
          b: '34',
        });
        const proof = await groth16.createProof(setup.pkey, witness, randomBytes);
        deepStrictEqual(groth16.verifyProof(setup.vkey, proof), true);
      });
      it('toxic waste', () => {
        const allFF = (len) => new Uint8Array(len).fill(0xff);
        const { toxic } = groth16.setup(smallCircuit, allFF);
        deepStrictEqual(
          Object.fromEntries(Object.entries(toxic).map(([k, v]) => [k, v < bn254.fields.Fr.ORDER])),
          { t: true, kalfa: true, kbeta: true, kgamma: true, kdelta: true }
        );
        const zero = (len) => new Uint8Array(len);
        throws(() => groth16.setup(smallCircuit, zero), /outside the evaluation domain after 128/);
      });
      it('samples toxic t outside the evaluation domain with a bounded retry count', async () => {
        const circuit = {
          nVars: 4,
          nPubInputs: 1,
          nOutputs: 0,
          constraints: [
            [{ 0: 1n }, { 0: 1n }, { 2: 1n }],
            [{ 0: 1n }, { 2: 1n }, { 1: 1n }],
          ],
        };
        let next = 1;
        const sequence = (len) => {
          const out = new Uint8Array(len);
          out[len - 1] = next++;
          return out;
        };
        const { pkey, vkey, toxic } = groth16.setup(circuit, sequence);
        deepStrictEqual(toxic.t, 2n);
        const forged = await groth16.createProof(pkey, [1n, 2n, 1n, 0n], sequence);
        deepStrictEqual(groth16.verifyProof(vkey, forged), false);

        let attempts = 0;
        const stuckInDomain = (len) => {
          attempts++;
          const out = new Uint8Array(len);
          out[len - 1] = 1;
          return out;
        };
        throws(
          () => groth16.setup(circuit, stuckInDomain),
          /outside the evaluation domain after 128 attempts/
        );
        deepStrictEqual(attempts, 128);
      });
      it('domain bounds', async () => {
        const randomBytes = (len) => new Uint8Array(len).fill(1);
        const rootBoundGroth = zkp.buildSnark(bn254, {
          limits: { maxConstraints: 2 ** 30, maxDomainSize: 2 ** 31 },
        }).groth;
        const badCircuit = (len) => ({
          ...circuitSum,
          nVars: 1,
          nPubInputs: 0,
          nOutputs: 0,
          constraints: new Array(len),
        });
        for (const len of [2 ** 28, 2 ** 30])
          throws(
            () => rootBoundGroth.setup(badCircuit(len), randomBytes),
            /expected domainBits <=/
          );
        throws(
          () => groth16.setup(badCircuit(2 ** 16 + 1), randomBytes),
          /constraint count exceeds configured limit/
        );
        throws(
          () => groth16.setup({ ...smallCircuit, nVars: 0xfffffffe }, randomBytes),
          /nVars exceeds configured limit/
        );
        throws(
          () => groth16.setup({ ...smallCircuit, constraints: [[{ 2: 1n }, {}, {}]] }, randomBytes),
          /constraint 0 index out of range/
        );
        const setup = groth16.setup(circuitSum, randomBytes);
        const witness = generateWitness(circuitSum, { unsafeAllowJsEvalCircuit: true })({
          a: '33',
          b: '34',
        });
        await rejects(
          () => groth16.createProof({ ...setup.pkey, domainSize: 2 ** 32 }, witness, randomBytes),
          /expected uint32 positive integer/
        );
      });
      it('validates proving-key dimensions before calculating H', async () => {
        const randomBytes = (len) => new Uint8Array(len).fill(1);
        const setup = groth16.setup(circuitSum, randomBytes);
        const witness = generateWitness(circuitSum, { unsafeAllowJsEvalCircuit: true })({
          a: '33',
          b: '34',
        });
        await rejects(
          () => groth16.createProof({ ...setup.pkey, domainSize: 127 }, witness, randomBytes),
          /domainSize to be a power of two/
        );
        await rejects(
          () => groth16.createProof({ ...setup.pkey, domainBits: 6 }, witness, randomBytes),
          /pkey.domainBits === 7/
        );
        await rejects(
          () => groth16.createProof(setup.pkey, witness.slice(1), randomBytes),
          /witness.length === 101/
        );
        for (const name of ['A', 'B1', 'B2', 'C']) {
          await rejects(
            () =>
              groth16.createProof(
                { ...setup.pkey, [name]: setup.pkey[name].slice(1) },
                witness,
                randomBytes
              ),
            new RegExp(`pkey.${name}\\.length === 101`)
          );
        }
        await rejects(
          () =>
            groth16.createProof(
              { ...setup.pkey, hExps: setup.pkey.hExps.slice(1) },
              witness,
              randomBytes
            ),
          /pkey.hExps.length === 129/
        );
        await rejects(
          () => groth16.createProof({ ...setup.pkey, ccoefs: [] }, witness, randomBytes),
          /exactly one polynomial representation/
        );
        const polsA = setup.pkey.polsA.map((polynomial, index) =>
          index === 0 ? { ...polynomial, [setup.pkey.domainSize]: 1n } : polynomial
        );
        await rejects(
          () => groth16.createProof({ ...setup.pkey, polsA }, witness, randomBytes),
          /proving-key constraint index out of range/
        );
      });
      it('unsupported root capacity', () => {
        throws(() => zkp.buildSnark(bls12_381), /expected roots powerOfTwo <= 30/);
      });
    });
  });
});
it.runWhen(import.meta.url);
