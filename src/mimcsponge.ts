import { keccak_256 } from '@noble/hashes/sha3';
import { bn254 } from '@noble/curves/bn254';

const Fr = bn254.fields.Fr;
const SEED = 'mimcsponge';
const NROUNDS = 220;

export function getIV(seed: string = SEED): bigint {
  return Fr.create(Fr.fromBytes(keccak_256(`${seed}_iv`)));
}

export function getConstants(seed: string = SEED, nRounds: number = NROUNDS): bigint[] {
  const cts = [BigInt(0)];
  let c = keccak_256(seed);
  for (let i = 0; i < nRounds - 2; i++) cts.push(Fr.create(Fr.fromBytes((c = keccak_256(c)))));
  cts.push(BigInt(0));
  return cts;
}
const CONSTANTS = getConstants(SEED, NROUNDS);

export function hash(L: bigint, R: bigint, k: bigint): { xL: bigint; xR: bigint } {
  for (let i = 0; i < NROUNDS; i++) {
    const t = i == 0 ? Fr.addN(L, k) : Fr.addN(Fr.addN(L, k), CONSTANTS[i]);
    const tmp = Fr.addN(R, Fr.pow(t, BigInt(5)));
    if (i < NROUNDS - 1) {
      R = L;
      L = tmp;
    } else R = tmp;
  }
  return { xL: Fr.create(L), xR: Fr.create(R) };
}

export function multiHash(lst: bigint[], key: bigint = Fr.ZERO, numOutputs = 1): bigint | bigint[] {
  let R = Fr.ZERO;
  let C = Fr.ZERO;
  for (let i = 0; i < lst.length; i++)
    ({ xL: R, xR: C } = hash(Fr.addN(R, BigInt(lst[i])), C, key));
  const out = [R];
  for (let i = 1; i < numOutputs; i++, out.push(R)) ({ xL: R, xR: C } = hash(R, C, key));
  const res = out.map((x) => Fr.create(x));
  return numOutputs === 1 ? res[0] : res;
}
