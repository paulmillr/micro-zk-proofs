/**
 * MiMC: Efficient Encryption and Cryptographic
 * Hashing with Minimal Multiplicative Complexity.
 * {@link https://eprint.iacr.org/2016/492.pdf}
 * {@link https://crypto.ethereum.org/bounties/mimc-hash-challenge}
 * @module
 */

import { bn254 } from '@noble/curves/bn254.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';

const Fr = bn254.fields.Fr;
const SEED = 'mimcsponge';
const NROUNDS = 220;

/**
 * Derives the MiMC sponge IV from the seed.
 * @param seed - Seed string used for derivation.
 * @returns Field element used as the initial vector.
 * @example
 * Derive the default MiMC IV, or pass your own seed for compatibility tests.
 * ```ts
 * const iv = getIV('mimcsponge');
 * ```
 */
export function getIV(seed: string = SEED): bigint {
  return Fr.create(Fr.fromBytes(keccak_256(utf8ToBytes(`${seed}_iv`)), true));
}

/**
 * Derives the MiMC round constants from the seed.
 * @param seed - Seed string used for derivation.
 * @param nRounds - Number of MiMC rounds to generate.
 * @returns Round constant list.
 * @example
 * Rebuild a short constant table for test vectors or compatibility checks.
 * ```ts
 * const constants = getConstants('mimcsponge', 4);
 * ```
 */
export function getConstants(seed: string = SEED, nRounds: number = NROUNDS): bigint[] {
  const cts = [BigInt(0)];
  let c = keccak_256(utf8ToBytes(seed));
  for (let i = 0; i < nRounds - 2; i++)
    cts.push(Fr.create(Fr.fromBytes((c = keccak_256(c)), true)));
  cts.push(BigInt(0));
  return cts;
}
const CONSTANTS = /* @__PURE__ */ getConstants(SEED, NROUNDS);

/**
 * Runs one MiMC sponge hash round sequence.
 * @param L - Left input lane.
 * @param R - Right input lane.
 * @param k - Key value.
 * @returns Updated left and right lanes.
 * @example
 * Run one MiMC round sequence on two field elements with an optional key.
 * ```ts
 * const round = hash(1n, 2n, 0n);
 * round.xL;
 * ```
 */
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

/**
 * Hashes one or more field elements with the MiMC sponge.
 * @param lst - Input field elements.
 * @param key - Optional key value.
 * @param numOutputs - Number of outputs to squeeze.
 * @returns One field element or an array of field elements.
 * @example
 * Hash one or more field elements and optionally squeeze multiple outputs.
 * ```ts
 * const out = multiHash([1n, 2n], 0n, 2);
 * ```
 */
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
