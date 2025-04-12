import { bn254 as nobleBn254 } from '@noble/curves/bn254';
// import { bls12_381 as nobleBls12 } from '@noble/curves/bls12-381';
import { randomBytes } from '@noble/hashes/utils';
import { bytesToNumberBE } from '@noble/curves/abstract/utils';
import { type CurveFn as BLSCurveFn } from '@noble/curves/abstract/bls';
import type { Fp2 } from '@noble/curves/abstract/tower';
import type { ProjConstructor, ProjPointType } from '@noble/curves/abstract/weierstrass';
import type { MSMInput } from './msm-worker.ts';
import { modifyArgs } from './msm.js';

// It is hard to make groth16 async / fast, because MSM perf is
// non-linear (2048 => 1024 points is not 2x faster).
// It also depends on hamming weight (amount of zeros) on scalars.
// Workers may not significantly increase performance on small circuits.
// Check out 'msm.ts' for web workers.

// Utils
export interface Coder<F, T> {
  encode(from: F): T;
  decode(to: T): F;
}
type RandFn = (len: number) => Uint8Array;

function log2(n: number) {
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error('Input must be a safe positive integer');
  return 31 - Math.clz32(n);
}

// Basic utility to deep convert bigints to strings and back
function deepConvert(o: any, mapper: (o: any) => any): any {
  const t = mapper(o);
  if (t !== undefined) return t;
  if (o === null) return o as any;
  if (Array.isArray(o)) return o.map((i) => deepConvert(i, mapper)) as any;
  if (typeof o == 'object') {
    return Object.fromEntries(
      Object.entries(o).map(([k, v]) => [k, deepConvert(v, mapper)])
    ) as any;
  }
  return o as any;
}
// TODO: should be something like 'Deep' type here?
// prettier-ignore
export type BigintToString<T> =
  T extends bigint ? `${T}` :
  T extends Array<infer U> ? Array<BigintToString<U>> :
  T extends null ? null :
  T extends object ? { [K in keyof T]: BigintToString<T[K]> } :
  T;

// prettier-ignore
export type StringToBigint<T> =
  T extends `${bigint}` ? bigint :
  T extends Array<infer U> ? Array<StringToBigint<U>> :
  T extends null ? null :
  T extends object ? { [K in keyof T]: StringToBigint<T[K]> } :
  T;
export const stringBigints = {
  encode<F>(o: F): BigintToString<F> {
    return deepConvert(o, (o) =>
      typeof o === 'bigint' ? o.toString(10) : undefined
    ) as BigintToString<F>;
  },
  decode<T>(o: T): StringToBigint<T> {
    return deepConvert(o, (o) =>
      typeof o == 'string' && /^[0-9]+$/.test(o) ? BigInt(o) : undefined
    ) as StringToBigint<T>;
  },
};

function pointCoder<T, F>(
  cons: ProjConstructor<T>,
  coder: Coder<T, F>
): Coder<ProjPointType<T>, [F, F, F]> {
  return {
    encode: (p): [F, F, F] => {
      const { px, py, pz } = cons.fromAffine(p.toAffine());
      return [px, py, pz].map(coder.encode) as [F, F, F];
    },
    decode: (p) => {
      if (!p) return cons.ZERO; // sometimes can be null?
      const [x, y, z] = p.map(coder.decode);
      // TODO: validation increases time 3x
      // res.assertValidity();
      return new cons(x, y, z);
    },
  };
}

export type Constraint = Record<number, bigint>;
export type CircuitInfo = {
  nVars: number;
  nPubInputs: number;
  nOutputs: number;
  constraints: [Constraint, Constraint, Constraint][]; // [A, B, C]
};
export type G1Point = [bigint, bigint, bigint];
export type G2Point = [[bigint, bigint], [bigint, bigint], [bigint, bigint]];
export interface PointsWithCoders {
  G1: ProjConstructor<bigint>;
  G2: ProjConstructor<Fp2>;
  G1c: Coder<ProjPointType<bigint>, G1Point>;
  G2c: Coder<ProjPointType<Fp2>, G2Point>;
}
export type VkProver = {
  protocol?: 'groth';
  nVars: number;
  nPublic: number;
  domainBits: number;
  domainSize: number;
  // Polynominals
  polsA: Constraint[];
  polsB: Constraint[];
  polsC: Constraint[];
  //
  A: G1Point[];
  B1: G1Point[];
  B2: G2Point[];
  C: G1Point[];
  //
  vk_alfa_1: G1Point;
  vk_beta_1: G1Point;
  vk_delta_1: G1Point;
  vk_beta_2: G2Point;
  vk_delta_2: G2Point;
  //
  hExps: G1Point[];
};

export type VkVerifier = {
  protocol?: 'groth';
  nPublic: number;
  IC: G1Point[];
  //
  vk_alfa_1: G1Point;
  vk_beta_2: G2Point;
  vk_gamma_2: G2Point;
  vk_delta_2: G2Point;
};

export type GrothProof = {
  protocol: 'groth';
  pi_a: G1Point;
  pi_b: G2Point;
  pi_c: G1Point;
};

/**
 * nqr: Override NonQuadratic Residue
 * unsafePreserveToxic: Output toxic values for tests
 */
export type GrothOpts = {
  nqr?: number | bigint; //
  unsafePreserveToxic?: boolean;
  G1msm?: (input: MSMInput<bigint>[]) => Promise<ProjPointType<bigint>>;
  G2msm?: (input: MSMInput<Fp2>[]) => Promise<ProjPointType<Fp2>>;
};

export interface ToxicWaste {
  t: bigint;
  kalfa: bigint;
  kbeta: bigint;
  kgamma: bigint;
  kdelta: bigint;
}

export interface ProofWithSignals {
  proof: GrothProof;
  publicSignals: bigint[];
}

export interface SnarkConstructorOutput {
  utils: PointsWithCoders;
  groth: {
    setup(
      circuit: CircuitInfo,
      rnd?: RandFn
    ): {
      pkey: VkProver;
      vkey: VkVerifier;
      toxic: ToxicWaste | undefined;
    };
    createProof(
      pkey: VkProver,
      witness: bigint[],
      rnd?: RandFn
    ): Promise<ProofWithSignals>;
    verifyProof(vkey: VkVerifier, proofWithSignals: ProofWithSignals): boolean;
  };
}

export function buildSnark(curve: BLSCurveFn, opts: GrothOpts = {}): SnarkConstructorOutput {
  // Utils
  const G1 = curve.G1.ProjectivePoint;
  const G2 = curve.G2.ProjectivePoint;
  const { Fr, Fp, Fp2, Fp12 } = curve.fields;
  const Fpc: Coder<bigint, bigint> = {
    encode: (from) => from,
    decode: (to) => Fp.create(to),
  };
  const Fp2c: Coder<Fp2, [bigint, bigint]> = {
    encode: (from) => [from.c0, from.c1],
    decode: (to) => Fp2.create({ c0: Fp.create(to[0]), c1: Fp.create(to[1]) }),
  };
  const G1c = pointCoder(G1, Fpc);
  const G2c = pointCoder(G2, Fp2c);

  const G1msm = !opts.G1msm ? G1.msm : modifyArgs(Fr, G1, opts.G1msm);
  const G2msm = !opts.G2msm ? G2.msm : modifyArgs(Fr, G2, opts.G2msm);

  const Frandom = (rnd: RandFn = randomBytes) => {
    return bytesToNumberBE(rnd(Fr.BYTES));
  };
  // Factor Fr.ORDER-1 as oddFactor * 2^powerOfTwo
  let oddFactor = Fr.ORDER - BigInt(1);
  let powerOfTwo = 0;
  for (; (oddFactor & BigInt(1)) !== BigInt(1); powerOfTwo++, oddFactor >>= 1n);
  // Find non quadratic residue
  let NQR;
  if (opts.nqr) NQR = BigInt(opts.nqr);
  else for (NQR = 2n; Fr.eql(Fr.pow(NQR, Fr.ORDER >> 1n), Fr.ONE); NQR++);
  // Primitive roots of unity
  const rootsOfUnity = [Fr.pow(NQR, oddFactor)];
  for (let i = 0; i < powerOfTwo; i++) rootsOfUnity.push(Fr.sqr(rootsOfUnity[i]));
  rootsOfUnity.reverse();
  // Compute all roots of unity for powers up to maxPower
  const rootsCache: bigint[][] = [];
  const precomputeRoots = (maxPower: number) => {
    for (let power = maxPower; power >= 0; power--) {
      if (rootsCache[power]) continue; // Skip if we've already computed roots for this power
      const rootsAtPower: bigint[] = (rootsCache[power] = []);
      for (let j = 0, cur = Fr.ONE; j < 1 << power; j++, cur = Fr.mul(cur, rootsOfUnity[power]))
        rootsAtPower.push(cur);
    }
  };

  const poly = {
    reduce(p: bigint[]) {
      while (p.length > 0 && Fr.is0(p[p.length - 1])) p.pop();
      return p;
    },
    sub(a: bigint[], b: bigint[]) {
      const res = [];
      for (let i = 0; i < Math.max(a.length, b.length); i++)
        res.push(Fr.sub(a[i] || Fr.ZERO, b[i] || Fr.ZERO));
      return poly.reduce(res);
    },
    // Iterative Cooley-Tukey FFT
    fft(p: bigint[], bits: number): bigint[] {
      const n = 1 << bits;
      while (p.length < n) p.push(Fr.ZERO);
      const out = new Array<bigint>(n);
      // Bit-reversal permutation: reorder input array into 'out'
      for (let i = 0; i < n; i++) {
        let rev = 0;
        for (let j = 0; j < bits; j++) rev = (rev << 1) | ((i >> j) & 1);
        out[rev] = p[i];
      }
      // For each stage s (sub-FFT length m = 2^s)
      for (let s = 1; s <= bits; s++) {
        const m = 1 << s;
        const m2 = m >> 1;
        // Loop over each subarray of length m
        for (let k = 0; k < n; k += m) {
          // Loop over each butterfly within the subarray
          for (let j = 0; j < m2; j++) {
            // Multiply the lower half by the appropriate twiddle factor.
            const t = Fr.mul(rootsCache[s][j], out[k + j + m2]);
            const u = out[k + j];
            // Combine to form the butterfly outputs.
            out[k + j] = Fr.add(u, t);
            out[k + j + m2] = Fr.sub(u, t);
          }
        }
      }
      return out;
    },
    // Inverse FFT.
    ifft(p: bigint[]) {
      if (p.length <= 1) return p;
      const bits = log2(p.length - 1) + 1;
      precomputeRoots(bits);
      const invm = Fr.inv(Fr.create(BigInt(1 << bits)));
      const res = poly.fft(p, bits);
      for (let i = 0; i < res.length; i++) res[i] = Fr.mul(res[i], invm);
      return [res[0]].concat(res.slice(1).reverse());
    },
    // Polynomial multiplication via FFT.
    mul(a: bigint[], b: bigint[]) {
      if (a.length !== b.length || a.length < 2) throw new Error('wrong polynominal length');
      // We compute bits = log2(longestN - 1) + 2 to ensure enough room for convolution,
      // since the product of two degree-(n-1) polynomials can have degree up to 2n-2.
      const bits = log2(Math.max(a.length, b.length) - 1) + 2;
      precomputeRoots(bits);
      const a2 = poly.fft(a, bits);
      const b2 = poly.fft(b, bits);
      for (let i = 0; i < a2.length; i++) a2[i] = Fr.mul(a2[i], b2[i]);
      return poly.reduce(poly.ifft(a2));
    },
    // Evaluate the Lagrange basis polynomials at a point t over the FFT domain of size m = 2^bits.
    // If t is one of the m-th roots of unity, returns the Kronecker delta vector.
    // Otherwise, computes L_i(t) = ((t^m - 1)/m) * (ω_i/(t - ω_i)),
    // where ω_i = rootsCache[bits][i] (the i-th m-th root of unity).
    evaluateLagrangePolynomials(bits: number, t: bigint): bigint[] {
      const m = 1 << bits;
      const tm = Fr.pow(t, BigInt(m));
      const u = new Array(m).fill(Fr.ZERO);
      precomputeRoots(bits);
      // Special case: if t is one of the roots of unity, the Lagrange basis is a Kronecker delta.
      for (let i = 0; i < m; i++) {
        if (Fr.eql(t, rootsCache[bits][i])) {
          u.fill(Fr.ZERO);
          u[i] = Fr.ONE;
          return u;
        }
      }
      const omega = rootsOfUnity[bits];
      let l = Fr.mul(Fr.sub(tm, Fr.ONE), Fr.inv(BigInt(m)));
      for (let i = 0; i < m; i++) {
        u[i] = Fr.mul(l, Fr.inv(Fr.sub(t, rootsCache[bits][i])));
        l = Fr.mul(l, omega);
      }
      return u;
    },
    sumABC(
      size: number,
      weights: bigint[],
      A: Constraint[],
      B: Constraint[],
      C: Constraint[],
      transpose = false
    ) {
      function build(constraints: Constraint[]) {
        const res = new Array(size).fill(Fr.ZERO);
        for (let s = 0; s < weights.length; s++) {
          for (let c in constraints[s]) {
            const idx = transpose ? s : +c;
            res[idx] = Fr.add(
              res[idx],
              Fr.mul(transpose ? weights[+c] : weights[s], constraints[s][c])
            );
          }
        }
        return res;
      }
      return { pA: build(A), pB: build(B), pC: build(C) };
    },
  };

  function calculateH(proof: VkProver, witness: bigint[]) {
    const m = proof.domainSize;
    const { pA, pB, pC } = poly.sumABC(m, witness, proof.polsA, proof.polsB, proof.polsC);
    // FFT only needed to optimize multiplication O(n²) to O(n log n)
    // pA * pB - pC
    return poly.sub(poly.mul(poly.ifft(pA), poly.ifft(pB)), poly.ifft(pC)).slice(m);
  }
  const utils = { G1, G2, G1c, G2c } satisfies PointsWithCoders;
  // TODO: add other proofs, which re-use many polynomial operations
  // * We don't export alfabeta_12! It is only used for optimization, and is specific to
  //   pairing implementation (different values after final exponentiation).
  // * We accept raw circuit json here, no need for Circuit object!
  return {
    utils: utils,
    groth: {
      setup(circuit: CircuitInfo, rnd: RandFn = randomBytes) {
        // Sizes
        const nConstraints = circuit.constraints.length;
        const domainBits = log2(nConstraints + circuit.nPubInputs + circuit.nOutputs + 1 - 1) + 1;
        const domainSize = 1 << domainBits;
        const nPublic = circuit.nPubInputs + circuit.nOutputs;
        const maxH = domainSize + 1;
        // Toxic
        const toxic = {
          t: Frandom(rnd),
          kalfa: Frandom(rnd),
          kbeta: Frandom(rnd),
          kgamma: Frandom(rnd),
          kdelta: Frandom(rnd),
        };
        // G1
        const alfaP1 = G1c.encode(G1.BASE.multiplyUnsafe(Fr.create(toxic.kalfa)));
        const betaP1 = G1c.encode(G1.BASE.multiplyUnsafe(Fr.create(toxic.kbeta)));
        const deltaP1 = G1c.encode(G1.BASE.multiplyUnsafe(Fr.create(toxic.kdelta)));
        // G2
        const betaP2 = G2c.encode(G2.BASE.multiplyUnsafe(Fr.create(toxic.kbeta)));
        const deltaP2 = G2c.encode(G2.BASE.multiplyUnsafe(Fr.create(toxic.kdelta)));
        const gammaP2 = G2c.encode(G2.BASE.multiplyUnsafe(Fr.create(toxic.kgamma)));
        // Pols
        const pols: Constraint[][] = [0, 1, 2].map((side) =>
          Array.from({ length: circuit.nVars }, (_, s) =>
            Object.fromEntries(
              circuit.constraints
                .map((constraint, c) => [c, constraint[side]?.[s]])
                .filter(([, v]) => v !== undefined)
                .map(([c, v]) => [c, BigInt(v)])
            )
          )
        );
        const [polsA, polsB, polsC] = pols;
        for (let i = 0; i < circuit.nPubInputs + circuit.nOutputs + 1; i++)
          polsA[i][nConstraints + i] = Fr.ONE;
        // Evaluate
        const zt = Fr.sub(Fr.pow(toxic.t, BigInt(1 << domainBits)), Fr.ONE);
        const u = poly.evaluateLagrangePolynomials(domainBits, toxic.t);
        const { pA, pB, pC } = poly.sumABC(circuit.nVars, u, polsA, polsB, polsC, true);
        // C
        const C = new Array(circuit.nVars);
        const invDelta = Fr.inv(toxic.kdelta);
        for (let s = nPublic + 1; s < circuit.nVars; s++) {
          C[s] = G1c.encode(
            G1.BASE.multiplyUnsafe(
              Fr.mul(
                invDelta,
                Fr.add(Fr.add(Fr.mul(pA[s], toxic.kbeta), Fr.mul(pB[s], toxic.kalfa)), pC[s])
              )
            )
          );
        }
        // IC
        const IC = [];
        const invGamma = Fr.inv(toxic.kgamma);
        for (let s = 0; s <= nPublic; s++) {
          IC.push(
            G1c.encode(
              G1.BASE.multiplyUnsafe(
                Fr.mul(
                  invGamma,
                  Fr.add(Fr.add(Fr.mul(pA[s], toxic.kbeta), Fr.mul(pB[s], toxic.kalfa)), pC[s])
                )
              )
            )
          );
        }
        // hExps
        const zod = Fr.mul(invDelta, zt);
        const hExps = [G1c.encode(G1.BASE.multiplyUnsafe(zod))];
        for (let i = 1, eT = toxic.t; i < maxH; i++, eT = Fr.mul(eT, toxic.t))
          hExps.push(G1c.encode(G1.BASE.multiplyUnsafe(Fr.mul(eT, zod))));

        const vk_proof: VkProver = {
          protocol: 'groth',
          nVars: circuit.nVars,
          nPublic,
          domainBits,
          domainSize,
          // Polynominals
          polsA,
          polsB,
          polsC,
          //
          A: Array.from({ length: circuit.nVars }, (_, j) => G1.BASE.multiplyUnsafe(pA[j])).map(
            G1c.encode
          ),
          B1: Array.from({ length: circuit.nVars }, (_, j) => G1.BASE.multiplyUnsafe(pB[j])).map(
            G1c.encode
          ),
          B2: Array.from({ length: circuit.nVars }, (_, j) => G2.BASE.multiplyUnsafe(pB[j])).map(
            G2c.encode
          ),
          C,
          //
          vk_alfa_1: alfaP1,
          vk_beta_1: betaP1,
          vk_delta_1: deltaP1,
          vk_beta_2: betaP2,
          vk_delta_2: deltaP2,
          //
          hExps,
        };
        const vk_verifier: VkVerifier = {
          protocol: 'groth',
          nPublic: circuit.nPubInputs + circuit.nOutputs,
          IC,
          //
          vk_alfa_1: alfaP1,
          vk_beta_2: betaP2,
          vk_gamma_2: gammaP2,
          vk_delta_2: deltaP2,
        };
        return {
          pkey: vk_proof,
          vkey: vk_verifier,
          toxic: opts.unsafePreserveToxic ? toxic : undefined,
        };
      },
      async createProof(
        pkey: VkProver,
        witness: bigint[],
        rnd: RandFn = randomBytes
      ): Promise<ProofWithSignals> {
        witness = witness.map(Fr.create);
        // Blinding salt for zero-knowledge
        const r = Fr.create(Frandom(rnd));
        const s = Fr.create(Frandom(rnd));
        const A = pkey.A.map(G1c.decode);
        const B1 = pkey.B1.map(G1c.decode);
        const B2 = pkey.B2.map(G2c.decode);
        const C = pkey.C.map(G1c.decode);
        const hExps = pkey.hExps.map(G1c.decode);
        const vk_alfa_1 = G1c.decode(pkey.vk_alfa_1);
        const vk_beta_1 = G1c.decode(pkey.vk_beta_1);
        const vk_beta_2 = G2c.decode(pkey.vk_beta_2);
        const vk_delta_1 = G1c.decode(pkey.vk_delta_1);
        const vk_delta_2 = G2c.decode(pkey.vk_delta_2);
        // Actual algorithm
        // pi_a = WITNESS_A + delta1*r
        const pi_a_msm = await G1msm(A, witness);
        const pi_a = pi_a_msm.add(vk_alfa_1).add(vk_delta_1.multiplyUnsafe(r));
        // pi_b = WITNESS_B + delta2*s
        const pi_b_msm = await G2msm(B2, witness);
        const pi_b = pi_b_msm.add(vk_beta_2).add(vk_delta_2.multiplyUnsafe(s));
        const pib1n_msm = await G1msm(B1, witness);
        const pib1n = pib1n_msm.add(vk_beta_1).add(vk_delta_1.multiplyUnsafe(s));
        const cOffset = pkey.nPublic + 1;
        const h = calculateH(pkey, witness).map(Fr.create);
        //WITNESS3 + pi_a * s + WITNESS4 * r
        const pi_c_msm = await G1msm(
          C.slice(cOffset).concat(hExps.slice(0, h.length)),
          witness.slice(cOffset).concat(h)
        );
        const pi_c = pi_c_msm
          .add(pi_a.multiplyUnsafe(s))
          .add(pib1n.multiplyUnsafe(r))
          .add(vk_delta_1.multiplyUnsafe(Fr.create(Fr.neg(Fr.mul(r, s)))));
        return {
          proof: {
            protocol: 'groth',
            pi_a: G1c.encode(pi_a),
            pi_b: G2c.encode(pi_b),
            pi_c: G1c.encode(pi_c),
          },
          publicSignals: witness.slice(1, pkey.nPublic + 1),
        };
      },
      verifyProof(vkey: VkVerifier, proofWithSignals: ProofWithSignals): boolean {
        const { proof, publicSignals } = proofWithSignals;
        const cpub = G1.msm(vkey.IC.map(G1c.decode), [1n, ...publicSignals]);
        // old e(pi_a, pi_b) = alfa_beta * e(cpub, gamma_2) * e(pi_c, delta_2)
        // new: e(-pi_a, pi_b) * e(cpub, gamma_2) * e(pi_c, delta_2) * e(alfa_1, beta_2) = 1
        // Major difference: old version uses pre-computed alfa_beta,
        // but this makes it incompatible with noble, because we use cyclomatic exp
        // (Fp12 values different even if math is same).
        const newRes = curve.pairingBatch([
          { g1: G1c.decode(proof.pi_a).negate(), g2: G2c.decode(proof.pi_b) },
          { g1: cpub, g2: G2c.decode(vkey.vk_gamma_2) },
          { g1: G1c.decode(proof.pi_c), g2: G2c.decode(vkey.vk_delta_2) },
          { g1: G1c.decode(vkey.vk_alfa_1), g2: G2c.decode(vkey.vk_beta_2) },
        ]);
        return Fp12.eql(newRes, Fp12.ONE);
      },
    },
  };
}

export const bn254: SnarkConstructorOutput = buildSnark(nobleBn254, {});
// NOTE: this is unsafe and may not work (untested for now)
//export const bls12_381 = buildSnark(nobleBls12, {});
