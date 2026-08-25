/*! micro-zk-proofs - MIT License (c) 2025 Paul Miller (paulmillr.com) */
import type { BlsCurvePair as BLSCurvePair } from '@noble/curves/abstract/bls.js';
import { pippenger } from '@noble/curves/abstract/curve.js';
import { FFT, poly as polyCurves, rootsOfUnity } from '@noble/curves/abstract/fft.js';
import type { Fp2 } from '@noble/curves/abstract/tower.js';
import type { WeierstrassPoint, WeierstrassPointCons } from '@noble/curves/abstract/weierstrass.js';
import { bn254 as nobleBn254 } from '@noble/curves/bn254.js';
import { bytesToNumberBE } from '@noble/curves/utils.js';
import { randomBytes } from '@noble/hashes/utils.js';
import type { TArg, TRet } from '@noble/hashes/utils.js';
import { resolveArtifactLimits, type ArtifactLimits } from './artifact-limits.js';
import type { MSMInput } from './msm-worker.ts';
import { modifyArgs } from './msm.ts';

export type { TArg, TRet } from '@noble/hashes/utils.js';
export type { ArtifactLimits } from './artifact-limits.js';

// It is hard to make groth16 async / fast, because MSM perf is
// non-linear (2048 => 1024 points is not 2x faster).
// It also depends on hamming weight (amount of zeros) on scalars.
// Workers may not significantly increase performance on small circuits.
// Check out 'msm.ts' for web workers.

// Utils
/** Bidirectional value coder. */
export interface Coder<F, T> {
  /**
   * Encodes a value into its serialized form.
   * @param from - Value to encode.
   * @returns Encoded representation.
   */
  encode(from: F): T;
  /**
   * Decodes a serialized value back into its native form.
   * @param to - Encoded representation to decode.
   * @returns Decoded value.
   */
  decode(to: T): F;
}
type RandFn = (len: number) => Uint8Array;
const U32_MAX = 0xffffffff;
const MAX_DOMAIN_BITS = 30;
const MAX_TOXIC_T_ATTEMPTS = 128;
const MAX_BIGINT_CONVERSION_DEPTH = 256;
const MIN_BIGINT_CYCLE_CHECK_DEPTH = 32;
const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);

function log2(n: number) {
  // Domain sizes are serialized as U32LE in witness artifacts, and clz32 truncates above uint32.
  if (!Number.isSafeInteger(n) || n <= 0 || n > U32_MAX)
    throw new Error(`expected uint32 positive integer, got ${n}`);
  return 31 - Math.clz32(n);
}

// Basic utility to deep convert bigints to strings and back with bounded call-stack use.
function deepConvert(root: any, mapper: (value: any) => any): any {
  const active: object[] = [];
  const visit = (value: any, depth: number): any => {
    if (depth > MAX_BIGINT_CONVERSION_DEPTH)
      throw new Error(`maximum bigint conversion depth exceeded (${MAX_BIGINT_CONVERSION_DEPTH})`);
    const mapped = mapper(value);
    if (mapped !== undefined) return mapped;
    if (value === null || typeof value !== 'object') return value;
    // Ordinary proof/key JSON is shallow. Delay the ancestor scan until a cycle could otherwise
    // consume meaningful work; the hard depth limit remains an unconditional backstop.
    if (depth >= MIN_BIGINT_CYCLE_CHECK_DEPTH && active.includes(value))
      throw new Error('cyclic bigint conversion value');
    active.push(value);
    const converted = Array.isArray(value)
      ? value.map((item) => visit(item, depth + 1))
      : Object.fromEntries(
          Object.entries(value).map(([key, item]) => [key, visit(item, depth + 1)])
        );
    active.pop();
    return converted;
  };
  return visit(root, 0);
}
// TODO: should be something like 'Deep' type here?
// prettier-ignore
/** Recursively converts bigint leaves into decimal strings. */
export type BigintToString<T> =
  T extends bigint ? `${T}` :
  T extends Array<infer U> ? Array<BigintToString<U>> :
  T extends null ? null :
  T extends object ? { [K in keyof T]: BigintToString<T[K]> } :
  T;

// prettier-ignore
/** Recursively converts decimal-string leaves back into bigint values. */
export type StringToBigint<T> =
  T extends `-${string}` ? T :
  T extends `${bigint}` ? bigint :
  T extends Array<infer U> ? Array<StringToBigint<U>> :
  T extends null ? null :
  T extends object ? { [K in keyof T]: StringToBigint<T[K]> } :
  T;
/**
 * Helper to serialize bigint-heavy objects through JSON-compatible strings.
 * Structures deeper than 256 levels and cyclic values reject explicitly.
 * @example
 * Encode bigint-heavy data for JSON transport, then decode it back.
 * ```ts
 * const encoded = stringBigints.encode({ value: 1n });
 * const decoded = stringBigints.decode(encoded);
 * ```
 */
export const stringBigints: {
  encode: <F>(o: F) => BigintToString<F>;
  decode: <T>(o: T) => StringToBigint<T>;
} = /* @__PURE__ */ Object.freeze({
  encode: <F>(o: F): BigintToString<F> => {
    return deepConvert(o, (o) => {
      if (typeof o !== 'bigint') return undefined;
      // Old proof/key JSON is unsigned field-element data; signed values would not decode back.
      if (o < _0n) throw new Error(`expected non-negative bigint, got ${o}`);
      return o.toString(10);
    }) as BigintToString<F>;
  },
  decode: <T>(o: T): StringToBigint<T> => {
    // Only canonical unsigned base-10 strings are decoded for proof/key JSON compatibility.
    return deepConvert(o, (o) =>
      typeof o == 'string' && /^(0|[1-9][0-9]*)$/.test(o) ? BigInt(o) : undefined
    ) as StringToBigint<T>;
  },
});

function pointCoder<T, F>(
  cons: WeierstrassPointCons<T>,
  coder: Coder<T, F>
): Coder<WeierstrassPoint<T>, [F, F, F]> {
  return Object.freeze({
    encode: (p: WeierstrassPoint<T>): [F, F, F] => {
      const { X: px, Y: py, Z: pz } = cons.fromAffine(p.toAffine());
      return [px, py, pz].map(coder.encode) as [F, F, F];
    },
    decode: (p: [F, F, F] | undefined) => {
      // snarkjs-style proving keys use null placeholders for zero C-query entries.
      if (!p) return cons.ZERO; // sometimes can be null?
      const [x, y, z] = p.map(coder.decode);
      // TODO: validation increases time 3x
      // res.assertValidity();
      return new cons(x, y, z);
    },
  });
}

/** One linear constraint side keyed by signal index. */
export type Constraint = Record<number, bigint>;
/** Jacobian point over G1. */
export type G1Point = [bigint, bigint, bigint];
/** Jacobian point over G2. */
export type G2Point = [[bigint, bigint], [bigint, bigint], [bigint, bigint]];
/** Sparse coefficient reference inside a proving key matrix. */
export type Coefficient = {
  /** Field coefficient value. */
  value: bigint;
  /** Matrix index that owns the coefficient. */
  matrix: number;
  /** Constraint row index. */
  constraint: number;
  /** Signal column index. */
  signal: number;
};

/**
 * Groth16 proving key.
 * @warning Query points are decoded without curve or subgroup validation. Authenticate proving
 * keys before using them with private witnesses.
 */
export interface ProvingKey {
  /** Protocol name. */
  protocol?: 'groth';
  /** Total number of circuit variables. */
  nVars: number;
  /**
   * Number of public signals, including outputs and inputs.
   * Validate this value against trusted circuit metadata before proving.
   */
  nPublic: number;
  /** Log2 of the evaluation domain size. */
  domainBits: number;
  /** Evaluation domain size. */
  domainSize: number;
  // Polynominals
  /** Sparse A-matrix polynomials. */
  polsA?: Constraint[];
  /** Sparse B-matrix polynomials. */
  polsB?: Constraint[];
  /** Sparse C-matrix polynomials. */
  polsC?: Constraint[];
  /** Compact coefficient table used to reconstruct the sparse matrices. */
  ccoefs?: Coefficient[];
  //
  /** A-query points in G1. */
  A: G1Point[];
  /** B-query points in G1. */
  B1: G1Point[];
  /** B-query points in G2. */
  B2: G2Point[];
  /** C-query points in G1. */
  C: G1Point[];
  //
  /** Alpha verifier key element in G1. */
  vk_alfa_1: G1Point;
  /** Beta verifier key element in G1. */
  vk_beta_1: G1Point;
  /** Delta verifier key element in G1. */
  vk_delta_1: G1Point;
  /** Beta verifier key element in G2. */
  vk_beta_2: G2Point;
  /** Delta verifier key element in G2. */
  vk_delta_2: G2Point;
  //
  /** H-exponent points used for quotient commitments. */
  hExps: G1Point[];
}

/** Groth16 verification key. */
export interface VerificationKey {
  /** Protocol name. */
  protocol?: 'groth';
  /** Number of public signals expected by the verifier. */
  nPublic: number;
  /** Public input commitment bases. */
  IC: G1Point[];
  //
  /** Alpha verifier key element in G1. */
  vk_alfa_1: G1Point;
  /** Beta verifier key element in G2. */
  vk_beta_2: G2Point;
  /** Gamma verifier key element in G2. */
  vk_gamma_2: G2Point;
  /** Delta verifier key element in G2. */
  vk_delta_2: G2Point;
}

/** Witness vector produced by a circuit execution. */
export type Witness = bigint[];

/** Groth16 proof object. */
export interface GrothProof {
  /** Protocol name. */
  protocol: 'groth';
  /** A proof element in G1. */
  pi_a: G1Point;
  /** B proof element in G2. */
  pi_b: G2Point;
  /** C proof element in G1. */
  pi_c: G1Point;
}
/** Proof together with public signals. */
export interface ProofWithSignals {
  /** Groth16 proof object. */
  proof: GrothProof;
  /** Public signals used during verification. */
  publicSignals: Witness;
  /**
   * Optional commitment points for proof systems that emit them.
   * @warning These points are not bound to this proof or its public signals. Do not accept them
   * from untrusted proofs without a complete external committed-Groth16 protocol.
   */
  commitments?: G1Point[];
}

/** Minimal circuit metadata required for setup. */
export type CircuitInfo = {
  /** Total number of circuit variables. */
  nVars: number;
  /** Number of public inputs. */
  nPubInputs: number;
  /** Number of public outputs. */
  nOutputs: number;
  /** Constraint rows in `[A, B, C]` order. */
  constraints: [Constraint, Constraint, Constraint][];
};

/** Toxic waste values produced during setup. */
export interface ToxicWaste {
  /** Secret evaluation point. */
  t: bigint;
  /** Alpha secret multiplier. */
  kalfa: bigint;
  /** Beta secret multiplier. */
  kbeta: bigint;
  /** Gamma secret multiplier. */
  kgamma: bigint;
  /** Delta secret multiplier. */
  kdelta: bigint;
}

/** Groth16 constructor options. */
export type GrothOpts = {
  /** Override the non-quadratic residue used by the FFT helper tables. */
  nqr?: number | bigint;
  /** Return toxic waste values for tests and fixture generation. */
  unsafePreserveToxic?: boolean;
  /** Resource limits checked before circuit or proving-key metadata drives allocations. */
  limits?: ArtifactLimits;
  /**
   * Reduce data-dependent leakage when using custom MSM backends by preserving zero-scalar entries.
   * Defaults to `false` to retain sparse-MSM performance.
   */
  hardenSideChannel?: boolean;
  /**
   * Custom G1 MSM implementation.
   * @param input - Point-scalar pairs to multiply.
   * @returns MSM result in G1.
   */
  G1msm?: (input: MSMInput<bigint>[]) => Promise<WeierstrassPoint<bigint>>;
  /**
   * Custom G2 MSM implementation.
   * @param input - Point-scalar pairs to multiply.
   * @returns MSM result in G2.
   */
  G2msm?: (input: MSMInput<Fp2>[]) => Promise<WeierstrassPoint<Fp2>>;
};

/** Curve points bundled together with their coders. */
export interface PointsWithCoders {
  /** G1 point constructor. */
  G1: WeierstrassPointCons<bigint>;
  /** G2 point constructor. */
  G2: WeierstrassPointCons<Fp2>;
  /** Coder for G1 points. */
  G1c: Coder<WeierstrassPoint<bigint>, G1Point>;
  /** Coder for G2 points. */
  G2c: Coder<WeierstrassPoint<Fp2>, G2Point>;
}

/** Snark helpers returned by `buildSnark()`. */
export interface SnarkConstructorOutput {
  /** Curve constructors and point coders used by the proof helpers. */
  utils: PointsWithCoders;
  /** Groth16 setup, proving, and verification helpers. */
  groth: {
    /**
     * Builds proving and verification keys for a circuit.
     * @param circuit - Circuit metadata and constraints.
     * @param rnd - Optional randomness source used to sample toxic waste.
     * @returns Proving key, verification key, and optional toxic waste.
     * @throws If a valid evaluation point cannot be sampled within 128 attempts.
     */
    setup(
      circuit: CircuitInfo,
      rnd?: TArg<RandFn>
    ): {
      pkey: ProvingKey;
      vkey: VerificationKey;
      toxic: ToxicWaste | undefined;
    };
    /**
     * Creates a Groth16 proof for a witness.
     * @param pkey - Proving key.
     * @param witness - Witness vector.
     * @param rnd - Optional randomness source.
     * @returns Proof and public signals.
     * @warning The proving key controls which witness entries are returned as public signals.
     */
    createProof(pkey: ProvingKey, witness: Witness, rnd?: TArg<RandFn>): Promise<ProofWithSignals>;
    /**
     * Verifies a Groth16 proof.
     * @param vkey - Verification key.
     * @param proofWithSignals - Proof plus public signals.
     * @returns `true` when the proof verifies; malformed or non-canonical inputs return `false`.
     */
    verifyProof(vkey: VerificationKey, proofWithSignals: ProofWithSignals): boolean;
  };
}

/**
 * Builds Groth16 helpers for a pairing-friendly curve.
 * @param curve - Pairing-friendly curve implementation.
 * @param opts - Options for FFT setup and optional MSM backends. See {@link GrothOpts}.
 * @returns Snark setup, proof, and verification helpers.
 * @throws If the curve root table exceeds the supported FFT domain size. {@link Error}
 * @example
 * Build curve-specific Groth16 helpers, then run a tiny self-contained proof round-trip.
 * ```ts
 * import { buildSnark, type CircuitInfo } from 'micro-zk-proofs';
 * const { bn254: nobleBn254 } = await import('@noble/curves/bn254.js');
 * const snark = buildSnark(nobleBn254);
 * const circuit: CircuitInfo = {
 *   nVars: 2,
 *   nPubInputs: 0,
 *   nOutputs: 0,
 *   constraints: [[{}, {}, {}]],
 * };
 * const setup = snark.groth.setup(circuit);
 * const proof = await snark.groth.createProof(setup.pkey, [1n, 0n]);
 * snark.groth.verifyProof(setup.vkey, proof);
 * ```
 */
export function buildSnark(
  curve: BLSCurvePair,
  opts: GrothOpts = {}
): TRet<SnarkConstructorOutput> {
  const limits = resolveArtifactLimits(opts.limits);
  // Utils
  const G1 = curve.G1.Point;
  const G2 = curve.G2.Point;
  type G1Point = typeof G1.BASE;
  type G2Point = typeof G2.BASE;

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
  const isCanonicalFp = (value: unknown): value is bigint =>
    typeof value === 'bigint' && value >= _0n && value < Fp.ORDER;
  const isCanonicalFr = (value: unknown): value is bigint =>
    typeof value === 'bigint' && value >= _0n && value < Fr.ORDER;
  const decodeCanonicalG1 = (raw: unknown): G1Point => {
    if (!Array.isArray(raw) || raw.length !== 3 || !raw.every(isCanonicalFp))
      throw new Error('invalid canonical G1 tuple');
    const point = new G1(raw[0], raw[1], raw[2]);
    const encoded = G1c.encode(point);
    if (!encoded.every((value, index) => value === raw[index]))
      throw new Error('non-canonical G1 point');
    return point;
  };
  const decodeCanonicalG2 = (raw: unknown): G2Point => {
    if (
      !Array.isArray(raw) ||
      raw.length !== 3 ||
      !raw.every(
        (coordinate) =>
          Array.isArray(coordinate) && coordinate.length === 2 && coordinate.every(isCanonicalFp)
      )
    )
      throw new Error('invalid canonical G2 tuple');
    const coordinates = raw as [bigint, bigint][];
    const point = new G2(
      Fp2.create({ c0: coordinates[0][0], c1: coordinates[0][1] }),
      Fp2.create({ c0: coordinates[1][0], c1: coordinates[1][1] }),
      Fp2.create({ c0: coordinates[2][0], c1: coordinates[2][1] })
    );
    const encoded = G2c.encode(point);
    if (
      !encoded.every((coordinate, i) => coordinate.every((value, j) => value === coordinates[i][j]))
    )
      throw new Error('non-canonical G2 point');
    return point;
  };

  const G1msm = !opts.G1msm
    ? (p: G1Point[], s: bigint[]) => pippenger(curve.G1.Point, p, s)
    : modifyArgs(Fr, G1, opts.G1msm, { hardenSideChannel: opts.hardenSideChannel });
  const G2msm = !opts.G2msm
    ? (p: G2Point[], s: bigint[]) => pippenger(curve.G2.Point, p, s)
    : modifyArgs(Fr, G2, opts.G2msm, { hardenSideChannel: opts.hardenSideChannel });

  const Frandom = (rnd: TArg<RandFn> = randomBytes) => {
    // Reduce random bytes once so unsafePreserveToxic exposes the same field elements setup uses.
    return Fr.create(bytesToNumberBE(rnd(Fr.BYTES)));
  };
  const roots = rootsOfUnity(Fr, opts.nqr ? BigInt(opts.nqr) : undefined);
  // Some internal FFT paths still use signed JS shifts; reject roots that could reach bit 31+.
  if (roots.info.powerOfTwo > MAX_DOMAIN_BITS)
    throw new Error(
      `expected roots powerOfTwo <= ${MAX_DOMAIN_BITS}, got ${roots.info.powerOfTwo}`
    );
  const fftFr = FFT(roots, Fr);
  const polyFr = polyCurves(Fr, roots, undefined, fftFr);
  const checkDomainBits = (bits: number) => {
    if (!Number.isSafeInteger(bits) || bits < 0 || bits > roots.info.powerOfTwo)
      throw new Error(`expected domainBits <= ${roots.info.powerOfTwo}, got ${bits}`);
  };
  const checkCount = (value: number, name: string, allowZero = false) => {
    if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1) || value > U32_MAX)
      throw new Error(
        `expected uint32 ${allowZero ? 'non-negative' : 'positive'} integer for ${name}, got ${value}`
      );
  };
  const checkLimit = (value: number, limit: number, name: string) => {
    if (value > limit) throw new Error(`${name} exceeds configured limit ${limit}: ${value}`);
  };
  const checkedDomainBits = (domainSize: number) => {
    checkCount(domainSize, 'domainSize');
    const bits = log2(domainSize);
    if (2 ** bits !== domainSize)
      throw new Error(`expected domainSize to be a power of two, got ${domainSize}`);
    checkDomainBits(bits);
    checkLimit(domainSize, limits.maxDomainSize, 'domainSize');
    return bits;
  };
  const checkConstraintIndex = (key: string, upperBound: number, label: string) => {
    if (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= upperBound)
      throw new Error(`${label} index out of range: ${key}`);
  };
  const validateCircuit = (circuit: CircuitInfo) => {
    if (circuit === null || typeof circuit !== 'object' || Array.isArray(circuit))
      throw new TypeError('"circuit" expected object, got type=' + typeof circuit);
    checkCount(circuit.nVars, 'nVars');
    checkCount(circuit.nPubInputs, 'nPubInputs', true);
    checkCount(circuit.nOutputs, 'nOutputs', true);
    checkLimit(circuit.nVars, limits.maxVariables, 'nVars');
    const nPublic = circuit.nPubInputs + circuit.nOutputs;
    if (!Number.isSafeInteger(nPublic) || nPublic >= circuit.nVars)
      throw new Error(`expected nPubInputs + nOutputs < nVars, got ${nPublic}`);
    if (!Array.isArray(circuit.constraints))
      throw new TypeError('"circuit.constraints" expected array');
    checkLimit(circuit.constraints.length, limits.maxConstraints, 'constraint count');
    const domainBits = log2(circuit.constraints.length + nPublic) + 1;
    checkDomainBits(domainBits);
    const domainSize = 2 ** domainBits;
    checkLimit(domainSize, limits.maxDomainSize, 'domainSize');
    for (let row = 0; row < circuit.constraints.length; row++) {
      const constraint = circuit.constraints[row];
      if (!Array.isArray(constraint) || constraint.length !== 3)
        throw new Error(`constraint ${row} must contain exactly three sides`);
      for (const side of constraint) {
        if (side === null || typeof side !== 'object' || Array.isArray(side))
          throw new Error(`constraint ${row} side must be an object`);
        for (const key of Object.keys(side))
          checkConstraintIndex(key, circuit.nVars, `constraint ${row}`);
      }
    }
    return { domainBits, domainSize, nPublic };
  };
  const checkArrayLength = (value: unknown, expected: number, name: string) => {
    if (!Array.isArray(value) || value.length !== expected)
      throw new Error(
        `expected ${name}.length === ${expected}, got ${Array.isArray(value) ? value.length : 'non-array'}`
      );
  };
  const validateProvingInput = (pkey: ProvingKey, witness: Witness) => {
    if (pkey === null || typeof pkey !== 'object' || Array.isArray(pkey))
      throw new TypeError('"pkey" expected object, got type=' + typeof pkey);
    checkCount(pkey.nVars, 'pkey.nVars');
    checkCount(pkey.nPublic, 'pkey.nPublic', true);
    checkLimit(pkey.nVars, limits.maxVariables, 'pkey.nVars');
    if (pkey.nPublic >= pkey.nVars)
      throw new Error(`expected pkey.nPublic < pkey.nVars, got ${pkey.nPublic}`);
    const domainBits = checkedDomainBits(pkey.domainSize);
    if (pkey.domainBits !== domainBits)
      throw new Error(`expected pkey.domainBits === ${domainBits}, got ${pkey.domainBits}`);
    checkArrayLength(witness, pkey.nVars, 'witness');
    checkArrayLength(pkey.A, pkey.nVars, 'pkey.A');
    checkArrayLength(pkey.B1, pkey.nVars, 'pkey.B1');
    checkArrayLength(pkey.B2, pkey.nVars, 'pkey.B2');
    checkArrayLength(pkey.C, pkey.nVars, 'pkey.C');

    const compact = pkey.ccoefs !== undefined;
    const legacy = pkey.polsA !== undefined || pkey.polsB !== undefined || pkey.polsC !== undefined;
    if (compact === legacy)
      throw new Error('wrong proving key: expected exactly one polynomial representation');
    if (compact) {
      if (!Array.isArray(pkey.ccoefs)) throw new Error('expected pkey.ccoefs array');
      checkArrayLength(pkey.hExps, pkey.domainSize, 'pkey.hExps');
      for (const coefficient of pkey.ccoefs) {
        if (
          coefficient === null ||
          typeof coefficient !== 'object' ||
          !Number.isInteger(coefficient.matrix) ||
          coefficient.matrix < 0 ||
          coefficient.matrix > 2 ||
          !Number.isInteger(coefficient.constraint) ||
          coefficient.constraint < 0 ||
          coefficient.constraint >= pkey.domainSize ||
          !Number.isInteger(coefficient.signal) ||
          coefficient.signal < 0 ||
          coefficient.signal >= pkey.nVars
        )
          throw new Error('invalid proving-key coefficient index');
      }
    } else {
      checkArrayLength(pkey.polsA, pkey.nVars, 'pkey.polsA');
      checkArrayLength(pkey.polsB, pkey.nVars, 'pkey.polsB');
      checkArrayLength(pkey.polsC, pkey.nVars, 'pkey.polsC');
      checkArrayLength(pkey.hExps, pkey.domainSize + 1, 'pkey.hExps');
      for (const polynomials of [pkey.polsA!, pkey.polsB!, pkey.polsC!]) {
        for (const polynomial of polynomials) {
          if (polynomial === null || typeof polynomial !== 'object' || Array.isArray(polynomial))
            throw new Error('expected proving-key polynomial object');
          for (const key of Object.keys(polynomial))
            checkConstraintIndex(key, pkey.domainSize, 'proving-key constraint');
        }
      }
    }
  };
  // TODO: cleanup more later
  const poly = {
    reduce(p: bigint[]) {
      while (p.length > 0 && Fr.is0(p[p.length - 1])) p.pop();
      return p;
    },
    sub(a: bigint[], b: bigint[]) {
      const len = Math.max(a.length, b.length);
      return poly.reduce(polyFr.sub(polyFr.extend(a, len), polyFr.extend(b, len)));
    },
    fft(p: bigint[], bits: number): bigint[] {
      const n = 1 << bits;
      while (p.length < n) p.push(Fr.ZERO);
      return fftFr.direct(p);
    },
    ifft(p: bigint[]) {
      if (p.length <= 1) return p;
      return fftFr.inverse(p);
    },
    // Polynomial multiplication via FFT.
    mul(a: bigint[], b: bigint[]) {
      if (a.length !== b.length || a.length < 2) throw new Error('wrong polynominal length');
      return poly.reduce(polyFr.convolve(a, b));
    },
    evaluateLagrangePolynomials(bits: number, t: bigint): bigint[] {
      return polyFr.lagrange.basis(t, 2 ** bits);
    },
  };
  function sumABC(
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
          // Setup stores sparse matrices by signal, while proving uses row-major proving-key matrices.
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
  }

  function calculateH(proof: ProvingKey, witness: Witness) {
    const m = proof.domainSize;
    const bits = log2(m);
    checkDomainBits(bits);
    // new snarkjs omit polsC and re-construct them via coset stuff & shifts.
    if (proof.ccoefs) {
      const pols = [];
      for (let i = 0; i < 3; i++) pols.push(new Array(m).fill(Fr.ZERO));
      for (const { matrix, constraint, signal, value } of proof.ccoefs) {
        pols[matrix][constraint] = Fr.add(pols[matrix][constraint], Fr.mul(value, witness[signal]));
      }
      const [pA, pB] = pols; // ignore polC
      const pC = polyFr.dot(pA, pB);
      // FFT to the shifted (coset) domain
      // A(x)·B(x) − C(x) = H(x)·Z_H(x) -> H(g·ω^i) = (Acos[i]·Bcos[i] − Ccos[i]) / Z_H(g·ω^i)
      const shift =
        bits === roots.info.powerOfTwo ? Fr.mul(roots.info.G, roots.info.G) : roots.omega(bits + 1);
      const Acos = poly.fft(polyFr.shift(poly.ifft(pA), shift), bits);
      const Bcos = poly.fft(polyFr.shift(poly.ifft(pB), shift), bits);
      const Ccos = poly.fft(polyFr.shift(poly.ifft(pC), shift), bits);
      return polyFr.sub(polyFr.dot(Acos, Bcos), Ccos);
    } else if (proof.polsA && proof.polsB && proof.polsC) {
      const { pA, pB, pC } = sumABC(m, witness, proof.polsA, proof.polsB, proof.polsC);
      // FFT only needed to optimize multiplication O(n²) to O(n log n)
      // pA * pB - pC
      return poly.sub(poly.mul(poly.ifft(pA), poly.ifft(pB)), poly.ifft(pC)).slice(m);
    }
    throw new Error('wrong proving key: no polynomials');
  }
  const utils = Object.freeze({ G1, G2, G1c, G2c } satisfies PointsWithCoders);
  // TODO: add other proofs, which re-use many polynomial operations
  // * We don't export alfabeta_12! It is only used for optimization, and is specific to
  //   pairing implementation (different values after final exponentiation).
  // * We accept raw circuit json here, no need for Circuit object!
  return Object.freeze({
    utils: utils,
    groth: Object.freeze({
      setup(circuit: CircuitInfo, rnd: TArg<RandFn> = randomBytes) {
        // Sizes
        const { domainBits, domainSize, nPublic } = validateCircuit(circuit);
        const nConstraints = circuit.constraints.length;
        const maxH = domainSize + 1;
        // Toxic
        let t = Fr.ZERO;
        let zt = Fr.ZERO;
        for (let attempt = 0; attempt < MAX_TOXIC_T_ATTEMPTS; attempt++) {
          const candidate = Frandom(rnd);
          if (Fr.is0(candidate)) continue;
          const candidateZt = Fr.sub(Fr.pow(candidate, BigInt(domainSize)), Fr.ONE);
          if (Fr.is0(candidateZt)) continue;
          t = candidate;
          zt = candidateZt;
          break;
        }
        if (Fr.is0(t))
          throw new Error(
            `failed to sample toxic t outside the evaluation domain after ${MAX_TOXIC_T_ATTEMPTS} attempts`
          );
        const toxic = {
          t,
          kalfa: Frandom(rnd),
          kbeta: Frandom(rnd),
          kgamma: Frandom(rnd),
          kdelta: Frandom(rnd),
        };
        // Zero toxic scalars make degenerate setup data and currently hit inverse paths for gamma/delta.
        for (const [k, v] of Object.entries(toxic))
          if (Fr.is0(v)) throw new Error(`expected non-zero toxic ${k}`);
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
        const u = poly.evaluateLagrangePolynomials(domainBits, toxic.t);
        const { pA, pB, pC } = sumABC(circuit.nVars, u, polsA, polsB, polsC, true);
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

        const pkey: ProvingKey = {
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
        const vkey: VerificationKey = {
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
          pkey,
          vkey,
          toxic: opts.unsafePreserveToxic ? toxic : undefined,
        };
      },
      async createProof(
        pkey: ProvingKey,
        witness: Witness,
        rnd: TArg<RandFn> = randomBytes
      ): Promise<ProofWithSignals> {
        validateProvingInput(pkey, witness);
        witness = witness.map((i) => Fr.create(i));
        // Blinding salt for zero-knowledge
        const r = Frandom(rnd);
        const s = Frandom(rnd);
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
        const h = calculateH(pkey, witness).map((i) => Fr.create(i));
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
      verifyProof(vkey: VerificationKey, proofWithSignals: ProofWithSignals): boolean {
        try {
          if (
            proofWithSignals === null ||
            typeof proofWithSignals !== 'object' ||
            vkey === null ||
            typeof vkey !== 'object'
          )
            return false;
          const { proof, publicSignals, commitments } = proofWithSignals;
          if (proof === null || typeof proof !== 'object' || proof.protocol !== 'groth')
            return false;
          if (
            !Number.isSafeInteger(vkey.nPublic) ||
            vkey.nPublic < 0 ||
            !Array.isArray(vkey.IC) ||
            vkey.IC.length !== vkey.nPublic + 1 ||
            !Array.isArray(publicSignals) ||
            publicSignals.length !== vkey.nPublic ||
            !publicSignals.every(isCanonicalFr)
          )
            return false;
          const piA = decodeCanonicalG1(proof.pi_a);
          const piB = decodeCanonicalG2(proof.pi_b);
          const piC = decodeCanonicalG1(proof.pi_c);
          let cpub = pippenger(G1, vkey.IC.map(G1c.decode), [_1n, ...publicSignals]);
          if (commitments !== undefined) {
            if (!Array.isArray(commitments)) return false;
            for (const commitment of commitments) {
              const point = decodeCanonicalG1(commitment);
              point.assertValidity();
              cpub = cpub.add(point);
            }
          }
          // old e(pi_a, pi_b) = alfa_beta * e(cpub, gamma_2) * e(pi_c, delta_2)
          // new: e(-pi_a, pi_b) * e(cpub, gamma_2) * e(pi_c, delta_2) * e(alfa_1, beta_2) = 1
          // Major difference: old version uses pre-computed alfa_beta,
          // but this makes it incompatible with noble, because we use cyclomatic exp
          // (Fp12 values different even if math is same).
          // pairingBatch validates every proof point's curve and subgroup membership.
          const newRes = curve.pairingBatch([
            { g1: piA.negate(), g2: piB },
            { g1: cpub, g2: G2c.decode(vkey.vk_gamma_2) },
            { g1: piC, g2: G2c.decode(vkey.vk_delta_2) },
            { g1: G1c.decode(vkey.vk_alfa_1), g2: G2c.decode(vkey.vk_beta_2) },
          ]);
          return Fp12.eql(newRes, Fp12.ONE);
        } catch {
          return false;
        }
      },
    }),
  }) as TRet<SnarkConstructorOutput>;
}

/**
 * ZK Snarks over bn254 (aka bn128) curve.
 * @example
 * Build the bundled bn254 helpers and run a tiny self-contained Groth16 round-trip.
 * ```ts
 * import { bn254, type CircuitInfo } from 'micro-zk-proofs';
 * const circuit: CircuitInfo = {
 *   nVars: 2,
 *   nPubInputs: 0,
 *   nOutputs: 0,
 *   constraints: [[{}, {}, {}]],
 * };
 * const setup = bn254.groth.setup(circuit);
 * const proof = await bn254.groth.createProof(setup.pkey, [1n, 0n]);
 * bn254.groth.verifyProof(setup.vkey, proof);
 * ```
 */
export const bn254: TRet<SnarkConstructorOutput> = /* @__PURE__ */ buildSnark(nobleBn254, {});
// NOTE: this is unsafe and may not work (untested for now)
//export const bls12_381 = buildSnark(nobleBls12, {});
