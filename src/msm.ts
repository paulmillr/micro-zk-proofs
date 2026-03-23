/**
 * MSM - Multi Scalar Multiplication. Done in parallel using micro-wrkr.
 * MSM is a fast algorithm to add & multiply many elliptic curve points at once.
 * @module
 */
import { type IField } from '@noble/curves/abstract/modular.js';
import type {
  WeierstrassPointCons as ProjConstructor,
  WeierstrassPoint as ProjPointType,
} from '@noble/curves/abstract/weierstrass.js';
import { bn254 } from '@noble/curves/bn254.js';
import { wrkr } from 'micro-wrkr';
import { type Handlers, type MSMInput } from './msm-worker.ts';

function reducePoint<T>(p: ProjConstructor<T>) {
  return (lst: ProjPointType<T>[]) =>
    lst.map((i) => new p(i.X, i.Y, i.Z)).reduce((acc, i) => acc.add(i), p.ZERO);
}

/**
 * Initializes batched MSM workers and reduction helpers.
 * @returns Worker methods together with a `terminate()` hook.
 * @example
 * Create the bn254 worker pool and terminate it when the batch work is done.
 * ```ts
 * const ctx = initMSM();
 * ctx.terminate();
 * ```
 */
export function initMSM(): { methods: any; terminate: () => void } {
  const { methods, terminate } = wrkr.initBatch<Handlers>(
    () => new Worker(new URL('./msm-worker.js', import.meta.url), { type: 'module' }),
    {
      bn254_msmG1: reducePoint(bn254.G1.Point),
      bn254_msmG2: reducePoint(bn254.G2.Point),
    }
  );
  return { methods, terminate };
}

/**
 * Adapts a worker MSM function into the point-array/scalar-array shape used by Groth16.
 * @param field - Scalar field used to drop zero scalars.
 * @param point - Projective point constructor for normalization.
 * @param fn - Worker-backed MSM implementation.
 * @returns Helper that accepts separate point and scalar arrays.
 * @example
 * Wrap a worker MSM function so Groth16 can call it with separate point and scalar arrays.
 * ```ts
 * const { bn254 } = await import('@noble/curves/bn254.js');
 * const workerMsm = async () => bn254.G1.Point.ZERO;
 * const msm = modifyArgs(bn254.fields.Fr, bn254.G1.Point, workerMsm);
 * await msm([bn254.G1.Point.BASE], [1n]);
 * ```
 */
export function modifyArgs<T>(
  field: IField<bigint>,
  point: ProjConstructor<T>,
  fn: (input: MSMInput<T>[]) => Promise<ProjPointType<T>>
): (points: ProjPointType<T>[], scalars: bigint[]) => Promise<ProjPointType<T>> {
  return async (points: ProjPointType<T>[], scalars: bigint[]): Promise<ProjPointType<T>> => {
    if (points.length !== scalars.length) throw new Error('points.length !== scalars.length');
    const input: MSMInput<T>[] = [];
    for (let i = 0; i < points.length; i++) {
      const scalar = scalars[i];
      if (field.is0(scalar)) continue;
      input.push({ point: points[i], scalar });
    }
    // NOTE: buildGroth accepts curve and can be build with different version of @noble/curves,
    // so we convert it here.
    const res = (await fn(input)) as any;
    return res instanceof point ? res : new point(res.px, res.py, res.pz);
  };
}
