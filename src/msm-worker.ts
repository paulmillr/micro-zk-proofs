/**
 * MSM parallel worker, using micro-wrkr.
 * @module
 */
import { pippenger } from '@noble/curves/abstract/curve.js';
import type { Fp2 } from '@noble/curves/abstract/tower.js';
import {
  type WeierstrassPoint,
  type WeierstrassPointCons,
} from '@noble/curves/abstract/weierstrass.js';
import { bn254 } from '@noble/curves/bn254.js';
import { wrkr } from 'micro-wrkr';

/** Multi-scalar multiplication input pair. */
export type MSMInput<T> = {
  /** Curve point to multiply. */
  point: WeierstrassPoint<T>;
  /** Scalar multiplier. */
  scalar: bigint;
};
/** Worker handlers exposed for bn254 MSM execution. */
export type bn254MSMInput = {
  /**
   * Runs a G1 multi-scalar multiplication batch.
   * @param list - Point-scalar pairs.
   * @returns MSM result in G1.
   */
  bn254_msmG1: (list: MSMInput<bigint>[]) => WeierstrassPoint<bigint>;
  /**
   * Runs a G2 multi-scalar multiplication batch.
   * @param list - Point-scalar pairs.
   * @returns MSM result in G2.
   */
  bn254_msmG2: (list: MSMInput<Fp2>[]) => WeierstrassPoint<Fp2>;
};

function buildMSM<T>(point: WeierstrassPointCons<T>) {
  return (list: MSMInput<T>[]): WeierstrassPoint<T> => {
    if (!list.length) return point.ZERO;
    const points = list.map((i: any) => new point(i.point.X, i.point.Y, i.point.Z));
    const scalars = list.map((i: any) => i.scalar);
    return pippenger(point, points, scalars);
  };
}

const handlers: bn254MSMInput = {
  bn254_msmG1: buildMSM(bn254.G1.Point),
  bn254_msmG2: buildMSM(bn254.G2.Point),
};

/** Worker handler type exported for `wrkr`. */
export type Handlers = bn254MSMInput;
wrkr.initWorker(handlers);
