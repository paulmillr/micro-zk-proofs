/**
 * MSM parallel worker, using micro-wrkr.
 * @module
 */
import type { Fp2 } from '@noble/curves/abstract/tower';
import { type ProjConstructor, type ProjPointType } from '@noble/curves/abstract/weierstrass';
import { bn254 } from '@noble/curves/bn254';
import { wrkr } from 'micro-wrkr';

export type MSMInput<T> = { point: ProjPointType<T>; scalar: bigint };
export type bn254MSMInput = {
  bn254_msmG1: (list: MSMInput<bigint>[]) => ProjPointType<bigint>;
  bn254_msmG2: (list: MSMInput<Fp2>[]) => ProjPointType<Fp2>;
};

function buildMSM<T>(point: ProjConstructor<T>) {
  return (list: MSMInput<T>[]): ProjPointType<T> => {
    if (!list.length) return point.ZERO;
    const points = list.map((i: any) => new point(i.point.px, i.point.py, i.point.pz));
    const scalars = list.map((i: any) => i.scalar);
    return point.msm(points, scalars);
  };
}

const handlers: bn254MSMInput = {
  bn254_msmG1: buildMSM(bn254.G1.ProjectivePoint),
  bn254_msmG2: buildMSM(bn254.G2.ProjectivePoint),
};

export type Handlers = bn254MSMInput;
wrkr.initWorker(handlers);
