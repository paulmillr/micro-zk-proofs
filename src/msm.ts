/**
 * MSM - Multi Scalar Multiplication. Done in parallel using micro-wrkr.
 * MSM is a fast algorithm to add & multiply many elliptic curve points at once.
 * @module
 */
import { type IField } from '@noble/curves/abstract/modular';
import { type ProjConstructor, type ProjPointType } from '@noble/curves/abstract/weierstrass';
import { bn254 } from '@noble/curves/bn254';
import { wrkr } from 'micro-wrkr';
import { type Handlers, type MSMInput } from './msm-worker.ts';

function reducePoint<T>(p: ProjConstructor<T>) {
  return (lst: ProjPointType<T>[]) =>
    lst.map((i) => new p(i.px, i.py, i.pz)).reduce((acc, i) => acc.add(i), p.ZERO);
}

export function initMSM(): { methods: any; terminate: () => void } {
  const { methods, terminate } = wrkr.initBatch<Handlers>(
    () => new Worker(new URL('./msm-worker.js', import.meta.url), { type: 'module' }),
    {
      bn254_msmG1: reducePoint(bn254.G1.ProjectivePoint),
      bn254_msmG2: reducePoint(bn254.G2.ProjectivePoint),
    }
  );
  return { methods, terminate };
}

export function modifyArgs<T>(
  field: IField<bigint>,
  point: ProjConstructor<T>,
  fn: (input: MSMInput<T>[]) => Promise<ProjPointType<T>>
) {
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
