/**
 * Pedersen Hash over babyjubjub elliptic curve, defined in
 * [EIP-2494](https://eips.ethereum.org/EIPS/eip-2494).
 * jubjub     - edwards over bls12-381 scalar
 * babyjubjub - edwards over bn254 scalar
 * Using scalar as field allows to be used inside of zk-circuits.
 * @module
 */
import { twistedEdwards, type ExtPointType } from '@noble/curves/abstract/edwards';
import { bytesToNumberLE, numberToBytesLE } from '@noble/curves/abstract/utils';
import { bn254 } from '@noble/curves/bn254';
import { blake256 } from '@noble/hashes/blake1';
import { randomBytes } from '@noble/hashes/utils';
const { Fr } = bn254.fields;

const babyjubjub = twistedEdwards({
  Fp: Fr,
  Gx: BigInt('995203441582195749578291179787384436505546430278305826713579947235728471134'),
  Gy: BigInt('5472060717959818805561601436314318772137091100104008585924551046643952123905'),
  n: BigInt('21888242871839275222246405745257275088614511777268538073601725287587578984328'),
  h: BigInt(8),
  a: BigInt(168700),
  d: BigInt(168696),
  hash: blake256,
  randomBytes: randomBytes,
});
type EdwardsPoint = typeof babyjubjub.ExtendedPoint.BASE;

// Seems like twistedEdwards fromBytes/toBytes, but with 'x > Fr.ORDER >> 1n' instead of oddity?
// NOTE: we need to be as close as possible to original, otherwise hashes will change!
export const Point = {
  encode(p: any): Uint8Array {
    const { x, y } = p.toAffine();
    const bytes = numberToBytesLE(y, 32);
    // Check highest bit instead of lowest in other twisted edwards
    if (x > Fr.ORDER >> 1n) bytes[31] |= 0x80;
    return bytes;
  },
  // NOTE: decode doesn't check oddity of x before negate, which means this heavily depends on
  // formula and sqrt implementation. Other implementations may return different root first.
  // However it uses exactly same tonneli shanks as @noble/curves, but selects lower root
  // This is very fragile, but probably since used for hashes only
  decode(bytes: Uint8Array): ExtPointType {
    const sign = !!(bytes[31] & 0x80);
    bytes[31] &= 0x7f; // clean sign bit
    const y = bytesToNumberLE(bytes);
    if (y >= Fr.ORDER) throw new Error('bigger than order');
    const y2 = Fr.sqr(y);
    let x = Fr.sqrt(
      Fr.div(Fr.sub(Fr.ONE, y2), Fr.sub(babyjubjub.CURVE.a, Fr.mul(babyjubjub.CURVE.d, y2)))
    );
    // This forces lowest root (instead of isOdd in twisted edwards)
    if (x > Fr.ORDER >> 1n) x = Fr.neg(x);
    if (sign) x = Fr.neg(x);
    return babyjubjub.ExtendedPoint.fromAffine({ x, y });
  },
};

// We cannot do nice precomputes here since input can be unlimited in size
let POINT_CACHE: EdwardsPoint[] = [];
function basePoint(idx: number) {
  if (idx < POINT_CACHE.length) return POINT_CACHE[idx];
  let p = undefined;
  for (let i = 0; !p; i++) {
    const s = `PedersenGenerator_${('' + idx).padStart(32, '0')}_${('' + i).padStart(32, '0')}`;
    const h = blake256(s);
    h[31] = h[31] & 0b1011_1111; // clear 255 bit
    try {
      p = Point.decode(h);
    } catch {}
  }
  p = p.clearCofactor();
  p.assertValidity();
  POINT_CACHE[idx] = p;
  return p;
}

const SUBORDER = babyjubjub.CURVE.n >> 3n;
function getScalars(msg: Uint8Array) {
  const res: bigint[] = [];
  // Very fragile wNAF (4-bit) like structure to avoid zero points
  const window = (n: number) => {
    const sign = !!(n & 0b1000); // highest bit is sign
    n = (n & 0b0111) + 1;
    return BigInt(sign ? -n : n);
  };
  // Process in chunks up to 25 bytes
  const blockLen = 25;
  for (let pos = 0; pos < msg.length; pos += blockLen) {
    const cur = msg.subarray(pos, pos + blockLen);
    let scalar = 0n;
    let shift = 1n;
    for (const b of cur) {
      // NOTE: we need to use multiplication here, because of negative values
      scalar += window(b & 0xf) * shift;
      shift <<= BigInt(5);
      scalar += window((b >>> 4) & 0xf) * shift;
      shift <<= BigInt(5);
    }
    if (scalar < 0n) scalar = SUBORDER + scalar;
    res.push(scalar);
  }
  return res;
}

export function pedersenHash(msg: Uint8Array): Uint8Array {
  const p = getScalars(msg).reduce(
    (acc, i, j) => acc.add(basePoint(j).multiply(i)),
    babyjubjub.ExtendedPoint.ZERO
  );
  return Point.encode(p);
}
