import { randomBytes } from 'crypto';

import BN from 'bn.js';
import { curve } from 'elliptic';
import createKeccakHash from 'keccak';

import { ec } from './crypto-data';
import {
  encodeInt,
  decodePoint,
  reduceScalar,
  encodePoint,
  decodeScalar,
  decodeInt,
} from './helpers';

export function fastHash(data: Buffer): Buffer {
  const hash: Buffer = createKeccakHash('keccak256').update(data).digest();
  return hash;
}

export function hashToScalar(data: Buffer): Buffer {
  const hash: Buffer = fastHash(data);
  return reduceScalar32(hash);
}

export function reduceScalar32(scalar: Buffer): Buffer {
  const num: BN = decodeInt(scalar);
  return encodeInt(num.umod(ec.curve.n));
}

export function secretKeyToPublicKey(secretViewKey: Buffer): string {
  const s: BN = decodeScalar(secretViewKey, 'Invalid secret key');
  const basePoint: curve.base.BasePoint = ec.curve.g;
  const P2: curve.base.BasePoint = basePoint.mul(s);
  return encodePoint(P2).toString('hex');
}

export function generateSignature(message: Buffer, privateKey: Buffer, pubKey: Buffer): string {
  const h: Buffer = fastHash(message);
  const s: BN = decodeScalar(privateKey);
  const publicKey: string = secretKeyToPublicKey(privateKey);
  const pubKeyBuf: Buffer = Buffer.from(publicKey, 'hex');

  if (!pubKeyBuf.equals(pubKey)) {
    throw new RangeError('Incorrect public key');
  }

  while (true) {
    const k: BN = decodeInt(getRandomScalar(randomBytes(32), 32));
    const K: curve.base.BasePoint = ec.curve.g.mul(k);

    const buf = {
      h: h,
      key: pubKeyBuf,
      comm: encodePoint(K),
    };

    const bufForHash: Buffer = Buffer.concat([buf.h, buf.key, buf.comm]);
    const hashFromBuffer: Buffer = hashToScalar(bufForHash);

    const c: BN = decodeInt(hashFromBuffer);

    if (c.isZero()) {
      continue;
    }

    const r: BN = k
      .sub(s.mul(c))
      .umod(ec.curve.n);

    if (r.isZero()) {
      continue;
    }

    const encodedC: Buffer = c.toArrayLike(Buffer, 'le', 32);
    const encodedR: Buffer = r.toArrayLike(Buffer, 'le', 32);

    return encodedR.toString('hex') + encodedC.toString('hex');
  }
}

export function checkSignature(
  message: Buffer,
  publicKey: Buffer,
  signature: { r: Buffer; c: Buffer },
): boolean {
  try {
    const r: BN = decodeScalar(signature.r);
    const c: BN = decodeScalar(signature.c);
    const P: curve.edwards.EdwardsPoint = decodePoint(publicKey);
    const h: Buffer = fastHash(message);
    const B: curve.base.BasePoint = ec.curve.g;

    const R: curve.base.BasePoint = P.mul(c).add(B.mul(r));
    const bufComm: Buffer = encodePoint(R);

    const buf = {
      h,
      key: publicKey,
      comm: bufComm,
    };

    const bufForHash: Buffer = Buffer.concat([buf.h, buf.key, buf.comm]);
    const hashFromBuffer: Buffer = hashToScalar(bufForHash);

    const calculatedC: BN = decodeInt(hashFromBuffer);

    return calculatedC.eq(c);

  } catch (error) {
    console.error('Error during signature verification:', error.message);
    return false;
  }
}

function getRandomScalar(aPart: Buffer, keysSeedBinarySize: number) {
  // aPart == 32 bytes
  const tmp: Buffer = Buffer.alloc(64).fill(0);

  if (!(tmp.length >= keysSeedBinarySize)) {
    throw new Error('size mismatch');
  }

  tmp.set(aPart);

  const hash: Buffer = fastHash(tmp.subarray(0, 32));
  hash.copy(tmp, 32);

  const scalar: BN = decodeInt(tmp);

  const reducedScalarBuff: Buffer = Buffer.alloc(32);

  const reducedScalar: BN = reduceScalar(scalar, ec.curve.n);
  // for working in web building, without to Buffer
  reducedScalarBuff.set(reducedScalar.toArrayLike(Buffer, 'le', 32));

  const secretKey: Buffer = reducedScalarBuff.subarray(0, 32);

  return secretKey;
}
