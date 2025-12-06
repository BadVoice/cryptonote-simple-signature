import type { SchnorrSignature, SignableMessage } from './types';
import {
  checkSignature,
  generateSignature,
  secretKeyToPublicKey,
} from '../core/crypto';

/**
 * Normalizes any message to a Buffer for signing.
 */
function normalizeMessage(message: string | Record<string, any> | Buffer): Buffer {
  if (Buffer.isBuffer(message)) {
    return message;
  }
  if (typeof message === 'string') {
    return Buffer.from(message, 'utf8');
  }
  return Buffer.from(JSON.stringify(message), 'utf8');
}

/**
 * Validates a private key (strict, throws on error).
 */
function validatePrivateKey(keyHex: string): Buffer {
  if (typeof keyHex !== 'string' || keyHex.length !== 64) {
    throw new Error('Invalid private key: expected 64-character hex string');
  }
  let buf: Buffer;
  try {
    buf = Buffer.from(keyHex, 'hex');
    if (buf.length !== 32) {
      throw new Error();
    }
  } catch {
    throw new Error('Invalid private key: not a valid hex string or not 32 bytes');
  }
  return buf;
}

/**
 * Safely checks if a public key is a valid 32-byte hex string.
 * Does NOT verify if it's a valid curve point — that's done inside `checkSignature`.
 * @returns true if syntactically valid, false otherwise
 */
function isValidPublicKey(keyHex: string): Buffer | false {
  if (typeof keyHex !== 'string' || keyHex.length !== 64) {
    return false;
  }
  try {
    const buf = Buffer.from(keyHex, 'hex');
    return buf.length === 32 ? buf : false;
  } catch {
    return false;
  }
}


/**
 * The signature format is: `r || c` (64 + 64 hex characters = 128 chars total),
 * where:
 * - `r = k - c·x (mod l)` (response)
 * - `c = H(message || public_key || R)` (challenge)
 * - `R = k·G` (ephemeral public key)
 *
 * @param message - The data to sign. Can be a string, a JSON-serializable object, or a raw Buffer.
 * @param privateKey - A 64-character hex string representing a 32-byte Ed25519 secret key.
 * @returns A 128-character hex string representing the signature (`r` followed by `c`).
 * @throws {Error} If the private key is not a valid 64-char hex string or does not decode to 32 bytes.
 */
export function createSignature(
  message: SignableMessage,
  privateKey: string,
): string {
  const msgBuf: Buffer = normalizeMessage(message);
  const secBuf: Buffer  = validatePrivateKey(privateKey);

  const pubHex: string = secretKeyToPublicKey(secBuf);
  const pubBuf: Buffer  = Buffer.from(pubHex, 'hex');

  return generateSignature(msgBuf, secBuf, pubBuf);
}

/**
 *
 * @param message - The original message that was signed (must be identical to the one used during signing).
 * @param publicKey - A 64-character hex string representing a 32-byte Ed25519 public key.
 * @param signature - A 128-character hex string (`r || c`) produced by `createSignature`.
 * @returns `true` if the signature is valid; `false` if it is invalid, malformed, or the key/message do not match.
 */
export function verifySignature(
  message: SignableMessage,
  publicKey: string,
  signature: string,
): boolean {
  if (signature.length !== 128) {
    return false;
  }

  let r: Buffer, c: Buffer;
  try {
    r = Buffer.from(signature.slice(0, 64), 'hex');
    c = Buffer.from(signature.slice(64, 128), 'hex');
    if (r.length !== 32 || c.length !== 32) {
      return false;
    }
  } catch {
    return false;
  }

  let msgBuf: Buffer;
  try {
    msgBuf = normalizeMessage(message);
  } catch {
    return false;
  }

  const pubBuf: Buffer | false = isValidPublicKey(publicKey);
  if (pubBuf === false) {
    return false;
  }

  try {
    return checkSignature(msgBuf, pubBuf, { r, c });
  } catch {
    return false;
  }
}

export function parseSignature(signature: string): SchnorrSignature | null {
  if (signature.length !== 128) {
    return null;
  }
  try {
    const r: Buffer = Buffer.from(signature.slice(0, 64), 'hex');
    const c: Buffer = Buffer.from(signature.slice(64, 128), 'hex');
    if (r.length === 32 && c.length === 32) {
      return { r, c };
    }
  } catch {
    // ignore
  }
  return null;
}

export function serializeSignature(sig: SchnorrSignature): string {
  const { r, c } = sig;
  if (r.length !== 32 || c.length !== 32) {
    throw new Error('r and c must be 32-byte Buffers');
  }
  return r.toString('hex') + c.toString('hex');
}
