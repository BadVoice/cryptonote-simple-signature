/**
 * A message that can be signed: string, JSON-serializable object, or raw Buffer.
 */
export type SignableMessage = string | Record<string, any> | Buffer;

export interface SchnorrSignature {
  r: Buffer;
  c: Buffer;
}
