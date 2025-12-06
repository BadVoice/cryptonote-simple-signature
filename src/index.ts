export {
  createSignature,
  verifySignature,
  parseSignature,
  serializeSignature,
} from './crypto/signature-lib';

export type {
  SignableMessage,
  SchnorrSignature,
} from './crypto/types';
