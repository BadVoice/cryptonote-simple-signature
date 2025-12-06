import { createSignature, verifySignature, parseSignature } from '../src';

describe('simple signature', () => {
  const secretSpendKey = '80b3e96a3eb765332b0fd3e44e0fefa58747a70025bf91aa4a7b758ab6f5590d';
  const publicSpendKey = 'b3eee2376f32bf2bfb5cf9c023f569380c84ac8c64ddc8f7c109730dc8e97d7a';

  const rawMessageArray = [
    'post',
    'http://localhost:3333/api/v1/auth/register',
    'Fri, 21 Feb 2025 03:04:19 GMT',
    '48c35187e5b6f2bb39214e1311d3d50f9d480bda56e7563fac689a1d867992a4',
  ];
  const rawMessageString = rawMessageArray.join(' ');
  const rawMessageObject = {
    method: 'post',
    url: 'http://localhost:3333/api/v1/auth/register',
    timestamp: 'Fri, 21 Feb 2025 03:04:19 GMT',
    bodyHash: '48c35187e5b6f2bb39214e1311d3d50f9d480bda56e7563fac689a1d867992a4',
  };
  const rawMessageBuffer = Buffer.from(rawMessageString, 'utf8');

  describe('Happy path: valid signatures', () => {
    const testCases = [
      { name: 'string', message: rawMessageString },
      { name: 'string array (joined)', message: rawMessageArray },
      { name: 'object', message: rawMessageObject },
      { name: 'Buffer', message: rawMessageBuffer },
    ];

    testCases.forEach(({ name, message }) => {
      it(`creates and verifies signature for ${name}`, () => {
        const sig = createSignature(message, secretSpendKey);
        expect(typeof sig).toBe('string');
        expect(sig).toHaveLength(128);
        expect(verifySignature(message, publicSpendKey, sig)).toBe(true);
      });
    });

    it('creates different signatures on each call (non-deterministic)', () => {
      const sig1 = createSignature(rawMessageString, secretSpendKey);
      const sig2 = createSignature(rawMessageString, secretSpendKey);
      expect(sig1).not.toBe(sig2); // nonce is random -> signatures differ
    });

    it('10 iterations all valid', () => {
      for (let i = 0; i < 10; i++) {
        const sig = createSignature(rawMessageString, secretSpendKey);
        expect(verifySignature(rawMessageString, publicSpendKey, sig)).toBe(true);
      }
    });
  });

  describe('Verification edge cases', () => {
    let validSignature: string;

    beforeAll(() => {
      validSignature = createSignature(rawMessageString, secretSpendKey);
    });

    it('fails if message is tampered', () => {
      const tampered = rawMessageString + 'x';
      expect(verifySignature(tampered, publicSpendKey, validSignature)).toBe(false);
    });

    it('fails if public key is wrong', () => {
      const wrongPubKey = 'a'.repeat(64);
      expect(verifySignature(rawMessageString, wrongPubKey, validSignature)).toBe(false);
    });

    it('fails if signature is corrupted', () => {
      const corrupted = validSignature.slice(0, -1) + '0';
      expect(verifySignature(rawMessageString, publicSpendKey, corrupted)).toBe(false);
    });

    it('fails if signature length < 128', () => {
      expect(verifySignature(rawMessageString, publicSpendKey, 'short')).toBe(false);
      expect(verifySignature(rawMessageString, publicSpendKey, validSignature + '00')).toBe(false);
    });

    it('fails if signature contains invalid hex', () => {
      const invalid = 'x'.repeat(128);
      expect(verifySignature(rawMessageString, publicSpendKey, invalid)).toBe(false);
    });

    it('accepts Buffer message that matches original signed data', () => {
      const sig = createSignature(rawMessageBuffer, secretSpendKey);
      expect(verifySignature(rawMessageBuffer, publicSpendKey, sig)).toBe(true);
    });
  });

  describe('Input validation', () => {
    it('throws on invalid private key length', () => {
      expect(() => createSignature('msg', '123')).toThrow('Invalid private key');
    });

    it('throws on invalid private key format', () => {
      expect(() => createSignature('msg', 'x'.repeat(64))).toThrow('Invalid private key');
    });
  });

  describe('parseSignature utility', () => {
    it('parses valid signature', () => {
      const sig = createSignature('test', secretSpendKey);
      const parsed = parseSignature(sig);
      expect(parsed).not.toBeNull();
      if (parsed) {
        expect(Buffer.isBuffer(parsed.r)).toBe(true);
        expect(Buffer.isBuffer(parsed.c)).toBe(true);
        expect(parsed.r).toHaveLength(32);
        expect(parsed.c).toHaveLength(32);
      }
    });

    it('returns null for invalid signature', () => {
      expect(parseSignature('short')).toBeNull();
      expect(parseSignature('x'.repeat(128))).toBeNull();
      expect(parseSignature('a'.repeat(127))).toBeNull();
    });
  });
});
