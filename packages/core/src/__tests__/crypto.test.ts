import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  sign,
  verify,
  hash,
  secureRandom,
  toHex,
  fromHex,
  toBase64Url,
  fromBase64Url,
  textToBytes,
  bytesToText,
} from '../crypto.js';

describe('generateKeyPair', () => {
  it('returns 32-byte private key and 32-byte public key', async () => {
    const kp = await generateKeyPair();
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.privateKey.length).toBe(32);
    expect(kp.publicKey.length).toBe(32);
  });

  it('generates unique keypairs each time', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    expect(toHex(kp1.publicKey)).not.toBe(toHex(kp2.publicKey));
    expect(toHex(kp1.privateKey)).not.toBe(toHex(kp2.privateKey));
  });
});

describe('sign / verify', () => {
  it('round-trips: a valid signature verifies', async () => {
    const kp = await generateKeyPair();
    const msg = textToBytes('hello sentinel');
    const sig = await sign(msg, kp.privateKey);
    const valid = await verify(sig, msg, kp.publicKey);
    expect(valid).toBe(true);
  });

  it('rejects a signature from a different key', async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const msg = textToBytes('hello sentinel');
    const sig = await sign(msg, kp1.privateKey);
    const valid = await verify(sig, msg, kp2.publicKey);
    expect(valid).toBe(false);
  });

  it('rejects a tampered message', async () => {
    const kp = await generateKeyPair();
    const msg = textToBytes('original');
    const sig = await sign(msg, kp.privateKey);
    const tampered = textToBytes('tampered');
    const valid = await verify(sig, tampered, kp.publicKey);
    expect(valid).toBe(false);
  });

  it('produces a 64-byte Ed25519 signature', async () => {
    const kp = await generateKeyPair();
    const sig = await sign(textToBytes('test'), kp.privateKey);
    expect(sig.length).toBe(64);
  });
});

describe('hash', () => {
  it('produces a 32-byte SHA-256 digest', () => {
    const digest = hash(textToBytes('hello'));
    expect(digest.length).toBe(32);
  });

  it('is deterministic', () => {
    const a = hash(textToBytes('same input'));
    const b = hash(textToBytes('same input'));
    expect(toHex(a)).toBe(toHex(b));
  });

  it('different inputs produce different hashes', () => {
    const a = hash(textToBytes('input a'));
    const b = hash(textToBytes('input b'));
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe('secureRandom', () => {
  it('returns bytes of the requested length', () => {
    expect(secureRandom(16).length).toBe(16);
    expect(secureRandom(32).length).toBe(32);
    expect(secureRandom(1).length).toBe(1);
  });

  it('produces different output each time', () => {
    const a = secureRandom(32);
    const b = secureRandom(32);
    expect(toHex(a)).not.toBe(toHex(b));
  });
});

describe('hex encoding', () => {
  it('round-trips', () => {
    const original = new Uint8Array([0, 1, 127, 128, 255]);
    const hex = toHex(original);
    const decoded = fromHex(hex);
    expect(Array.from(decoded)).toEqual(Array.from(original));
  });

  it('encodes known value', () => {
    expect(toHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe('deadbeef');
  });

  it('decodes known value', () => {
    const bytes = fromHex('cafebabe');
    expect(Array.from(bytes)).toEqual([0xca, 0xfe, 0xba, 0xbe]);
  });

  it('rejects odd-length hex strings', () => {
    expect(() => fromHex('abc')).toThrow('Invalid hex string');
  });
});

describe('base64url encoding', () => {
  it('round-trips', () => {
    const original = secureRandom(64);
    const encoded = toBase64Url(original);
    const decoded = fromBase64Url(encoded);
    expect(toHex(decoded)).toBe(toHex(original));
  });

  it('does not contain +, /, or = characters', () => {
    // Generate multiple to increase chance of hitting padding/special chars
    for (let i = 0; i < 10; i++) {
      const encoded = toBase64Url(secureRandom(33)); // 33 bytes forces padding
      expect(encoded).not.toMatch(/[+/=]/);
    }
  });
});

describe('text encoding', () => {
  it('round-trips ASCII', () => {
    const text = 'Hello, Sentinel!';
    expect(bytesToText(textToBytes(text))).toBe(text);
  });

  it('round-trips unicode', () => {
    const text = '🛡️ Agent Trust Layer';
    expect(bytesToText(textToBytes(text))).toBe(text);
  });
});
