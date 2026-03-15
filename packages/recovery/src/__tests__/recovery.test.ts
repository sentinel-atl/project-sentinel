import { describe, it, expect } from 'vitest';
import { splitSecret, reconstructSecret } from '../index.js';
import { secureRandom, toHex } from '@sentinel-atl/core';

describe('Shamir Secret Sharing', () => {
  describe('splitSecret / reconstructSecret', () => {
    it('round-trips a 32-byte secret (3-of-5)', () => {
      const secret = secureRandom(32);
      const shares = splitSecret(secret, 5, 3);

      expect(shares).toHaveLength(5);
      expect(shares[0].threshold).toBe(3);
      expect(shares[0].totalShares).toBe(5);

      // Use first 3 shares
      const recovered = reconstructSecret(shares.slice(0, 3));
      expect(toHex(recovered)).toBe(toHex(secret));
    });

    it('recovers from any 3 of 5 shares', () => {
      const secret = secureRandom(32);
      const shares = splitSecret(secret, 5, 3);

      // Try different combinations of 3 shares
      const combinations = [
        [0, 1, 2],
        [0, 2, 4],
        [1, 3, 4],
        [2, 3, 4],
        [0, 1, 4],
      ];

      for (const combo of combinations) {
        const selected = combo.map((i) => shares[i]);
        const recovered = reconstructSecret(selected);
        expect(toHex(recovered)).toBe(toHex(secret));
      }
    });

    it('round-trips a 64-byte secret (2-of-3)', () => {
      const secret = secureRandom(64);
      const shares = splitSecret(secret, 3, 2);
      const recovered = reconstructSecret(shares.slice(0, 2));
      expect(toHex(recovered)).toBe(toHex(secret));
    });

    it('round-trips a 1-byte secret', () => {
      const secret = new Uint8Array([42]);
      const shares = splitSecret(secret, 3, 2);
      const recovered = reconstructSecret(shares.slice(0, 2));
      expect(toHex(recovered)).toBe(toHex(secret));
    });

    it('round-trips a secret of all zeros', () => {
      const secret = new Uint8Array(32); // all zeros
      const shares = splitSecret(secret, 5, 3);
      const recovered = reconstructSecret(shares.slice(0, 3));
      expect(toHex(recovered)).toBe(toHex(secret));
    });

    it('round-trips a secret of all 0xFF', () => {
      const secret = new Uint8Array(32).fill(0xff);
      const shares = splitSecret(secret, 5, 3);
      const recovered = reconstructSecret(shares.slice(0, 3));
      expect(toHex(recovered)).toBe(toHex(secret));
    });
  });

  describe('edge cases and validation', () => {
    it('rejects threshold > totalShares', () => {
      expect(() => splitSecret(secureRandom(32), 3, 5)).toThrow('Threshold cannot exceed');
    });

    it('rejects threshold < 2', () => {
      expect(() => splitSecret(secureRandom(32), 5, 1)).toThrow('Threshold must be at least 2');
    });

    it('rejects > 255 shares', () => {
      expect(() => splitSecret(secureRandom(32), 256, 3)).toThrow('Maximum 255 shares');
    });

    it('rejects reconstruction with 0 shares', () => {
      expect(() => reconstructSecret([])).toThrow('No shares provided');
    });

    it('rejects reconstruction below threshold', () => {
      const shares = splitSecret(secureRandom(32), 5, 3);
      expect(() => reconstructSecret(shares.slice(0, 2))).toThrow('Need at least 3 shares');
    });

    it('rejects duplicate share indices', () => {
      const shares = splitSecret(secureRandom(32), 5, 3);
      expect(() => reconstructSecret([shares[0], shares[0], shares[1]])).toThrow('Duplicate share indices');
    });
  });

  describe('security properties', () => {
    it('produces unique shares (not identical)', () => {
      const secret = secureRandom(32);
      const shares = splitSecret(secret, 5, 3);
      const datas = new Set(shares.map((s) => s.data));
      expect(datas.size).toBe(5);
    });

    it('fewer than threshold shares produce wrong output', () => {
      const secret = secureRandom(32);
      const shares = splitSecret(secret, 5, 3);

      // 2 shares should NOT reconstruct correctly (with high probability)
      // We lower the threshold check by modifying the shares
      const hackedShares = shares.slice(0, 2).map((s) => ({ ...s, threshold: 2 }));
      const wrong = reconstructSecret(hackedShares);
      // With overwhelming probability, this won't match
      expect(toHex(wrong)).not.toBe(toHex(secret));
    });
  });
});
