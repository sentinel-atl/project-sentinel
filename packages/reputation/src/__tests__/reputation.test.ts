import { describe, it, expect } from 'vitest';
import { ReputationEngine } from '../index.js';

function makeVouch(overrides: Partial<Parameters<ReputationEngine['addVouch']>[0]> = {}) {
  return {
    voucherDid: 'did:key:z6MkVoucher',
    subjectDid: 'did:key:z6MkSubject',
    polarity: 'positive' as const,
    weight: 0.8,
    voucherVerified: true,
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('ReputationEngine', () => {
  describe('addVouch', () => {
    it('accepts a valid vouch', () => {
      const engine = new ReputationEngine();
      const result = engine.addVouch(makeVouch());
      expect(result.allowed).toBe(true);
    });

    it('rejects self-vouching', () => {
      const engine = new ReputationEngine();
      const result = engine.addVouch(
        makeVouch({ voucherDid: 'did:key:z6MkSame', subjectDid: 'did:key:z6MkSame' })
      );
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Self-vouching');
    });

    it('rate-limits: 1 vouch per peer per 24h', () => {
      const engine = new ReputationEngine();
      const vouch = makeVouch();
      engine.addVouch(vouch);

      const second = engine.addVouch(vouch);
      expect(second.allowed).toBe(false);
      expect(second.reason).toContain('Rate limit');
    });

    it('allows vouching for different subjects', () => {
      const engine = new ReputationEngine();
      const r1 = engine.addVouch(makeVouch({ subjectDid: 'did:key:z6MkA' }));
      const r2 = engine.addVouch(makeVouch({ subjectDid: 'did:key:z6MkB' }));
      expect(r1.allowed).toBe(true);
      expect(r2.allowed).toBe(true);
    });
  });

  describe('computeScore', () => {
    it('returns neutral 50 for unknown agents', () => {
      const engine = new ReputationEngine();
      const score = engine.computeScore('did:key:z6MkUnknown');
      expect(score.score).toBe(50);
      expect(score.totalVouches).toBe(0);
      expect(score.isQuarantined).toBe(false);
    });

    it('increases score with positive vouches', () => {
      const engine = new ReputationEngine();
      engine.addVouch(makeVouch({
        voucherDid: 'did:key:z6MkV1',
        subjectDid: 'did:key:z6MkTarget',
        polarity: 'positive',
        weight: 0.8,
      }));
      const score = engine.computeScore('did:key:z6MkTarget');
      expect(score.score).toBeGreaterThan(50);
      expect(score.positiveVouches).toBe(1);
    });

    it('decreases score with negative vouches', () => {
      const engine = new ReputationEngine();
      engine.addVouch(makeVouch({
        voucherDid: 'did:key:z6MkV1',
        subjectDid: 'did:key:z6MkTarget',
        polarity: 'negative',
        weight: 0.8,
        reason: 'scope_violation',
      }));
      const score = engine.computeScore('did:key:z6MkTarget');
      expect(score.score).toBeLessThan(50);
      expect(score.negativeVouches).toBe(1);
    });

    it('negative vouches weigh 2x (safety bias)', () => {
      const engine = new ReputationEngine();

      // One positive
      engine.addVouch(makeVouch({
        voucherDid: 'did:key:z6MkV1',
        subjectDid: 'did:key:z6MkTarget',
        polarity: 'positive',
        weight: 0.5,
      }));

      // One negative with same weight — should dominate
      engine.addVouch(makeVouch({
        voucherDid: 'did:key:z6MkV2',
        subjectDid: 'did:key:z6MkTarget',
        polarity: 'negative',
        weight: 0.5,
      }));

      const score = engine.computeScore('did:key:z6MkTarget');
      expect(score.score).toBeLessThan(50); // Negative wins due to 2x multiplier
    });

    it('caps unverified agent influence at 0.3', () => {
      const engine = new ReputationEngine();

      // High-weight vouch from unverified agent
      engine.addVouch(makeVouch({
        voucherDid: 'did:key:z6MkUnverified',
        subjectDid: 'did:key:z6MkTarget',
        polarity: 'positive',
        weight: 1.0,
        voucherVerified: false,
      }));

      const scoreUnverified = engine.computeScore('did:key:z6MkTarget');

      // Same vouch from verified agent
      const engine2 = new ReputationEngine();
      engine2.addVouch(makeVouch({
        voucherDid: 'did:key:z6MkVerified',
        subjectDid: 'did:key:z6MkTarget2',
        polarity: 'positive',
        weight: 1.0,
        voucherVerified: true,
      }));

      const scoreVerified = engine2.computeScore('did:key:z6MkTarget2');

      // Verified should have more impact
      expect(scoreVerified.score).toBeGreaterThan(scoreUnverified.score);
    });

    it('quarantines agent with 3+ independent verified negative vouches', () => {
      const engine = new ReputationEngine();
      const subject = 'did:key:z6MkBadAgent';

      // 3 independent verified negative vouches
      for (let i = 1; i <= 3; i++) {
        engine.addVouch(makeVouch({
          voucherDid: `did:key:z6MkVerifiedV${i}`,
          subjectDid: subject,
          polarity: 'negative',
          weight: 0.7,
          voucherVerified: true,
          reason: 'scope_violation',
        }));
      }

      const score = engine.computeScore(subject);
      expect(score.isQuarantined).toBe(true);
      expect(score.quarantineReason).toContain('3');
    });

    it('does not quarantine with only 2 negatives', () => {
      const engine = new ReputationEngine();
      const subject = 'did:key:z6MkBorderline';

      for (let i = 1; i <= 2; i++) {
        engine.addVouch(makeVouch({
          voucherDid: `did:key:z6MkV${i}`,
          subjectDid: subject,
          polarity: 'negative',
          weight: 0.7,
          voucherVerified: true,
        }));
      }

      const score = engine.computeScore(subject);
      expect(score.isQuarantined).toBe(false);
    });
  });

  describe('getVouches', () => {
    it('returns all vouches for a DID', () => {
      const engine = new ReputationEngine();
      engine.addVouch(makeVouch({
        voucherDid: 'did:key:z6MkV1',
        subjectDid: 'did:key:z6MkTarget',
      }));
      engine.addVouch(makeVouch({
        voucherDid: 'did:key:z6MkV2',
        subjectDid: 'did:key:z6MkTarget',
      }));

      const vouches = engine.getVouches('did:key:z6MkTarget');
      expect(vouches).toHaveLength(2);
    });

    it('returns empty array for unknown DID', () => {
      const engine = new ReputationEngine();
      expect(engine.getVouches('did:key:z6MkUnknown')).toEqual([]);
    });
  });

  describe('unavailableScore', () => {
    it('returns a neutral score', () => {
      const score = ReputationEngine.unavailableScore('did:key:z6MkOffline');
      expect(score.score).toBe(50);
      expect(score.source).toBe('unavailable');
      expect(score.isQuarantined).toBe(false);
    });
  });
});
