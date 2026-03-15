/**
 * @sentinel/reputation — Weighted Trust Scoring Engine
 *
 * Unlike simple "thumbs up" systems, Sentinel reputation is:
 * - Weighted: vouches from high-reputation agents count more
 * - Time-decayed: stale vouches lose influence (90-day half-life)
 * - Sybil-resistant: unverified agents have capped influence
 * - Negative-capable: bad agents get penalized, not just ignored
 * - Rate-limited: 1 vouch per peer per 24h, burst detection
 *
 * Score range: 0–100. New agents start at 50 (neutral).
 */

import type { NegativeReason } from '@sentinel/core';

export interface Vouch {
  /** DID of the agent issuing the vouch */
  voucherDid: string;
  /** DID of the agent being vouched for */
  subjectDid: string;
  /** Positive or negative */
  polarity: 'positive' | 'negative';
  /** Weight: 0-1, based on voucher's own reputation */
  weight: number;
  /** Whether the voucher has a verified human principal */
  voucherVerified: boolean;
  /** Reason (for negative vouches) */
  reason?: NegativeReason;
  /** ISO 8601 timestamp */
  timestamp: string;
}

export interface ReputationScore {
  did: string;
  score: number; // 0-100
  totalVouches: number;
  positiveVouches: number;
  negativeVouches: number;
  isQuarantined: boolean;
  quarantineReason?: string;
  lastUpdated: string;
  source: 'live' | 'cached' | 'unavailable';
}

export interface VouchRateLimitResult {
  allowed: boolean;
  reason?: string;
  retryAfterMs?: number;
}

const NEUTRAL_SCORE = 50;
const HALF_LIFE_DAYS = 90;
const HALF_LIFE_MS = HALF_LIFE_DAYS * 24 * 60 * 60 * 1000;
const NEGATIVE_WEIGHT_MULTIPLIER = 2;
const UNVERIFIED_AGENT_CAP = 0.3; // Max influence of unverified agents
const QUARANTINE_THRESHOLD = 3; // Negative vouches from independent verified agents
const MAX_VOUCHES_PER_PEER_PER_DAY = 1;
const BURST_THRESHOLD_PER_HOUR = 10;

/**
 * Compute time-decay factor for a vouch.
 * Exponential decay with 90-day half-life.
 */
function timeDecay(vouchTimestamp: string, now: number = Date.now()): number {
  const age = now - new Date(vouchTimestamp).getTime();
  return Math.pow(0.5, age / HALF_LIFE_MS);
}

export class ReputationEngine {
  /** All vouches indexed by subject DID */
  private vouches = new Map<string, Vouch[]>();
  /** Rate limit tracking: `${voucherDid}:${subjectDid}` → last vouch time */
  private vouchTimestamps = new Map<string, number>();
  /** Hourly vouch counts per voucher for burst detection */
  private hourlyVouchCounts = new Map<string, { count: number; windowStart: number }>();

  /**
   * Check if a vouch is allowed (rate limits + self-vouch rejection).
   */
  checkVouchRateLimit(voucherDid: string, subjectDid: string): VouchRateLimitResult {
    // Self-vouch rejection
    if (voucherDid === subjectDid) {
      return { allowed: false, reason: 'Self-vouching is not allowed' };
    }

    // Per-peer rate limit: 1 vouch per peer per 24h
    const pairKey = `${voucherDid}:${subjectDid}`;
    const lastVouch = this.vouchTimestamps.get(pairKey);
    if (lastVouch) {
      const elapsed = Date.now() - lastVouch;
      const dayMs = 24 * 60 * 60 * 1000;
      if (elapsed < dayMs) {
        return {
          allowed: false,
          reason: 'Rate limit: 1 vouch per peer per 24 hours',
          retryAfterMs: dayMs - elapsed,
        };
      }
    }

    // Burst detection: >10 vouches/hour triggers suppression
    const hourly = this.hourlyVouchCounts.get(voucherDid);
    const now = Date.now();
    if (hourly && now - hourly.windowStart < 3600_000) {
      if (hourly.count >= BURST_THRESHOLD_PER_HOUR) {
        return {
          allowed: false,
          reason: 'Burst vouch pattern detected. Temporarily suppressed.',
          retryAfterMs: 3600_000 - (now - hourly.windowStart),
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Record a vouch (positive or negative).
   */
  addVouch(vouch: Vouch): VouchRateLimitResult {
    const rateCheck = this.checkVouchRateLimit(vouch.voucherDid, vouch.subjectDid);
    if (!rateCheck.allowed) return rateCheck;

    // Record the vouch
    const existing = this.vouches.get(vouch.subjectDid) ?? [];
    existing.push(vouch);
    this.vouches.set(vouch.subjectDid, existing);

    // Update rate limit tracking
    const pairKey = `${vouch.voucherDid}:${vouch.subjectDid}`;
    this.vouchTimestamps.set(pairKey, Date.now());

    // Update hourly count
    const now = Date.now();
    const hourly = this.hourlyVouchCounts.get(vouch.voucherDid);
    if (!hourly || now - hourly.windowStart >= 3600_000) {
      this.hourlyVouchCounts.set(vouch.voucherDid, { count: 1, windowStart: now });
    } else {
      hourly.count++;
    }

    return { allowed: true };
  }

  /**
   * Compute reputation score for an agent.
   *
   * Formula: score = 50 + Σ(polarity × vouch_weight × time_decay × verified_factor)
   * Clamped to [0, 100].
   *
   * Negative vouches carry 2x weight (safety bias).
   * Unverified vouchers capped at 0.3 influence.
   */
  computeScore(did: string): ReputationScore {
    const agentVouches = this.vouches.get(did) ?? [];
    const now = Date.now();

    let weightedSum = 0;
    let positiveCount = 0;
    let negativeCount = 0;
    let independentVerifiedNegatives = new Set<string>();

    for (const vouch of agentVouches) {
      const decay = timeDecay(vouch.timestamp, now);
      const verifiedFactor = vouch.voucherVerified
        ? vouch.weight
        : Math.min(vouch.weight, UNVERIFIED_AGENT_CAP);

      const effectiveWeight = decay * verifiedFactor;

      if (vouch.polarity === 'positive') {
        weightedSum += effectiveWeight;
        positiveCount++;
      } else {
        weightedSum -= effectiveWeight * NEGATIVE_WEIGHT_MULTIPLIER;
        negativeCount++;
        if (vouch.voucherVerified) {
          independentVerifiedNegatives.add(vouch.voucherDid);
        }
      }
    }

    // Normalize: weightedSum is roughly in [-N, N], scale to [0, 100] around 50
    const rawScore = NEUTRAL_SCORE + weightedSum * 10;
    const score = Math.max(0, Math.min(100, Math.round(rawScore * 100) / 100));

    // Quarantine check
    const isQuarantined = independentVerifiedNegatives.size >= QUARANTINE_THRESHOLD;

    return {
      did,
      score,
      totalVouches: agentVouches.length,
      positiveVouches: positiveCount,
      negativeVouches: negativeCount,
      isQuarantined,
      quarantineReason: isQuarantined
        ? `${independentVerifiedNegatives.size} independent verified negative vouches`
        : undefined,
      lastUpdated: new Date().toISOString(),
      source: 'live',
    };
  }

  /**
   * Get all vouches for a DID (for audit/dispute resolution).
   */
  getVouches(did: string): Vouch[] {
    return this.vouches.get(did) ?? [];
  }

  /**
   * Create a "cached" score for offline/degraded mode.
   */
  static unavailableScore(did: string): ReputationScore {
    return {
      did,
      score: NEUTRAL_SCORE,
      totalVouches: 0,
      positiveVouches: 0,
      negativeVouches: 0,
      isQuarantined: false,
      lastUpdated: new Date().toISOString(),
      source: 'unavailable',
    };
  }
}
