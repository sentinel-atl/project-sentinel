/**
 * Rate-limit response headers per RFC 6585 / draft-ietf-httpapi-ratelimit-headers.
 *
 * Adds standard headers so clients know their quota status:
 *   RateLimit-Limit:     total requests allowed per window
 *   RateLimit-Remaining: requests remaining in current window
 *   RateLimit-Reset:     seconds until window resets
 *   Retry-After:         seconds to wait (only on 429)
 */

import type { ServerResponse } from 'node:http';

// ─── Types ───────────────────────────────────────────────────────────

export interface RateLimitInfo {
  /** Maximum requests per window */
  limit: number;
  /** Remaining requests in current window */
  remaining: number;
  /** When the window resets (Unix timestamp in seconds) */
  resetAt: number;
}

// ─── Header Application ──────────────────────────────────────────────

/**
 * Set rate limit headers on a response.
 */
export function setRateLimitHeaders(res: ServerResponse, info: RateLimitInfo): void {
  const retryAfter = Math.max(0, Math.ceil(info.resetAt - Date.now() / 1000));

  res.setHeader('RateLimit-Limit', String(info.limit));
  res.setHeader('RateLimit-Remaining', String(Math.max(0, info.remaining)));
  res.setHeader('RateLimit-Reset', String(retryAfter));
}

/**
 * Send a 429 Too Many Requests response with Retry-After header.
 */
export function sendRateLimited(res: ServerResponse, info: RateLimitInfo): void {
  const retryAfter = Math.max(1, Math.ceil(info.resetAt - Date.now() / 1000));

  res.writeHead(429, {
    'Content-Type': 'application/json',
    'Retry-After': String(retryAfter),
    'RateLimit-Limit': String(info.limit),
    'RateLimit-Remaining': '0',
    'RateLimit-Reset': String(retryAfter),
  });
  res.end(JSON.stringify({
    error: 'Too Many Requests',
    retryAfter,
  }));
}

// ─── Enhanced Rate Limiter ──────────────────────────────────────────

/**
 * Production-grade rate limiter with header support.
 */
export class RateLimiter {
  private windows = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private maxRequests: number,
    private windowMs: number
  ) {}

  /**
   * Check if a request is allowed and return rate limit info.
   */
  check(key: string): { allowed: boolean; info: RateLimitInfo } {
    const now = Date.now();
    const entry = this.windows.get(key);

    if (!entry || now >= entry.resetAt) {
      const resetAt = now + this.windowMs;
      this.windows.set(key, { count: 1, resetAt });
      return {
        allowed: true,
        info: {
          limit: this.maxRequests,
          remaining: this.maxRequests - 1,
          resetAt: Math.ceil(resetAt / 1000),
        },
      };
    }

    if (entry.count >= this.maxRequests) {
      return {
        allowed: false,
        info: {
          limit: this.maxRequests,
          remaining: 0,
          resetAt: Math.ceil(entry.resetAt / 1000),
        },
      };
    }

    entry.count++;
    return {
      allowed: true,
      info: {
        limit: this.maxRequests,
        remaining: this.maxRequests - entry.count,
        resetAt: Math.ceil(entry.resetAt / 1000),
      },
    };
  }

  /**
   * Clean up expired windows to prevent memory leaks.
   * Call periodically (e.g., every 5 minutes).
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;
    for (const [key, entry] of this.windows) {
      if (now >= entry.resetAt) {
        this.windows.delete(key);
        removed++;
      }
    }
    return removed;
  }
}

/**
 * Parse a rate limit spec like "100/min" into limiter parameters.
 */
export function parseRateLimit(spec: string): { max: number; windowMs: number } {
  const match = spec.match(/^(\d+)\/(min|hour|day)$/);
  if (!match) return { max: 100, windowMs: 60_000 };

  const max = parseInt(match[1]);
  const windowMs = match[2] === 'min' ? 60_000
    : match[2] === 'hour' ? 3_600_000
    : 86_400_000;

  return { max, windowMs };
}

// ─── Distributed Rate Limiter ───────────────────────────────────────

/**
 * SentinelStore-compatible interface subset needed for distributed rate limiting.
 */
interface RateLimitStore {
  increment(key: string, by?: number): Promise<number>;
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;
}

/**
 * Distributed rate limiter backed by an external store (Redis, Postgres, etc.).
 * Uses atomic increment for multi-instance deployments.
 */
export class DistributedRateLimiter {
  private prefix: string;

  constructor(
    private store: RateLimitStore,
    private maxRequests: number,
    private windowMs: number,
    prefix = 'rl:'
  ) {
    this.prefix = prefix;
  }

  async check(key: string): Promise<{ allowed: boolean; info: RateLimitInfo }> {
    const windowId = Math.floor(Date.now() / this.windowMs);
    const storeKey = `${this.prefix}${key}:${windowId}`;
    const ttlSeconds = Math.ceil(this.windowMs / 1000);
    const resetAt = Math.ceil(((windowId + 1) * this.windowMs) / 1000);

    const count = await this.store.increment(storeKey);
    // Set TTL on first increment
    if (count === 1) {
      await this.store.set(storeKey, '1', ttlSeconds);
    }

    if (count > this.maxRequests) {
      return {
        allowed: false,
        info: { limit: this.maxRequests, remaining: 0, resetAt },
      };
    }

    return {
      allowed: true,
      info: {
        limit: this.maxRequests,
        remaining: this.maxRequests - count,
        resetAt,
      },
    };
  }
}
