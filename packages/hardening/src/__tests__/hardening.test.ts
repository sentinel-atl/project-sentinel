import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { IncomingMessage, ServerResponse } from 'node:http';
import { mkdtemp, writeFile, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { EventEmitter } from 'node:events';
import {
  authenticate, hasScope, authConfigFromEnv, sendUnauthorized, sendForbidden,
  type AuthConfig,
} from '../auth.js';
import {
  applyCors, defaultCorsConfig, corsConfigFromEnv,
  type CorsConfig,
} from '../cors.js';
import {
  RateLimiter, setRateLimitHeaders, sendRateLimited, parseRateLimit,
} from '../rate-limit.js';
import {
  rotateIfNeeded, cleanupRotatedFiles,
} from '../audit-rotation.js';
import {
  applySecurityHeaders,
} from '../security-headers.js';

// ─── Helpers ──────────────────────────────────────────────────────────

function mockReq(opts: {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
}): IncomingMessage {
  const req = new EventEmitter() as IncomingMessage;
  req.method = opts.method ?? 'GET';
  req.url = opts.url ?? '/';
  req.headers = opts.headers ?? {};
  return req;
}

function mockRes(): ServerResponse & { _status?: number; _headers: Record<string, string>; _body: string } {
  const res = new EventEmitter() as any;
  res._headers = {};
  res._body = '';
  res._status = undefined;
  res.setHeader = (key: string, val: string) => { res._headers[key.toLowerCase()] = val; };
  res.getHeader = (key: string) => res._headers[key.toLowerCase()];
  res.writeHead = (status: number, headers?: Record<string, string>) => {
    res._status = status;
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        res._headers[k.toLowerCase()] = v;
      }
    }
  };
  res.write = (data: string) => { res._body += data; };
  res.end = (data?: string) => { if (data) res._body += data; };
  return res;
}

// ═══════════════════════════════════════════════════════════════════════
//  Auth
// ═══════════════════════════════════════════════════════════════════════

describe('authenticate', () => {
  const config: AuthConfig = {
    enabled: true,
    keys: [
      { key: 'test-key-read', scopes: ['read'], label: 'reader' },
      { key: 'test-key-admin', scopes: ['admin'], label: 'admin' },
      { key: 'test-key-rw', scopes: ['read', 'write'], label: 'readwrite' },
    ],
    publicPaths: ['/health', '/badge'],
  };

  it('allows requests when auth is disabled', () => {
    const req = mockReq({ headers: {} });
    const result = authenticate(req, { enabled: false, keys: [] });
    expect(result.authenticated).toBe(true);
  });

  it('allows public paths without key', () => {
    const req = mockReq({ url: '/health' });
    const result = authenticate(req, config);
    expect(result.authenticated).toBe(true);
  });

  it('rejects missing key on protected path', () => {
    const req = mockReq({ url: '/api/certificates' });
    const result = authenticate(req, config);
    expect(result.authenticated).toBe(false);
    expect(result.error).toContain('Missing');
  });

  it('authenticates via Bearer token', () => {
    const req = mockReq({
      url: '/api/data',
      headers: { authorization: 'Bearer test-key-read' },
    });
    const result = authenticate(req, config);
    expect(result.authenticated).toBe(true);
    expect(result.key?.label).toBe('reader');
  });

  it('authenticates via X-API-Key header', () => {
    const req = mockReq({
      url: '/api/data',
      headers: { 'x-api-key': 'test-key-admin' },
    });
    const result = authenticate(req, config);
    expect(result.authenticated).toBe(true);
    expect(result.key?.scopes).toContain('admin');
  });

  it('authenticates via query param', () => {
    const req = mockReq({ url: '/api/data?apiKey=test-key-rw' });
    const result = authenticate(req, config);
    expect(result.authenticated).toBe(true);
    expect(result.key?.scopes).toEqual(['read', 'write']);
  });

  it('rejects invalid key', () => {
    const req = mockReq({
      url: '/api/data',
      headers: { 'x-api-key': 'wrong-key' },
    });
    const result = authenticate(req, config);
    expect(result.authenticated).toBe(false);
    expect(result.error).toContain('Invalid');
  });
});

describe('hasScope', () => {
  it('returns true for admin on any scope', () => {
    expect(hasScope({ authenticated: true, key: { key: 'k', scopes: ['admin'] } }, 'write')).toBe(true);
    expect(hasScope({ authenticated: true, key: { key: 'k', scopes: ['admin'] } }, 'read')).toBe(true);
  });

  it('returns false when scope missing', () => {
    expect(hasScope({ authenticated: true, key: { key: 'k', scopes: ['read'] } }, 'write')).toBe(false);
  });

  it('returns true for matching scope', () => {
    expect(hasScope({ authenticated: true, key: { key: 'k', scopes: ['read', 'write'] } }, 'write')).toBe(true);
  });

  it('returns true when auth disabled (no key)', () => {
    expect(hasScope({ authenticated: true }, 'admin')).toBe(true);
  });

  it('returns false when not authenticated', () => {
    expect(hasScope({ authenticated: false }, 'read')).toBe(false);
  });
});

describe('sendUnauthorized / sendForbidden', () => {
  it('sends 401 with WWW-Authenticate', () => {
    const res = mockRes();
    sendUnauthorized(res, { enabled: true, keys: [], realm: 'TestRealm' }, 'Bad key');
    expect(res._status).toBe(401);
    expect(res._headers['www-authenticate']).toContain('TestRealm');
    expect(res._body).toContain('Bad key');
  });

  it('sends 403 for forbidden', () => {
    const res = mockRes();
    sendForbidden(res, 'No write access');
    expect(res._status).toBe(403);
    expect(res._body).toContain('No write access');
  });
});

describe('authConfigFromEnv', () => {
  afterEach(() => { delete process.env['SENTINEL_API_KEYS']; });

  it('returns disabled when env not set', () => {
    const cfg = authConfigFromEnv();
    expect(cfg.enabled).toBe(false);
  });

  it('parses keys from env', () => {
    process.env['SENTINEL_API_KEYS'] = 'mykey:read,write;admin-key:admin';
    const cfg = authConfigFromEnv();
    expect(cfg.enabled).toBe(true);
    expect(cfg.keys).toHaveLength(2);
    expect(cfg.keys[0].key).toBe('mykey');
    expect(cfg.keys[0].scopes).toEqual(['read', 'write']);
    expect(cfg.keys[1].scopes).toEqual(['admin']);
  });
});

// ═══════════════════════════════════════════════════════════════════════
//  CORS
// ═══════════════════════════════════════════════════════════════════════

describe('applyCors', () => {
  const strictConfig: CorsConfig = {
    allowedOrigins: ['https://app.example.com'],
    allowedMethods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 3600,
  };

  it('allows matching origin', () => {
    const req = mockReq({ headers: { origin: 'https://app.example.com' } });
    const res = mockRes();
    const isPreflight = applyCors(req, res, strictConfig);
    expect(isPreflight).toBe(false);
    expect(res._headers['access-control-allow-origin']).toBe('https://app.example.com');
    expect(res._headers['vary']).toBe('Origin');
  });

  it('blocks non-matching origin', () => {
    const req = mockReq({ headers: { origin: 'https://evil.com' } });
    const res = mockRes();
    applyCors(req, res, strictConfig);
    expect(res._headers['access-control-allow-origin']).toBeUndefined();
  });

  it('handles preflight with 204', () => {
    const req = mockReq({ method: 'OPTIONS', headers: { origin: 'https://app.example.com' } });
    const res = mockRes();
    const isPreflight = applyCors(req, res, strictConfig);
    expect(isPreflight).toBe(true);
    expect(res._status).toBe(204);
    expect(res._headers['access-control-allow-methods']).toBe('GET, POST');
    expect(res._headers['access-control-max-age']).toBe('3600');
  });

  it('wildcard mode sets * origin', () => {
    const req = mockReq({ headers: { origin: 'https://anything.com' } });
    const res = mockRes();
    applyCors(req, res, defaultCorsConfig());
    expect(res._headers['access-control-allow-origin']).toBe('*');
  });

  it('same-origin request (no Origin header) sets no CORS header', () => {
    const req = mockReq({ headers: {} });
    const res = mockRes();
    applyCors(req, res, strictConfig);
    expect(res._headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('corsConfigFromEnv', () => {
  afterEach(() => { delete process.env['SENTINEL_CORS_ORIGINS']; });

  it('defaults to wildcard', () => {
    const cfg = corsConfigFromEnv();
    expect(cfg.allowedOrigins).toEqual(['*']);
  });

  it('parses origins from env', () => {
    process.env['SENTINEL_CORS_ORIGINS'] = 'https://a.com, https://b.com';
    const cfg = corsConfigFromEnv();
    expect(cfg.allowedOrigins).toEqual(['https://a.com', 'https://b.com']);
  });
});

// ═══════════════════════════════════════════════════════════════════════
//  Rate Limiter
// ═══════════════════════════════════════════════════════════════════════

describe('RateLimiter', () => {
  it('allows requests within limit', () => {
    const limiter = new RateLimiter(3, 60_000);
    const r1 = limiter.check('user-1');
    const r2 = limiter.check('user-1');
    const r3 = limiter.check('user-1');
    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
    expect(r3.allowed).toBe(true);
    expect(r3.info.remaining).toBe(0);
  });

  it('blocks when limit exceeded', () => {
    const limiter = new RateLimiter(2, 60_000);
    limiter.check('user-1');
    limiter.check('user-1');
    const r3 = limiter.check('user-1');
    expect(r3.allowed).toBe(false);
    expect(r3.info.remaining).toBe(0);
  });

  it('tracks different keys independently', () => {
    const limiter = new RateLimiter(1, 60_000);
    expect(limiter.check('a').allowed).toBe(true);
    expect(limiter.check('b').allowed).toBe(true);
    expect(limiter.check('a').allowed).toBe(false);
  });

  it('cleanup removes expired windows', () => {
    const limiter = new RateLimiter(1, 1); // 1ms window
    limiter.check('expired-key');
    // Wait for expiry
    const start = Date.now();
    while (Date.now() - start < 5) { /* spin */ }
    const removed = limiter.cleanup();
    expect(removed).toBeGreaterThanOrEqual(1);
  });

  it('provides rate limit info with correct fields', () => {
    const limiter = new RateLimiter(10, 60_000);
    const result = limiter.check('test');
    expect(result.info.limit).toBe(10);
    expect(result.info.remaining).toBe(9);
    expect(result.info.resetAt).toBeGreaterThan(0);
  });
});

describe('setRateLimitHeaders', () => {
  it('sets standard rate limit headers', () => {
    const res = mockRes();
    setRateLimitHeaders(res, {
      limit: 100,
      remaining: 50,
      resetAt: Math.ceil(Date.now() / 1000) + 30,
    });
    expect(res._headers['ratelimit-limit']).toBe('100');
    expect(res._headers['ratelimit-remaining']).toBe('50');
    expect(res._headers['ratelimit-reset']).toBeDefined();
  });
});

describe('sendRateLimited', () => {
  it('sends 429 with Retry-After', () => {
    const res = mockRes();
    sendRateLimited(res, {
      limit: 100,
      remaining: 0,
      resetAt: Math.ceil(Date.now() / 1000) + 60,
    });
    expect(res._status).toBe(429);
    expect(res._headers['retry-after']).toBeDefined();
    expect(parseInt(res._headers['retry-after'])).toBeGreaterThan(0);
    expect(res._body).toContain('Too Many Requests');
  });
});

describe('parseRateLimit', () => {
  it('parses "100/min"', () => {
    const { max, windowMs } = parseRateLimit('100/min');
    expect(max).toBe(100);
    expect(windowMs).toBe(60_000);
  });

  it('parses "500/hour"', () => {
    const { max, windowMs } = parseRateLimit('500/hour');
    expect(max).toBe(500);
    expect(windowMs).toBe(3_600_000);
  });

  it('parses "1000/day"', () => {
    const { max, windowMs } = parseRateLimit('1000/day');
    expect(max).toBe(1000);
    expect(windowMs).toBe(86_400_000);
  });

  it('returns defaults for invalid spec', () => {
    const { max, windowMs } = parseRateLimit('invalid');
    expect(max).toBe(100);
    expect(windowMs).toBe(60_000);
  });
});

// ═══════════════════════════════════════════════════════════════════════
//  Audit Rotation
// ═══════════════════════════════════════════════════════════════════════

describe('rotateIfNeeded', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'sentinel-rotation-'));
  });

  it('does not rotate when file is below size limit', async () => {
    const logPath = join(tmpDir, 'test.jsonl');
    await writeFile(logPath, 'small content');
    const rotated = await rotateIfNeeded({ logPath, maxSizeBytes: 1_000_000 });
    expect(rotated).toBe(false);
  });

  it('rotates when file exceeds size limit', async () => {
    const logPath = join(tmpDir, 'test.jsonl');
    await writeFile(logPath, 'x'.repeat(200));
    const rotated = await rotateIfNeeded({ logPath, maxSizeBytes: 100, maxFiles: 3 });
    expect(rotated).toBe(true);
    // Original moved to .1
    const content = await readFile(logPath + '.1', 'utf-8');
    expect(content).toBe('x'.repeat(200));
  });

  it('shifts existing rotated files', async () => {
    const logPath = join(tmpDir, 'test.jsonl');
    await writeFile(logPath + '.1', 'old rotation 1');
    await writeFile(logPath, 'x'.repeat(200));
    const rotated = await rotateIfNeeded({ logPath, maxSizeBytes: 100, maxFiles: 5 });
    expect(rotated).toBe(true);
    const shifted = await readFile(logPath + '.2', 'utf-8');
    expect(shifted).toBe('old rotation 1');
  });

  it('returns false when file does not exist', async () => {
    const rotated = await rotateIfNeeded({ logPath: join(tmpDir, 'nope.jsonl') });
    expect(rotated).toBe(false);
  });
});

describe('cleanupRotatedFiles', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'sentinel-cleanup-'));
  });

  it('removes files beyond maxFiles', async () => {
    const logPath = join(tmpDir, 'test.jsonl');
    await writeFile(logPath + '.1', 'keep');
    await writeFile(logPath + '.2', 'keep');
    await writeFile(logPath + '.3', 'remove');
    await writeFile(logPath + '.4', 'remove');
    const removed = await cleanupRotatedFiles({ logPath, maxFiles: 2 });
    expect(removed).toBe(2);
  });
});

// ═══════════════════════════════════════════════════════════════════════
//  Security Headers
// ═══════════════════════════════════════════════════════════════════════

describe('applySecurityHeaders', () => {
  it('sets standard security headers', () => {
    const res = mockRes();
    applySecurityHeaders(res);
    expect(res._headers['x-content-type-options']).toBe('nosniff');
    expect(res._headers['x-xss-protection']).toBe('0');
    expect(res._headers['x-frame-options']).toBe('DENY');
    expect(res._headers['content-security-policy']).toBe("default-src 'none'");
    expect(res._headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    expect(res._headers['permissions-policy']).toContain('camera=()');
  });

  it('does not set HSTS by default', () => {
    const res = mockRes();
    applySecurityHeaders(res);
    expect(res._headers['strict-transport-security']).toBeUndefined();
  });

  it('sets HSTS when enabled', () => {
    const res = mockRes();
    applySecurityHeaders(res, { hsts: true });
    expect(res._headers['strict-transport-security']).toContain('max-age=31536000');
    expect(res._headers['strict-transport-security']).toContain('includeSubDomains');
  });

  it('allows custom HSTS max-age', () => {
    const res = mockRes();
    applySecurityHeaders(res, { hsts: true, hstsMaxAge: 86400 });
    expect(res._headers['strict-transport-security']).toBe('max-age=86400; includeSubDomains');
  });

  it('allows custom CSP', () => {
    const res = mockRes();
    applySecurityHeaders(res, { contentSecurityPolicy: "default-src 'self'" });
    expect(res._headers['content-security-policy']).toBe("default-src 'self'");
  });

  it('can disable X-Frame-Options', () => {
    const res = mockRes();
    applySecurityHeaders(res, { frameOptions: false });
    expect(res._headers['x-frame-options']).toBeUndefined();
  });
});
