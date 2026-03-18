/**
 * API Key Authentication middleware.
 *
 * Supports:
 * - Bearer token in Authorization header
 * - X-API-Key header
 * - ?apiKey query parameter
 *
 * Keys are validated using constant-time comparison to prevent timing attacks.
 * Multiple keys can be configured with different scopes (read, write, admin).
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';

// ─── Types ───────────────────────────────────────────────────────────

export type AuthScope = 'read' | 'write' | 'admin';

export interface ApiKey {
  /** The key value (plaintext — in production, store hashed) */
  key: string;
  /** Human-readable label */
  label?: string;
  /** Scopes this key grants */
  scopes: AuthScope[];
}

export interface AuthConfig {
  /** Whether auth is enabled (default: false — opt-in) */
  enabled: boolean;
  /** Registered API keys */
  keys: ApiKey[];
  /** Paths that don't require auth (e.g., /health, badge endpoints) */
  publicPaths?: string[];
  /** Custom realm for WWW-Authenticate header */
  realm?: string;
}

export interface AuthResult {
  authenticated: boolean;
  key?: ApiKey;
  error?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────

function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  return timingSafeEqual(bufA, bufB);
}

function extractApiKey(req: IncomingMessage): string | undefined {
  // 1. Authorization: Bearer <key>
  const authHeader = req.headers['authorization'];
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }

  // 2. X-API-Key header
  const xApiKey = req.headers['x-api-key'];
  if (typeof xApiKey === 'string' && xApiKey) {
    return xApiKey;
  }

  // 3. Query parameter
  const url = new URL(req.url ?? '/', `http://localhost`);
  const queryKey = url.searchParams.get('apiKey');
  if (queryKey) {
    return queryKey;
  }

  return undefined;
}

// ─── Auth Check ──────────────────────────────────────────────────────

/**
 * Authenticate an incoming request.
 */
export function authenticate(req: IncomingMessage, config: AuthConfig): AuthResult {
  if (!config.enabled) {
    return { authenticated: true };
  }

  // Check public paths
  const url = new URL(req.url ?? '/', `http://localhost`);
  const path = url.pathname;
  if (config.publicPaths?.some(p => path === p || path.startsWith(p + '/'))) {
    return { authenticated: true };
  }

  const providedKey = extractApiKey(req);
  if (!providedKey) {
    return { authenticated: false, error: 'Missing API key' };
  }

  // Find matching key (constant-time comparison)
  for (const registeredKey of config.keys) {
    if (constantTimeCompare(providedKey, registeredKey.key)) {
      return { authenticated: true, key: registeredKey };
    }
  }

  return { authenticated: false, error: 'Invalid API key' };
}

/**
 * Check if request has the required scope.
 */
export function hasScope(result: AuthResult, required: AuthScope): boolean {
  if (!result.authenticated) return false;
  if (!result.key) return true; // Auth disabled or public path
  if (result.key.scopes.includes('admin')) return true;
  return result.key.scopes.includes(required);
}

/**
 * Send a 401 Unauthorized response.
 */
export function sendUnauthorized(res: ServerResponse, config: AuthConfig, error?: string): void {
  const realm = config.realm ?? 'Sentinel';
  res.writeHead(401, {
    'Content-Type': 'application/json',
    'WWW-Authenticate': `Bearer realm="${realm}"`,
  });
  res.end(JSON.stringify({ error: error ?? 'Unauthorized' }));
}

/**
 * Send a 403 Forbidden response.
 */
export function sendForbidden(res: ServerResponse, error?: string): void {
  res.writeHead(403, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: error ?? 'Forbidden: insufficient scope' }));
}

/**
 * Create a default auth config from environment variables.
 *
 * SENTINEL_API_KEYS=key1:read,write;key2:admin
 */
export function authConfigFromEnv(): AuthConfig {
  const envKeys = process.env['SENTINEL_API_KEYS'];
  if (!envKeys) {
    return { enabled: false, keys: [] };
  }

  const keys: ApiKey[] = envKeys.split(';').filter(Boolean).map((entry, i) => {
    const [key, scopeStr] = entry.split(':');
    const scopes = (scopeStr ?? 'read').split(',').map(s => s.trim()) as AuthScope[];
    return { key: key.trim(), label: `key-${i}`, scopes };
  });

  return {
    enabled: keys.length > 0,
    keys,
    publicPaths: ['/health'],
  };
}
