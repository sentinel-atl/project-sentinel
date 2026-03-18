/**
 * CORS middleware — configurable origin allowlist.
 *
 * Replaces the `Access-Control-Allow-Origin: *` wildcard with
 * explicit origin checking and proper Vary headers.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';

// ─── Types ───────────────────────────────────────────────────────────

export interface CorsConfig {
  /** Allowed origins. Use ['*'] to allow all (not recommended for production). */
  allowedOrigins: string[];
  /** Allowed HTTP methods */
  allowedMethods?: string[];
  /** Allowed request headers */
  allowedHeaders?: string[];
  /** Headers to expose to the browser */
  exposedHeaders?: string[];
  /** Whether to allow credentials (cookies, auth headers) */
  allowCredentials?: boolean;
  /** Max age for preflight cache (seconds) */
  maxAge?: number;
}

// ─── Default Config ──────────────────────────────────────────────────

export function defaultCorsConfig(): CorsConfig {
  return {
    allowedOrigins: ['*'],
    allowedMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Caller-Id', 'X-Server-Name'],
    allowCredentials: false,
    maxAge: 86400, // 24 hours
  };
}

// ─── CORS Application ───────────────────────────────────────────────

/**
 * Apply CORS headers to a response.
 * Returns true if this was a preflight request (caller should end the response).
 */
export function applyCors(
  req: IncomingMessage,
  res: ServerResponse,
  config: CorsConfig
): boolean {
  const origin = req.headers['origin'];

  // Determine if origin is allowed
  let allowedOrigin: string;
  if (config.allowedOrigins.includes('*')) {
    // Wildcard — but if credentials are enabled, must echo specific origin
    allowedOrigin = config.allowCredentials && origin ? origin : '*';
  } else if (origin && config.allowedOrigins.includes(origin)) {
    allowedOrigin = origin;
  } else if (!origin) {
    // Same-origin or non-browser request — no CORS header needed
    allowedOrigin = '';
  } else {
    // Origin not allowed — don't set any CORS headers
    allowedOrigin = '';
  }

  if (allowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);

    // Vary: Origin — critical for caching when origin-specific
    if (allowedOrigin !== '*') {
      res.setHeader('Vary', 'Origin');
    }
  }

  if (config.allowCredentials) {
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  if (config.exposedHeaders?.length) {
    res.setHeader('Access-Control-Expose-Headers', config.exposedHeaders.join(', '));
  }

  // Handle preflight
  if (req.method === 'OPTIONS') {
    if (config.allowedMethods?.length) {
      res.setHeader('Access-Control-Allow-Methods', config.allowedMethods.join(', '));
    }
    if (config.allowedHeaders?.length) {
      res.setHeader('Access-Control-Allow-Headers', config.allowedHeaders.join(', '));
    }
    if (config.maxAge !== undefined) {
      res.setHeader('Access-Control-Max-Age', String(config.maxAge));
    }
    res.writeHead(204);
    res.end();
    return true;
  }

  return false;
}

/**
 * Create a CORS config from environment variable.
 *
 * SENTINEL_CORS_ORIGINS=https://example.com,https://app.example.com
 */
export function corsConfigFromEnv(): CorsConfig {
  const envOrigins = process.env['SENTINEL_CORS_ORIGINS'];
  const origins = envOrigins
    ? envOrigins.split(',').map(o => o.trim()).filter(Boolean)
    : ['*'];

  return {
    ...defaultCorsConfig(),
    allowedOrigins: origins,
  };
}
