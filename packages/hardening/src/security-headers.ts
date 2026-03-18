/**
 * Security Response Headers — standard HTTP security headers for all Sentinel servers.
 *
 * Sets headers recommended by OWASP:
 *   X-Content-Type-Options: nosniff
 *   X-Frame-Options: DENY
 *   X-XSS-Protection: 0  (modern browsers use CSP instead)
 *   Content-Security-Policy: default-src 'none'
 *   Strict-Transport-Security: max-age=31536000; includeSubDomains (when TLS)
 *   Referrer-Policy: strict-origin-when-cross-origin
 *   Permissions-Policy: camera=(), microphone=(), geolocation=()
 */

import type { ServerResponse } from 'node:http';

export interface SecurityHeadersConfig {
  /** Whether to add HSTS header (only makes sense over TLS) */
  hsts?: boolean;
  /** HSTS max-age in seconds (default: 31536000 = 1 year) */
  hstsMaxAge?: number;
  /** Custom Content-Security-Policy (default: "default-src 'none'") */
  contentSecurityPolicy?: string;
  /** Custom Permissions-Policy */
  permissionsPolicy?: string;
  /** Whether to add X-Frame-Options (default: true) */
  frameOptions?: boolean;
}

/**
 * Apply standard security headers to a response.
 */
export function applySecurityHeaders(
  res: ServerResponse,
  config?: SecurityHeadersConfig
): void {
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Disable legacy XSS filter (CSP is the modern approach)
  res.setHeader('X-XSS-Protection', '0');

  // Content Security Policy
  res.setHeader(
    'Content-Security-Policy',
    config?.contentSecurityPolicy ?? "default-src 'none'"
  );

  // Clickjacking protection
  if (config?.frameOptions !== false) {
    res.setHeader('X-Frame-Options', 'DENY');
  }

  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions policy
  res.setHeader(
    'Permissions-Policy',
    config?.permissionsPolicy ?? 'camera=(), microphone=(), geolocation=()'
  );

  // HSTS (only over TLS)
  if (config?.hsts) {
    const maxAge = config.hstsMaxAge ?? 31_536_000;
    res.setHeader('Strict-Transport-Security', `max-age=${maxAge}; includeSubDomains`);
  }
}

/**
 * Create a security headers config from environment variables.
 *
 * SENTINEL_HSTS=true (enabled when TLS is enabled)
 */
export function securityHeadersConfigFromEnv(): SecurityHeadersConfig {
  return {
    hsts: process.env['SENTINEL_HSTS'] === 'true' ||
          !!process.env['SENTINEL_TLS_CERT'],
  };
}
