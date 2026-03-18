/**
 * TLS support — wraps HTTP servers with HTTPS using Node.js native TLS.
 *
 * Reads cert/key from files or environment variables:
 *   SENTINEL_TLS_CERT — path to PEM certificate
 *   SENTINEL_TLS_KEY  — path to PEM private key
 */

import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { createServer as createHttpServer, type Server as HttpServer, type RequestListener } from 'node:http';
import { readFileSync } from 'node:fs';

// ─── Types ───────────────────────────────────────────────────────────

export interface TlsConfig {
  /** Whether TLS is enabled */
  enabled: boolean;
  /** Path to PEM certificate file */
  certPath?: string;
  /** Path to PEM private key file */
  keyPath?: string;
  /** PEM certificate string (alternative to certPath) */
  cert?: string;
  /** PEM private key string (alternative to keyPath) */
  key?: string;
}

// ─── Factory ──────────────────────────────────────────────────────────

/**
 * Create an HTTP or HTTPS server based on TLS configuration.
 */
export function createSecureServer(
  handler: RequestListener,
  tls?: TlsConfig
): HttpServer | HttpsServer {
  if (!tls?.enabled) {
    return createHttpServer(handler);
  }

  const cert = tls.cert ?? (tls.certPath ? readFileSync(tls.certPath, 'utf-8') : undefined);
  const key = tls.key ?? (tls.keyPath ? readFileSync(tls.keyPath, 'utf-8') : undefined);

  if (!cert || !key) {
    throw new Error('TLS enabled but no certificate/key provided. Set certPath/keyPath or cert/key.');
  }

  return createHttpsServer({ cert, key }, handler);
}

/**
 * Create TLS config from environment variables.
 *
 * SENTINEL_TLS_CERT=./certs/server.crt
 * SENTINEL_TLS_KEY=./certs/server.key
 */
export function tlsConfigFromEnv(): TlsConfig {
  const certPath = process.env['SENTINEL_TLS_CERT'];
  const keyPath = process.env['SENTINEL_TLS_KEY'];

  return {
    enabled: !!(certPath && keyPath),
    certPath,
    keyPath,
  };
}
