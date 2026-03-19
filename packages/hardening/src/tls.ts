/**
 * TLS support — wraps HTTP servers with HTTPS using Node.js native TLS.
 *
 * Reads cert/key from files or environment variables:
 *   SENTINEL_TLS_CERT — path to PEM certificate
 *   SENTINEL_TLS_KEY  — path to PEM private key
 *
 * In production mode (NODE_ENV=production), warns if TLS is not configured.
 */

import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import { createServer as createHttpServer, type Server as HttpServer, type RequestListener, type IncomingMessage, type ServerResponse } from 'node:http';
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
 * Warns on stderr if running in production without TLS.
 */
export function createSecureServer(
  handler: RequestListener,
  tls?: TlsConfig
): HttpServer | HttpsServer {
  if (!tls?.enabled) {
    if (process.env['NODE_ENV'] === 'production') {
      process.stderr.write(
        '[sentinel] WARNING: Running without TLS in production. ' +
        'Set SENTINEL_TLS_CERT and SENTINEL_TLS_KEY or use a reverse proxy with HTTPS.\n'
      );
    }
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
 * Middleware that redirects HTTP to HTTPS.
 * Use when running both an HTTP redirect server and HTTPS main server.
 */
export function httpsRedirectHandler(httpsPort: number): RequestListener {
  return (req: IncomingMessage, res: ServerResponse) => {
    const host = (req.headers.host ?? 'localhost').replace(/:\d+$/, '');
    const portSuffix = httpsPort === 443 ? '' : `:${httpsPort}`;
    const location = `https://${host}${portSuffix}${req.url ?? '/'}`;
    res.writeHead(301, { Location: location });
    res.end();
  };
}

/**
 * Start an HTTP→HTTPS redirect server alongside an HTTPS server.
 * Only starts if TLS is enabled.
 */
export function startHttpsRedirect(httpPort: number, httpsPort: number): HttpServer | null {
  if (!process.env['SENTINEL_TLS_CERT'] || !process.env['SENTINEL_TLS_KEY']) {
    return null;
  }
  const server = createHttpServer(httpsRedirectHandler(httpsPort));
  server.listen(httpPort);
  return server;
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
