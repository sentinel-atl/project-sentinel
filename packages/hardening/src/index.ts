/**
 * @sentinel-atl/hardening — Production Hardening Middleware
 *
 * Reusable security middleware for all Sentinel HTTP servers:
 * - API key authentication with scoped access
 * - CORS with configurable origin allowlist
 * - TLS/HTTPS support
 * - Rate limit headers (RFC 6585)
 * - Persistent nonce replay protection
 * - Audit log rotation
 */

export {
  authenticate,
  hasScope,
  sendUnauthorized,
  sendForbidden,
  authConfigFromEnv,
  type AuthConfig,
  type AuthScope,
  type ApiKey,
  type AuthResult,
} from './auth.js';

export {
  applyCors,
  defaultCorsConfig,
  corsConfigFromEnv,
  type CorsConfig,
} from './cors.js';

export {
  createSecureServer,
  tlsConfigFromEnv,
  type TlsConfig,
} from './tls.js';

export {
  RateLimiter,
  setRateLimitHeaders,
  sendRateLimited,
  parseRateLimit,
  type RateLimitInfo,
} from './rate-limit.js';

export {
  NonceStore,
  type NonceStoreConfig,
} from './nonce-store.js';

export {
  rotateIfNeeded,
  cleanupRotatedFiles,
  totalLogSize,
  type RotationConfig,
} from './audit-rotation.js';
