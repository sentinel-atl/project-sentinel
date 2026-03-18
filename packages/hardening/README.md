# @sentinel-atl/hardening

Production hardening middleware for Sentinel services — API key auth, CORS, TLS, rate limiting, nonce replay protection, audit log rotation, and security headers.

## Install

```bash
npm install @sentinel-atl/hardening
```

## Modules

### Authentication

API key auth with scoped access control and constant-time comparison.

```ts
import { authenticate, hasScope, authConfigFromEnv } from '@sentinel-atl/hardening';

const config = authConfigFromEnv();
// Or manual: { enabled: true, keys: [{ key: 'secret', scopes: ['read', 'write'] }] }

const result = authenticate(req, config);
if (!result.authenticated) sendUnauthorized(res);
if (!hasScope(result, 'write')) sendForbidden(res);
```

Key extraction order: `Authorization: Bearer <key>` → `X-API-Key` header → `?apiKey=` query param.

**Environment**: `SENTINEL_API_KEYS=key1:read,write;key2:admin`

### CORS

```ts
import { applyCors, corsConfigFromEnv } from '@sentinel-atl/hardening';

const config = corsConfigFromEnv();
const isPreflight = applyCors(req, res, config);
if (isPreflight) return; // Already responded to OPTIONS
```

**Environment**: `SENTINEL_CORS_ORIGINS=https://example.com,https://app.example.com`

### TLS

```ts
import { createSecureServer, tlsConfigFromEnv } from '@sentinel-atl/hardening';

const tls = tlsConfigFromEnv();
const server = createSecureServer(tls, handler);
// Returns https.Server when TLS is configured, http.Server otherwise
```

**Environment**: `SENTINEL_TLS_CERT_PATH`, `SENTINEL_TLS_KEY_PATH`

### Rate Limiting

RFC 6585 compliant, in-memory rate limiter.

```ts
import { RateLimiter, parseRateLimit } from '@sentinel-atl/hardening';

const { max, windowMs } = parseRateLimit('100/min');
const limiter = new RateLimiter(max, windowMs);

const info = limiter.check(clientId);
setRateLimitHeaders(res, info);
if (!info.allowed) sendRateLimited(res, info);
```

### Nonce Store (Replay Protection)

```ts
import { NonceStore } from '@sentinel-atl/hardening';

const nonces = new NonceStore({ backend: store, ttl: 300 });
const isNew = await nonces.consume(nonce);
if (!isNew) return res.end('Replay detected');
```

### Audit Log Rotation

```ts
import { rotateIfNeeded, cleanupRotatedFiles } from '@sentinel-atl/hardening';

await rotateIfNeeded('./audit.jsonl', { maxSize: 10_000_000 }); // 10MB
await cleanupRotatedFiles('./audit.jsonl', { maxAge: 30 * 86400_000 }); // 30 days
```

### Security Headers

```ts
import { applySecurityHeaders } from '@sentinel-atl/hardening';

applySecurityHeaders(res, { hsts: true });
// Sets: Content-Security-Policy, X-Content-Type-Options, X-Frame-Options,
//       X-XSS-Protection, Referrer-Policy, Permissions-Policy, HSTS
```

## License

MIT
