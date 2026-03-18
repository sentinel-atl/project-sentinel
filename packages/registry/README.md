# @sentinel-atl/registry

Trust Registry API — publish, query, and verify Sentinel Trust Certificates.

Provides an HTTP server for storing and querying STCs (Sentinel Trust Certificates) with SVG trust badges, optional persistent storage, API key auth, CORS, TLS, and rate limiting.

## Install

```bash
npm install @sentinel-atl/registry
```

## Quick Start

### CLI

```bash
npx sentinel-registry                # Start on default port 3200
npx sentinel-registry --port 8080    # Custom port
```

### Programmatic

```ts
import { RegistryServer, CertificateStore } from '@sentinel-atl/registry';

const server = new RegistryServer({ port: 3200 });
await server.start();
```

### With Persistent Storage

```ts
import { RegistryServer, CertificateStore } from '@sentinel-atl/registry';
import { RedisStore } from '@sentinel-atl/store';

const backend = new RedisStore({ url: 'redis://localhost:6379' });
const store = new CertificateStore({ backend });
const server = new RegistryServer({ port: 3200, store });
await server.start(); // Loads existing certificates from backend
```

## API Endpoints

### Certificates

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/certificates` | Register a new STC |
| `GET` | `/api/v1/certificates/:id` | Get certificate by ID |
| `GET` | `/api/v1/certificates` | Query certificates (filters: `package`, `grade`, `minScore`, `limit`, `offset`) |
| `DELETE` | `/api/v1/certificates/:id` | Remove a certificate |

### Packages

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/packages/:name` | Latest certificate for package |
| `GET` | `/api/v1/packages/:name/history` | All certificates for package |
| `GET` | `/api/v1/packages/:name/badge` | SVG grade badge |
| `GET` | `/api/v1/packages/:name/badge/score` | SVG score badge |

### Utility

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/stats` | Registry statistics |
| `GET` | `/health` | Health check |

## Configuration

```ts
const server = new RegistryServer({
  port: 3200,
  store: new CertificateStore({ backend }),
  auth: { enabled: true, keys: [{ key: 'secret', scopes: ['admin'] }] },
  cors: { allowedOrigins: ['https://example.com'] },
  tls: { certPath: './cert.pem', keyPath: './key.pem' },
});
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SENTINEL_API_KEYS` | API key auth — format: `key1:read,write;key2:admin` |
| `SENTINEL_CORS_ORIGINS` | Comma-separated allowed origins (default: `*`) |
| `SENTINEL_TLS_CERT_PATH` | Path to TLS certificate |
| `SENTINEL_TLS_KEY_PATH` | Path to TLS private key |

## Security

The registry enforces:
- **Content-Type validation** — POST endpoints require `application/json`
- **STC schema validation** — Validates all required fields, score ranges, grade values
- **Security headers** — CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
- **HSTS** — Enabled automatically when TLS is active
- **API key auth** — Optional, with scoped access control

## License

MIT
