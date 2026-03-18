# @sentinel-atl/trust-gateway

YAML-configured MCP trust gateway — runtime enforcement of Sentinel Trust Certificates.

Acts as a reverse proxy between MCP clients and servers, enforcing trust policies based on scan results and STCs. Supports stdio and HTTP/SSE upstreams, strict/permissive modes, per-server policies, and tool-level access control.

## Install

```bash
npm install @sentinel-atl/trust-gateway
```

## Quick Start

### 1. Create a config file

```yaml
# sentinel.yaml
gateway:
  name: my-gateway
  port: 3100
  mode: strict        # reject untrusted servers (or 'permissive' to warn only)
  minTrustScore: 60
  minGrade: C

servers:
  - name: filesystem
    upstream: stdio://node ./fs-server.js
    trust:
      minScore: 75
      minGrade: B
      requireCertificate: true
      maxFindingsCritical: 0
      maxFindingsHigh: 2
      allowedPermissions: [filesystem]
    blockedTools: [delete_file]
```

### 2. Start the gateway

```bash
npx sentinel-gateway --config sentinel.yaml
```

### 3. Validate config without starting

```bash
npx sentinel-gateway validate sentinel.yaml
```

## Configuration Reference

### Gateway Settings

```yaml
gateway:
  name: my-gateway
  port: 3100
  mode: strict | permissive
  minTrustScore: 60          # Global minimum (0-100)
  minGrade: C                # Global minimum (A-F)
  logPath: ./audit.jsonl     # Audit log location
  apiKeys: [key1, key2]      # API key auth
  corsOrigins: ['*']         # CORS origins
  tlsCert: /path/to/cert.pem
  tlsKey: /path/to/key.pem
  rateLimit: "1000/min"
```

### Per-Server Policies

```yaml
servers:
  - name: my-server
    upstream: http://localhost:4000/sse  # or stdio://command args
    trust:
      minScore: 75
      minGrade: B
      requireCertificate: true
      maxFindingsCritical: 0
      maxFindingsHigh: 2
      allowedPermissions: [filesystem, network]
      blockedPermissions: [native]
    rateLimit: "100/min"
    blockedTools: [dangerous_tool]
    allowedTools: [safe_tool_a, safe_tool_b]
    certificatePath: ./server.stc.json
```

## Programmatic Usage

```ts
import { TrustGateway, loadConfig } from '@sentinel-atl/trust-gateway';

const config = await loadConfig('./sentinel.yaml');
const gateway = new TrustGateway(config);

const decision = await gateway.evaluate({
  serverName: 'filesystem',
  tool: 'read_file',
});
// { allowed: true, score: 85, grade: 'B', ... }
```

### With Persistent Storage

```ts
import { TrustStore } from '@sentinel-atl/trust-gateway';
import { RedisStore } from '@sentinel-atl/store';

const backend = new RedisStore({ url: 'redis://localhost:6379' });
const trustStore = new TrustStore({ backend });
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SENTINEL_API_KEYS` | API key auth |
| `SENTINEL_CORS_ORIGINS` | CORS allowed origins |
| `SENTINEL_TLS_CERT_PATH` | TLS certificate path |
| `SENTINEL_TLS_KEY_PATH` | TLS private key path |

## Security

- **Content-Type enforcement** on `/message` endpoint
- **Security headers** — CSP, X-Content-Type-Options, X-Frame-Options
- **HSTS** when TLS is active
- **Rate limiting** — global and per-server
- **Audit logging** to JSONL with rotation

## License

MIT
