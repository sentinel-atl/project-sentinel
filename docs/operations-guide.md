# Sentinel Operations Guide

## Deployment

### Docker Compose (recommended for single-node)

```bash
# Start the stack
docker compose up -d

# Verify health
curl http://localhost:3000/health
curl http://localhost:3100/health

# View logs
docker compose logs -f sentinel-server
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_PORT` | `3000` | HTTP port for the STP server |
| `SENTINEL_HOST` | `0.0.0.0` | Bind address |
| `SENTINEL_DATA_DIR` | `./data` | Directory for audit logs and data |
| `SENTINEL_API_KEYS` | *(none)* | API keys: `key1:read,write;key2:admin` |
| `SENTINEL_CORS_ORIGINS` | `[]` | Allowed CORS origins (comma-separated) |
| `SENTINEL_TLS_CERT` | *(none)* | Path to TLS certificate |
| `SENTINEL_TLS_KEY` | *(none)* | Path to TLS private key |
| `SENTINEL_HSTS` | `false` | Enable HSTS header (auto-enabled with TLS) |
| `REDIS_URL` | *(none)* | Redis URL for distributed state |
| `NODE_ENV` | `production` | Node environment |

### Health Checks

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness: returns `{ status: "ok", uptime: N }` |
| `GET /ready` | Readiness: returns `{ status: "ready" }` when all subsystems are up |
| `GET /.well-known/sentinel-configuration` | Protocol discovery |

## Scaling

### Horizontal Scaling

To run multiple replicas:

1. **Set `REDIS_URL`** — rate-limit state is shared via Redis
2. **Use a load balancer** — health checks on `/health`
3. **Shared audit storage** — mount a shared volume or use external log aggregation

### Resource Requirements

| Service | Memory | CPU | Disk |
|---------|--------|-----|------|
| sentinel-server | 128–512 MB | 0.5–1 core | Minimal (audit logs) |
| mcp-proxy | 128–512 MB | 0.5–1 core | Minimal |
| redis | 256–384 MB | 0.5 core | Persistent AOF |

## Monitoring

### Structured Logs

All server logs are JSON-formatted to stdout/stderr:
```json
{"ts":"2026-03-18T12:00:00.000Z","level":"info","service":"stp-server-main","msg":"Server started","port":3000}
```

Parse with `jq`, ship to ELK/Datadog/Grafana Loki.

### OpenTelemetry

Enable telemetry by providing a `SentinelTelemetry` instance:
```typescript
import { SentinelTelemetry } from '@sentinel-atl/telemetry';
const tel = new SentinelTelemetry({ serviceName: 'sentinel-prod' });
```

Exported metrics:
- `sentinel.trust.decisions` — trust decisions by outcome
- `sentinel.trust.latency` — decision latency (ms)
- `sentinel.gateway.calls` — gateway tool calls by tool/caller
- `sentinel.safety.violations` — content safety violations
- `sentinel.reputation.score` — reputation score per agent

### Audit Log Integrity

Verify the tamper-evident hash chain:
```bash
curl -X POST http://localhost:3000/v1/audit/verify
# { "valid": true, "totalEntries": 1234 }
```

## Troubleshooting

### Server won't start
- Check `SENTINEL_PORT` isn't already in use
- Verify `SENTINEL_DATA_DIR` is writable
- Check logs: `docker compose logs sentinel-server`

### 429 Too Many Requests
- Default rate limit: 100 req/min per caller DID
- Increase via `rateLimitMax` in gateway config
- Check if Redis is healthy for distributed rate limiting

### Audit chain broken
- Run `POST /v1/audit/verify` to find the break point
- Rotated files: check `*.jsonl.1`, `*.jsonl.2`, etc.
- Each rotated file has its own independent chain

### TLS/HTTPS
- Set `SENTINEL_TLS_CERT` and `SENTINEL_TLS_KEY` env vars
- HSTS header is auto-enabled when TLS is configured
- For Docker, mount certs as read-only volumes

## Disaster Recovery

### Key Recovery (Shamir's Secret Sharing)
Sentinel uses 3-of-5 threshold secret sharing for key backup:
```typescript
import { recoverKey } from '@sentinel-atl/recovery';
const key = await recoverKey([share1, share2, share3]);
```

### Audit Log Backup
- Logs rotate at 10 MB by default (configurable)
- Up to 10 rotated files kept
- Export: `GET /v1/audit` returns all entries as JSON
- Copy rotated files to cold storage on a schedule

### Emergency Revocation
```bash
# Kill switch — immediately revoke an agent
curl -X POST http://localhost:3000/v1/revocation/kill-switch \
  -H "Authorization: STP <token>" \
  -d '{"targetDid":"did:key:z6Mk...","reason":"compromised","cascade":true}'
```
