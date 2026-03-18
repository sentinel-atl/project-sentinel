# v0.2.0 — The "Build All 10" Release

**Project Sentinel** now ships everything an agent developer actually needs. This release adds 5 new TypeScript packages, a full Python SDK, real framework integrations, production deployment artifacts, and more.

## New Packages

### `@sentinel-atl/store` — Persistent Storage
State that survives restarts. Pluggable adapters for Redis, PostgreSQL, SQLite, and in-memory.
```bash
npm install @sentinel-atl/store
```

### `@sentinel-atl/telemetry` — OpenTelemetry Observability
Traces, metrics, and spans for every trust decision, handshake, and safety check. Drop-in OpenTelemetry integration.
```bash
npm install @sentinel-atl/telemetry
```

### `@sentinel-atl/budget` — Token/Cost Control
Per-agent and per-tool budgets, sliding windows, circuit breakers, and a global cost ceiling. Built-in model pricing table.
```bash
npm install @sentinel-atl/budget
```

### `@sentinel-atl/mcp-proxy` — Real MCP Transport Proxy
A real stdio/SSE proxy binary that intercepts MCP traffic, applies Sentinel trust checks, and exposes audit/stats endpoints.
```bash
npx sentinel-proxy --listen 3100 --upstream "npx my-mcp-server"
```

### `@sentinel-atl/approval` — Human Approval Workflows
Deliver step-up auth challenges via Webhook, Slack (Block Kit), Web UI (dark theme dashboard), or Console. Fan-out routing included.
```bash
npm install @sentinel-atl/approval
```

## Python SDK — `sentinel-atl`
Full-featured Python implementation: Ed25519 DID, Verifiable Credentials, reputation engine, audit log, safety pipeline, STP HTTP client, and LangChain callback handler. 15 tests passing.
```bash
pip install sentinel-atl
```

## Enhanced Packages

### Safety — Real Classifiers
- **Azure Content Safety** — calls Azure REST API with category mapping
- **OpenAI Moderation** — calls `/v1/moderations` endpoint
- **Llama Guard** — calls OpenAI-compatible endpoint running Llama Guard

### Adapters — Real Framework Integrations
- **Vercel AI SDK** — `createVercelAIMiddleware()` for tool verification
- **LangChain.js** — `SentinelCallbackHandler` implementing BaseCallbackHandler
- **MCP SDK** — `wrapMCPServer()` intercepting `tools/call` on @modelcontextprotocol/sdk

### Audit — Standalone API
- `createAuditLog(path)` and `verifyAuditFile(path)` work without Sentinel SDK or DID setup

## Production Deployment
- Multi-stage `Dockerfile` and `Dockerfile.proxy` (node:20-alpine, non-root user, healthcheck)
- `docker-compose.yml` — full stack with Redis, server, proxy, and approval UI
- Health checks, data volumes, proper networking

## Stats
- **25 TypeScript packages** (5 new + 20 updated)
- **1 Python package**
- **360 TypeScript tests passing**
- **15 Python tests passing**
- **~5,700 lines of new code**
