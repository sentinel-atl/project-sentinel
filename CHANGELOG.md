# Changelog

All notable changes to Project Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-03-18

### Added
- **Security headers**: All HTTP responses now include `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy` via `@sentinel-atl/hardening`
- **Structured logging**: JSON-formatted logs with levels (debug/info/warn/error), request IDs, and service names
- **Health endpoints**: `GET /health` (liveness) and `GET /ready` (readiness) on all servers
- **Request ID tracking**: Every response includes `X-Request-Id` header
- **Typed errors**: New `STPError` class with status codes and error codes
- **Global error boundary**: Unhandled rejections and uncaught exceptions are caught and logged
- **Graceful shutdown**: SIGTERM/SIGINT handlers drain connections before exit
- **Distributed rate limiting**: Gateway supports Redis-backed rate limits via `SentinelStore`
- **Audit log rotation**: Size-based, daily, or hourly rotation with configurable retention
- **Config validation**: Server fails fast on invalid configuration at startup
- **Telemetry wiring**: Gateway emits `sentinel.gateway.calls` and `sentinel.trust.decisions` metrics
- **Integration tests**: End-to-end test covering identity → credentials → reputation → audit flow
- **Load benchmark**: `packages/server/src/benchmark.ts` for throughput/latency testing
- **Release automation**: Changesets + GitHub Actions workflow for automated versioning and npm publishing
- **Container scanning**: Trivy vulnerability scanning in CI pipeline
- **npm audit**: Dependency audit step added to CI
- **Operations guide**: `docs/operations-guide.md` with deployment, scaling, monitoring, and troubleshooting
- **Registry persistence**: CLI auto-detects `REDIS_URL` for backend storage
- **Docker resource limits**: Memory/CPU limits and log rotation on all containers

### Changed
- **CORS default changed** from `['*']` to `[]` (no cross-origin by default)
- **Auth default**: Registry uses `authConfigFromEnv()` (enabled when `SENTINEL_API_KEYS` is set)
- **Docker healthcheck** uses `/health` endpoint instead of `/.well-known/sentinel-configuration`
- **Docker Compose** adds resource limits and JSON log driver with 10MB rotation

### Security
- OWASP security headers applied to all HTTP responses by default
- CORS no longer defaults to wildcard `*`
- API authentication is guided to be enabled in `sentinel.example.yaml`

## [0.2.0] - 2026-03-15

### Added
- Publisher scanner: npm registry identity checks (age, downloads, provenance)
- HTTP proxy: SSE + JSON-RPC relay with TrustGateway enforcement
- Trust Registry API with SVG badge generator
- Scanner package with 4 sub-scanners
- GitHub Action for CI trust scanning
- VS Code extension for package scanning
- Marketing assets and launch materials
- 31 packages, 474+ tests

### Changed
- Trust score calculation uses real publisher data
- Gateway supports configurable tool policies

## [0.1.0] - 2026-02-28

### Added
- Initial release of the Agent Trust Layer
- Core: DID (did:key), Verifiable Credentials (W3C VC 2.0), Ed25519 crypto
- Handshake: Zero-trust 5-step mutual verification protocol
- Reputation: Weighted scoring with sybil resistance and time decay
- Audit: Tamper-evident hash-chain logging (JSONL)
- Recovery: Shamir's Secret Sharing (3-of-5 threshold)
- Revocation: DID + VC revocation, key rotation, kill switch
- Safety: Content classification pipeline
- MCP Plugin: Trust middleware for MCP servers
- SDK: Developer-facing 5-line integration
- CLI: Command-line trust operations
- Conformance: STP-Lite/Standard/Full protocol test suites
