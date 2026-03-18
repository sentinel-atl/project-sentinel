# Contributing to Project Sentinel

Thank you for your interest in the Agent Trust Layer. This guide will help you get started.

## Development Setup

```bash
# Clone and install
git clone https://github.com/YOUR_ORG/project-sentinel.git
cd project-sentinel
npm install

# Build all packages
npm run build

# Run all tests
npx vitest run

# Run the demo
npx tsx examples/two-agent-handshake/demo.ts
```

## Project Structure

```
packages/
  core/          — DID, VC, crypto, Proof of Intent, Agent Passport
  handshake/     — Zero-trust 5-step mutual verification protocol
  reputation/    — Weighted scoring with negative vouches + quarantine
  audit/         — Append-only hash-chain integrity logging
  recovery/      — Shamir's Secret Sharing for key backup
  revocation/    — DID + VC revocation, key rotation, kill switch
  safety/        — Content classification pipeline
  mcp-plugin/    — MCP server middleware (identity at tool-call boundary)
  gateway/       — MCP Security Gateway with tool policies
  sdk/           — Developer-facing SDK (5-line integration)
  cli/           — sentinel CLI tool
  hardening/     — Production security middleware (auth, CORS, TLS, headers)
  telemetry/     — OpenTelemetry instrumentation
  store/         — Persistent storage adapters (Memory, Redis, Postgres, SQLite)
  registry/      — Trust Certificate registry with REST API + badges
  scanner/       — npm package security scanner
  server/        — STP-compliant HTTP server
specs/           — Protocol specifications
examples/        — Working demos
docs/            — Documentation and marketing
```

## Making Changes

1. **Fork** the repo and create a feature branch from `main`
2. **Write code** — follow existing patterns (TypeScript, ESM, Ed25519)
3. **Write tests** — every new feature needs tests. Run `npx vitest run` to verify
4. **Build** — `npm run build` must pass with zero errors
5. **Add a changeset** — run `npx changeset` to describe your change
6. **Submit a PR** — describe what and why

## Code Conventions

- **TypeScript** with strict mode
- **ESM** (`"type": "module"`) — use `.js` extensions in imports
- **Ed25519** for all signing operations (`@noble/ed25519`)
- **SHA-256** for all hashing (`@noble/hashes`)
- **DID method:** `did:key` with Ed25519 multicodec
- **VCs:** W3C Verifiable Credentials Data Model v2.0
- **Canonicalization:** Recursive deep-sort of object keys before signing
- **Structured logging:** Use JSON format with `ts`, `level`, `service`, `msg` fields
- **Error handling:** Use typed errors (`STPError`) with status codes and error codes
- **Dependencies:** Internal deps use `workspace:*`; external deps use `^` semver

## Release Process

This project uses [changesets](https://github.com/changesets/changesets) for versioning:

1. Make your changes on a feature branch
2. Run `npx changeset` and follow the prompts to describe the change
3. Commit the changeset file with your PR
4. When merged to `main`, the release workflow creates a "Version Packages" PR
5. Merging the Version Packages PR publishes to npm with SLSA provenance

## Testing

```bash
# Run all tests
npx vitest run

# Run tests for a specific package
npx vitest run --filter=packages/core

# Run integration tests
npx vitest run packages/server/src/integration.test.ts

# Run the benchmark
npx tsx packages/server/src/benchmark.ts
```

## Security

If you discover a security vulnerability, please email it privately instead of opening a public issue. Refer to [SECURITY.md](SECURITY.md) for our vulnerability reporting policy.

**Do not:**
- Commit secrets, API keys, or credentials
- Disable security headers or auth in production code
- Use `corsOrigins: ['*']` in examples without a warning comment

## Architecture Decision Records

When making significant architectural decisions, document them as a comment in the PR description with:
- **Context:** What is the issue?
- **Decision:** What did we decide?
- **Consequences:** What are the trade-offs?

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
