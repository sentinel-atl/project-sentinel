# v0.1.0 — Sentinel Trust Protocol

The first public release of **Project Sentinel**, an Agent Trust Layer (ATL) implementing the **Sentinel Trust Protocol (STP) v1.0**.

## Highlights

- **STP v1.0 Protocol** — Industry-standard trust protocol for AI agent authentication, reputation, and delegation
- **20 packages** covering identity (DID), verifiable credentials, handshake, delegation, intent, reputation, audit, recovery, revocation, attestation, step-up auth, content safety, offline mode, HSM, and more
- **Multi-framework adapters** — LangChain, AutoGen, CrewAI, Semantic Kernel
- **MCP Security Gateway** — Protect Model Context Protocol servers
- **HTTP Server** with OpenAPI 3.1.0 spec
- **Conformance test suite** — 46 tests across STP-Lite, STP-Standard, and STP-Full levels
- **360 tests** passing across 23 test files

## Packages

| Package | Description |
|---------|-------------|
| `@sentinel-atl/core` | DID identity, verifiable credentials, STP tokens |
| `@sentinel-atl/handshake` | Mutual agent authentication |
| `@sentinel-atl/reputation` | Trust scoring and reputation |
| `@sentinel-atl/audit` | Immutable audit logging |
| `@sentinel-atl/recovery` | Key rotation and recovery |
| `@sentinel-atl/revocation` | Credential revocation |
| `@sentinel-atl/attestation` | Third-party attestations |
| `@sentinel-atl/stepup` | Step-up authentication |
| `@sentinel-atl/offline` | Offline trust verification |
| `@sentinel-atl/safety` | Content safety filters |
| `@sentinel-atl/adapters` | Multi-framework adapters |
| `@sentinel-atl/mcp-plugin` | MCP integration plugin |
| `@sentinel-atl/sdk` | High-level SDK |
| `@sentinel-atl/cli` | Command-line interface |
| `@sentinel-atl/hsm` | Hardware security module backends |
| `@sentinel-atl/dashboard` | Trust dashboard UI |
| `@sentinel-atl/gateway` | MCP Security Gateway |
| `@sentinel-atl/server` | HTTP server with REST API |
| `@sentinel-atl/conformance` | STP conformance test suite |

## Install

```bash
echo "@sentinel-atl:registry=https://npm.pkg.github.com" >> .npmrc
npm install @sentinel-atl/core @sentinel-atl/server
```
