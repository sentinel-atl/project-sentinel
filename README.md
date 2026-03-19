# Project Sentinel

**Cryptographic identity and verifiable authorization for AI agents.**

Every agent gets a DID, W3C Verifiable Credentials with scoped permissions, and a signed Proof of Intent that traces every action back to the human who authorized it — through the full delegation chain. Not just "is this request safe" but "this request was authorized by Alice, delegated through Agent A, scope `travel:book`, expiring in 2 hours, here's the Ed25519 signature."

[![npm](https://img.shields.io/npm/v/@sentinel-atl/core)](https://www.npmjs.com/package/@sentinel-atl/core)
[![Tests](https://img.shields.io/badge/Tests-592%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/Protocol-STP%20v1.0-green.svg)](specs/sentinel-trust-protocol-v1.0.md)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7+-3178C6.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg)](python/)

```bash
npx create-sentinel-app my-agent && cd my-agent && npm start
```

---

## What's inside

| Capability | What it does |
|---|---|
| **Cryptographic Identity** | Every agent gets a `did:key` (Ed25519). No central registry required. |
| **W3C Verifiable Credentials** | Scoped permissions, delegation chains, expiry — all cryptographically signed |
| **Proof of Intent** | Every action traces back to a signed human authorization through the full delegation chain |
| **Zero-trust Handshake** | Two agents that have never met mutually verify in 5 steps, no central authority |
| **Supply Chain Scanning** | Audit MCP packages *before* they run — `npx @sentinel-atl/scanner scan <pkg>` |
| **Emergency Kill Switch** | Revoke a compromised agent + cascade to all delegates in <5s |
| **Open Protocol** | [STP v1.0](specs/sentinel-trust-protocol-v1.0.md) is a spec with a conformance suite, not a product |

---

## Try it

### Scan an MCP package (no setup)

```bash
npx @sentinel-atl/scanner scan @modelcontextprotocol/server-filesystem
```
```
📊 Trust Score: 82/100 (Grade: B)
   Dependencies:  ✅ No known vulnerabilities
   Code Patterns: ⚠️  1 high (child_process usage)
   Permissions:   ✅ filesystem, network
   Publisher:     ✅ Verified on npm (2 years, 50K downloads/week)
```

### Secure an MCP server (2 minutes)

```bash
npx create-sentinel-app my-server --template mcp-secure-server
```

Every tool call goes through: **identity → credentials → scope → reputation → safety → audit.**

### Zero-trust handshake between two agents

```bash
npx create-sentinel-app demo --template two-agent-handshake
```
```
1️⃣  Alice → Init (nonce + DID + passport)
2️⃣  Bob → Response (nonce + DID)
3️⃣  Alice → VC Exchange → Bob verifies: ✅
4️⃣  Bob → VC Exchange → Alice verifies: ✅
🔐 Session established. Neither trusted a central authority.
```

---

## The 5-line version

```ts
import { createTrustedAgent } from '@sentinel-atl/sdk';

const agent = await createTrustedAgent({
  name: 'my-agent',
  capabilities: ['search', 'book'],
  enableSafety: true,
});

console.log(agent.did);  // did:key:z6Mk...
```

That agent now has: a DID, credential issuance, zero-trust handshake, content safety (prompt injection / jailbreak / PII blocking), and a tamper-evident audit trail.

---

## Proof of Intent — the core idea

Every other agent identity system answers: *"Is this agent who it claims to be?"*

Sentinel also answers: *"Was this action authorized by a real human, through what delegation chain, for what scope, and is it still valid?"*

```
Human → issues credential (scope: travel:search, travel:book)
  └─→ Agent A → delegates to Agent B (scope narrows to: travel:search only)
        └─→ Agent B → calls search_flights()
              └─→ Intent Envelope: signed by B, chain proves A authorized it,
                   chain proves Human authorized A, scope covers this tool ✅
```

Every hop narrows. Never widens. If any link is revoked, expired, or out of scope — the chain breaks.

---

## Agent Notary: scan → certify → enforce

A full supply-chain trust pipeline for MCP servers.

**Scan** — 7-layer analysis (dependencies, code patterns, permissions, publisher identity, typosquatting, semantic analysis):
```bash
npx @sentinel-atl/scanner scan some-mcp-server
# Trust Score: 58/100 (Grade: D) — eval() usage, young npm account
```

**Certify** — issue a signed Sentinel Trust Certificate (STC):
```ts
const report = await scan({ packageName: 'some-mcp-server' });
const stc = await issueSTC({ issuer, subject, findings: report.findings });
```

**Enforce** — the Trust Gateway blocks uncertified or low-score servers:
```yaml
# sentinel.yaml
gateway:
  mode: strict
  minTrustScore: 70
servers:
  - name: filesystem
    upstream: stdio://node ./fs-server.js
    trust:
      requireCertificate: true
      maxFindingsCritical: 0
    blockedTools: [delete_file]
```

```bash
npx sentinel-gateway --config sentinel.yaml
```

---

## How it works

```
 Human                        Agent A                     Agent B
   │                            │                            │
   │ 1. Issue credential        │                            │
   │  (scoped permissions)      │                            │
   │───────────────────────────>│                            │
   │                            │ 2. Zero-trust handshake    │
   │                            │<─────────────────────────>│
   │                            │     ✓ Mutually verified    │
   │                            │ 3. Delegate (scope narrows)│
   │                            │──────────────────────────>│
   │  4. Step-up auth?          │                            │
   │  (if high sensitivity)     │                            │
   │<────────────────────────────────────────────────────────│
   │  ✓ Approved                │                            │
   │─────────────────────────────────────────────────────────>
   │                            │ 5. Reputation vouch        │
   │                            │<────────────────────────>│
```

Every arrow is cryptographically signed. Every step is audit-logged.

---

## Packages — 33 modules, use what you need

<details>
<summary><b>Core identity & credentials</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/core`](https://www.npmjs.com/package/@sentinel-atl/core) | DID identity, W3C Verifiable Credentials, Proof of Intent, Ed25519 crypto |
| [`@sentinel-atl/sdk`](https://www.npmjs.com/package/@sentinel-atl/sdk) | High-level SDK — 5-line integration |
| [`@sentinel-atl/handshake`](https://www.npmjs.com/package/@sentinel-atl/handshake) | Zero-trust mutual agent verification (5-step protocol) |
| [`@sentinel-atl/attestation`](https://www.npmjs.com/package/@sentinel-atl/attestation) | Code attestation — cryptographic bind of DID → code hash |

</details>

<details>
<summary><b>Trust scoring & lifecycle</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/reputation`](https://www.npmjs.com/package/@sentinel-atl/reputation) | Weighted scoring, Sybil resistance, time decay, quarantine |
| [`@sentinel-atl/revocation`](https://www.npmjs.com/package/@sentinel-atl/revocation) | VC/DID revocation, key rotation, emergency kill switch |
| [`@sentinel-atl/audit`](https://www.npmjs.com/package/@sentinel-atl/audit) | Tamper-evident hash-chain audit log |
| [`@sentinel-atl/safety`](https://www.npmjs.com/package/@sentinel-atl/safety) | Content safety — prompt injection, jailbreak, PII detection |

</details>

<details>
<summary><b>Gateways & proxies</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/gateway`](https://www.npmjs.com/package/@sentinel-atl/gateway) | Full MCP security gateway with policies & rate limiting |
| [`@sentinel-atl/trust-gateway`](https://www.npmjs.com/package/@sentinel-atl/trust-gateway) | YAML-configured trust enforcement proxy |
| [`@sentinel-atl/mcp-plugin`](https://www.npmjs.com/package/@sentinel-atl/mcp-plugin) | Drop-in MCP middleware (10-step verification) |
| [`@sentinel-atl/mcp-proxy`](https://www.npmjs.com/package/@sentinel-atl/mcp-proxy) | Transport-level proxy (stdio/SSE) |

</details>

<details>
<summary><b>Supply chain scanning</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/scanner`](https://www.npmjs.com/package/@sentinel-atl/scanner) | 7-layer MCP package security analysis (score 0–100, grade A–F) |
| [`@sentinel-atl/registry`](https://www.npmjs.com/package/@sentinel-atl/registry) | Trust certificate registry API + SVG badges |
| [`@sentinel-atl/crawler`](https://www.npmjs.com/package/@sentinel-atl/crawler) | MCP server discovery across Glama, npm, PyPI |
| [`@sentinel-atl/pipeline`](https://www.npmjs.com/package/@sentinel-atl/pipeline) | Large-scale scanning workers |

</details>

<details>
<summary><b>Production & operations</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/hardening`](https://www.npmjs.com/package/@sentinel-atl/hardening) | Auth, CORS, TLS, rate limiting, security headers, nonce replay protection |
| [`@sentinel-atl/store`](https://www.npmjs.com/package/@sentinel-atl/store) | Redis, PostgreSQL, SQLite, in-memory persistence |
| [`@sentinel-atl/telemetry`](https://www.npmjs.com/package/@sentinel-atl/telemetry) | OpenTelemetry traces, metrics, spans |
| [`@sentinel-atl/budget`](https://www.npmjs.com/package/@sentinel-atl/budget) | Token/cost control, circuit breakers |
| [`@sentinel-atl/server`](https://www.npmjs.com/package/@sentinel-atl/server) | HTTP REST API server (STP-compliant) |
| [`@sentinel-atl/conformance`](https://www.npmjs.com/package/@sentinel-atl/conformance) | STP protocol conformance test suite |

</details>

<details>
<summary><b>Human-in-the-loop & resilience</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/approval`](https://www.npmjs.com/package/@sentinel-atl/approval) | Human approval workflows (Slack, Webhook, Web UI) |
| [`@sentinel-atl/stepup`](https://www.npmjs.com/package/@sentinel-atl/stepup) | Step-up auth — re-prompt humans for sensitive actions |
| [`@sentinel-atl/offline`](https://www.npmjs.com/package/@sentinel-atl/offline) | Cached trust decisions, CRDT merge, degraded mode |
| [`@sentinel-atl/recovery`](https://www.npmjs.com/package/@sentinel-atl/recovery) | Shamir's Secret Sharing (3-of-5 key backup) |
| [`@sentinel-atl/hsm`](https://www.npmjs.com/package/@sentinel-atl/hsm) | HSM backends (AWS CloudHSM, Azure Managed HSM, PKCS#11) |

</details>

<details>
<summary><b>Integrations & tools</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/adapters`](https://www.npmjs.com/package/@sentinel-atl/adapters) | LangChain.js, CrewAI, AutoGen, Vercel AI SDK, MCP SDK |
| [`@sentinel-atl/cli`](https://www.npmjs.com/package/@sentinel-atl/cli) | Command-line tool |
| [`@sentinel-atl/dashboard`](https://www.npmjs.com/package/@sentinel-atl/dashboard) | Web trust visualization dashboard |
| [`create-sentinel-app`](https://www.npmjs.com/package/create-sentinel-app) | Project scaffolder |
| [`sentinel-atl`](https://pypi.org/project/sentinel-atl/) | Full Python SDK |

</details>

---

## Framework adapters

Works with what you already use:

```ts
import { wrapMCPServer } from '@sentinel-atl/adapters';    // MCP SDK
import { SentinelCallbackHandler } from '@sentinel-atl/adapters'; // LangChain.js
import { createVercelAIMiddleware } from '@sentinel-atl/adapters'; // Vercel AI SDK
import { withTrust } from '@sentinel-atl/adapters';         // Any async function
```

Python:
```python
from sentinel_atl.langchain import SentinelCallbackHandler
```

---

## Production-ready

Dockerized, observable, hardened:

```bash
docker compose up -d  # Server + MCP Proxy + Approval UI + Redis
```

| | |
|---|---|
| **Hardening** | Security headers, CORS lockdown, TLS, nonce replay protection, rate limiting |
| **Observability** | OpenTelemetry traces/metrics, structured JSON logging, request IDs |
| **Operations** | Health/readiness probes, graceful shutdown, env validation, audit log rotation |
| **Storage** | Redis, PostgreSQL, SQLite backends via `@sentinel-atl/store` |
| **Docker** | Read-only filesystem, resource limits, non-root user |

See the [Operations Guide](docs/operations-guide.md) for deployment, scaling, and monitoring details.

---

## Install

```bash
npm install @sentinel-atl/core @sentinel-atl/sdk   # TypeScript
pip install sentinel-atl                             # Python
```

Or scaffold a ready-to-run app:

```bash
npx create-sentinel-app my-agent
npx create-sentinel-app my-server --template mcp-secure-server
npx create-sentinel-app demo --template two-agent-handshake
```

## Open protocol

Sentinel implements the [Sentinel Trust Protocol (STP) v1.0](specs/sentinel-trust-protocol-v1.0.md) — an open specification, not a proprietary product. Three compliance levels:

| Level | What you get |
|---|---|
| **STP-Lite** | DID + Verifiable Credentials |
| **STP-Standard** | + Handshake + Reputation + Audit |
| **STP-Full** | + Revocation + Attestation + Safety + Offline |

Test any implementation against the spec:
```bash
STP_SERVER_URL=http://localhost:3000 npx @sentinel-atl/conformance
```

## Contributing

```bash
git clone https://github.com/sentinel-atl/project-sentinel.git
cd project-sentinel && npm install && npm run build && npm test
# 592 tests across 33 packages
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE) — Built because trust cannot be a proprietary product.

---

**Sentinel is not a competitor to MCP or A2A. It's the trust layer they're missing.**
