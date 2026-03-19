# Project Sentinel

**Security scanner and trust gateway for MCP servers.**

Scan any MCP package for vulnerabilities, dangerous code patterns, and publisher risk — then enforce trust policies at the gateway before requests reach your servers.

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

[![npm](https://img.shields.io/npm/v/@sentinel-atl/scanner)](https://www.npmjs.com/package/@sentinel-atl/scanner)
[![Tests](https://img.shields.io/badge/Tests-592%20passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7+-3178C6.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg)](python/)

---

## What the scanner checks

7-layer analysis, zero setup:

| Layer | What it catches |
|---|---|
| **Dependencies** | Known CVEs via npm audit |
| **Code patterns** | `eval()`, `child_process`, dynamic `require()`, `fs` writes |
| **Permissions** | Filesystem, network, shell access — flagged by risk level |
| **Publisher identity** | npm account age, weekly downloads, provenance signatures |
| **Typosquatting** | Name similarity to popular packages (Levenshtein + prefix matching) |
| **Semantic analysis** | Optional LLM-based code review for subtle issues |
| **Trust score** | Weighted composite: 0–100, grade A–F |

```bash
# Scan any npm package
npx @sentinel-atl/scanner scan some-mcp-server

# Scan in CI (GitHub Action)
- uses: sentinel-atl/scan-action@v1
  with:
    packages: some-mcp-server
    min-score: 70
    max-critical: 0
```

---

## Enforce with the Trust Gateway

Scanning tells you what's risky. The gateway *enforces* it — blocks untrusted packages, dangerous tools, and low-score servers before requests reach them:

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

**scan → certify → enforce:** Scan a package, issue a signed trust certificate, publish it to a registry, then the gateway only routes to certified servers.

```ts
import { scan, issueSTC } from '@sentinel-atl/scanner';

const report = await scan({ packageName: 'some-mcp-server' });
const stc = await issueSTC({ issuer, subject, findings: report.findings });
// Publish to your trust registry → gateway enforces it
```

---

## Under the hood: agent identity layer

The scanner and gateway are the entry point. Underneath, Sentinel has a full cryptographic identity system for AI agents — for when you need to go beyond scanning:

<details>
<summary><b>Cryptographic identity & credentials</b></summary>

Every agent gets a DID (`did:key`, Ed25519), W3C Verifiable Credentials with scoped permissions, and a signed **Proof of Intent** that traces every action back to the human who authorized it.

```ts
import { createTrustedAgent } from '@sentinel-atl/sdk';

const agent = await createTrustedAgent({
  name: 'my-agent',
  capabilities: ['search', 'book'],
  enableSafety: true,
});

console.log(agent.did);  // did:key:z6Mk...
```

</details>

<details>
<summary><b>Zero-trust handshake</b></summary>

Two agents that have never met can mutually verify in 5 cryptographic steps — no central authority needed:

```
1️⃣  Alice → Init (nonce + DID + passport)
2️⃣  Bob → Response (nonce + DID)
3️⃣  Alice → VC Exchange → Bob verifies: ✅
4️⃣  Bob → VC Exchange → Alice verifies: ✅
🔐 Session established.
```

```bash
npx create-sentinel-app demo --template two-agent-handshake
```

</details>

<details>
<summary><b>Proof of Intent</b></summary>

Every action carries a signed envelope tying it to a human authorization through the full delegation chain. Scope can only narrow, never widen:

```
Human → credential (scope: travel:search, travel:book)
  └─→ Agent A → delegates to Agent B (scope narrows: travel:search only)
        └─→ Agent B → calls search_flights()
              └─→ Intent Envelope: signed chain proves Human → A → B, scope ✅
```

</details>

<details>
<summary><b>Emergency kill switch</b></summary>

Revoke a compromised agent + cascade to all its delegates in <5 seconds:

```ts
await revMgr.killSwitch(principalKey, keyId, principalDid, compromisedDid, 'breach', { cascade: true });
```

</details>

<details>
<summary><b>Content safety</b></summary>

Blocks prompt injection, jailbreak attempts, and PII leaks — on both inputs and outputs:

```ts
const check = await agent.checkSafety('Ignore previous instructions...');
// { safe: false, blocked: true, violations: [{ category: 'prompt_injection' }] }
```

</details>

---

## Packages

**Scanning & enforcement** (start here):

| Package | Purpose |
|---|---|
| [`@sentinel-atl/scanner`](https://www.npmjs.com/package/@sentinel-atl/scanner) | 7-layer MCP package security scanner (score 0–100, grade A–F) |
| [`@sentinel-atl/trust-gateway`](https://www.npmjs.com/package/@sentinel-atl/trust-gateway) | YAML-configured trust enforcement gateway |
| [`@sentinel-atl/registry`](https://www.npmjs.com/package/@sentinel-atl/registry) | Trust certificate registry API + SVG badges |
| [`@sentinel-atl/crawler`](https://www.npmjs.com/package/@sentinel-atl/crawler) | MCP server discovery across Glama, npm, PyPI |
| [`@sentinel-atl/pipeline`](https://www.npmjs.com/package/@sentinel-atl/pipeline) | Large-scale scanning workers |

<details>
<summary><b>Identity & credentials (deeper integration)</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/core`](https://www.npmjs.com/package/@sentinel-atl/core) | DID identity, W3C Verifiable Credentials, Proof of Intent, Ed25519 crypto |
| [`@sentinel-atl/sdk`](https://www.npmjs.com/package/@sentinel-atl/sdk) | High-level SDK — 5-line integration |
| [`@sentinel-atl/handshake`](https://www.npmjs.com/package/@sentinel-atl/handshake) | Zero-trust mutual agent verification (5-step protocol) |
| [`@sentinel-atl/attestation`](https://www.npmjs.com/package/@sentinel-atl/attestation) | Code attestation — cryptographic bind of DID → code hash |
| [`@sentinel-atl/reputation`](https://www.npmjs.com/package/@sentinel-atl/reputation) | Weighted scoring, Sybil resistance, time decay, quarantine |
| [`@sentinel-atl/revocation`](https://www.npmjs.com/package/@sentinel-atl/revocation) | VC/DID revocation, key rotation, emergency kill switch |
| [`@sentinel-atl/safety`](https://www.npmjs.com/package/@sentinel-atl/safety) | Content safety — prompt injection, jailbreak, PII detection |
| [`@sentinel-atl/audit`](https://www.npmjs.com/package/@sentinel-atl/audit) | Tamper-evident hash-chain audit log |

</details>

<details>
<summary><b>Gateways & MCP integration</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/gateway`](https://www.npmjs.com/package/@sentinel-atl/gateway) | Full MCP security gateway with policies & rate limiting |
| [`@sentinel-atl/mcp-plugin`](https://www.npmjs.com/package/@sentinel-atl/mcp-plugin) | Drop-in MCP middleware (10-step verification) |
| [`@sentinel-atl/mcp-proxy`](https://www.npmjs.com/package/@sentinel-atl/mcp-proxy) | Transport-level proxy (stdio/SSE) |
| [`@sentinel-atl/adapters`](https://www.npmjs.com/package/@sentinel-atl/adapters) | LangChain.js, CrewAI, AutoGen, Vercel AI SDK, MCP SDK |

</details>

<details>
<summary><b>Production & operations</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/hardening`](https://www.npmjs.com/package/@sentinel-atl/hardening) | Auth, CORS, TLS, rate limiting, security headers |
| [`@sentinel-atl/store`](https://www.npmjs.com/package/@sentinel-atl/store) | Redis, PostgreSQL, SQLite, in-memory persistence |
| [`@sentinel-atl/telemetry`](https://www.npmjs.com/package/@sentinel-atl/telemetry) | OpenTelemetry traces, metrics, spans |
| [`@sentinel-atl/budget`](https://www.npmjs.com/package/@sentinel-atl/budget) | Token/cost control, circuit breakers |
| [`@sentinel-atl/approval`](https://www.npmjs.com/package/@sentinel-atl/approval) | Human approval workflows (Slack, Webhook, Web UI) |
| [`@sentinel-atl/stepup`](https://www.npmjs.com/package/@sentinel-atl/stepup) | Step-up auth — re-prompt humans for sensitive actions |
| [`@sentinel-atl/offline`](https://www.npmjs.com/package/@sentinel-atl/offline) | Cached trust decisions, CRDT merge, degraded mode |
| [`@sentinel-atl/recovery`](https://www.npmjs.com/package/@sentinel-atl/recovery) | Shamir's Secret Sharing (3-of-5 key backup) |
| [`@sentinel-atl/hsm`](https://www.npmjs.com/package/@sentinel-atl/hsm) | HSM backends (AWS CloudHSM, Azure Managed HSM, PKCS#11) |
| [`@sentinel-atl/server`](https://www.npmjs.com/package/@sentinel-atl/server) | HTTP REST API server (STP-compliant) |
| [`@sentinel-atl/conformance`](https://www.npmjs.com/package/@sentinel-atl/conformance) | STP protocol conformance test suite |

</details>

<details>
<summary><b>Tools & SDKs</b></summary>

| Package | Purpose |
|---|---|
| [`@sentinel-atl/cli`](https://www.npmjs.com/package/@sentinel-atl/cli) | Command-line tool |
| [`@sentinel-atl/dashboard`](https://www.npmjs.com/package/@sentinel-atl/dashboard) | Web trust visualization dashboard |
| [`create-sentinel-app`](https://www.npmjs.com/package/create-sentinel-app) | Project scaffolder |
| [`sentinel-atl`](https://pypi.org/project/sentinel-atl/) | Full Python SDK |

</details>

---

## Install

```bash
# Scanner (zero config, works immediately)
npx @sentinel-atl/scanner scan <package-name>

# Full SDK
npm install @sentinel-atl/scanner @sentinel-atl/trust-gateway  # scanning + enforcement
npm install @sentinel-atl/core @sentinel-atl/sdk                # identity layer
pip install sentinel-atl                                         # Python
```

## Production deployment

```bash
docker compose up -d  # Server + MCP Proxy + Approval UI + Redis
```

See the [Operations Guide](docs/operations-guide.md) for scaling, monitoring, and hardening details.

## Open protocol

Sentinel implements the [Sentinel Trust Protocol (STP) v1.0](specs/sentinel-trust-protocol-v1.0.md) — an open specification, not a product. Test any implementation:

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

[Apache License 2.0](LICENSE)
