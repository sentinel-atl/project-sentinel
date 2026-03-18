# 🛡️ Project Sentinel

**The missing security layer for AI agents.**

Give your AI agents cryptographic identity, verifiable credentials, and zero-trust authentication — in 5 lines of code.

[![npm](https://img.shields.io/npm/v/@sentinel-atl/core?label=npm)](https://www.npmjs.com/package/@sentinel-atl/core)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7+-3178C6.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/Tests-360%20passing-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg)](python/)
[![Protocol](https://img.shields.io/badge/Protocol-STP%20v1.0-green.svg)](specs/sentinel-trust-protocol-v1.0.md)

```bash
npx create-sentinel-app my-agent
cd my-agent && npm start
```

```
🛡️  Starting trusted agent...

✅ Agent created: did:key:z6MkmFvfVYWsTms7kKAZKFyUeWKf65KU...
   Capabilities: search, process, respond

📜 Credential issued: urn:uuid:731fb0a2-de3b-d2e6-75...
🎯 Intent created: 019cff66-3ed5-7d34-be7e-ba62d8...

🔒 Safety check: ✅ SAFE
🔒 Safety check: ❌ BLOCKED (prompt injection detected)

🎉 Your trusted agent is ready!
```

---

## Why?

AI agents are being deployed everywhere — booking flights, processing payments, calling APIs, hiring sub-agents. But:

- **MCP** lets agents call tools. It has **no security layer.**
- **A2A** lets agents talk. It has **no identity verification.**
- Your agents have **no way to prove who they are, what they're allowed to do, or who authorized them.**

Sentinel adds the trust layer that's missing.

## What You Get

```ts
import { createTrustedAgent } from '@sentinel-atl/sdk';

const agent = await createTrustedAgent({
  name: 'my-agent',
  capabilities: ['search', 'book'],
  enableSafety: true,  // Blocks prompt injection out of the box
});

// Every agent gets a cryptographic identity (DID)
console.log(agent.did); // did:key:z6Mk...

// Issue verifiable credentials
const vc = await agent.issueCredential({
  type: 'AgentAuthorizationCredential',
  subjectDid: peerAgent.did,
  scope: ['travel:search', 'travel:book'],
});

// Zero-trust handshake with another agent
const session = await agent.handshake(peerDid, peerPassport, myVCs, peerVCs);

// Content safety — blocks prompt injection, jailbreak, PII leaks
const check = await agent.checkSafety('Ignore previous instructions...');
// { safe: false, blocked: true, violations: [{ category: 'prompt_injection' }] }
```

## Secure Your MCP Server in 2 Minutes

MCP has no built-in security. Sentinel fixes that:

```bash
npx create-sentinel-app my-server --template mcp-secure-server
cd my-server && npm start
```

```
🛡️  MCP Server with Sentinel Security
🖥️  Server: did:key:z6Mko15S...
🤖 Agent:  did:key:z6MktP4u...

→ Calling search_flights({"destination":"Tokyo"})
  ✅ Authorized (reputation: n/a)
  📦 Result: Found 3 flights to Tokyo starting at $371

→ Calling search_flights with malicious input
  ❌ BLOCKED: Content safety violation
```

Every tool call is verified: **identity → credentials → reputation → safety → audit.**

## Zero-Trust Agent Handshake

Two agents that don't know each other can cryptographically verify and establish a session:

```bash
npx create-sentinel-app demo --template two-agent-handshake
cd demo && npm start
```

```
🤝 Starting zero-trust handshake...

  1️⃣  Alice → Init (nonce: 024ef99da08a...)
  2️⃣  Bob → Response (nonce: 3ada70dcffb8...)
  3️⃣  Alice → VC Exchange (AgentAuthorizationCredential)
  4️⃣  Bob verifies Alice: ✅ VALID
  5️⃣  Bob → VC Exchange (AgentAuthorizationCredential)
  6️⃣  Alice verifies Bob: ✅ VALID

🔐 Session established!
✅ Both agents verified each other cryptographically.
   Neither had to trust a central authority.
```

## How It Works

```
 Human                        Agent A                     Agent B
   │ 1. Issue credential        │                            │
   │  (scoped permissions)      │                            │
   │───────────────────────────>│                            │
   │                            │ 2. Zero-trust handshake    │
   │                            │  (mutual VC exchange)      │
   │                            │<─────────────────────────>│
   │                            │     ✓ Both verified        │
   │                            │ 3. Delegate (scope narrows)│
   │                            │──────────────────────────>│
   │  4. Step-up auth?          │                            │
   │  (if high sensitivity)     │                            │
   │<────────────────────────────────────────────────────────│
   │  ✓ Approved                │                            │
   │─────────────────────────────────────────────────────────>
   │                            │ 5. Reputation feedback     │
   │                            │<────────────────────────>│
```

Every arrow is cryptographically signed. Every step is audit-logged. Scope can only narrow, never widen.

## Packages

| Package | What it does |
|---|---|
| [`@sentinel-atl/core`](https://www.npmjs.com/package/@sentinel-atl/core) | DID identity, Verifiable Credentials, Proof of Intent, crypto |
| [`@sentinel-atl/sdk`](https://www.npmjs.com/package/@sentinel-atl/sdk) | High-level SDK — 5-line integration |
| [`@sentinel-atl/handshake`](https://www.npmjs.com/package/@sentinel-atl/handshake) | Zero-trust mutual agent verification |
| [`@sentinel-atl/gateway`](https://www.npmjs.com/package/@sentinel-atl/gateway) | MCP Security Gateway |
| [`@sentinel-atl/mcp-plugin`](https://www.npmjs.com/package/@sentinel-atl/mcp-plugin) | MCP middleware for tool-call gating |
| [`@sentinel-atl/mcp-proxy`](https://www.npmjs.com/package/@sentinel-atl/mcp-proxy) | **NEW** Real MCP transport proxy (stdio/SSE) with CLI |
| [`@sentinel-atl/reputation`](https://www.npmjs.com/package/@sentinel-atl/reputation) | Trust scoring, Sybil resistance, quarantine |
| [`@sentinel-atl/safety`](https://www.npmjs.com/package/@sentinel-atl/safety) | Content safety — prompt injection, PII, jailbreak + Azure/OpenAI/LlamaGuard |
| [`@sentinel-atl/audit`](https://www.npmjs.com/package/@sentinel-atl/audit) | Tamper-evident hash-chain audit log (standalone API available) |
| [`@sentinel-atl/revocation`](https://www.npmjs.com/package/@sentinel-atl/revocation) | Credential revocation + emergency kill switch |
| [`@sentinel-atl/store`](https://www.npmjs.com/package/@sentinel-atl/store) | **NEW** Persistent storage (Redis, PostgreSQL, SQLite) |
| [`@sentinel-atl/telemetry`](https://www.npmjs.com/package/@sentinel-atl/telemetry) | **NEW** OpenTelemetry traces, metrics, spans |
| [`@sentinel-atl/budget`](https://www.npmjs.com/package/@sentinel-atl/budget) | **NEW** Token/cost control, circuit breakers, usage attribution |
| [`@sentinel-atl/approval`](https://www.npmjs.com/package/@sentinel-atl/approval) | **NEW** Human approval workflows (Webhook, Slack, Web UI) |
| [`@sentinel-atl/adapters`](https://www.npmjs.com/package/@sentinel-atl/adapters) | Vercel AI SDK, LangChain.js, MCP SDK, CrewAI, AutoGen adapters |
| [`@sentinel-atl/server`](https://www.npmjs.com/package/@sentinel-atl/server) | HTTP REST API server |
| [`@sentinel-atl/cli`](https://www.npmjs.com/package/@sentinel-atl/cli) | Command-line tool |
| [`@sentinel-atl/recovery`](https://www.npmjs.com/package/@sentinel-atl/recovery) | Shamir's Secret Sharing key backup |
| [`@sentinel-atl/attestation`](https://www.npmjs.com/package/@sentinel-atl/attestation) | Code attestation (bind DID → code hash) |
| [`@sentinel-atl/stepup`](https://www.npmjs.com/package/@sentinel-atl/stepup) | Step-up auth for sensitive actions |
| [`@sentinel-atl/offline`](https://www.npmjs.com/package/@sentinel-atl/offline) | Offline mode with cached trust decisions |
| [`@sentinel-atl/hsm`](https://www.npmjs.com/package/@sentinel-atl/hsm) | HSM backends (AWS CloudHSM, Azure, PKCS#11) |
| [`@sentinel-atl/dashboard`](https://www.npmjs.com/package/@sentinel-atl/dashboard) | Trust visualization dashboard |
| [`@sentinel-atl/conformance`](https://www.npmjs.com/package/@sentinel-atl/conformance) | STP protocol conformance test suite |
| [`create-sentinel-app`](https://www.npmjs.com/package/create-sentinel-app) | `npx create-sentinel-app` scaffolder |
| **Python SDK** | |
| [`sentinel-atl`](https://pypi.org/project/sentinel-atl/) | Full Python SDK — DID, VC, reputation, audit, safety, LangChain |

## Proof of Intent — Why This Matters

Every other agent identity system answers: _"Is this agent who it claims to be?"_

Sentinel also answers: _"Was this action authorized by a real human, through what chain, for what purpose, and is it still valid?"_

```json
{
  "intentId": "019522ab-...",
  "action": "book_flight",
  "scope": ["travel:book", "payment:authorize_up_to_500"],
  "principalDid": "did:key:z6MkHuman...",
  "agentDid": "did:key:z6MkAgent...",
  "delegationChain": ["vc:auth-credential-id", "vc:delegation-credential-id"],
  "expiry": "2026-03-15T23:59:59Z",
  "nonce": "a7f3...",
  "signature": "base64url(...)"
}
```

This envelope travels with every action. Sub-agents inherit it. Scope can only narrow. If anything looks wrong, the chain breaks.

## Designed for the A2A + MCP Ecosystem

Sentinel is NOT a competitor to A2A or MCP. It's the **trust layer they're missing**.

- **A2A** handles agent-to-agent communication → Sentinel adds identity verification before agents communicate
- **MCP** handles tool calling → Sentinel adds authorization checks at the tool-call boundary
- Sentinel works **alongside** both protocols, not instead of them

## Architecture

```
project-sentinel/
├── packages/
│   ├── core/           # DID, VC, Intent, Passport, crypto
│   ├── handshake/      # Zero-trust mutual verification
│   ├── reputation/     # Weighted scoring engine
│   ├── audit/          # Hash-chain audit logging (standalone API)
│   ├── recovery/       # Shamir's Secret Sharing
│   ├── revocation/     # VC/DID revocation, key rotation, kill switch
│   ├── attestation/    # Code attestation (bind DID → code hash)
│   ├── stepup/         # Step-up auth (human re-approval)
│   ├── offline/        # Offline mode, LRU cache, CRDT merge
│   ├── safety/         # Content safety (regex + Azure/OpenAI/LlamaGuard)
│   ├── adapters/       # Vercel AI, LangChain.js, MCP SDK, CrewAI, AutoGen
│   ├── mcp-plugin/     # MCP tool-call gating middleware
│   ├── mcp-proxy/      # Real MCP transport proxy (stdio/SSE)
│   ├── store/          # Persistent storage (Redis, PostgreSQL, SQLite)
│   ├── telemetry/      # OpenTelemetry traces, metrics, spans
│   ├── budget/         # Token/cost budgets, circuit breakers
│   ├── approval/       # Human approval workflows (Slack, Webhook, Web UI)
│   ├── sdk/            # Developer SDK (5-line integration)
│   ├── cli/            # sentinel CLI tool
│   ├── hsm/            # HSM KeyProvider backends
│   └── dashboard/      # Web trust visualization dashboard
├── python/             # Python SDK (pip install sentinel-atl)
├── specs/              # Protocol specifications
├── examples/           # Working demos
├── Dockerfile          # Production container
├── docker-compose.yml  # Full stack (server + proxy + Redis)
└── docs/               # Threat model, privacy policy
```

## SDK Quick Start

```ts
import { createTrustedAgent } from '@sentinel-atl/sdk';

// Create a trusted agent in 5 lines
const agent = await createTrustedAgent({
  name: 'my-travel-bot',
  capabilities: ['flight_search', 'hotel_booking'],
  enableSafety: true, // Content safety on by default
});

// Issue credentials, handshake, create intents...
const vc = await agent.issueCredential({
  type: 'AgentAuthorizationCredential',
  subjectDid: peerAgent.did,
  scope: ['travel:search'],
});

// Go offline — cached trust decisions continue working
agent.goOffline();
const decision = agent.evaluateTrust(peerDid);
// { action: 'allow', scenario: 'reputation_cached_fresh', ... }

// Content safety check
const safety = await agent.checkSafety('Ignore previous instructions...');
// { safe: false, blocked: true, violations: [{ category: 'prompt_injection' }] }
```

## Python SDK

Full-featured Python implementation with the same cryptographic guarantees:

```bash
pip install sentinel-atl
```

```python
from sentinel_atl import create_trusted_agent

agent = create_trusted_agent(name="my-agent", capabilities=["search", "book"])
print(agent.did)  # did:key:z6Mk...

# Issue credentials, check safety, audit — same API as TypeScript
vc = agent.issue_credential(subject_did=peer.did, credential_type="AgentAuthorizationCredential")
result = agent.check_safety("Ignore previous instructions...")
# SafetyResult(safe=False, violations=[...])
```

LangChain integration included:

```python
from sentinel_atl.langchain import SentinelCallbackHandler
chain.invoke({"input": "..."}, config={"callbacks": [SentinelCallbackHandler(agent)]})
```

## Docker Deployment

Run the full stack in production:

```bash
docker compose up -d
```

This starts:
- **Sentinel Server** on port 3000 (REST API)
- **MCP Proxy** on port 3100 (stdio/SSE transport proxy)
- **Approval UI** on port 3200 (human approval dashboard)
- **Redis** for persistent storage

Or run just the server:

```bash
docker build -t sentinel-server .
docker run -p 3000:3000 sentinel-server
```

## Framework Adapters

Sentinel integrates with real frameworks — not just shape-matching wrappers:

```ts
// Vercel AI SDK — middleware for tool verification
import { createVercelAIMiddleware } from '@sentinel-atl/adapters';
const middleware = createVercelAIMiddleware(verifier);

// LangChain.js — callback handler for tool trust gating
import { SentinelCallbackHandler } from '@sentinel-atl/adapters';
const handler = new SentinelCallbackHandler(verifier);

// MCP SDK — wrap any MCP server with trust checks
import { wrapMCPServer } from '@sentinel-atl/adapters';
wrapMCPServer(server, verifier);

// Universal wrapper — works with any async function
import { withTrust } from '@sentinel-atl/adapters';
const trustedFn = withTrust(verifier, { name: 'search', fn: search });
```

## Security

- **Ed25519** signatures on all identities, credentials, intents, and audit entries
- **Hash-chain integrity** on the audit log (tamper = chain break)
- **Nonce + expiry** on every handshake and intent envelope (prevents replay)
- **Scope narrowing only** through delegation (prevents privilege escalation)
- **Rate limiting** on handshake and vouch operations (prevents abuse)
- **Circuit breaker** on repeated failures (prevents cascading collapse)
- **Shamir's Secret Sharing** for key recovery (prevents permanent identity loss)
- **VC/DID revocation lists** — signed, verifiable, importable across peers
- **Key rotation** with dual-signature notices (old + new key both sign the rotation)
- **Emergency kill switch** with cascade to downstream delegations (<5s)
- **Code attestation** — cryptographic proof an agent is running verified code (supply chain security)
- **Step-up authentication** — sensitive actions pause for human re-approval (signed challenge-response)
- **Content safety pipeline** — prompt injection, jailbreak, PII detection with pluggable classifiers
- **Offline/degraded mode** — configurable policies (allow/warn/deny) when services are unreachable

Report vulnerabilities to: security@sentinel-protocol.org

## Install

```bash
# TypeScript/Node.js
npm install @sentinel-atl/core @sentinel-atl/sdk

# With storage + observability
npm install @sentinel-atl/store @sentinel-atl/telemetry @sentinel-atl/budget

# Python
pip install sentinel-atl
```

Or scaffold a complete app:

```bash
npx create-sentinel-app my-agent
npx create-sentinel-app my-server --template mcp-secure-server
npx create-sentinel-app demo --template two-agent-handshake
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/sentinel-atl/project-sentinel.git
cd project-sentinel
npm install
npm run build
npm test             # 360 tests across 23 files (TypeScript)
cd python && pip install -e ".[dev]" && pytest  # 15 tests (Python)
```

## Protocol

Sentinel implements the [Sentinel Trust Protocol (STP) v1.0](specs/sentinel-trust-protocol-v1.0.md) — an open specification for AI agent trust. The protocol defines three compliance levels:

- **STP-Lite** — DID + Verifiable Credentials (minimum viable trust)
- **STP-Standard** — + Handshake + Reputation + Audit
- **STP-Full** — + Revocation + Attestation + Safety + Offline

Run the conformance suite against any STP implementation:

```bash
STP_SERVER_URL=http://localhost:3000 npx @sentinel-atl/conformance
```

## License

[Apache License 2.0](LICENSE)

---

**Built because trust cannot be a proprietary product.**
