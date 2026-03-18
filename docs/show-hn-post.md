---
title: "Show HN: Sentinel – Open-source security layer for AI agents (MCP, LangChain, CrewAI)"
published: true
tags: ai, security, typescript, opensource
---

# Show HN: Sentinel – Open-source security layer for AI agents

AI agents are calling APIs, processing payments, and hiring sub-agents. MCP lets them use tools. A2A lets them talk. But neither has authentication, authorization, or audit.

**Sentinel adds the missing security layer.**

## Try it in 30 seconds

```bash
npx create-sentinel-app my-agent
cd my-agent && npm start
```

You get an agent with a cryptographic identity (DID), verifiable credentials, content safety (blocks prompt injection), and an audit trail. Every action is signed and scoped.

## The problem

MCP (Model Context Protocol) is growing fast. It lets AI agents call tools. But:

- **Any agent can call any tool** — no authentication
- **No way to verify who authorized an action** — no credentials
- **No audit trail** — no accountability
- **No kill switch** — you can't revoke a rogue agent in under 5 seconds

This is fine for demos. It's terrifying for production.

## What Sentinel does

```ts
import { createTrustedAgent } from '@sentinel-atl/sdk';

const agent = await createTrustedAgent({
  name: 'my-agent',
  enableSafety: true, // blocks prompt injection out of the box
});

// Every agent gets a DID (did:key:z6Mk...)
// Issue verifiable credentials with scoped permissions
// Zero-trust handshake between agents
// Tamper-evident audit log
// Emergency kill switch (<5s revocation)
```

## Secure your MCP server

```bash
npx create-sentinel-app my-server --template mcp-secure-server
```

Every tool call goes through: **identity → credentials → reputation → content safety → audit.**

```
→ Calling search_flights({"destination":"Tokyo"})
  ✅ Authorized
  📦 Result: Found 3 flights to Tokyo

→ Calling search_flights with malicious input
  ❌ BLOCKED: Content safety violation
```

## Zero-trust agent handshake

Two agents that don't know each other can cryptographically verify and establish a secure session:

```bash
npx create-sentinel-app demo --template two-agent-handshake
```

```
  1️⃣  Alice → Init (nonce: 024ef99da08a...)
  2️⃣  Bob → Response (nonce: 3ada70dcffb8...)
  3️⃣  Alice → VC Exchange: ✅ VALID
  4️⃣  Bob → VC Exchange: ✅ VALID
  🔐 Session established!
```

Neither agent had to trust a central authority.

## What's inside

29 packages covering the full trust pipeline:

**Agent Notary (scan → certify → enforce):**
- **Scanner**: `npx @sentinel-atl/scanner scan <package>` — dependency audit, code pattern detection, permission analysis, publisher identity verification. Outputs a trust score (0-100, grade A-F).
- **Trust Certificates**: Ed25519-signed attestations of scan results (like SSL certs for AI agents).
- **Trust Gateway**: YAML-configured reverse proxy that enforces trust policies on MCP requests.
- **Trust Registry**: REST API for publishing, querying, and badging trust scores.

**Agent Trust Layer (identity + verification):**
- **Identity**: DID (did:key), W3C Verifiable Credentials, Proof of Intent
- **Verification**: Zero-trust handshake, VC exchange, mutual authentication
- **Security**: Content safety (prompt injection/jailbreak/PII), emergency kill switch, key revocation
- **Trust**: Reputation scoring with Sybil resistance, negative vouches, quarantine
- **Resilience**: Offline mode with cached trust decisions, Shamir key recovery
- **Integration**: LangChain, CrewAI, AutoGen, OpenAI adapters, MCP gateway
- **Standards**: [Sentinel Trust Protocol v1.0](https://github.com/sentinel-atl/project-sentinel/blob/main/specs/sentinel-trust-protocol-v1.0.md) with conformance suite

Built with Ed25519 cryptography. 502 tests. TypeScript. Apache 2.0.

## Try it right now

```bash
npx @sentinel-atl/scanner scan express
```

## Links

- **GitHub**: https://github.com/sentinel-atl/project-sentinel
- **npm**: https://www.npmjs.com/org/sentinel-atl
- **Protocol spec**: [STP v1.0](https://github.com/sentinel-atl/project-sentinel/blob/main/specs/sentinel-trust-protocol-v1.0.md)

---

We built this because MCP is going to be everywhere, and right now it has zero security. We'd love feedback — especially from anyone building multi-agent systems, MCP servers, or dealing with agent authorization in production.
