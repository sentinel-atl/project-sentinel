---
title: "npm audit for AI agents — how we built a trust verification system for MCP servers"
published: true
tags: ai, security, typescript, mcp
cover_image: https://raw.githubusercontent.com/sentinel-atl/project-sentinel/main/docs/landing/og-image.png
canonical_url: https://github.com/sentinel-atl/project-sentinel
---

# npm audit for AI agents

MCP (Model Context Protocol) is becoming the USB-C of AI — the standard way agents call tools. Anthropic made it. OpenAI adopted it. LangChain, Vercel AI, and dozens of frameworks support it.

But MCP has a supply chain security problem.

Any MCP server can:
- Run arbitrary code with the host process permissions
- Access the filesystem, network, environment variables
- Execute `child_process`, `eval`, native modules
- Exfiltrate data through network calls

And there's **no standard way to verify if a server is safe** before your agent connects to it.

Sound familiar? It's the same problem npm had before `npm audit`. The same problem the web had before SSL certificates.

## We built the security layer

**Sentinel** is an open-source trust verification system for MCP servers. Three steps: **scan → certify → enforce.**

### Step 1: Scan

```bash
npx @sentinel-atl/scanner scan some-mcp-server
```

The scanner analyzes four dimensions:

1. **Dependency vulnerabilities** — npm audit integration
2. **Code patterns** — detects eval, child_process, fs access, network calls, obfuscation, data exfiltration
3. **Permissions** — profiles what system resources the server needs
4. **Publisher identity** — checks npm registry age, weekly downloads, maintainer count, repository presence

Output: a **trust score (0-100)** with a letter grade (A-F).

### Step 2: Certify

The scan result becomes a **Sentinel Trust Certificate (STC)** — a signed attestation:

```json
{
  "@context": "https://sentinel-protocol.org/v1",
  "type": "SentinelTrustCertificate",
  "issuer": { "did": "did:key:z6Mk..." },
  "subject": { "packageName": "my-server", "packageVersion": "1.2.0" },
  "trustScore": { "overall": 85, "grade": "B" },
  "issuedAt": "2026-03-18T...",
  "expiresAt": "2026-06-18T...",
  "proof": { "type": "Ed25519Signature2020", "signature": "..." }
}
```

Think SSL certificates, but for AI agent servers. Verifiable. Portable. Expirable.

### Step 3: Enforce

A YAML-configured gateway sits between your client and MCP servers:

```yaml
gateway:
  port: 3100
  mode: strict
  minTrustScore: 70

servers:
  - name: filesystem
    upstream: stdio://node ./fs-server.js
    trust:
      minScore: 75
      minGrade: B
      requireCertificate: true
      maxFindingsCritical: 0
    blockedTools: [delete_file]
    rateLimit: "100/min"
```

```bash
npx sentinel-gateway --config sentinel.yaml
```

Every MCP request passes through the gateway. If the server doesn't meet your trust policy, the request is blocked.

## Beyond scanning

Sentinel is more than a scanner. The full Agent Trust Layer includes:

- **Cryptographic identity** — Ed25519 DIDs for every agent
- **Verifiable Credentials** — scoped permissions that can only narrow through delegation
- **Zero-trust handshake** — mutual verification between agents (no central authority)
- **Proof of Intent** — signed chain from human authorization to agent action
- **Content safety** — blocks prompt injection, jailbreak attempts, PII leaks
- **Emergency kill switch** — revoke any agent in under 5 seconds with cascade
- **Audit trail** — tamper-evident hash-chain logging

## Numbers

- 29 TypeScript packages
- 502 tests passing
- Zero npm audit vulnerabilities
- Published on npm under `@sentinel-atl`
- Apache 2.0 license

## Try it

```bash
# Scan any package
npx @sentinel-atl/scanner scan express

# Create a trusted agent app
npx create-sentinel-app my-agent

# Start a trust gateway
npx sentinel-gateway --config sentinel.yaml
```

## Links

- **GitHub**: [github.com/sentinel-atl/project-sentinel](https://github.com/sentinel-atl/project-sentinel)
- **npm**: [@sentinel-atl](https://www.npmjs.com/org/sentinel-atl)

---

We built this because MCP is going to be everywhere, and its security story is "trust me bro." We'd love feedback — especially from anyone deploying MCP servers in production.
