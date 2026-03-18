# Twitter/X Launch Thread

Copy-paste ready. Post as a thread (each `---` is a new tweet).

---

**Tweet 1 (Hook)**

MCP lets AI agents call any tool.

But it has zero authentication. No audit trail. No kill switch.

I built the missing security layer. Open source.

🧵👇

---

**Tweet 2 (The Problem)**

Right now, if you deploy an MCP server:

• Any agent can call any tool
• No way to verify who authorized an action
• No way to revoke a rogue agent
• No audit trail

This is fine for demos. It's terrifying for production.

---

**Tweet 3 (The Scanner)**

Step 1: Scan any MCP server in one command.

```
npx @sentinel-atl/scanner scan some-mcp-server
```

You get a trust score (0-100) covering:
→ Dependency vulnerabilities
→ Dangerous code patterns (eval, child_process)
→ Permission analysis
→ Publisher identity verification

---

**Tweet 4 (Trust Certificates)**

Step 2: Issue a Sentinel Trust Certificate (STC).

Think SSL certificates, but for AI agents.

The STC is a signed attestation that says:
"This server was scanned on [date], scored [X/100], by [issuer DID]."

Verifiable. Portable. Expirable.

---

**Tweet 5 (The Gateway)**

Step 3: Enforce with a YAML-configured trust gateway.

```yaml
gateway:
  mode: strict
  minTrustScore: 70
servers:
  - name: filesystem
    trust:
      minScore: 75
      requireCertificate: true
    blockedTools: [delete_file]
```

One config file. Every MCP request is verified.

---

**Tweet 6 (Full Stack)**

The full stack:

🔍 Scanner — npm audit for MCP servers
📜 Trust Certificates — SSL certs for AI agents
🛡️ Gateway — YAML-configured enforcement proxy
📋 Registry — publish & query trust scores + SVG badges
🔒 Hardening — auth, CORS, TLS, rate limiting

All open source. All on npm.

---

**Tweet 7 (Beyond Scanning)**

But Sentinel is more than a scanner.

It's a complete Agent Trust Layer:
• DID identity for every agent
• Verifiable Credentials with scoped permissions
• Zero-trust handshakes between agents
• Proof of Intent (who authorized this chain?)
• Content safety (blocks prompt injection)
• Emergency kill switch (<5s)

---

**Tweet 8 (CTA)**

29 packages. 502 tests. Published on npm.

GitHub: github.com/sentinel-atl/project-sentinel
npm: @sentinel-atl/scanner

Try it:
```
npx @sentinel-atl/scanner scan express
```

Star ⭐ if you think MCP needs a security layer.

---

## Posting Tips

- Post at **9-10am ET on Tue/Wed/Thu** for max visibility
- Tag: @anthropic @alexalbert__ @modelaborian
- Add an image/screenshot of the scanner output for Tweet 3
- Pin the thread to your profile after posting
