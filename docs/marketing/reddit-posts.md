# Reddit Launch Posts

Three tailored posts for different subreddits.

---

## Post 1: r/MCP

**Title:** I built a security scanner + trust gateway for MCP servers (open source)

**Body:**

Hey r/MCP,

I've been building MCP servers for a few months and kept running into the same problem: there's no way to verify if a server is safe before connecting to it.

So I built **Sentinel** — an open-source security scanner, certificate system, and enforcement gateway for MCP.

**What it does:**

1. **Scan** any MCP server package for vulnerabilities, dangerous code patterns (eval, child_process, fs), and publisher identity:

```
npx @sentinel-atl/scanner scan some-mcp-server
```

2. **Issue trust certificates** (STCs) — like SSL certs but for MCP servers. Signed attestation of a scan result.

3. **Enforce via a gateway** — a YAML-configured reverse proxy that sits between your client and MCP servers:

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

4. **Trust Registry** — REST API to publish, query, and display trust badges for your server's README.

Everything's open source and on npm: https://github.com/sentinel-atl/project-sentinel

Would love feedback from people actually building MCP servers. What security checks would you want to see?

---

## Post 2: r/LocalLLaMA

**Title:** Open-source "npm audit" for MCP servers — scans for vulnerabilities, dangerous code, and publisher identity

**Body:**

With MCP adoption exploding, I got worried about the security story. Any MCP server can run arbitrary code, access the filesystem, make network requests — and there's no standard way to verify if it's safe.

So I built **Sentinel**, which is essentially **npm audit + Verisign for AI agents**:

**The Scanner** (try it right now):
```
npx @sentinel-atl/scanner scan any-mcp-package
```

It checks:
- 🔍 Dependency vulnerabilities (npm audit integration)
- ⚠️ Dangerous code patterns (eval, child_process, obfuscation, data exfiltration)
- 🔐 Permission analysis (filesystem, network, native modules)
- 👤 Publisher identity (npm registry age, downloads, maintainers)

Output: a trust score (0-100, grade A-F).

**The Gateway** — a reverse proxy you configure with YAML. It sits between Claude/your client and MCP servers, blocking requests that don't meet your trust policy. You can set minimum scores, required certificates, blocked tools, rate limits — all in one config file.

**Trust Certificates** — signed attestations of scan results. Think SSL certs for MCP servers. Publishable to a registry. Embeddable as README badges.

29 packages, 502 tests, all TypeScript, all on npm.

GitHub: https://github.com/sentinel-atl/project-sentinel

Curious what the community thinks about MCP security in general. Is this something you worry about?

---

## Post 3: r/programming

**Title:** Show r/programming: We built a certificate authority for AI agents — open source trust verification for MCP servers

**Body:**

The AI agent ecosystem has a supply chain security problem that nobody's talking about.

**MCP** (Model Context Protocol) is becoming the standard for AI tool calling. It lets agents call any tool on any server. But it has:

- No authentication
- No authorization
- No way to verify a server before connecting
- No audit trail
- No kill switch

Sound familiar? It's the same problem npm had before `npm audit`, or the web had before SSL certificates.

**We built the security layer.**

**Sentinel** is an open-source trust verification system for MCP servers:

1. **Scanner** — Analyzes packages for dependency vulns, dangerous code patterns (eval, child_process, obfuscation), permission requirements, and publisher identity. Produces a 0-100 trust score.

2. **Trust Certificates (STCs)** — Signed, portable attestations of scan results. Think X.509 certs but for AI agent servers. Include issuer DID, scan findings, trust score, expiry.

3. **Trust Gateway** — A YAML-configured reverse proxy that enforces trust policies at the network boundary. Minimum scores, required certificates, blocked tools, rate limits.

4. **Trust Registry** — REST API for publishing, querying, and displaying trust scores. SVG badges for READMEs.

**Technical details:**
- 29 TypeScript packages (monorepo with Turborepo)
- 502 tests, zero type errors, zero npm audit vulnerabilities
- Ed25519 signatures, DID:key identifiers, W3C Verifiable Credentials
- Persistence via Redis, PostgreSQL, or SQLite
- Production hardening: API key auth, CORS, TLS, rate limiting, security headers

The deeper layer includes cryptographic agent identity (DIDs), zero-trust handshakes, scoped delegation chains, and a formal protocol spec (Sentinel Trust Protocol v1.0).

GitHub: https://github.com/sentinel-atl/project-sentinel
npm: `@sentinel-atl/scanner`

Try it: `npx @sentinel-atl/scanner scan express`

---

## Post 4: r/netsec

**Title:** MCP (Model Context Protocol) has zero authentication — here's an open-source trust verification framework

**Body:**

Security take on a growing problem:

MCP is becoming the standard way AI agents call tools. Anthropic, OpenAI, and dozens of frameworks support it. But the protocol has **no security layer**:

- No server authentication
- No client identity verification  
- No authorization framework
- No signed audit trail
- No certificate/attestation system

Any MCP server can execute arbitrary code with the permissions of the host process. There's no standard way to verify a server's safety before connecting. The ecosystem is growing fast and nobody's building the PKI layer.

**Sentinel** is our attempt at fixing this. Open source (Apache 2.0):

- **Scanner**: Static analysis of MCP server packages — dependency audit, code pattern detection (eval, child_process, fs, obfuscation, data exfiltration), permission profiling, publisher identity checks against npm registry. Produces signed trust scores.

- **Trust Certificates**: Ed25519-signed attestations binding a scan result to an issuer DID. Include findings, score, grade, expiry. Structured as W3C Verifiable Credential-compatible.

- **Enforcement Gateway**: Reverse proxy with YAML-configurable policies. Enforces minimum trust scores, required certificates, tool-level allow/blocklists. RFC 6585 rate limiting, API key auth, TLS termination.

- **Production hardening**: Constant-time auth comparison, nonce replay protection, security headers (CSP, HSTS, X-Frame-Options), audit log rotation.

The trust model uses DID:key (Ed25519), W3C Verifiable Credentials with scoped permissions, and a zero-trust handshake protocol for mutual agent verification.

Repo: https://github.com/sentinel-atl/project-sentinel

Looking for feedback from security folks — especially on the threat model and certificate validation approach. Happy to discuss design decisions.

---

## Posting Tips

- **r/MCP**: Post anytime, smaller sub, engaged audience
- **r/LocalLLaMA**: Post afternoon ET, avoid weekends
- **r/programming**: Post morning ET Tue-Thu. Must be self-post (no direct links)
- **r/netsec**: Post morning ET. Technical tone required. They'll tear apart anything hand-wavy
- Space posts 1-2 hours apart, don't spam all at once
- Respond to every comment in the first 2 hours
