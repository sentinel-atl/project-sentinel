# LinkedIn Launch Post

---

**Post (copy-paste ready):**

I've been building something for the last few months that I'm excited to share.

**The problem**: MCP (Model Context Protocol) is becoming the standard for AI tool calling. Anthropic created it. OpenAI adopted it. But it has zero built-in security — no authentication, no authorization, no way to verify if a server is safe before your agent connects.

This is the same gap the web had before SSL. The same gap npm had before npm audit.

**What I built**: Sentinel — an open-source trust verification system for MCP servers.

Three concepts:

🔍 **Scanner** — scans MCP server packages for dependency vulnerabilities, dangerous code patterns, and publisher identity. Produces a trust score (0-100).

📜 **Trust Certificates** — signed attestations of scan results. Think SSL certificates for AI agents. Verifiable, portable, expirable.

🛡️ **Trust Gateway** — a YAML-configured reverse proxy that enforces trust policies. Block untrusted servers, require certificates, set per-server rules.

Try it right now:
npx @sentinel-atl/scanner scan express

29 packages. 502 tests. Open source. Apache 2.0.

GitHub: https://github.com/sentinel-atl/project-sentinel

If you're building with MCP or deploying AI agents in production, I'd love to hear what security challenges you're facing.

#AI #MCP #Security #OpenSource #AIAgents #TypeScript

---

## Posting Tips

- Post on Tuesday-Thursday, 8-10am in your timezone
- Tag connections who work in AI/security
- If the post gets early engagement, comment with an "AMA" follow-up
- Connect with people who comment and DM them the GitHub link

---

# Product Hunt

**Tagline**: npm audit for AI agents — trust verification for MCP servers

**Description**:

MCP (Model Context Protocol) is becoming the standard for AI tool calling. But it has no security layer. Any server can run arbitrary code, access your filesystem, and exfiltrate data — with no verification.

Sentinel adds the missing trust layer:

🔍 Scan any MCP server package for vulnerabilities, dangerous code, and publisher identity
📜 Issue trust certificates (like SSL certs for AI agents)
🛡️ Enforce trust policies via a YAML-configured gateway
📋 Publish scores to a trust registry with embeddable badges

Try it: npx @sentinel-atl/scanner scan express

29 TypeScript packages. 502 tests. Zero vulnerabilities. Open source.

**Topics**: Developer Tools, Artificial Intelligence, Security, Open Source

**First Comment**: "We built this because MCP is going to power millions of AI tool calls, and right now there's zero verification of what servers your agents connect to. Think of it as Verisign + npm audit for the AI agent ecosystem. Happy to answer any questions!"

---

## Product Hunt Tips

- Schedule for **Tuesday 12:01am PT** (PH resets daily at midnight PT)  
- Get 5-10 people to upvote in the first hour
- Respond to every comment within 30 minutes
- Post a "maker comment" immediately with the backstory
