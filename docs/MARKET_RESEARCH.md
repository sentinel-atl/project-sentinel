# Sentinel Hub — Competitive Market Research Report

**Date:** March 18, 2026  
**Objective:** Map the competitive landscape for a trust-first AI Agent Marketplace targeting non-developers

---

## Executive Summary

The AI agent ecosystem is fragmented across **5 categories** with no single player owning the full stack of discovery + trust + execution + safety. The gap is clear: **MCP registries are developer-only directories with zero trust verification, consumer agent platforms have no security layer, and enterprise gateway tools ignore end-users entirely.** Sentinel Hub can own the intersection.

---

## 1. MCP Server Registries / Directories

These are the current "Yellow Pages" for MCP servers. Developer-only, no execution, no trust.

### Smithery (smithery.ai)
- **What:** Leading MCP server registry + gateway. "The fastest way to extend your AI."
- **Scale:** 5,329+ MCP servers, 128,615+ Skills
- **Features:**
  - CLI-based setup (`npx @smithery/cli@latest setup`)
  - Managed OAuth for connections
  - "Skills" marketplace (pre-built workflows)
  - Built-in observability for published servers
  - Protocol gateway (handles MCP spec updates)
- **Pricing:** Free (25K RPCs/mo) → $30/mo Pay-as-you-go ($0.50/1K RPCs) → Custom
- **Audience:** Developers and agent builders only
- **Trust/Security:** None. No scanning, no trust scores, no safety checks
- **Weakness:** CLI-only, no consumer UX, no trust layer, no hosted execution
- **Threat Level:** 🟡 Medium — strong distribution, could add trust later

### Glama (glama.ai/mcp/servers)
- **What:** "All-in-one AI workspace" with largest MCP directory
- **Scale:** 19,602 servers (largest catalog), 30+ categories
- **Features:**
  - Security/license/quality grades (A/B/C) per server
  - Deep categorization (Remote, Python, TypeScript, Developer Tools, etc.)
  - MCP Inspector, Connectors, Clients, Tools sections
  - LLM Router (multi-model gateway)
  - Usage-based sorting (last 30 days popularity)
  - API access
- **Pricing:** Unknown (has /pricing page)
- **Audience:** Developers
- **Trust/Security:** Has basic A/B/C grading for security/license/quality — surface-level only
- **Weakness:** Directory only, no execution, grades are automated metadata checks not real security analysis
- **Threat Level:** 🟡 Medium — biggest catalog, rudimentary trust signals exist

### MCP.so
- **What:** Community-driven MCP marketplace
- **Scale:** 18,719 servers
- **Features:**
  - Featured, Hosted, Official server categories
  - Client directory (HyperChat, DeepChat, Cherry Studio, VS Code, Cursor, etc.)
  - Playground for testing
  - DXT (Desktop Extension) support
  - FAQ-focused, educational
- **Built with:** ShipAny template
- **Audience:** Developers + curious early adopters
- **Trust/Security:** None
- **Weakness:** Built on a template (ShipAny), thin product layer, no execution environment
- **Threat Level:** 🟢 Low — directory only, template-built

### PulseMCP (pulsemcp.com)
- **What:** "Everything MCP" — editorial + directory + newsletter
- **Scale:** Undisclosed server count
- **Features:**
  - Weekly newsletter ("The Pulse")
  - Blog posts, use cases, guides
  - Server + client directory
  - MCP statistics page
  - Founder is on the official MCP Steering Committee
- **Revenue:** Likely sponsorships + "Work With Us" consulting
- **Audience:** MCP community, developers
- **Trust/Security:** None
- **Weakness:** Content-first, thin product. But founder's MCP Steering Committee role = influence
- **Threat Level:** 🟢 Low as product, 🟡 Medium as influencer

### Turbo MCP (turbomcp.ai, formerly mcp.run)
- **What:** Enterprise MCP gateway + management platform (self-hosted)
- **Features:**
  - Self-hosted or cloud deployment (K8s, PaaS, VMs)
  - Trusted MCP server registry with RBAC approvals
  - Full audit logging of all MCP activity
  - AI kill-switch (deactivate agent access instantly)
  - DLP features
  - OAuth + Dynamic Client Registration
  - OIDC-compatible IdP integration
  - Team-based server approval workflow
- **Pricing:** Enterprise (contact sales)
- **Audience:** Enterprise IT teams
- **Trust/Security:** Strong — audit, RBAC, kill-switch, DLP. But no public trust scores or scanning
- **Weakness:** Enterprise-only, no consumer UX, no marketplace, no trust certification
- **Threat Level:** 🟠 Medium-High for enterprise segment — aligned security vision

---

## 2. AI Agent Marketplaces (Consumer)

These are the closest to our vision — but none have a trust/security layer.

### Agent.ai
- **What:** "#1 Marketplace for Professional AI Agents" (Dharmesh Shah / HubSpot)
- **Scale:** 2,332 agents
- **Features:**
  - Browse & use agents in-browser (zero code, one-click)
  - Agent Teams (multi-agent workflows: Sales Prospecting, Meeting Intelligence, Market Research)
  - Premium agents (paid)
  - Ratings & reviews (1-5 stars)
  - Agent categories: Sales, Marketing, Research, Content, Productivity
  - Community-built agents alongside first-party
- **Pricing:** Free tier + Premium agents
- **Audience:** **Non-developers** — business professionals, marketers, sales teams
- **Trust/Security:** Ratings only. No scanning, no safety pipeline, no trust certificates
- **Key People:** Dharmesh Shah (HubSpot founder), Andrei Oprisan
- **Weakness:** No trust verification, no safety filtering, no audit trail, no budget controls
- **Threat Level:** 🔴 High — closest to our consumer marketplace vision, strong brand (HubSpot founder), but zero security layer

### Toolhouse (toolhouse.ai)
- **What:** No-code agent builder + marketplace. "Don't build agents. Delegate work."
- **Features:**
  - Natural language agent creation (describe what you want)
  - Template library (Workout Planner, Content Creator, etc.)
  - Hosted execution — agents run in cloud
  - Zapier + n8n integrations
  - Community templates with usage stats
  - Web-based builder — no code required
- **Pricing:** Free (50 runs/mo) → Pro $10/mo (1K credits) → Enterprise
- **Audience:** Non-developers, small businesses
- **Trust/Security:** Minimal. No scanning, no trust scoring
- **Weakness:** Small scale, European-focused (EU funding), no security differentiation
- **Threat Level:** 🟡 Medium — good no-code UX but small

### Zapier Agents (zapier.com/agents)
- **What:** AI agent platform built on Zapier's 7,000+ app integration network
- **Features:**
  - Agent builder with templates (SEO Writer, Lead Qualifier, Meeting Prep, etc.)
  - Chrome extension
  - Live business data connections from Zapier integrations
  - Chat interface
  - Monitor activity dashboards
  - Fine-tuned models for research & task management
- **Pricing:** Activity-based within Zapier plans
- **Audience:** Zapier's 2.2M existing business users
- **Trust/Security:** Zapier's existing security (SOC 2), but no agent-level trust scoring
- **Weakness:** Agents are secondary to Zapier's automation platform, no trust marketplace
- **Threat Level:** 🟠 Medium-High — massive distribution (2.2M users), could become dominant if they focus

---

## 3. AI Assistant Platforms (Not Marketplaces, but Compete for Users)

### Lindy.ai
- **What:** "AI work assistant" — personal executive assistant via iMessage/web
- **Features:**
  - Manages inbox, calendar, meetings automatically
  - Proactive — texts you before you ask
  - Learns from feedback over time
  - Works via iMessage, web, anywhere
  - Hundreds of integrations
  - Meeting prep, follow-ups, email drafting
- **Pricing:** Plus $49.99/mo → Enterprise (contact)
- **Compliance:** GDPR, SOC 2, HIPAA, PIPEDA
- **Audience:** Professionals (40,000+ users)
- **Trust/Security:** Privacy-first marketing, SOC 2/HIPAA compliant, "data never sold"
- **Weakness:** Single-product assistant, not a marketplace. Not extensible by third parties
- **Threat Level:** 🟢 Low — different model (single assistant vs marketplace)

### Relevance AI (relevanceai.com)
- **What:** "AI Workforce" platform for GTM teams
- **Features:**
  - SuperGTM assistant
  - Multi-agent systems
  - AI workforce building (autonomous teams of agents)
  - 1,000+ app integrations
  - SOC 2 Type II, GDPR, SSO, RBAC
  - Version control on agents, monitoring dashboards
- **Pricing:** Enterprise (contact sales)
- **Customers:** Canva, Autodesk, KPMG, Databricks
- **Audience:** Enterprise GTM teams
- **Trust/Security:** Enterprise-grade (SOC 2, audit logs) but not marketplace-oriented
- **Threat Level:** 🟢 Low — enterprise-only, not a public marketplace

---

## 4. Developer Tool Platforms (Behind the Scenes)

### Composio (composio.dev)
- **What:** "Your agent decides what to do. We handle the rest." — tool infrastructure for agents
- **Features:**
  - 1,000+ app connectors (MCP-compatible)
  - Managed OAuth for every connector
  - Intent-based tool resolution (agent says what it needs, Composio picks the right tool)
  - Sandboxed remote execution
  - Context-aware sessions
  - Model & framework agnostic
  - Used by Claude Code, Cursor users
- **Pricing:** Unknown
- **Compliance:** SOC 2, ISO 27001:2022
- **Audience:** Agent developers building on top of AI frameworks
- **Trust/Security:** SOC 2/ISO, data access controls. But this is infrastructure, not consumer-facing
- **Threat Level:** 🟢 Low — developer infrastructure, potential partner not competitor

---

## 5. Competitive Matrix

| Feature | Smithery | Glama | Agent.ai | Toolhouse | Zapier Agents | Turbo MCP | **Sentinel Hub** |
|---|---|---|---|---|---|---|---|
| **MCP Server Directory** | ✅ 5.3K | ✅ 19.6K | ❌ | ❌ | ❌ | ✅ (private) | ✅ |
| **Consumer Agent Marketplace** | ❌ | ❌ | ✅ 2.3K | ✅ | ✅ | ❌ | ✅ |
| **No-Code UX** | ❌ (CLI) | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Hosted Execution** | ✅ (proxy) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Trust Scoring** | ❌ | 🟡 Basic | ❌ | ❌ | ❌ | ❌ | ✅ Real scanning |
| **Security Scanning** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 4 scanners |
| **DID/VC Identity** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Content Safety** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Budget Controls** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Audit Trail** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ Hash-chain |
| **Step-up Auth** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Kill Switch** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Revocation** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Agent Reviews/Ratings** | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ + Trust Score |
| **Revenue Share for Devs** | ❌ | ❌ | ✅ (Premium) | ❌ | ❌ | ❌ | ✅ |
| **Enterprise Ready** | 🟡 | ❌ | ❌ | 🟡 | ✅ | ✅ | ✅ |

---

## 6. Key Insights

### The Gap
**Nobody combines "App Store simplicity" with "cryptographic trust."**
- Agent.ai has the consumer UX but zero security
- Turbo MCP has enterprise security but no consumer marketplace
- Smithery has MCP distribution but is developer-only
- Glama has the biggest catalog but is a static directory

### Our Unique Position
Sentinel Hub is the **only platform** that can offer:
1. **Browse & use agents with zero code** (like Agent.ai)
2. **Every agent trust-scored and safety-verified** (like nothing else)
3. **Real cryptographic identity** (DIDs, not just OAuth)
4. **Tamper-evident audit trails** (not just logs)
5. **Budget controls + step-up auth** (humans approve sensitive actions)
6. **Built on an open protocol** (STP v1.0 — not proprietary lock-in)

### Market Sizing
| Metric | Value | Source |
|---|---|---|
| MCP servers registered | ~20,000+ | Glama (19.6K), MCP.so (18.7K) |
| Smithery MCP traffic | 25K RPCs/mo free tier | Smithery pricing |
| Agent.ai agents | 2,332 | Agent.ai homepage |
| Zapier users | 2.2 million | Zapier homepage |
| Toolhouse pricing | $0 → $10/mo | Toolhouse pricing |
| Lindy pricing | $49.99/mo | Lindy homepage |
| Smithery pricing | $0 → $30/mo | Smithery pricing |

### Moat Assessment
| Moat | Strength | Why |
|---|---|---|
| Trust Protocol (STP v1.0) | 🟢 Strong | Open spec = ecosystem effects. Hard to replicate the full DID+VC+reputation+safety stack |
| Scanner + Trust Certificates | 🟢 Strong | 4-scanner pipeline (deps, code patterns, permissions, publisher) with cryptographic certificates |
| Hash-chain Audit | 🟢 Strong | Tamper-evident by design — competitors would need to rebuild |
| Safety Pipeline | 🟡 Medium | Regex + Azure/OpenAI/LlamaGuard — could be replicated |
| Kill Switch + Revocation | 🟢 Strong | <5s emergency cascade — enterprise killer feature |
| Open Source | 🟡 Medium | Apache 2.0 = trust + adoption, but also forkable |

---

## 7. Go-to-Market Strategy Recommendation

### Phase 1: MCP Trust Layer (Now → Month 2)
- Position as "the trust scanner that works alongside existing registries"
- Offer trust badge embeds to Smithery, Glama, MCP.so
- Build inbound via `npx @sentinel-atl/scanner scan <server>`
- Target: MCP server developers who want trust badges

### Phase 2: Sentinel Hub MVP (Month 2 → Month 4)
- Launch web marketplace with trust-scored agents
- One-click run: agent executes in sandboxed container behind Sentinel gateway
- Chat UI — anyone can interact with agents
- Import existing MCP servers from Smithery/Glama catalogs
- Target: Non-technical users who want safe AI agents

### Phase 3: Agent Economy (Month 4 → Month 8)
- Developer publishing flow (submit → auto-scan → get certified → list)
- Revenue sharing (70/30 split on premium agents)
- Agent Teams (multi-agent workflows like Agent.ai)
- Enterprise plan (SSO, compliance reports, self-hosted option)
- Target: Agent developers who want distribution + revenue

### Pricing Recommendation
| Tier | Price | Includes |
|---|---|---|
| Free | $0 | 50 agent calls/day, browsing, trust scores |
| Pro | $19/mo | Unlimited calls, premium agents, full audit trail |
| Builder | $49/mo | Publish agents, analytics, revenue sharing |
| Enterprise | Custom | Self-hosted, SSO, compliance, SLA |

---

## 8. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Smithery adds trust scoring | Our 4-scanner pipeline + STP protocol is 12+ months ahead. Partner, don't compete |
| Agent.ai adds security | Their stack is proprietary, not protocol-based. Our open standard = ecosystem |
| Low consumer awareness of agent security | Lead with UX first, trust second ("safe + easy" not "security product") |
| MCP protocol changes | We're protocol-native. Conformance suite keeps us compatible |
| Enterprise buyers want Turbo MCP | Offer self-hosted Hub. Our audit + DID layer is deeper |

---

## 9. Conclusion

The market is wide open for a **trust-first AI agent marketplace**. The two worlds — consumer agent platforms (Agent.ai, Toolhouse) and developer tool registries (Smithery, Glama) — are converging, but neither side has security. Sentinel has the most complete trust stack in the ecosystem (31 packages, 513 tests, STP v1.0 protocol). Building the consumer layer on top transforms us from "security library" to "the safe way to use AI agents."

**Bottom line: Build the Hub. The timing is now.**
