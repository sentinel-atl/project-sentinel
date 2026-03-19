# Sentinel Hub — Product & Engineering Blueprint

**The trust-first AI Agent Marketplace**  
**Date:** March 18, 2026 | **Version:** 1.1

---

## Table of Contents

1. [Product Vision](#1-product-vision)
2. [User Personas & Journeys](#2-user-personas--journeys)
3. [UI/UX Design](#3-uiux-design)
4. [System Architecture](#4-system-architecture)
5. [Backend API Design](#5-backend-api-design)
6. [Data Models](#6-data-models)
7. [Sentinel Package Integration Map](#7-sentinel-package-integration-map)
8. [Agent Runtime](#8-agent-runtime)
9. [Security Model](#9-security-model)
10. [Infrastructure & Deployment](#10-infrastructure--deployment)
11. [Monetization](#11-monetization)
12. [Phased Implementation Plan](#12-phased-implementation-plan)
13. [Sentinel Forge — Self-Building Environment](#13-sentinel-forge--self-building-environment)

---

## 1. Product Vision

### One-liner
**"The App Store for AI Agents — where every agent is trust-verified before you use it."**

### Problem
- 20,000+ MCP servers exist with zero security verification
- Consumer agent platforms (Agent.ai, Toolhouse) have no trust layer
- Non-developers can't use MCP agents without CLI/code knowledge
- No platform tells you: "Is this agent safe to give access to my data?"

### Solution
A web marketplace where anyone can:
1. **Click one button** and start using any agent — no signup, no install, no config
2. **Trust** every agent because it's scanned, certified, and monitored in real-time
3. **Understand everything** because the UI hides all technical complexity

### Core Principles
- **Trust is the product** — not a feature, the foundation
- **Scope can only narrow** — agents never get more access than you grant
- **Open protocol** — built on STP v1.0, not proprietary lock-in

### NON-NEGOTIABLE Design Mandates

These two rules override every other design decision. If a feature conflicts with
either mandate, the feature changes — not the mandate.

#### Mandate 1: ONE-CLICK USE

> A person who has never heard of "MCP" or "AI agents" must be able to
> go from landing on the site to chatting with a working agent in **one click**.

What this means in practice:
- **No signup wall.** First 3 agent sessions are anonymous (cookie-based guest).
- **No detail page required.** Every agent card has a "Use" button → chat opens instantly.
- **No configuration.** Budget, safety, permissions — all auto-applied with smart defaults.
- **No install.** Everything runs server-side in a sandboxed container.
- **No page nav to chat.** Chat opens as a slide-up panel/overlay on the current page.

The user journey is: **See agent → Click "Use" → Chatting in < 2 seconds.**

Anything that adds a step between "see" and "chatting" is a bug.

#### Mandate 2: RADICAL SIMPLICITY

> If your grandmother can't figure out the UI in 30 seconds,
> it's too complicated. Redesign it.

What this means in practice:
- **No jargon visible to consumers.** No "MCP," no "DID," no "STP," no "verifiable credential." These are internal terms. The user sees: "Verified ✓", "Safe ✓", trust shield colors.
- **Progressive disclosure only.** The default view shows: agent name, one-line description, trust color, "Use" button. That's it. Everything else (scan details, audit trail, permissions breakdown) is behind an "info" tap.
- **Conversation starters.** Every agent shows 3-4 suggested prompts so users never face a blank input box.
- **WhatsApp-level chat.** The chat UI is a familiar message thread — not a dashboard, not a terminal, not a form. Type → send → response appears.
- **App Store-level browsing.** Cards in a grid, categories you tap, a search bar. Nothing else.
- **Zero settings.** There is no settings page for consumers. Power users and enterprises get settings — consumers don't.
- **Mobile-native.** Chat is full-screen on phone. Browse is swipeable cards. It feels like an app, not a website.
- **Onboarding IS usage.** There is no tutorial, no walkthrough modal, no 5-step onboarding. The first use of an agent IS the onboarding. The chat opens with a friendly greeting + suggested prompts. Done.

---

## 2. User Personas & Journeys

### Persona A: "Consumer" (Emma, Marketing Manager)
- **Tech level:** Uses Canva, Slack, Notion. No CLI experience
- **Goal:** Find an AI agent to automate competitive research
- **Pain:** Scared of giving random AI tools access to company data
- **Journey (ONE CLICK):**
  ```
  Homepage → Sees "Competitive Intel Agent" card with green shield ✓
  → Clicks [Use] → Chat panel slides up INSTANTLY (no page navigation)
  → Sees: "Hi! I research competitors. Try one of these:"
     • "Analyze Stripe's top competitors"
     • "Market trends in CRM software"
     • "Compare Figma vs Sketch vs Canva"
  → Emma taps a suggestion (or types her own)
  → Agent works. Tool calls show as simple "Searching..." indicator.
  → Results appear. Emma didn't sign up, didn't configure anything.
  → She likes it → saves chat → gentle prompt: "Sign in to keep history"
  ```
  **Total steps to first value: 2 (see card → click Use)**
  **Signup required: No**

### Persona B: "Builder" (Raj, Full-Stack Dev)
- **Tech level:** Builds MCP servers, knows TypeScript
- **Goal:** Publish his flight-booking agent and earn revenue
- **Pain:** No distribution channel, users don't trust unknown agents
- **Journey (simplicity for builders too):**
  ```
  Clicks "Publish" → Pastes npm package name → Auto-scan runs
  → Score: 84/B — plain-English explanation: "1 thing to fix"
  → Raj fixes it, clicks "Rescan" → 95/A ✓
  → Fills 3 fields: Name, Category (dropdown), One-line description
  → Clicks "Go Live" → Agent is on the marketplace in 60 seconds
  → Pricing defaults to Free (can upgrade to paid later)
  → Users start clicking "Use" on his agent card immediately
  ```
  **Publish flow: 3 steps, 3 fields, < 2 minutes**

### Persona C: "Enterprise Admin" (Sarah, Head of IT)
- **Tech level:** Manages corporate tool access, RBAC experience
- **Goal:** Safely roll out AI agents to 500 employees
- **Pain:** Can't let employees install random MCP servers
- **Journey:**
  ```
  Enterprise Dashboard → "Approved Agents" registry
  → Sets org policy: minTrustScore=80, blockedCategories=[financial_write]
  → Reviews agent requests from employees → Approve/Deny
  → Monitors: audit trail, budget spend, safety incidents
  → Gets weekly compliance report
  ```

---

## 3. UI/UX Design

### 3.1 Page Map

```
sentinel-hub.com/
├── / .......................... Homepage (search + agent grid — that's it)
├── /browse .................... Full catalog (search, filter, sort)
├── /agent/:slug ............... Agent info (accessible, never required)
├── /categories/:name .......... Category listing
├── /requests .................. Agent wishlist (popular requests, vote, submit)
├── /publish ................... Builder: 3-step submit flow
├── /dashboard ................. Auth-gated: my history, billing
├── /admin ..................... Enterprise-only: policies, audit
├── /auth/login ................ Login (Google, GitHub, Email)
└── /api/... ................... REST API

  CHAT IS NOT A PAGE.
  Chat is a slide-up overlay panel that opens on ANY page
  when the user clicks "Use" on any agent card.
  URL does not change. No navigation. Instant.
```

### 3.2 Homepage (/)

```
┌─────────────────────────────────────────────────────────┐
│  🛡️ Sentinel Hub                      [Publish] [Sign in] │
├─────────────────────────────────────────────────────────┤
│                                                         │
│        Use any AI agent in one click.                    │
│        Every one is verified safe.                        │
│                                                         │
│   [🔍 What do you need help with?              ]          │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  [Research] [Travel] [Marketing] [Writing] [Code] [All]  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐  │
│  │ 📊          │ │ ✈️          │ │ 📝          │  │
│  │ Research    │ │ Travel     │ │ Write      │  │
│  │ Agent       │ │ Booker     │ │ Assistant  │  │
│  │             │ │            │ │            │  │
│  │ Competitor  │ │ Book       │ │ Blog posts,│  │
│  │ analysis &  │ │ flights &  │ │ emails &   │  │
│  │ reports     │ │ hotels     │ │ copy       │  │
│  │             │ │            │ │            │  │
│  │ 🛡️████████  │ │ 🛡️███████   │ │ 🛡️████████  │  │
│  │ Verified    │ │ Verified   │ │ Verified   │  │
│  │             │ │            │ │            │  │
│  │  [ Use → ]  │ │  [ Use → ] │ │  [ Use → ] │  │
│  └─────────────┘ └─────────────┘ └─────────────┘  │
│                                                         │
│  (more agents in scrollable grid...)                     │
│                                                         │
└─────────────────────────────────────────────────────────┘

NOTE: Homepage has 3 elements only:
  1. Search bar
  2. Category pills
  3. Agent cards with [Use] button
No "How It Works" section. No builder marketing.
Those exist at /about and /publish respectively.
The homepage is a storefront, not a landing page.

SEARCH EMPTY STATE (critical for agent requests):
  When a search returns no results, the page shows:
  ┌─────────────────────────────────────────────────────┐
  │  No agents found for "tax filing assistant"          │
  │                                                     │
  │  Want this agent to exist?                          │
  │  [Request this agent]                                │
  │                                                     │
  │  12 other people have also requested tax help agents │
  └─────────────────────────────────────────────────────┘
  One tap → request submitted. That's it.
  Guests can request too (no sign-in needed).
```

### 3.3 Agent Card Component (SIMPLIFIED)

The card is intentionally minimal. All detail lives behind a tap.

```
┌───────────────────────────┐
│  📊  Research Agent        │  ← Icon + Name
│                           │
│  Competitor analysis &     │  ← One-line description
│  market reports            │
│                           │
│  🛡️ Verified   ★★★★★ 2.3K  │  ← Trust badge + rating + users
│                           │     (trust badge is a COLOR not a number:
│                           │      green = safe, that's all they need)
│  ┌─────────────────────┐ │
│  │      [ Use → ]       │ │  ← ONE primary action. Nothing else.
│  └─────────────────────┘ │
└───────────────────────────┘

What is NOT on the card:
  ✗ Trust score number (just green/yellow/red shield)
  ✗ Permissions list
  ✗ Scan details
  ✗ "View Details" link (accessible by tapping card background)
  ✗ Publisher name (shown on detail, not card)
  ✗ Pricing info (shown after free limit is hit)
```

### 3.4 Agent Detail Page (/agent/:slug)

This page is **never a blocker** to using an agent. It's accessible by:
- Tapping the card background (not the Use button)
- Tapping the ⓘ info icon inside the chat panel
- Direct URL share

It exists for users who WANT more info, not users who NEED it to proceed.

```
┌───────────────────────────────────────────────────┐
│  ← Back                                  [Use →] │
│                                                  │
│  📊 Research Agent                               │
│  Competitor analysis & market reports             │
│  by @market-insights                              │
│                                                  │
│  ┌──────────────────────────────────────────────┐ │
│  │  🛡️ Verified Safe                              │ │
│  │                                              │ │
│  │  Dependencies     ✅ Clear                    │ │
│  │  Code patterns    ✅ Clear                    │ │
│  │  Permissions      ✅ Minimal                  │ │
│  │  Publisher        ✅ 2yr+ on npm              │ │
│  │  Content safety   ✅ Enabled                  │ │
│  │                                              │ │
│  │  Last scanned: 2 days ago                    │ │
│  └──────────────────────────────────────────────┘ │
│                                                  │
│  What this agent can do:                          │
│  • Search the web                                 │
│  • Summarize articles                             │
│  • Compare companies                              │
│  • Generate reports                               │
│                                                  │
│  ★★★★★ 142 reviews  ·  2.3K users                │
│                                                  │
│  "Replaced our manual research" — Emma S.          │
│  "Great for comp analysis" — Raj P.                │
│                                                  │
└───────────────────────────────────────────────────┘

Note: Uses plain English everywhere.
- "Verified Safe" not "STC issued"
- "2yr+ on npm" not "publisher DID attestation p=0.95"
- "Clear" not "0 findings in dep-scan sub-module"
```

### 3.5 Chat Panel (OVERLAY — not a separate page)

Chat is the core product experience. It opens as a **slide-up overlay panel**
on whatever page the user is currently on. URL does not change.
This means: user clicks "Use" on homepage → chat slides up → user can
dismiss it and they're still on the homepage. No navigation, no back button.

On mobile: chat takes full screen (like opening a message thread).

```
│  (current page dimmed behind)                    │
│                                                  │
┌───────────────────────────────────────────────────┐
│  📊 Research Agent       🛡️ Verified   [ⓘ] [✕] │
├───────────────────────────────────────────────────┤
│                                                  │
│  ┌──────────────────────────────────────────────┐ │
│  │ Hi! I research competitors and markets.     │ │
│  │ Try one of these:                            │ │
│  │                                              │ │
│  │  ┌──────────────────────────────────────┐  │ │
│  │  │ "Analyze Stripe's top competitors"      │  │ │
│  │  ├──────────────────────────────────────┤  │ │
│  │  │ "Market trends in CRM software"          │  │ │
│  │  ├──────────────────────────────────────┤  │ │
│  │  │ "Compare Figma vs Sketch vs Canva"       │  │ │
│  │  └──────────────────────────────────────┘  │ │
│  └──────────────────────────────────────────────┘ │
│                                                  │
│  Taps "Analyze Stripe's top competitors"          │
│                                                  │
│  ┌─ You ─────────────────────────────────────────┐ │
│  │ Analyze Stripe's top competitors              │ │
│  └───────────────────────────────────────────────┘ │
│                                                  │
│  ┌─ Agent ───────────────────────────────────────┐ │
│  │  Searching...                                 │ │
│  │  ███████████████ (progress bar)              │ │
│  │                                               │ │
│  │  Here's my analysis of Stripe's top 5          │ │
│  │  competitors in payment processing...          │ │
│  │                                               │ │
│  │  1. **Adyen** — Enterprise-focused...           │ │
│  │  2. **Square** — SMB + in-person...             │ │
│  └───────────────────────────────────────────────┘ │
│                                                  │
│  ┌─────────────────────────────────────┐ [➤]  │
│  │ Type a message...                     │       │
│  └─────────────────────────────────────┘       │
└───────────────────────────────────────────────────┘

SIMPLICITY DECISIONS:
  - Tool calls show as "Searching..." with a progress bar
    NOT as "Calling: web_search(query) ✅ Allowed (trust verified)"
  - No sidebar. No stats panel. No audit trail visible by default.
  - Trust status is a single green shield icon in the header.
  - [ⓘ] info button opens agent detail as a drawer (not a page).
  - [✕] close button dismisses chat panel back to the page.
  - Step-up approval appears as a simple inline prompt:
    "This agent wants to access your email. [Allow] [Don't allow]"
    NOT: "⚠️ Step-up: Agent wants to access [payment API]"

FOR POWER USERS (toggled on in settings):
  - Session stats sidebar (tool calls, budget, safety blocks)
  - Live audit trail
  - Raw tool call details
  - Export audit as JSON
```

### 3.6 Progressive Auth (No Login Wall)

Signup is never required to use an agent. Auth is introduced progressively:

```
                        GUEST                    SIGNED IN
Action                  (cookie-based)           (auth token)
───────────────────────────────────────────────────────────────
 Browse agents           ✅ unlimited              ✅ unlimited
 Use agent (chat)        ✅ 3 sessions free        ✅ 50/day (free) or ∞ (pro)
 See trust card          ✅                        ✅
 Leave review            ❌ sign in prompt         ✅
 Save chat history       ❌ sign in prompt         ✅
 Publish agent           ❌ sign in prompt         ✅
 Dashboard               ❌ sign in prompt         ✅

Sign-in prompts are GENTLE, not blocking:
┌────────────────────────────────────────┐
│  Want to save this conversation?      │
│  Sign in to keep your chat history.   │
│                                        │
│  [Sign in with Google]                 │
│  [Sign in with GitHub]                 │
│  [Continue as guest]                   │
└────────────────────────────────────────┘

"Continue as guest" is ALWAYS an option.
The user is never locked out of using the product.
```

### 3.7 Agent Requests (/requests)

Anyone can request an agent that doesn't exist yet. This is a public
wishlist that drives what builders create next.

```
┌───────────────────────────────────────────────────────┐
│  🛡️ Sentinel Hub              [Publish] [Sign in]    │
├───────────────────────────────────────────────────────┤
│                                                       │
│  Agent Requests                                       │
│  Can't find what you need? Ask for it.                │
│                                                       │
│  [Describe the agent you want...           ] [Submit] │
│                                                       │
│  🔥 Most Requested                                    │
│                                                       │
│  ┌─ 142 votes ──────────────────────────────────────┐ │
│  │  📊 Tax Filing Assistant                          │ │
│  │  "An agent that helps file US taxes, pulls W-2s, │ │
│  │  calculates deductions, and generates forms"      │ │
│  │  Requested by 142 people · 3 days ago             │ │
│  │  [▲ Vote]                                         │ │
│  └──────────────────────────────────────────────────┘ │
│                                                       │
│  ┌─ 89 votes ───────────────────────────────────────┐ │
│  │  🏠 Real Estate Analyzer                          │ │
│  │  "Compare properties, estimate mortgage, pull     │ │
│  │  neighborhood data"                               │ │
│  │  Requested by 89 people · 1 week ago              │ │
│  │  [▲ Vote]   🏗️ A builder is working on this!      │ │
│  └──────────────────────────────────────────────────┘ │
│                                                       │
│  ┌─ 54 votes ───────────────────────────────────────┐ │
│  │  📧 Email Cleanup Agent                           │ │
│  │  "Unsubscribe from junk, organize inbox,          │ │
│  │  summarize important emails"                      │ │
│  │  [▲ Vote]                                         │ │
│  └──────────────────────────────────────────────────┘ │
│                                                       │
│  For Builders:                                        │
│  See what people want → Build it → Instant audience   │
│  [Browse requests as a builder →]                     │
│                                                       │
└───────────────────────────────────────────────────────┘

SIMPLICITY:
  - Submitting a request = type a sentence + tap Submit. That's it.
  - No category picker, no form fields. We auto-categorize.
  - Voting = one tap (▲). No downvotes.
  - Guests can submit and vote (no sign-in needed).
  - Duplicate detection: if a similar request exists, we show it
    and let the user vote instead of creating a duplicate.
  - Builders see a "Build this" badge on high-demand requests.
  - When a builder publishes an agent that matches a request,
    all voters get notified: "The agent you requested is here! [Use →]"
```

### 3.8 Publisher Flow (/publish) — Simplified

```
Step 1: Source                   Step 2: Scan              Step 3: Configure
┌──────────────────────┐  →  ┌────────────────────┐  →  ┌────────────────────┐
│ How to submit:       │     │ Scanning...        │     │ Agent Name:        │
│                      │     │                    │     │ [__________________]│
│ ○ npm package name   │     │ ✅ Dependencies    │     │                    │
│   [@scope/pkg-name]  │     │ ✅ Code patterns   │     │ Category: [▼]      │
│                      │     │ ⚠️ Permissions (1)  │     │ Description:       │
│ ○ GitHub repo URL    │     │ ✅ Publisher        │     │ [__________________]│
│   [github.com/...]   │     │                    │     │ [__________________]│
│                      │     │ Score: 84/B        │     │                    │
│ ○ Upload tarball     │     │                    │     │ Pricing:           │
│   [Choose file]      │     │ 1 issue to fix:    │     │ ○ Free             │
│                      │     │ · fs.readdir used  │     │ ○ Freemium         │
│ [Next →]             │     │   but not declared │     │ ○ Paid ($__/mo)    │
│                      │     │                    │     │                    │
│                      │     │ [Fix & Rescan]     │     │ [Publish →]        │
└──────────────────────┘     └────────────────────┘     └────────────────────┘

Step 4: Live!
┌────────────────────┐
│ 🎉 Published!       │
│                    │
│ Your agent is live │
│ at sentinel-hub/   │
│ agent/your-agent   │
│                    │
│ Trust Certificate: │
│ STC-2026...        │
│                    │
│ [View Listing]     │
│ [Share Link]       │
│ [View Analytics]   │
└────────────────────┘
```

### 3.9 Design System & Simplicity Rules

| Element | Spec |
|---|---|
| **Framework** | Next.js 15 (App Router) |
| **Styling** | Tailwind CSS + shadcn/ui components |
| **Icons** | Lucide React |
| **Charts** | Recharts (trust score visualization — power users only) |
| **Theme** | Dark mode default, light toggle. Trust = green. Danger = red. |
| **Typography** | Inter (body), JetBrains Mono (scores — detail page only) |
| **Trust Color Scale** | Green shield = verified safe. Yellow = caution. Red = avoid. That's it for consumers. A/B/C/D/F grade visible on detail page only. |
| **Responsive** | Mobile-first. Chat is full-screen on phone. Browse is swipeable cards. |
| **Animations** | Framer Motion. Chat panel slides up from bottom. Card hover lifts. |
| **Chat panel** | Slide-up overlay, 60% viewport height on desktop, full-screen on mobile |

#### Simplicity Rules (enforced in code review)

1. **No jargon in consumer UI.** The words MCP, DID, STP, verifiable credential, attestation, hash-chain NEVER appear in any consumer-facing page. Internal terms get translated:
   - "STC issued" → "Verified safe"
   - "4 sub-scanners passed" → "Fully checked"
   - "processToolCall()" → "Searching..." or "Working..."
   - "Gateway rate limit exceeded" → "You've used your free turns today. Upgrade for more."

2. **Maximum 1 primary action per screen.** Agent card: [Use]. Chat: message input. Publish: [Next]. Never present the user with competing CTAs.

3. **Progressive disclosure only.** Default state shows the minimum. Tapping info/details reveals more. Full scan report, audit log, permissions breakdown — all behind a deliberate tap, never visible by default.

4. **No empty states.** If there's nothing to show, show a helpful suggestion. Chat opens with conversation starters. Dashboard shows "Try your first agent" card. Publish shows example agents.

5. **Error messages tell you what to do, not what went wrong.** Not: "Error 429: rate limit exceeded." Instead: "You've used your free turns. [Upgrade to Pro] or [try again tomorrow]."

6. **3-second rule.** If any page takes more than 3 seconds to become interactive, it needs a loading skeleton or optimistic UI. Chat messages use streaming. Agent grid uses SSR + ISR.

---

## 4. System Architecture

### 4.1 High-Level Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SENTINEL HUB                              │
│                                                                  │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────────┐ │
│  │  Next.js App  │  │  Hub API       │  │  Agent Runtime       │ │
│  │  (Frontend)   │  │  (Backend)     │  │  (Sandboxed)         │ │
│  │              │  │               │  │                      │ │
│  │ - Pages      │──│ - REST API    │──│ - Container Pool     │ │
│  │ - Chat UI    │  │ - WebSocket   │  │ - MCP Proxy per sess │ │
│  │ - Dashboard  │  │ - Auth        │  │ - Gateway per agent  │ │
│  │ - Publisher  │  │ - Agent CRUD  │  │ - Budget enforcer    │ │
│  │              │  │ - Scanner     │  │ - Safety pipeline    │ │
│  │ Next.js 15   │  │ - Billing     │  │ - Audit logger       │ │
│  │ React 19     │  │               │  │                      │ │
│  │ Tailwind     │  │ Hono / Node   │  │ Docker / Firecracker │ │
│  └──────┬───────┘  └───────┬───────┘  └──────────┬───────────┘ │
│         │                  │                      │              │
│  ┌──────▼──────────────────▼──────────────────────▼───────────┐ │
│  │                    DATA LAYER                               │ │
│  │                                                             │ │
│  │  ┌──────────┐ ┌───────────┐ ┌───────┐ ┌─────────────────┐ │ │
│  │  │ Postgres │ │   Redis   │ │  S3   │ │ SentinelStore   │ │ │
│  │  │ (main DB)│ │ (cache,   │ │(scans,│ │ (trust state,   │ │ │
│  │  │          │ │  sessions,│ │ logs) │ │  reputation,    │ │ │
│  │  │ users,   │ │  rate     │ │       │ │  revocation)    │ │ │
│  │  │ agents,  │ │  limits)  │ │       │ │                 │ │ │
│  │  │ billing  │ │           │ │       │ │                 │ │ │
│  │  └──────────┘ └───────────┘ └───────┘ └─────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Component Breakdown

| Component | Tech | Purpose |
|---|---|---|
| **Frontend** | Next.js 15 (App Router), React 19, Tailwind, shadcn/ui | Web UI, SSR, auth pages |
| **Hub API** | Hono on Node.js (or Next.js API routes) | REST + WebSocket backend |
| **Agent Runtime** | Docker containers, 1 per session | Sandboxed MCP server execution |
| **MCP Proxy** | `@sentinel-atl/mcp-proxy` per container | stdio/SSE transport bridge |
| **Trust Gateway** | `@sentinel-atl/gateway` per agent | Tool-call verification |
| **Scanner Service** | `@sentinel-atl/scanner` (async worker) | Package scanning on publish |
| **Chat Relay** | WebSocket (frontend ↔ API ↔ MCP proxy) | Real-time message streaming |
| **Postgres** | Main relational DB | Users, agents, reviews, billing |
| **Redis** | Cache + pub/sub | Sessions, rate limiting, chat relay |
| **S3 / R2** | Object storage | Scan reports, audit archives, agent icons |
| **SentinelStore** | `@sentinel-atl/store` (Redis backend) | Trust state: reputation, revocation |

### 4.3 Request Flow: User Chats with Agent

```
Browser                    Hub API              Runtime              MCP Server
  │                          │                    │                    │
  │ 1. POST /chat/send       │                    │                    │
  │ ─────────────────────>   │                    │                    │
  │                          │ 2. Resolve session  │                    │
  │                          │    (or spawn container)                  │
  │                          │ ──────────────────> │                    │
  │                          │                    │ 3. MCP proxy sends │
  │                          │                    │    tool call       │
  │                          │                    │ ──────────────────>│
  │                          │                    │                    │
  │                          │                    │ 4. Gateway checks: │
  │                          │                    │    - Rate limit     │
  │                          │                    │    - Tool policy    │
  │                          │                    │    - Safety         │
  │                          │                    │    - Budget         │
  │                          │                    │                    │
  │                          │                    │ 5. If step-up needed│
  │                          │ <──────────────────│  (approval request)│
  │ 6. WS: approval_needed  │                    │                    │
  │ <─────────────────────   │                    │                    │
  │                          │                    │                    │
  │ 7. User approves         │                    │                    │
  │ ─────────────────────>   │ ──────────────────>│                    │
  │                          │                    │ 8. Forward to MCP  │
  │                          │                    │ ──────────────────>│
  │                          │                    │                    │
  │                          │                    │ <──────────────────│
  │                          │                    │ 9. Response         │
  │                          │ <──────────────────│    + audit log     │
  │ 10. WS: message          │                    │                    │
  │ <─────────────────────   │                    │                    │
```

---

## 5. Backend API Design

### 5.1 Public API

```
Guest Identity
  POST   /api/guest                 → { guestToken } (cookie-based, auto-created on first Use click)
                                      No signup. No email. Just a token.
                                      Limited to 3 agent sessions total.

Auth (only when user WANTS to sign in)
  POST   /api/auth/login            { provider: 'google'|'github' } → { token, user }
  POST   /api/auth/logout
  GET    /api/auth/me               → { user, subscription }
  POST   /api/auth/upgrade-guest    Converts guest token → real account (preserves chat history)

Agents (Browse — no auth required)
  GET    /api/agents                ?q=search&category=&minTrust=&sort=&page=
  GET    /api/agents/:slug          → AgentDetail (trust card, docs, pricing)
  GET    /api/agents/:slug/reviews  → Review[]
  POST   /api/agents/:slug/reviews  { rating, body } (auth required)

Chat (works for guests AND signed-in users)
  WS     /api/chat/:slug/ws         Bidirectional: send messages, receive responses
                                      Accepts guestToken OR authToken
  POST   /api/chat/:slug/send       { message } → { messageId } (REST fallback)
  POST   /api/chat/:slug/approve    { challengeId, decision } (step-up approval)

Sessions
  POST   /api/sessions              { agentSlug } → { sessionId }
                                      Auto-creates guest if no token exists.
                                      Returns session immediately — container spins up in background.
  DELETE /api/sessions/:id          (terminate session + container)

Agent Requests (no auth required — guests can submit & vote)
  GET    /api/requests              ?sort=votes|recent&category=&page=
  POST   /api/requests              { description } → { requestId }
                                      Auto-categorizes. Deduplicates against existing requests.
  POST   /api/requests/:id/vote     → { votes } (idempotent per user/guest)
  DELETE /api/requests/:id/vote     Remove vote
  POST   /api/requests/:id/claim    Builder claims they're working on it (auth required)
  POST   /api/requests/:id/fulfill  { agentSlug } Builder links published agent (auto-notifies voters)

Publisher (auth required)
  POST   /api/publish/scan          { source: 'npm'|'github', value } → ScanReport
  POST   /api/publish/submit        { scanId, name, category, description }
  PUT    /api/publish/:slug         Update listing metadata
  GET    /api/publish/:slug/analytics → { users, calls, revenue, ratings }
  DELETE /api/publish/:slug         Unpublish agent

User Dashboard
  GET    /api/dashboard/agents      My used agents + usage
  GET    /api/dashboard/published   My published agents
  GET    /api/dashboard/audit       My audit trail
  GET    /api/dashboard/billing     Usage, invoices, plan

Admin (Enterprise)
  GET    /api/admin/policies        Org trust policies
  PUT    /api/admin/policies        Update policies
  GET    /api/admin/agents          Approved agent registry
  POST   /api/admin/agents/:slug/approve
  POST   /api/admin/agents/:slug/deny
  GET    /api/admin/audit           Organization-wide audit
  GET    /api/admin/usage           Org usage & spend
```

### 5.2 Internal Services

```
Scanner Worker (async job queue)
  - Triggered by: publish/scan endpoint
  - Runs: @sentinel-atl/scanner.scan()
  - Stores: ScanReport → Postgres + S3
  - Issues: SentinelTrustCertificate → SentinelStore

Container Orchestrator
  - Manages: Docker container pool (warm pool of 10-50)
  - Per session: spawn container → inject MCP server → attach proxy
  - Limits: CPU, memory, network, filesystem (read-only)
  - Cleanup: auto-terminate after idle timeout (5 min)

Chat Relay
  - WebSocket manager: frontend ↔ Hub API ↔ MCP proxy
  - Handles: message routing, streaming responses, tool call notifications
  - Injects: trust context (user DID, budget state) into every forwarded message

Billing Worker
  - Tracks: tool calls per user per billing cycle
  - Enforces: plan limits (free: 50/day, pro: unlimited)
  - Calculates: publisher revenue share
  - Integrates: Stripe for payments
```

---

## 6. Data Models

### 6.1 Postgres Schema

```sql
-- Users (includes guests — guest rows have email=NULL)
CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE,              -- NULL for guests
  name          TEXT,
  avatar_url    TEXT,
  did           TEXT UNIQUE NOT NULL,     -- Sentinel DID (auto-generated, even for guests)
  auth_provider TEXT NOT NULL,            -- 'guest' | 'google' | 'github'
  is_guest      BOOLEAN DEFAULT TRUE,    -- TRUE until they sign in
  guest_token   TEXT UNIQUE,             -- Cookie token for anonymous sessions
  plan          TEXT DEFAULT 'free',      -- 'free' | 'pro' | 'builder' | 'enterprise'
  guest_sessions_used INTEGER DEFAULT 0, -- Tracks 3-session limit for guests
  stripe_customer_id TEXT,
  org_id        UUID REFERENCES orgs(id),
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- When a guest signs in, we UPDATE their row:
--   SET is_guest=FALSE, email=..., auth_provider=..., guest_token=NULL
--   All sessions + chat history preserved automatically.

-- Organizations (Enterprise)
CREATE TABLE orgs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            TEXT NOT NULL,
  slug            TEXT UNIQUE NOT NULL,
  trust_policy    JSONB DEFAULT '{}',     -- {minTrustScore, blockedCategories, etc}
  sso_provider    TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Agents (Marketplace Listings)
CREATE TABLE agents (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug            TEXT UNIQUE NOT NULL,
  name            TEXT NOT NULL,
  description     TEXT,
  long_description TEXT,
  icon_url        TEXT,
  category        TEXT NOT NULL,
  tags            TEXT[] DEFAULT '{}',
  publisher_id    UUID REFERENCES users(id),
  source_type     TEXT NOT NULL,          -- 'npm' | 'github' | 'upload'
  source_value    TEXT NOT NULL,          -- package name / repo URL
  source_version  TEXT,
  trust_score     INTEGER,               -- 0-100
  trust_grade     TEXT,                   -- A/B/C/D/F
  stc_id          TEXT,                   -- Sentinel Trust Certificate ID
  scan_report_url TEXT,                   -- S3 URL to full scan report
  status          TEXT DEFAULT 'pending', -- 'pending' | 'active' | 'suspended' | 'removed'
  pricing_model   TEXT DEFAULT 'free',    -- 'free' | 'freemium' | 'paid'
  price_monthly   NUMERIC(10,2),
  free_calls_day  INTEGER DEFAULT 5,
  mcp_config      JSONB NOT NULL,         -- {command, args, env, transport}
  tools_exposed   JSONB DEFAULT '[]',     -- [{name, description}]
  conversation_starters JSONB DEFAULT '[]', -- ["Analyze Stripe's competitors", ...] (3-4 per agent)
  permissions     JSONB DEFAULT '{}',     -- {network, filesystem, ...}
  safety_enabled  BOOLEAN DEFAULT TRUE,
  total_users     INTEGER DEFAULT 0,
  total_calls     INTEGER DEFAULT 0,
  avg_rating      NUMERIC(3,2) DEFAULT 0,
  review_count    INTEGER DEFAULT 0,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Scan Reports (historical)
CREATE TABLE scan_reports (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id        UUID REFERENCES agents(id),
  trust_score     INTEGER,
  trust_grade     TEXT,
  findings        JSONB NOT NULL,         -- Finding[]
  dep_scan        JSONB,
  code_scan       JSONB,
  perms_scan      JSONB,
  publisher_scan  JSONB,
  stc             JSONB,                  -- Sentinel Trust Certificate
  report_url      TEXT,                   -- S3 full report
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Reviews
CREATE TABLE reviews (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id        UUID REFERENCES agents(id),
  user_id         UUID REFERENCES users(id),
  rating          INTEGER CHECK (rating >= 1 AND rating <= 5),
  body            TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(agent_id, user_id)
);

-- Sessions (active agent usage)
CREATE TABLE sessions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID REFERENCES users(id),
  agent_id        UUID REFERENCES agents(id),
  container_id    TEXT,                   -- Docker container ID
  status          TEXT DEFAULT 'active',  -- 'active' | 'ended' | 'error'
  tool_calls      INTEGER DEFAULT 0,
  budget_spent    NUMERIC(10,4) DEFAULT 0,
  safety_blocks   INTEGER DEFAULT 0,
  started_at      TIMESTAMPTZ DEFAULT NOW(),
  ended_at        TIMESTAMPTZ
);

-- Chat Messages
CREATE TABLE chat_messages (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id      UUID REFERENCES sessions(id),
  role            TEXT NOT NULL,          -- 'user' | 'agent' | 'system'
  content         TEXT NOT NULL,
  tool_calls      JSONB,                 -- [{name, args, result, allowed, latency}]
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Billing
CREATE TABLE billing_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID REFERENCES users(id),
  agent_id        UUID REFERENCES agents(id),
  event_type      TEXT NOT NULL,          -- 'tool_call' | 'subscription' | 'payout'
  amount          NUMERIC(10,4),
  metadata        JSONB,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Agent Requests (public wishlist)
CREATE TABLE agent_requests (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  description     TEXT NOT NULL,          -- Free-text: "An agent that helps file taxes"
  category        TEXT,                   -- Auto-assigned by LLM classification
  status          TEXT DEFAULT 'open',    -- 'open' | 'claimed' | 'fulfilled'
  votes           INTEGER DEFAULT 1,      -- Denormalized vote count
  submitted_by    UUID REFERENCES users(id), -- Can be a guest user
  claimed_by      UUID REFERENCES users(id), -- Builder working on it
  fulfilled_by_agent UUID REFERENCES agents(id), -- The agent that fulfills this
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  fulfilled_at    TIMESTAMPTZ
);

CREATE TABLE request_votes (
  request_id      UUID REFERENCES agent_requests(id) ON DELETE CASCADE,
  user_id         UUID REFERENCES users(id),
  created_at      TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (request_id, user_id)
);

-- Indexes
CREATE INDEX idx_agents_category ON agents(category);
CREATE INDEX idx_agents_trust ON agents(trust_score DESC);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_chat_session ON chat_messages(session_id);
CREATE INDEX idx_reviews_agent ON reviews(agent_id);
CREATE INDEX idx_requests_votes ON agent_requests(votes DESC);
CREATE INDEX idx_requests_status ON agent_requests(status);
```

### 6.2 Redis Keys

```
session:{sessionId}              → {userId, agentId, containerId, startedAt}
session:{sessionId}:messages     → List<ChatMessage>  (recent, capped at 100)
guest:{guestToken}               → {userId, sessionsUsed, createdAt}  (TTL = 7 days)
ratelimit:{userId}:{agentSlug}   → counter (TTL = windowMs)
container:warm                   → Set<containerId>   (warm pool)
container:{containerId}          → {status, agentId, sessionId, createdAt}
user:{userId}:daily_calls        → counter (TTL = 24h)
agent:{slug}:online              → "true" (TTL = 30s, heartbeat)
```

### 6.3 SentinelStore Keys (Trust State)

```
reputation:{did}                 → ReputationScore
revocation:vc:{vcId}             → {revokedAt, reason}
revocation:did:{did}             → {revokedAt, reason}
stc:{stcId}                      → SentinelTrustCertificate
audit:{agentSlug}:{date}         → List<AuditEntry>
budget:{userId}:{agentSlug}      → UsageSummary
```

---

## 7. Sentinel Package Integration Map

Every existing package has a role in Sentinel Hub:

```
┌─────────────────────────────────────────────────────────────┐
│                  EXISTING PACKAGES → HUB ROLE                │
├──────────────────────┬──────────────────────────────────────┤
│  @sentinel-atl/core  │ DID generation for users + agents.   │
│                      │ VC issuance for agent certificates.  │
│                      │ Intent envelope for every chat msg.  │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Every agent runtime has a gateway.   │
│  gateway             │ processToolCall() on every tool use. │
│                      │ Rate limiting, policy enforcement.   │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Auto-scan on agent publish.          │
│  scanner             │ Trust score computation for listings.│
│                      │ STC issuance for certified agents.   │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/sdk   │ Hub API uses TrustedAgent internally │
│                      │ to manage trust for user sessions.   │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/store │ Redis backend for all shared state.  │
│                      │ Reputation, revocation, budgets.     │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Pre/post check on every tool call.   │
│  safety              │ Content safety in chat messages.     │
│                      │ Scan agent descriptions for abuse.   │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Per-user per-agent budget tracking.  │
│  budget              │ Free tier limits. Overage blocking.  │
│                      │ Circuit breaker on runaway agents.   │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Step-up auth in chat UI.             │
│  approval            │ WebUI channel → inline chat prompt.  │
│                      │ Enterprise: Slack channel for admins.│
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Adapted into Hub dashboard pages.    │
│  dashboard           │ getData() → Hub API data endpoints.  │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Used inside containers. Bridges      │
│  mcp-proxy           │ stdio/SSE MCP servers to Hub API.    │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/audit │ Hash-chain audit for every session.  │
│                      │ Viewable in dashboard + exportable.  │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Trust scoring for agent publishers.  │
│  reputation          │ User vouches → community trust.      │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Instant agent takedown.              │
│  revocation          │ Kill switch for compromised agents.  │
│                      │ Cascading revocation to sessions.    │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Bind agent DID → npm package hash.   │
│  attestation         │ Guarantees agent runs verified code. │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Step-up for sensitive actions in     │
│  stepup              │ chat (e.g., agent wants to send $).  │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Templates: mcp-secure-server         │
│  create-sentinel-app │ for builders publishing new agents.  │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Protocol conformance badge on agent  │
│  conformance         │ cards. "STP-Full Compliant ✓"        │
├──────────────────────┼──────────────────────────────────────┤
│  @sentinel-atl/      │ Enable connection hardening, auth,   │
│  hardening           │ env validation, security headers     │
│                      │ for the Hub API server itself.       │
└──────────────────────┴──────────────────────────────────────┘
```

---

## 8. Agent Runtime

### 8.1 Container Architecture

Each agent session runs in an isolated container:

```
┌─────────────────────────────────────────────────┐
│             Agent Container (per session)         │
│                                                   │
│  ┌──────────────┐     ┌──────────────────────┐  │
│  │  MCP Server   │────│  Sentinel MCP Proxy   │  │
│  │  (agent code) │    │  (@sentinel-atl/      │  │
│  │               │    │   mcp-proxy)          │  │
│  │  stdio/SSE    │    │                       │  │
│  └──────────────┘     │  + Gateway middleware  │  │
│                        │  + Safety pipeline    │  │
│                        │  + Budget enforcer    │  │
│                        │  + Audit logger       │  │
│                        │                       │  │
│                        │  Exposed: port 3100   │──── → Hub API (WebSocket)
│                        └──────────────────────┘  │
│                                                   │
│  Constraints:                                     │
│  - 256MB memory limit                            │
│  - 0.5 CPU limit                                 │
│  - Read-only filesystem                          │
│  - No outbound network*                          │
│  - 5 min idle timeout → auto-terminate           │
│  * except allowlisted domains per agent policy    │
└─────────────────────────────────────────────────┘
```

### 8.2 Warm Pool Strategy

```
Container Lifecycle:
  1. WARM POOL: 20 pre-created containers (base image, no agent loaded)
  2. ASSIGN: On session start, grab warm container + inject agent
  3. ACTIVE: Container serves chat session
  4. IDLE: After 5 min no activity → move to cooldown
  5. TERMINATE: After 15 min idle or session end → destroy

Cold Start: ~3s (pull agent npm package, start MCP server)
Warm Start: ~500ms (agent already cached in image)
```

### 8.3 Agent Installation in Container

```bash
# Inside container at startup:
npm install ${agent.source_value}@${agent.source_version} --production
# Start MCP server via configured command:
node ./node_modules/${agent.source_value}/${agent.mcp_config.entry}
# MCP Proxy connects via stdio and exposes HTTP
```

---

## 9. Security Model

### 9.1 Defense in Depth

```
Layer 1: SCAN TIME
  └─ 4-scanner pipeline before listing (deps, code, perms, publisher)
  └─ Trust certificate (STC) issued only to passing agents
  └─ Continuous re-scanning on package updates

Layer 2: CONTAINER ISOLATION
  └─ Read-only filesystem
  └─ No root access
  └─ Memory/CPU limits
  └─ Network allowlist (only declared domains)
  └─ Separate container per session (no cross-contamination)

Layer 3: RUNTIME GATEWAY
  └─ Every tool call verified by @sentinel-atl/gateway
  └─ Rate limiting (per user, per agent)
  └─ Tool policy enforcement (blocked tools, required scopes)
  └─ Content safety pipeline (prompt injection, PII, jailbreak)
  └─ Budget enforcement (prevent runaway costs)

Layer 4: USER CONTROLS
  └─ Step-up approval for sensitive actions
  └─ Per-session budget caps
  └─ Real-time audit trail visible in chat
  └─ Instant session termination

Layer 5: PLATFORM CONTROLS
  └─ Kill switch: revoke any agent in <5s (cascading)
  └─ Hash-chain audit log (tamper-evident)
  └─ Enterprise trust policies (min score, blocked categories)
  └─ Publisher reputation system (community vouching)
```

### 9.2 Threat Model

| Threat | Mitigation |
|---|---|
| Malicious agent code (data exfil) | Container isolation + network allowlist + scan |
| Prompt injection via agent | Safety pipeline catches known patterns |
| Compromised agent update | Continuous re-scan, attestation (DID → code hash) |
| Agent impersonation | DID-based identity, STC certificate verification |
| Runaway cost attack | BudgetManager + circuit breaker + plan limits |
| Cross-session data leak | Separate containers, no shared state |
| Admin account compromise | Audit trail, enterprise SSO, kill switch requires MFA |

---

## 10. Infrastructure & Deployment

### 10.1 Cloud Architecture

```
                    ┌─────────────────┐
                    │   Cloudflare    │
                    │   CDN + WAF     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   Load Balancer │
                    │   (ALB / nginx) │
                    └───┬─────────┬───┘
                        │         │
              ┌─────────▼──┐  ┌──▼──────────┐
              │  Next.js    │  │  Hub API     │
              │  (Vercel or │  │  (ECS/K8s    │
              │   self-host)│  │   2+ replicas│
              └─────────────┘  └──────┬──────┘
                                      │
                   ┌──────────────────┼──────────────────┐
                   │                  │                   │
          ┌────────▼───┐    ┌────────▼───┐     ┌────────▼───┐
          │  Postgres   │    │   Redis     │     │Container   │
          │  (RDS)      │    │  (Elasticache│    │ Runtime    │
          │  Primary +  │    │   or Upstash)│    │ (ECS/K8s   │
          │  Read replica│   └─────────────┘    │  auto-scale)│
          └─────────────┘                        └─────────────┘
```

### 10.2 Hosting Options

| Option | Frontend | API | Containers | DB | Cost Estimate |
|---|---|---|---|---|---|
| **MVP (cheap)** | Vercel Free | Railway / Fly.io | Fly Machines | Neon (free Postgres) + Upstash Redis | ~$50/mo |
| **Growth** | Vercel Pro | ECS Fargate | ECS Fargate | RDS + Elasticache | ~$500/mo |
| **Scale** | Self-hosted K8s | K8s | K8s + Firecracker | RDS Multi-AZ + Redis Cluster | ~$3K/mo |

### 10.3 Tech Stack Summary

| Layer | Technology |
|---|---|
| Frontend | Next.js 15, React 19, Tailwind CSS, shadcn/ui, Framer Motion |
| API | Hono (or Next.js API routes), TypeScript |
| Auth | NextAuth.js v5 (Google, GitHub, email magic link) |
| Database | PostgreSQL (Drizzle ORM) |
| Cache | Redis (Upstash for serverless) |
| Trust State | @sentinel-atl/store (Redis backend) |
| Containers | Docker (Fly Machines for MVP, ECS/K8s for scale) |
| Payments | Stripe (subscriptions + connect for publisher payouts) |
| Object Storage | Cloudflare R2 or S3 |
| Monitoring | OpenTelemetry → @sentinel-atl/telemetry |
| CI/CD | GitHub Actions (existing pipeline) |
| CDN | Cloudflare |

---

## 11. Monetization

### 11.1 Revenue Streams

```
1. USER SUBSCRIPTIONS
   Free:    50 agent calls/day, community agents only
   Pro:     $19/mo — unlimited calls, premium agents, full audit
   
2. BUILDER SUBSCRIPTIONS  
   Builder: $49/mo — publish agents, analytics dashboard, priority listing

3. AGENT MARKETPLACE CUT
   Paid agents: Hub takes 30%, publisher gets 70%
   (via Stripe Connect)

4. ENTERPRISE
   Custom pricing — SSO, self-hosted, compliance reports, SLA
   
5. FUTURE: TRUST-AS-A-SERVICE
   API access to scanner/trust-scoring for external platforms
   (Smithery, Glama could pay to embed our trust badges)
```

### 11.2 Unit Economics

```
Cost per agent session:
  Container: ~$0.002/min (256MB, 0.5 CPU on Fly)
  Average session: 5 min = $0.01
  Average tool calls per session: 10
  Cost per tool call: ~$0.001

Revenue per Pro user:
  $19/mo subscription
  ~200 sessions/mo (estimate)
  COGS: 200 × $0.01 = $2.00/mo
  Gross margin: ~89%

Revenue per paid agent (per user):
  $4.99/mo → Hub takes $1.50, publisher gets $3.49
  At 100 paying users: $150/mo revenue per agent
```

---

## 12. Phased Implementation Plan

### Phase 1: Foundation (Weeks 1-3)
**Goal:** Basic marketplace browsing with static agent data

```
packages/hub/
├── src/
│   ├── app/                    # Next.js App Router
│   │   ├── layout.tsx          # Root layout (nav, footer)
│   │   ├── page.tsx            # Homepage
│   │   ├── browse/page.tsx     # Agent catalog
│   │   ├── agent/[slug]/
│   │   │   ├── page.tsx        # Agent detail
│   │   │   └── chat/page.tsx   # Chat UI (Phase 2)
│   │   ├── publish/page.tsx    # Publisher flow (Phase 2)
│   │   ├── dashboard/          # User dashboard (Phase 3)
│   │   └── auth/               # Login/signup
│   ├── components/
│   │   ├── AgentCard.tsx
│   │   ├── TrustBadge.tsx
│   │   ├── TrustCard.tsx
│   │   ├── SearchBar.tsx
│   │   ├── CategoryGrid.tsx
│   │   └── ReviewList.tsx
│   ├── lib/
│   │   ├── db.ts               # Drizzle + Postgres
│   │   ├── auth.ts             # NextAuth config
│   │   ├── scanner.ts          # Scanner integration
│   │   └── stripe.ts           # Stripe integration
│   └── api/                    # API routes
│       ├── agents/route.ts
│       ├── auth/[...nextauth]/route.ts
│       └── ...
├── drizzle/
│   └── schema.ts               # DB schema
├── package.json
├── tailwind.config.ts
└── tsconfig.json
```

**Deliverables:**
- [ ] Next.js project setup with Tailwind + shadcn/ui
- [ ] Postgres schema + Drizzle ORM
- [ ] Auth (Google + GitHub via NextAuth)
- [ ] Homepage with hero, featured agents, categories
- [ ] Browse page with search, filter, sort
- [ ] Agent detail page with trust card
- [ ] Seed data: 10-20 agents from existing MCP registries (scanned)
- [ ] Agent request page (submit + vote + list)
- [ ] Search empty state → "Request this agent" flow
- [ ] Deploy to Vercel + Neon

### Phase 2: Chat & Publisher (Weeks 4-7)
**Goal:** Users can chat with agents; builders can publish

**Deliverables:**
- [ ] Agent runtime (Docker containers on Fly Machines)
- [ ] MCP Proxy integration in containers
- [ ] Gateway integration (trust verification on every tool call)
- [ ] WebSocket chat relay (Hub API ↔ containers)
- [ ] Chat UI with message streaming, tool call display
- [ ] Safety pipeline in chat (content filtering)
- [ ] Budget enforcement (free tier: 50 calls/day)
- [ ] Publisher flow: submit → scan → review → list
- [ ] Scanner async worker (queue-based)
- [ ] Step-up approval inline in chat
- [ ] Session audit trail in sidebar

### Phase 3: Monetization & Dashboard (Weeks 8-10)
**Goal:** Revenue flowing, users have usage visibility

**Deliverables:**
- [ ] Stripe integration (user subscriptions)
- [ ] Stripe Connect (publisher payouts)
- [ ] Paid agent support (freemium/paid models)
- [ ] User dashboard (my agents, usage, billing)
- [ ] Publisher analytics (users, calls, revenue)
- [ ] Audit trail viewer (with hash-chain verification)
- [ ] Review & rating system
- [ ] Agent update flow (re-scan on new version)

### Phase 4: Enterprise & Scale (Weeks 11-14)
**Goal:** Enterprise deployable, self-hosted option

**Deliverables:**
- [ ] Enterprise admin panel
- [ ] Org trust policies (min score, blocked categories)
- [ ] Agent approval workflow for orgs
- [ ] SSO integration (OIDC)
- [ ] Organization audit trail
- [ ] Container auto-scaling (warm pool)
- [ ] Continuous re-scanning (cron on agent updates)
- [ ] Public API for integrations
- [ ] Self-hosted deployment guide (Docker Compose + Helm chart)

### Phase 5: Growth (Weeks 15+)
**Goal:** Network effects, community, ecosystem

**Deliverables:**
- [ ] Agent Teams (multi-agent workflows)
- [ ] Trust-as-a-Service API (for Smithery, Glama, etc.)
- [ ] Embeddable trust badges for external sites
- [ ] Community features (agent forking, templates)
- [ ] Request fulfillment notifications ("The agent you wanted is here!")
- [ ] Mobile-responsive PWA
- [ ] Agent monitoring alerts (trust score drops)
- [ ] Import from Smithery/Glama catalogs

---

## 13. Sentinel Forge — Self-Building Environment

### 13.1 The Core Idea

Instead of manually building Sentinel Hub feature by feature, we build **the factory that builds the product**. An autonomous development environment where AI agents:

1. Read the blueprint (this document) as their spec
2. Decompose it into atomic tasks
3. Write code for each task
4. Build, test, and validate the output
5. Loop on failures until validation passes
6. Move to the next task
7. Human reviews at checkpoints

This is **not** "AI writes code and hopes it works." This is a structured loop with hard validation gates — the code literally cannot progress until it compiles, passes tests, meets the spec, and passes security scanning.

### 13.2 Why This Works for Sentinel Hub Specifically

We already have everything needed to make this real:

```
WHAT WE HAVE                          WHY IT MATTERS FOR FORGE
──────────────────────────────────────────────────────────────────
This blueprint (50+ pages)            Machine-readable spec for the agent
Turbo monorepo + workspace setup      Agent can build incrementally
tsconfig strict mode                  Type errors = instant validation signal
Vitest test runner                    Agent writes tests, then writes code
@sentinel-atl/scanner                 We scan our own output for security
@sentinel-atl/conformance             Protocol compliance checking
GitHub Actions CI                     Validation pipeline already exists
Docker + docker-compose               Environment is reproducible
ESM + Node 20/22                      Modern stack, well-documented for LLMs
```

The blueprint isn't just documentation — it becomes the **control program** for the build system.

### 13.3 Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        SENTINEL FORGE                           │
│                                                                 │
│  ┌───────────────┐                                             │
│  │   BLUEPRINT    │  ← This document (machine-readable spec)    │
│  └───────┬───────┘                                             │
│          │                                                      │
│          ▼                                                      │
│  ┌───────────────┐                                             │
│  │   PLANNER      │  Decomposes blueprint into ordered tasks    │
│  │   (LLM)        │  Each task: {spec, files, tests, deps}     │
│  └───────┬───────┘                                             │
│          │                                                      │
│          ▼                                                      │
│  ┌───────────────┐     ┌───────────────────────────────────┐   │
│  │  TASK QUEUE    │────▶│ Task: "Create Drizzle schema for  │   │
│  │  (ordered,     │     │ users table with guest support"    │   │
│  │   dependency-  │     │                                   │   │
│  │   aware)       │     │ Spec: Section 6.1 of blueprint    │   │
│  │               │     │ Files: src/lib/db/schema.ts        │   │
│  │               │     │ Tests: schema.test.ts              │   │
│  │               │     │ Deps: [Next.js setup, Drizzle init]│   │
│  └───────┬───────┘     └───────────────────────────────────┘   │
│          │                                                      │
│          ▼                                                      │
│  ┌────────────────────────────────────────────────────┐        │
│  │                  BUILD LOOP                         │        │
│  │                                                     │        │
│  │  ┌─────────┐    ┌─────────┐    ┌───────────────┐  │        │
│  │  │ BUILDER  │───▶│  DEV    │───▶│  VALIDATION   │  │        │
│  │  │ AGENT   │    │ SANDBOX │    │  PIPELINE     │  │        │
│  │  │ (LLM)   │    │         │    │               │  │        │
│  │  │         │    │ Docker  │    │ 1. TypeScript  │  │        │
│  │  │ Reads   │    │ + Node  │    │    compile    │  │        │
│  │  │ task,   │    │ + Git   │    │ 2. Vitest     │  │        │
│  │  │ context,│    │ + Turbo │    │    tests      │  │        │
│  │  │ writes  │    │         │    │ 3. ESLint     │  │        │
│  │  │ code +  │    │         │    │ 4. Sentinel   │  │        │
│  │  │ tests   │    │         │    │    scan       │  │        │
│  │  │         │    │         │    │ 5. Spec check │  │        │
│  │  │         │    │         │    │    (LLM eval) │  │        │
│  │  └────▲────┘    └─────────┘    └──────┬────────┘  │        │
│  │       │                               │           │        │
│  │       │    ┌──────────────────┐       │           │        │
│  │       └────│  FAIL? Retry     │◀──────┘           │        │
│  │            │  with error      │  PASS? ──────────────▶ Git │
│  │            │  context         │                    │  Commit│
│  │            │  (max 5 retries) │                    │        │
│  │            └──────────────────┘                    │        │
│  │                                                     │        │
│  └─────────────────────────────────────────────────────┘        │
│          │                                                      │
│          ▼                                                      │
│  ┌───────────────┐                                             │
│  │  HUMAN GATE    │  Review checkpoint every N tasks            │
│  │  (PR review)   │  Major phase boundaries require approval    │
│  └───────────────┘                                             │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

### 13.4 The Five Layers

#### Layer 1: Planner (Blueprint → Tasks)

The Planner is an LLM that reads this blueprint and generates an ordered task queue.

```
Input:  Section 6.1 (Postgres Schema) + Section 5.1 (API Design)
Output: 47 ordered tasks, each with:

  {
    id: "task-017",
    title: "Create Drizzle schema: users table with guest support",
    spec_reference: "blueprint.md#6.1, lines 634-658",
    files_to_create: ["src/lib/db/schema/users.ts"],
    files_to_modify: ["src/lib/db/schema/index.ts"],
    test_files: ["src/lib/db/__tests__/users.test.ts"],
    depends_on: ["task-001", "task-003"],  // Next.js init, Drizzle setup
    acceptance_criteria: [
      "Users table has all columns from blueprint Section 6.1",
      "is_guest column defaults to TRUE",
      "email is UNIQUE but nullable (for guests)",
      "guest_token column exists and is UNIQUE",
      "Migration generates valid SQL",
      "TypeScript compiles with strict mode"
    ],
    context_files: [
      "docs/SENTINEL_HUB_BLUEPRINT.md#section-6.1",
      "packages/hub/drizzle.config.ts",
      "packages/hub/package.json"
    ],
    estimated_complexity: "low"
  }
```

Task ordering rules:
1. Infrastructure first (project init, config, DB connection)
2. Data model (schema, migrations, query helpers)
3. Backend logic (API routes, workers, integrations)
4. Frontend components (UI primitives → composed pages)
5. Integration (wire backend to frontend)
6. Polish (animations, error states, loading states)

#### Layer 2: Builder Agent (LLM that writes code)

The Builder is an LLM agent (Claude, GPT-4o, or Codex) that receives a task and writes code.

```
BUILDER AGENT SYSTEM PROMPT:

You are a senior TypeScript developer building Sentinel Hub.
You are working in a Next.js 15 monorepo (packages/hub/).

For this task:
- Task: {task.title}
- Spec: {task.spec_reference} (extracted text from blueprint)
- Acceptance criteria: {task.acceptance_criteria}
- Files to create/modify: {task.files}
- Context: {relevant existing code from previous tasks}

Rules:
1. Write ONLY the files specified. Do not modify other files.
2. Write tests FIRST, then implementation (TDD).
3. Use the exact types, column names, and API shapes from the spec.
4. Follow existing code conventions (see context files).
5. No placeholder code. Every function must be complete.
6. No comments unless the logic is non-obvious.
7. Strict TypeScript. No `any`. No `as` casts unless unavoidable.

Output: {filepath: content} for each file.
```

Key capability: The Builder gets **rolling context** — not just the current task, but a summary of everything built so far + the full file tree. This prevents inconsistencies.

#### Layer 3: Dev Sandbox (Isolated build environment)

Every task runs in a fresh, reproducible environment:

```
┌──────────────────────────────────────────────────┐
│  Dev Sandbox (Docker container)                   │
│                                                   │
│  Base: node:20-alpine + turbo + git               │
│                                                   │
│  Mounted:                                        │
│  /workspace/        → Git repo (clean checkout)   │
│  /workspace/.forge/ → Forge metadata & logs       │
│                                                   │
│  Pre-installed:                                   │
│  - All workspace dependencies (npm ci)            │
│  - Playwright browsers (for E2E later)            │
│  - @sentinel-atl/scanner (for security scans)     │
│                                                   │
│  Agent writes files → runs in this container      │
│  Container is destroyed after task completes      │
│  Only committed code persists to next task        │
│                                                   │
│  Network: RESTRICTED                              │
│  - npm registry: allowed (for installs)           │
│  - everything else: blocked                       │
│  - LLM API: via Forge orchestrator only           │
│                                                   │
│  Limits: 2 CPU, 4GB RAM, 30 min timeout           │
└──────────────────────────────────────────────────┘
```

#### Layer 4: Validation Pipeline (Multi-gate verification)

Every task output goes through 5 validation gates. ALL must pass.

```
GATE 1: COMPILE
  Command:  cd packages/hub && npx turbo build
  Pass:     Exit code 0, zero TypeScript errors
  Fail:     Return error output to Builder → retry

GATE 2: TESTS
  Command:  cd packages/hub && npx vitest run --reporter=json
  Pass:     All tests pass (including newly written ones)
  Fail:     Return failing test names + output to Builder → retry

GATE 3: LINT + FORMAT
  Command:  npx eslint src/ && npx prettier --check src/
  Pass:     Zero warnings, zero errors
  Fail:     Return lint errors to Builder → retry

GATE 4: SECURITY SCAN
  Command:  node -e "
    import { scan } from '@sentinel-atl/scanner';
    const report = await scan({ target: 'packages/hub' });
    if (report.trustScore < 80) process.exit(1);
  "
  Pass:     Trust score ≥ 80, no critical findings
  Fail:     Return findings to Builder → retry

GATE 5: SPEC COMPLIANCE (LLM-as-judge)
  Prompt:   "Given this task spec: {spec}
             And these acceptance criteria: {criteria}
             And this code output: {code}
             Does the code fully satisfy all acceptance criteria?
             Respond: PASS or FAIL with reasons."
  Pass:     LLM says PASS
  Fail:     Return LLM reasons to Builder → retry

GATE 6: VISUAL CHECK (for UI tasks only, Phase 2+)
  Command:  npx playwright test --project=chromium
  Screenshot comparison against blueprint wireframes
  Pass:     Layout matches, no broken elements
  Fail:     Return screenshot diff to Builder → retry
```

Retry policy: Max 5 attempts per task. After 5 failures → task marked as `blocked` → human reviews.

#### Layer 5: Human Review Gates

The system is autonomous but not unsupervised:

```
CHECKPOINT TRIGGERS:
  - Every 10 completed tasks → PR created for review
  - Phase boundary (Phase 1→2, 2→3, etc.) → mandatory human review
  - Any task that fails 5 times → escalated to human
  - Any security scan finding rated "high" → immediate human alert
  
REVIEW UI:
  A simple dashboard showing:
  - Tasks completed / total
  - Current task + its status
  - Git diff of all changes since last checkpoint
  - Test coverage report
  - Validation pipeline results
  - [Approve & Continue] [Reject & Redirect] [Pause]
```

### 13.5 Task Decomposition for Sentinel Hub

Here's how the blueprint maps to ~200 atomic tasks:

```
PHASE 1 TASKS (Foundation) — ~60 tasks
──────────────────────────────────────
  Infrastructure (10 tasks)
    001  Initialize packages/hub with Next.js 15 + App Router
    002  Configure Tailwind CSS + shadcn/ui
    003  Configure TypeScript strict + path aliases
    004  Configure Drizzle ORM + Neon connection
    005  Create drizzle.config.ts + migration scripts
    006  Configure NextAuth.js v5 (Google + GitHub)
    007  Set up Vitest for packages/hub
    008  Set up Playwright for E2E
    009  Create base layout (Navbar + Footer)
    010  Configure environment variables schema (Zod)

  Data Model (12 tasks)
    011  Schema: users table (with guest support)
    012  Schema: orgs table
    013  Schema: agents table (with conversation_starters)
    014  Schema: scan_reports table
    015  Schema: reviews table
    016  Schema: sessions table
    017  Schema: chat_messages table
    018  Schema: billing_events table
    019  Schema: agent_requests + request_votes tables
    020  Generate initial migration
    021  Seed script: 20 agents with fake trust data
    022  Type-safe query helpers (agents, users, requests)

  API Routes (12 tasks)
    023  GET /api/agents (search, filter, sort, paginate)
    024  GET /api/agents/[slug] (detail + trust card)
    025  POST /api/guest (anonymous token)
    026  POST /api/auth/upgrade-guest
    027  POST /api/requests (submit + auto-categorize)
    028  GET /api/requests (list, sorted by votes)
    029  POST /api/requests/[id]/vote
    030  GET /api/agents/[slug]/reviews
    031  POST /api/agents/[slug]/reviews
    032  Auth middleware (guest + signed-in)
    033  Rate limiting middleware
    034  Error handling middleware

  UI Components (16 tasks)
    035  AgentCard component (simplified: icon, name, desc, shield, Use)
    036  TrustBadge component (green/yellow/red shield)
    037  AgentGrid component (responsive card grid)
    038  SearchBar component (with empty state → request)
    039  CategoryPills component (horizontal scrollable)
    040  ChatPanel component (slide-up overlay shell)
    041  TrustCard component (detail page verification card)
    042  ReviewList component
    043  RequestCard component (vote button + count)
    044  RequestForm component (single input + submit)
    045  Navbar component (logo, publish, sign in)
    046  Footer component
    047  ProgressiveAuthPrompt component (gentle sign-in)
    048  MobileNav component (hamburger menu)
    049  LoadingSkeleton components (cards, detail, list)
    050  EmptyState components (no results, no history)

  Pages (8 tasks)
    051  Homepage (search + categories + agent grid)
    052  Browse page (/browse with filters)
    053  Agent detail page (/agent/[slug])
    054  Requests page (/requests)
    055  Auth pages (/auth/login)
    056  404 page
    057  About page (/about — how it works)
    058  Legal pages (terms, privacy — template)

  Integration + Polish (2 tasks)
    059  Wire all pages to API routes + test E2E
    060  Deploy to Vercel + Neon + verify production
```

### 13.6 The Forge Orchestrator (Code)

The orchestrator is a Node.js script that runs the entire loop:

```typescript
// packages/forge/src/orchestrator.ts

interface ForgeTask {
  id: string;
  title: string;
  specReference: string;        // Blueprint section reference
  specText: string;             // Extracted spec text
  filesToCreate: string[];
  filesToModify: string[];
  testFiles: string[];
  dependsOn: string[];
  acceptanceCriteria: string[];
  contextFiles: string[];
  status: 'pending' | 'building' | 'validating' | 'passed' | 'failed' | 'blocked';
  attempts: number;
  maxAttempts: number;          // Default: 5
}

interface ForgeConfig {
  blueprintPath: string;         // docs/SENTINEL_HUB_BLUEPRINT.md
  workspacePath: string;         // packages/hub
  llmProvider: 'anthropic' | 'openai';
  llmModel: string;             // claude-sonnet-4-20250514, gpt-4o, etc.
  sandboxImage: string;         // forge-sandbox:latest
  checkpointInterval: number;   // Tasks between human reviews (default: 10)
  maxConcurrentTasks: number;   // 1 for now (sequential)
  gitBranch: string;            // forge/phase-1
}

// Main loop:
// 1. Load task queue
// 2. Pick next ready task (all deps satisfied)
// 3. Spin up sandbox
// 4. Send task + context to Builder LLM
// 5. Write files to sandbox
// 6. Run validation pipeline
// 7. If PASS → git commit → mark complete → next task
// 8. If FAIL → send errors to Builder → retry (up to maxAttempts)
// 9. If BLOCKED → alert human
// 10. If checkpoint → create PR → wait for human approval
```

### 13.7 Context Management

The hardest problem in autonomous coding is context. A task at position 47 needs to know what tasks 1-46 built. Here's how Forge manages this:

```
CONTEXT WINDOW FOR EACH TASK:

1. SPEC CONTEXT (always included)
   - The relevant section(s) of the blueprint
   - The task's acceptance criteria
   - A summary of the full blueprint structure

2. CODE CONTEXT (rolling window)
   - Full file tree of packages/hub/ (paths only)
   - Content of files the task will modify
   - Content of files the task depends on
   - Type definitions from recently created files

3. PATTERN CONTEXT (extracted from completed tasks)
   - "Here's how the previous API route was structured"
   - "Here's the naming convention used for components"
   - "Here's the Drizzle query pattern used in other files"
   Auto-extracted by scanning the last 5 completed tasks.

4. ERROR CONTEXT (on retries only)
   - The exact error output from the validation pipeline
   - The code that caused the failure
   - "Previous attempt failed because: {reason}. Fix this specific issue."

CONTEXT SIZE BUDGET:
   Total context per task: ~80K tokens max
   - Spec: ~10K
   - Code: ~40K
   - Patterns: ~10K  
   - Errors: ~20K (retries)
```

### 13.8 How Forge Bootstraps Itself

Forge itself needs to be built. Here's the bootstrap sequence:

```
STAGE 0: MANUAL (human does this once)
  - Create packages/forge/ directory
  - Write ForgeConfig type + orchestrator skeleton
  - Write Dockerfile for sandbox
  - Write validation pipeline scripts
  - Set up LLM API keys
  Estimated: ~1 day of manual work

STAGE 1: FORGE PLANS ITSELF
  - Feed the blueprint into the Planner LLM
  - Generate full task queue (~200 tasks)
  - Human reviews and adjusts task ordering
  - Save to packages/forge/tasks/phase-1.json

STAGE 2: FORGE BUILDS HUB
  - Run orchestrator: npx forge run --phase 1
  - Forge executes tasks 001-060 autonomously
  - Human reviews PR at checkpoints
  - Phase 1 complete → deployed marketplace frontend

STAGE 3: FORGE CONTINUES
  - Load phase-2.json tasks
  - Forge builds chat, publisher, runtime
  - Each phase builds on the previous
  
STAGE 4: FORGE IMPROVES ITSELF
  - Track which tasks fail most often → improve prompts
  - Track which validation gates catch most errors → tune
  - Forge learns patterns from its own output
```

### 13.9 Dogfooding: Forge as a Sentinel Hub Agent

Here's the recursive beautiful part: **Forge itself becomes an agent on Sentinel Hub.**

```
Once Sentinel Hub is built:
  → Forge is published as "Code Builder Agent" on the marketplace
  → Anyone can use Forge to build THEIR project
  → They upload a blueprint → Forge decomposes + builds
  → Trust-verified, sandboxed, audited
  → Sentinel Hub built Sentinel Hub, and now builds for others

This is the ultimate product-market fit:
  Sentinel Hub = marketplace for AI agents
  Forge = the AI agent that built the marketplace
  → listed ON the marketplace it built
  → used BY other people to build THEIR products
```

### 13.10 What Forge Replaces vs. What Humans Still Do

```
FORGE DOES:                              HUMANS DO:
──────────────────────────────────────────────────────────────
✅ Write boilerplate code                 ✅ Write the blueprint (spec)
✅ Create DB schemas from spec            ✅ Approve PRs at checkpoints
✅ Write API routes from spec             ✅ Make design decisions not in spec
✅ Write React components from wireframes ✅ Handle tasks Forge gets stuck on
✅ Write tests for each task              ✅ Tune acceptance criteria
✅ Fix its own type errors                ✅ User testing + feedback
✅ Fix its own test failures              ✅ Deploy to production
✅ Run security scans                     ✅ Marketing + launch
✅ Validate against blueprint             ✅ Customer support
✅ Generate migrations                    ✅ Infrastructure decisions
✅ Commit code with proper messages       ✅ Monitoring + incident response
```

### 13.11 Forge Tech Stack

| Component | Technology | Why |
|---|---|---|
| Orchestrator | Node.js + TypeScript | Same stack as the monorepo |
| Task storage | JSON files in repo (tasks/*.json) | Simple, version-controlled, editable |
| Sandbox | Docker (node:20-alpine + workspace) | Reproducible, isolated, disposable |
| Builder LLM | Claude Sonnet (primary), GPT-4o (fallback) | Best at code generation + following specs |
| Planner LLM | Claude Opus | Best at decomposition + reasoning |
| Spec checker LLM | Claude Haiku (cheap, fast) | PASS/FAIL decisions, run on every task |
| Git | Standard git CLI in sandbox | Forge commits to a branch per phase |
| CI | GitHub Actions (existing) | PRs trigger existing test pipeline |
| Dashboard | Simple HTML page served by Forge | Status, progress, logs |

### 13.12 File Structure

```
packages/forge/
├── src/
│   ├── orchestrator.ts          # Main loop
│   ├── planner.ts               # Blueprint → task decomposition
│   ├── builder.ts               # LLM agent that writes code
│   ├── sandbox.ts               # Docker container management
│   ├── validator.ts             # 6-gate validation pipeline
│   ├── context.ts               # Rolling context management
│   ├── git.ts                   # Git operations (commit, branch, PR)
│   └── dashboard.ts             # Progress dashboard (HTTP server)
├── tasks/
│   ├── phase-1.json             # 60 tasks for Phase 1
│   ├── phase-2.json             # Tasks for Phase 2
│   └── ...
├── prompts/
│   ├── planner-system.md        # System prompt for Planner
│   ├── builder-system.md        # System prompt for Builder
│   ├── spec-checker-system.md   # System prompt for spec validator
│   └── retry-template.md        # Template for retry prompts
├── sandbox/
│   ├── Dockerfile               # Dev sandbox image
│   └── validate.sh              # Validation pipeline script
├── package.json
├── tsconfig.json
└── README.md
```

### 13.13 Running Forge

```bash
# One-time setup
cd packages/forge
npm install
docker build -t forge-sandbox ./sandbox

# Plan: generate tasks from blueprint
npx forge plan --blueprint ../docs/SENTINEL_HUB_BLUEPRINT.md --phase 1
# Outputs: tasks/phase-1.json (human reviews + edits)

# Build: run the autonomous loop
npx forge run --phase 1 --model claude-sonnet-4-20250514
# Forge works through all tasks, commits to forge/phase-1 branch
# Creates PR every 10 tasks for human review

# Monitor: watch progress
npx forge dashboard
# Opens http://localhost:4000 with live status

# Resume: if interrupted
npx forge run --phase 1 --resume
# Picks up from last completed task
```

## Appendix A: Key Open Questions

| Question | Options | Recommendation |
|---|---|---|
| LLM for chat orchestration? | OpenAI, Anthropic, bring-your-own | Start with OpenAI (GPT-4o). Let users BYOK later |
| Container runtime? | Docker, Firecracker, gVisor, Fly Machines | Fly Machines for MVP (cheapest). K8s for scale |
| How to handle MCP stdio servers? | Container with proxy | MCP Proxy inside container bridges stdio→HTTP |
| How do users get chat context? | Hub provides system prompt + user message routing | Hub wraps MCP in a thin chat layer (system prompt + tool routing) |
| Domain? | sentinel-hub.com, hub.sentinel-atl.com, sentinelhub.ai | sentinelhub.ai if available |

---

## Appendix B: File Structure (packages/hub)

```
packages/hub/
├── src/
│   ├── app/
│   │   ├── (marketing)/        # Public pages (not auth-gated)
│   │   │   ├── page.tsx        # Homepage
│   │   │   ├── browse/
│   │   │   ├── agent/[slug]/
│   │   │   └── categories/
│   │   ├── (app)/              # Auth-gated app pages
│   │   │   ├── dashboard/
│   │   │   ├── publish/
│   │   │   ├── chat/[slug]/
│   │   │   └── admin/
│   │   ├── api/                # API routes
│   │   │   ├── agents/
│   │   │   ├── auth/
│   │   │   ├── chat/
│   │   │   ├── publish/
│   │   │   ├── sessions/
│   │   │   └── billing/
│   │   ├── layout.tsx
│   │   └── globals.css
│   ├── components/
│   │   ├── ui/                 # shadcn/ui primitives
│   │   ├── agent/
│   │   │   ├── AgentCard.tsx
│   │   │   ├── AgentGrid.tsx
│   │   │   ├── TrustBadge.tsx
│   │   │   ├── TrustCard.tsx
│   │   │   └── ToolList.tsx
│   │   ├── chat/
│   │   │   ├── ChatWindow.tsx
│   │   │   ├── MessageBubble.tsx
│   │   │   ├── ToolCallDisplay.tsx
│   │   │   ├── ApprovalPrompt.tsx
│   │   │   └── SessionSidebar.tsx
│   │   ├── publish/
│   │   │   ├── SourcePicker.tsx
│   │   │   ├── ScanProgress.tsx
│   │   │   ├── ScanReport.tsx
│   │   │   └── ListingForm.tsx
│   │   ├── dashboard/
│   │   │   ├── UsageChart.tsx
│   │   │   ├── AuditTable.tsx
│   │   │   └── BillingCard.tsx
│   │   └── layout/
│   │       ├── Navbar.tsx
│   │       ├── Footer.tsx
│   │       └── Sidebar.tsx
│   ├── lib/
│   │   ├── db/
│   │   │   ├── index.ts         # Drizzle client
│   │   │   ├── schema.ts        # All table definitions
│   │   │   └── queries.ts       # Type-safe query helpers
│   │   ├── auth.ts              # NextAuth configuration
│   │   ├── sentinel.ts          # Sentinel package integrations
│   │   ├── runtime.ts           # Container orchestration
│   │   ├── chat-relay.ts        # WebSocket manager
│   │   ├── scanner-worker.ts    # Async scan job processor
│   │   ├── stripe.ts            # Billing integration
│   │   └── constants.ts         # Categories, trust grades, etc.
│   ├── hooks/
│   │   ├── useChat.ts
│   │   ├── useSession.ts
│   │   └── useAgent.ts
│   └── types/
│       └── index.ts             # Shared TypeScript types
├── drizzle/
│   ├── 0000_initial.sql
│   └── meta/
├── public/
│   ├── logo.svg
│   └── og-image.png
├── package.json
├── next.config.ts
├── tailwind.config.ts
├── drizzle.config.ts
├── tsconfig.json
├── Dockerfile                   # For self-hosted deployment
└── README.md
```

---

**This blueprint is the single source of truth for building Sentinel Hub.**  
**Ready to execute Phase 1.**
