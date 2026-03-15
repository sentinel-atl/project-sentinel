# 🛡️ Project Sentinel

**The Agent Trust Layer — identity, credentials, and reputation for AI agents.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7+-3178C6.svg)]()
[![Protocol Version](https://img.shields.io/badge/Protocol-v1.0-green.svg)]()

---

## The Problem

AI agents are becoming autonomous economic actors — booking flights, processing payments, hiring sub-agents. But they have **no way to prove who they are, who they represent, or why they can be trusted.**

- **A2A** (Google) defines how agents **talk**. It does not define how they **trust**.
- **MCP** (Anthropic) defines how agents **use tools**. It has no identity layer.
- Existing agent identity projects cover **fragments** — a DID here, a credential there. Nobody has the **full trust pipeline**.

Sentinel fills the gap.

## What Sentinel Does (That Nobody Else Does)

| Capability | Sentinel | A2A | MCP | Attestix | Clawdentity | Skytale |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| Agent Identity (DID) | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| Verifiable Credentials (W3C) | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Proof of Intent** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Zero-Trust Handshake | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Delegation Chains + Scope Narrowing | ✅ | ❌ | ❌ | Partial | ❌ | ❌ |
| Negative Reputation + Quarantine | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Emergency Kill Switch (<5s) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Step-Up Auth for Sensitive Actions | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Offline/Degraded Mode | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Tamper-Evident Audit Log | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| Key Recovery (Shamir) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

**Sentinel's unique insight:** Trust isn't just identity. It's the full chain from **human intent → agent authorization → scoped delegation → action execution → reputation feedback** — with every step cryptographically signed, time-bounded, and auditable.

## Quick Start

```bash
# Install
npm install @sentinel/cli -g

# Create your agent identity
sentinel init

# See your DID
sentinel whoami

# Sign a message
sentinel sign "hello world"

# Issue a Verifiable Credential
sentinel issue-vc \
  --type AgentAuthorization \
  --subject did:key:z6MkTarget... \
  --scope "read:email,send:calendar" \
  --max-delegation-depth 2 \
  --expires 24

# Verify a credential
sentinel verify-vc ./credential.json

# Create a Proof of Intent
sentinel create-intent \
  --action "book_flight" \
  --scope "travel:book,payment:authorize_up_to_500" \
  --principal did:key:z6MkHuman...

# Backup your key (Shamir 3-of-5)
sentinel backup-key

# Verify audit log integrity
sentinel audit verify
```

## How It Works

```
 Human Principal                    Agent A                     Agent B (Sub-Agent)
       │                              │                              │
       │ 1. Issue AuthVC              │                              │
       │  (scoped permissions)        │                              │
       │─────────────────────────────>│                              │
       │                              │                              │
       │ 2. "Book a flight to Tokyo"  │                              │
       │─────────────────────────────>│                              │
       │                              │                              │
       │                              │ 3. Create Intent Envelope    │
       │                              │  (action + scope + chain)    │
       │                              │                              │
       │                              │ 4. Zero-Trust Handshake      │
       │                              │  (mutual VC exchange)        │
       │                              │─────────────────────────────>│
       │                              │     ✓ Both verified          │
       │                              │<─────────────────────────────│
       │                              │                              │
       │                              │ 5. Delegate (narrowed scope) │
       │                              │  maxDelegationDepth: 0       │
       │                              │─────────────────────────────>│
       │                              │                              │
       │  6. Step-up auth             │                              │
       │  (if sensitivity: high)      │                              │
       │<─────────────────────────────────────────────────────────────│
       │  ✓ Approved via passkey      │                              │
       │──────────────────────────────────────────────────────────────>
       │                              │                              │
       │                              │ 7. Task complete             │
       │                              │<─────────────────────────────│
       │                              │                              │
       │                              │ 8. Reputation vouches        │
       │                              │<────────────────────────────>│
```

**Every arrow is cryptographically signed. Every step is audit-logged. Every scope narrows, never widens.**

## Packages

| Package | Description |
|---|---|
| [`@sentinel/core`](packages/core) | DID identity, Verifiable Credentials, Proof of Intent, Agent Passport, crypto primitives |
| [`@sentinel/handshake`](packages/handshake) | Zero-trust mutual verification with rate limiting, circuit breaker, clock tolerance |
| [`@sentinel/reputation`](packages/reputation) | Weighted scoring, negative vouches, Sybil resistance, quarantine |
| [`@sentinel/audit`](packages/audit) | Append-only hash-chain audit logging |
| [`@sentinel/recovery`](packages/recovery) | Shamir's Secret Sharing key backup (3-of-5 default) |
| [`@sentinel/revocation`](packages/revocation) | VC/DID revocation lists, key rotation, emergency kill switch |
| [`@sentinel/attestation`](packages/attestation) | Code attestation — cryptographic proof an agent runs verified code |
| [`@sentinel/stepup`](packages/stepup) | Step-up authentication — human re-approval for sensitive actions |
| [`@sentinel/mcp-plugin`](packages/mcp-plugin) | MCP middleware — identity-aware tool call gating (revocation + attestation) |
| [`@sentinel/sdk`](packages/sdk) | Developer SDK — 5-line integration with revocation, attestation, kill switch |
| [`@sentinel/cli`](packages/cli) | `sentinel` command-line tool |

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
│   ├── audit/          # Hash-chain audit logging
│   ├── recovery/       # Shamir's Secret Sharing
│   ├── revocation/     # VC/DID revocation, key rotation, kill switch
│   ├── attestation/    # Code attestation (bind DID → code hash)
│   ├── stepup/         # Step-up auth (human re-approval)
│   ├── mcp-plugin/     # MCP tool-call gating middleware
│   ├── sdk/            # Developer SDK (5-line integration)
│   └── cli/            # sentinel CLI tool
├── specs/              # Protocol specifications
├── examples/           # Working demos
└── docs/               # Threat model, privacy policy
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

Report vulnerabilities to: security@sentinel-protocol.org

## License

[Apache License 2.0](LICENSE)

---

**Built because trust cannot be a proprietary product.**
