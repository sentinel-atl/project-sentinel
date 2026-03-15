# 🛡️ Project Sentinel: The Agent Trust Layer (ATL)

## 1. The Core Problem: The "Wild West" of Agent Interaction

As AI agents move from isolated tools to autonomous economic actors, they face a fundamental security gap: **they have no way to prove who they are, who they represent, or why they can be trusted.**

Current AI workflows suffer from:

- **Identity Impersonation:** No standard for verifying if "Agent B" is a legitimate service or a malicious script.
- **Credential Sprawl:** Agents often use static, long-lived API keys, which are high-risk if the agent is compromised.
- **Recursive Delegation Risk:** When an agent hires a "sub-agent," the original user's intent and permissions are often lost or over-shared.
- **The Reputation Vacuum:** There is no "credit score" for agents to track their reliability, accuracy, or safety history.

---

## 2. The Solution: A Lightweight Trust Network

An **open-source, decentralized protocol** for Agent Identity (AID) and Reputation (ARep).

### Key Pillars

| Pillar | Description |
|---|---|
| **Self-Sovereign Identity (SSI)** | Decentralized Identifiers (DIDs) so agents own their identity without a central gatekeeper. |
| **Verifiable Credentials (VCs)** | Cryptographic "badges" proving capabilities or compliance (e.g., "SOC2 Compliant," "Authorized by User X"). |
| **Proof of Intent** | A protocol binding every agent action to a specific, signed user request — preventing scope creep. |
| **Gossip-based Reputation** | A lightweight network where agents vouch for each other based on successful task completion. |

---

## 3. Technical Architecture

### 3.1 Identity Layer

- **DID Method:** Start with `did:key` (Ed25519) for simplicity and statelessness in v0. Add `did:peer` in Phase 2 for pairwise, session-scoped relationships.
- **Key Storage:** OS-native keychain (macOS Keychain / Windows DPAPI / Linux Secret Service) for private keys. No plaintext key files.
- **DID Document:** Minimal, auto-generated from the public key. Contains verification method + service endpoints.

```
did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP
```

### 3.2 Verifiable Credentials (VCs)

VCs follow the [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/).

**Example VC — Agent Authorization:**

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "AgentAuthorizationCredential"],
  "issuer": "did:key:z6Mkf5r...principal",
  "credentialSubject": {
    "id": "did:key:z6Mkq9w...agent",
    "scope": ["read:email", "send:calendar_invite"],
    "maxDelegationDepth": 1,
    "expiry": "2026-03-16T00:00:00Z"
  },
  "proof": { "type": "Ed25519Signature2020", "..." : "..." }
}
```

**Credential Types (v0):**

| Type | Issuer | Purpose |
|---|---|---|
| `AgentAuthorizationCredential` | Human principal | Grants scoped permissions to an agent |
| `DelegationCredential` | Parent agent | Allows sub-agent to act within parent's scope |
| `ComplianceCredential` | Auditor/registry | Attests to security posture (SOC2, etc.) |
| `ReputationCredential` | Peer agents | Vouches for reliability after task completion |

### 3.3 Proof of Intent Protocol

Every agent action is bound to a signed **Intent Envelope**:

```json
{
  "intentId": "uuid-v7",
  "action": "book_flight",
  "scope": ["travel:book", "payment:authorize_up_to_500"],
  "principalDid": "did:key:z6Mkf5r...principal",
  "agentDid": "did:key:z6Mkq9w...agent",
  "delegationChain": ["vc:...auth", "vc:...delegation"],
  "expiry": "2026-03-15T23:59:59Z",
  "nonce": "random-32-bytes-hex",
  "signature": "base64url(...)"
}
```

**Rules:**
- Every downstream sub-agent call MUST include the full `delegationChain`.
- Scope can only be **narrowed**, never widened, at each delegation hop.
- `maxDelegationDepth` prevents unbounded recursive delegation.
- `nonce` + `expiry` prevent replay attacks.

### 3.4 Handshake Protocol (Zero-Trust "Hello")

```
Agent A                          Agent B
   |                                |
   |-- 1. HandshakeInit ----------->|   (protocol_version + A's DID + supported VC types + nonce + timestamp)
   |                                |
   |<- 2. HandshakeResponse --------|   (protocol_version + B's DID + requested VCs + B's nonce + timestamp)
   |                                |
   |-- 3. VCExchange ------------->|   (A's VCs matching B's request, signed with A's nonce, channel_binding_token)
   |                                |
   |<- 4. VCExchange --------------|   (B's VCs matching A's request, signed with B's nonce, channel_binding_token)
   |                                |
   |-- 5. SessionEstablished ----->|   (Shared session key via X25519 DH, encrypted channel, TLS channel binding)
```

**Handshake Rules:**
- Both agents MUST verify all VCs before proceeding.
- Either side can abort if trust requirements aren't met.
- Session keys are ephemeral — rotated per interaction.
- **Protocol Versioning:** `HandshakeInit` includes `protocol_version`. Agents negotiate the highest mutually supported version. Unknown versions trigger graceful fallback or rejection — never silent downgrade.
- **Channel Binding:** Session key is bound to the underlying TLS channel via `tls-exporter` (RFC 9266) to prevent session migration/hijacking.
- **Timeout:** Handshake MUST complete within 5 seconds. Each step has a 2-second deadline. Timeout triggers clean abort + audit log entry.
- **Rate Limiting:** Agents MUST enforce per-DID rate limits on `HandshakeInit` (default: 10/minute). Exceeding the limit returns `429` with `Retry-After`. This prevents handshake-based DDoS.
- **Clock Tolerance:** Timestamps in handshake messages are validated with a ±30-second skew window. Messages outside this window are rejected.

### 3.5 Agent Passport (Machine-Readable Trust Profile)

Canonical format: **JSON-LD** (aligns with VC ecosystem). An `AGENTS.md` renderer is provided for human readability.

```json
{
  "@context": ["https://sentinel-protocol.org/v1"],
  "did": "did:key:z6Mkq9w...agent",
  "name": "TravelBookerAgent",
  "version": "1.2.0",
  "capabilities": ["flight_search", "hotel_booking", "payment_processing"],
  "requiredCredentials": ["AgentAuthorizationCredential"],
  "offeredCredentials": ["ComplianceCredential:SOC2"],
  "trustRoots": ["did:key:z6Mkf5r...company_root"],
  "maxDelegationDepth": 2,
  "endpoints": {
    "handshake": "https://agent.example.com/.well-known/sentinel/handshake",
    "reputation": "https://agent.example.com/.well-known/sentinel/reputation"
  }
}
```

### 3.6 Reputation System

**Scoring Model:**
- **Vouches:** After successful task completion, agents issue `ReputationCredential` vouches.
- **Weighted Score:** `reputation = Σ(vouch_weight × time_decay × voucher_reputation)`.
- **Time Decay:** Exponential decay (half-life: 90 days) — stale vouches lose influence.
- **Sybil Resistance:** Vouches from agents with `AgentAuthorizationCredential` issued by verified human principals carry higher weight. New/unverified agents have capped influence.
- **Cold Start:** New agents start at a neutral score. First N interactions are flagged as "unrated" to peers.

**Negative Reputation & Warnings:**
- Agents can issue `NegativeReputationCredential` after failed/harmful interactions (e.g., timeout, incorrect output, scope violation).
- Negative vouches carry 2x weight vs. positive vouches to bias toward safety.
- `NegativeReputationCredential` includes a machine-readable `reason` enum: `timeout | incorrect_output | scope_violation | content_safety | unresponsive | data_leak`.
- Three or more negative vouches from independent principal-verified agents triggers automatic **quarantine**: the agent is flagged in the registry and peers receive a warning before handshake.

**Rate Limits on Vouch Issuance:**
- An agent may issue at most **1 vouch per unique peer per 24-hour window**.
- Burst vouch patterns (>10 vouches/hour) trigger anomaly flagging and temporary vouch suppression.
- Self-vouching (vouch for own DID or DIDs sharing the same `trustRoot`) is cryptographically rejected.

### 3.7 MCP Integration Point

Identity verification hooks into MCP at the **tool-call boundary**:

```
User → Agent A → MCP tool_call → [SENTINEL CHECK] → Tool Execution
                                      ↓
                              1. Verify Agent A's DID
                              2. Validate Intent Envelope + delegation chain
                              3. Check scope covers requested tool
                              4. Query reputation (optional, configurable threshold)
                              5. Proceed or reject
```

---

## 4. Threat Model

| Threat | Mitigation |
|---|---|
| **Replay Attack** | Nonce + expiry on every Intent Envelope and handshake message. ±30s clock skew tolerance. |
| **VC Theft** | VCs are bound to DID; useless without the corresponding private key to complete handshake. Short-lived expiry windows. |
| **Reputation Collusion** | Sybil-weighted scoring; vouches from unverified agents are capped. Anomaly detection on vouch patterns. Rate-limited vouch issuance (+self-vouch rejection). |
| **Compromised Sub-Agent** | `maxDelegationDepth` limits blast radius. Scope narrowing prevents privilege escalation. Delegation chain is auditable. Emergency revocation kills active sessions. |
| **Key Compromise** | Key rotation via DID document updates. Revocation list for compromised DIDs. Key backup/recovery via Shamir's Secret Sharing. HSM support for high-value agents. |
| **Man-in-the-Middle** | Handshake establishes encrypted channel via X25519 DH. All messages signed. TLS channel binding (RFC 9266) prevents session migration. |
| **Scope Creep** | Intent Envelope strictly defines allowed actions. Validators reject out-of-scope requests. Step-up auth for sensitive actions. |
| **Tampered Agent Runtime** | Code attestation via signed manifest hash. Agent Passport includes `codeHash` field. Verifiers can optionally require attestation before handshake. |
| **Session Hijacking** | Channel binding ties session key to TLS connection. Session tokens are non-transferable. |
| **Handshake DDoS** | Per-DID rate limiting on `HandshakeInit` (10/min default). Exponential backoff on repeated failures. |
| **Reputation Wash-Trading** | 1 vouch per peer per 24h. Burst detection flags anomalous patterns. Negative vouches carry 2x weight. |
| **Runaway Agent** | Emergency kill switch: principal can broadcast revocation that terminates all active sessions within propagation window (<5s target). |
| **Content Safety Abuse** | Optional content safety hooks at Sentinel checkpoint. Configurable per-deployment (not part of core protocol, but SDK provides integration point). |
| **PII Leakage via DIDs/VCs** | DIDs are pseudonymous (no PII in `did:key`). VCs use selective disclosure (BBS+ signatures in Phase 2). Reputation data is aggregated, not individually attributable. |
| **Clock Skew Exploitation** | ±30s tolerance window on all timestamp checks. Handshake includes mutual timestamp exchange for drift detection. |
| **Identity Loss (Key Loss)** | Shamir's Secret Sharing (3-of-5 threshold) for key recovery. Social recovery via trusted principal group. |

---

## 5. Authentication Hardening

### 5.1 Agent Code Attestation

Verifying the key is not enough — we must verify the **code** holding the key.

- Agent Passport gains a `codeHash` field: SHA-256 of the agent's signed deployment artifact.
- At handshake, the verifier MAY request the agent to present a `CodeAttestationCredential` binding `did` → `codeHash` → `buildSignature`.
- For containerized agents: hash the container image digest. For serverless: hash the deployment bundle.
- This is **optional in v0** (not all environments support it) but **required for high-trust tiers** (payment, medical, legal).

### 5.2 Hardware Security Module (HSM) Support

- v0 uses OS keychain (software). This is acceptable for development and low-risk agents.
- **High-value agents** (financial, healthcare, legal) MUST support hardware-backed keys:
  - **macOS:** Secure Enclave via `Security.framework`
  - **Cloud:** AWS CloudHSM, Azure Managed HSM, GCP Cloud KMS
  - **On-prem:** PKCS#11 interface to hardware tokens (YubiHSM, Thales Luna)
- The `core` package abstracts key operations behind a `KeyProvider` interface so backends are swappable without changing protocol logic.

### 5.3 Step-Up Authentication

Not all actions within a scope are equal. A `read:email` scope doesn't mean `delete:email` should pass silently.

- VCs can include a `sensitivityLevel` field: `low | medium | high | critical`.
- Actions tagged `high` or `critical` trigger **step-up auth**: the agent must re-verify with the principal (via WebAuthn/passkey challenge) before proceeding.
- Step-up auth results are cached for a configurable window (default: 5 minutes) to avoid friction on sequential operations.

### 5.4 Key Backup & Recovery

- **Shamir's Secret Sharing (SSS):** Private key is split into 5 shares with a 3-of-5 reconstruction threshold.
- Shares are distributed to the principal's trusted parties (e.g., other devices, trusted colleagues, cold storage).
- Recovery is an **offline-first** process — no network call required to reconstruct.
- A recovered key generates a new DID document version, invalidating old sessions but preserving VC history.

---

## 6. Safety Framework

### 6.1 Audit Logging Specification

Every Sentinel event MUST be logged in a structured, append-only audit trail.

**Log Schema (JSON Lines):**

```json
{
  "timestamp": "2026-03-15T14:30:00.000Z",
  "eventType": "handshake_init | handshake_complete | handshake_failed | vc_issued | vc_verified | vc_revoked | intent_validated | intent_rejected | session_created | session_terminated | reputation_vouch | reputation_negative | emergency_revoke",
  "actorDid": "did:key:z6Mk...",
  "targetDid": "did:key:z6Mk...",
  "intentId": "uuid-v7 (if applicable)",
  "result": "success | failure",
  "reason": "human-readable reason on failure",
  "metadata": {}
}
```

**Rules:**
- Logs are **append-only**. No mutation or deletion.
- Default retention: **90 days** locally, configurable.
- Logs MUST NOT contain private keys, VC proof values, or session keys.
- Log integrity is protected by a hash chain (each entry includes `prevHash`).

### 6.2 Emergency Revocation (Kill Switch)

A human principal MUST be able to instantly revoke an agent's authority:

1. **`sentinel revoke --did <agent_did> --emergency`** — signs a revocation broadcast.
2. The revocation is pushed to the gossip network AND directly to any known active session peers.
3. On receiving an emergency revocation, agents MUST:
   - Terminate all active sessions with the revoked DID within **<5 seconds**.
   - Reject any new handshake attempts from the revoked DID.
   - Log the event.
4. Revocations are **irrecoverable** for the revoked DID. The agent must generate a new identity and obtain fresh VCs.

### 6.3 Content Safety Integration

The trust layer verifies *identity and authorization*, not *content*. However, the SDK provides **hooks** for content safety:

- **Pre-dispatch hook:** Inspect payloads before they reach the tool. Integrates with Azure Content Safety, OpenAI Moderation, or custom classifiers.
- **Post-response hook:** Inspect tool outputs before returning to the calling agent.
- These hooks are **opt-in per deployment** — not part of the core protocol — but the SDK makes integration a one-liner.
- Agents that enable content safety hooks can advertise `ContentSafetyCompliant` in their passport.

### 6.4 Privacy & Data Minimization

- **DIDs are pseudonymous:** `did:key` contains no PII — only a public key.
- **Selective Disclosure:** Phase 2 introduces BBS+ signatures for VCs, allowing agents to prove specific claims without revealing the full credential.
- **Reputation is aggregated:** Peers see a score, not individual vouch details. Vouch provenance is only revealed during dispute resolution.
- **Right to Erasure:** An agent can request deletion of its reputation data from the gossip network. Nodes SHOULD honor this within 30 days (aligns with GDPR Article 17).
- **Data Residency:** The SDK supports configurable data residency — reputation data can be pinned to specific geographic nodes.

---

## 7. Reliability Engineering

### 7.1 Clock Synchronization & Skew Handling

Expiry-based security is only as good as the clocks involved.

- All timestamp comparisons use a **±30-second tolerance window**.
- Handshake messages include both parties' timestamps; drift >30s triggers a `CLOCK_SKEW_WARNING` in the response (non-fatal but logged).
- Agents SHOULD use NTP or a platform-provided time source. The SDK emits a warning at startup if system clock drift exceeds 5 seconds from a reference.

### 7.2 Offline & Degraded Mode

The trust layer MUST NOT become a single point of failure.

| Scenario | Behavior |
|---|---|
| **Reputation registry unreachable** | Fall back to **local VC verification only**. Reputation score is marked `"source": "cached"` or `"unavailable"`. Policy decides if this is acceptable (configurable: `allow | warn | deny`). |
| **Revocation list unreachable** | Use last-known cached revocation list (max staleness: 1 hour, configurable). Log a `REVOCATION_STALE` warning. |
| **Gossip network partitioned** | Agents operate on local state. On reconnection, deltas are merged using CRDT-style conflict resolution for reputation scores. |
| **Full offline mode** | Agents can complete handshakes using pre-cached VCs and local key material. No reputation data. Transactions are logged locally and synced on reconnect. |

### 7.3 Caching Strategy

- **VC Cache:** Verified VCs are cached locally with a TTL matching their expiry (or 1 hour, whichever is shorter).
- **Reputation Cache:** Scores are cached for 5 minutes (configurable). Cache-miss triggers an async refresh — the stale score is used immediately.
- **Revocation Cache:** Revocation lists are refreshed every 10 minutes. Emergency revocations bypass the cache via push notification.
- All caches use LRU eviction with a configurable max size (default: 10,000 entries).

### 7.4 Handshake Retry & Timeout Policy

```
Handshake timeout: 5 seconds total
Per-step timeout:  2 seconds
Retry attempts:    3 (with exponential backoff: 100ms, 500ms, 2000ms)
Circuit breaker:   After 5 consecutive failures to same DID → cool-off 60s
```

- Failed handshakes MUST NOT be silently retried forever — the circuit breaker prevents cascading failures in multi-agent chains.
- All retry/timeout values are configurable per-agent via the passport or SDK config.

### 7.5 Protocol Versioning

- Every protocol message includes a `version` field (semver: `major.minor`).
- **Minor versions** add optional fields and are backwards-compatible.
- **Major versions** are breaking. Agents negotiate the highest mutually supported major version during `HandshakeInit`.
- Agents MUST support the current version and MAY support one prior major version.
- Version deprecation is announced 6 months in advance via the spec changelog.

---

## 8. Tech Stack (v0)

| Component | Technology |
|---|---|
| Language | TypeScript (Node.js) — widest agent ecosystem compatibility |
| DID Library | `@digitalbazaar/did-method-key`, `@digitalbazaar/ed25519-verification-key-2020` |
| VC Library | `@digitalbazaar/vc` (W3C VC issuance/verification) |
| Crypto | Ed25519 (signing), X25519 (key agreement), via `@noble/ed25519` |
| Key Storage | OS keychain via `keytar` (v0); `KeyProvider` interface supports HSM/Secure Enclave backends |
| CLI Framework | `commander` + `chalk` |
| Transport | JSON-RPC over HTTPS (aligns with MCP transport) |
| Reputation Store | SQLite (local) → DHT/libp2p (Phase 2) |
| Audit Log | JSON Lines → append-only file with hash-chain integrity |
| Clock Sync | NTP reference check at startup via `ntp-time-sync` |
| Secret Sharing | `@noble/shamir` (Shamir's Secret Sharing for key recovery) |
| Testing | Vitest |

---

## 9. Why This Must Be Open Source

Trust cannot be a proprietary product. For an A2A economy to flourish, the identity layer must be:

- **Neutral:** No single vendor controls the "Agent Yellow Pages."
- **Interoperable:** Works across OpenAI, Anthropic, Google, and local LLM frameworks.
- **Auditable:** The community can verify that trust logic is secure and unbiased.

**License:** Apache 2.0

---

## 10. Roadmap

### Phase 1: Foundation (Weeks 1–6)

| Milestone | Deliverable |
|---|---|
| **1a. DID Generation** | CLI tool: `sentinel init` → generates Ed25519 keypair, stores in OS keychain, outputs `did:key`. |
| **1b. Message Signing** | CLI tool: `sentinel sign <message>` → signs with agent's private key; `sentinel verify <message> <sig> <did>` → verifies. |
| **1c. VC Issuance** | CLI tool: `sentinel issue-vc --type AgentAuthorization --subject <did> --scope read:email` → issues signed VC. |
| **1d. VC Verification** | CLI tool: `sentinel verify-vc <vc.json>` → validates signature, expiry, and issuer chain. |
| **1e. Handshake Demo** | Two local agents perform the full handshake protocol with versioning, channel binding, rate limiting, and timeouts. |
| **1f. Audit Logging** | Structured append-only audit log with hash-chain integrity for all Sentinel events. |
| **1g. Key Backup** | `sentinel backup-key` → Shamir's Secret Sharing (3-of-5 split). `sentinel recover-key` → reconstruction. |
| **1h. Spec Document** | Published AID specification v0.1 covering identity, handshake, intent, and audit log formats. |

### Phase 2: Trust & Safety Network (Weeks 7–14)

| Milestone | Deliverable |
|---|---|
| **2a. Reputation Engine** | Local reputation scoring with SQLite. Positive and negative vouch issuance. Rate limits on vouching. |
| **2b. Trust Registry** | Decentralized registry via libp2p gossip protocol. Agents advertise passports and discover peers. |
| **2c. Delegation Chains** | Full recursive delegation with scope narrowing, depth limits, and step-up auth for sensitive actions. |
| **2d. Revocation** | DID and VC revocation lists. Emergency kill switch. Key rotation support. |
| **2e. Privacy Layer** | BBS+ selective disclosure for VCs. Aggregated reputation with no individual vouch exposure. |
| **2f. Offline Mode** | Degraded mode with cached VCs/reputation. CRDT-based reputation merge on reconnect. |
| **2g. Code Attestation** | `CodeAttestationCredential` binding agent DID to verified code hash. |

### Phase 3: Ecosystem Integration (Weeks 15–20)

| Milestone | Deliverable |
|---|---|
| **3a. MCP Plugin** | Sentinel middleware for MCP servers — identity check at tool-call boundary with full Sentinel pipeline. |
| **3b. SDK** | `@sentinel/sdk` npm package for agent developers to add trust in ~5 lines of code. Includes content safety hooks. |
| **3c. Dashboard** | Web UI to visualize trust graphs, reputation scores, delegation chains, and audit logs. |
| **3d. Multi-Framework** | Adapters for LangChain, CrewAI, AutoGen, and OpenAI Agents SDK. |
| **3e. HSM Backends** | `KeyProvider` implementations for Secure Enclave, AWS CloudHSM, Azure Managed HSM, PKCS#11. |

---

## 11. Project Structure (Target)

```
project-sentinel/
├── packages/
│   ├── core/              # DID, VC, crypto primitives, KeyProvider interface
│   ├── cli/               # sentinel CLI tool
│   ├── handshake/         # Handshake protocol (versioned, channel-bound)
│   ├── reputation/        # Scoring engine + negative vouches + rate limits
│   ├── audit/             # Structured logging, hash-chain integrity
│   ├── recovery/          # Shamir's Secret Sharing key backup/recovery
│   ├── mcp-plugin/        # MCP integration middleware
│   └── sdk/               # Developer-facing SDK (includes content safety hooks)
├── specs/
│   ├── aid-spec-v0.1.md   # Agent Identity Document spec
│   ├── handshake-spec.md  # Handshake protocol spec (versioning, timeouts, rate limits)
│   ├── intent-spec.md     # Proof of Intent spec
│   ├── audit-spec.md      # Audit log format + integrity spec
│   └── reputation-spec.md # Reputation scoring, negative vouches, privacy
├── examples/
│   ├── two-agent-handshake/
│   ├── mcp-with-sentinel/
│   ├── emergency-revocation/
│   └── offline-degraded-mode/
├── docs/
│   ├── threat-model.md
│   └── privacy-policy.md
├── package.json
├── turbo.json
└── README.md
```
